// MeshLink: offline-first mesh chat for a LAN (hostel wifi, hotspot, router).
// Zero dependencies. Nodes find each other by UDP broadcast, link over TCP,
// flood signed messages with dedupe, gossip peer lists, sync history on connect.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	maxHistory = 5000
	syncCount  = 400
)

type Msg struct {
	ID   string `json:"id"`
	From string `json:"from"` // node public key (hex)
	Nick string `json:"nick"`
	Chan string `json:"chan"`
	Text string `json:"text"`
	TS   int64  `json:"ts"` // unix ms
	SOS  bool   `json:"sos,omitempty"`
	U    string `json:"u,omitempty"`  // sender browser pubkey (hex)
	To   string `json:"to,omitempty"` // recipient browser pubkey: private (E2E encrypted) message
	Sig  string `json:"sig"`
}

type Frame struct {
	T     string   `json:"t"`
	ID    string   `json:"id,omitempty"`
	Nick  string   `json:"nick,omitempty"`
	Port  int      `json:"port,omitempty"`
	Addrs []string `json:"addrs,omitempty"`
	M     *Msg     `json:"m,omitempty"`
	U     string   `json:"u,omitempty"`
	TTL   int      `json:"ttl,omitempty"`
}

type Peer struct {
	conn      net.Conn
	id, nick  string
	addr      string
	initiator string
	wmu       sync.Mutex
}

func (p *Peer) send(f Frame) error {
	b, _ := json.Marshal(f)
	b = append(b, '\n')
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := p.conn.Write(b)
	return err
}

type Person struct {
	Nick       string
	Seen, Refl time.Time
}

type Node struct {
	priv               ed25519.PrivateKey
	id, nick           string
	meshPort, httpPort int

	mu       sync.Mutex
	msgs     []Msg
	seen     map[string]bool
	peers    map[string]*Peer
	known    map[string]int // addr -> consecutive dial failures
	pinned   map[string]bool
	selfAddr map[string]bool
	dialing  map[string]bool
	backoff  map[string]time.Time
	subs     map[chan Msg]bool
	people   map[string]*Person
	logf     *os.File
}

// ---------- crypto / messages ----------

func payload(m Msg) []byte {
	parts := []string{m.From, m.Nick, m.Chan, m.Text, strconv.FormatInt(m.TS, 10), strconv.FormatBool(m.SOS)}
	if m.U != "" || m.To != "" {
		parts = append(parts, m.U, m.To)
	}
	return []byte(strings.Join(parts, "\x00"))
}

func (n *Node) newMsg(nick, ch, text, u, to string, sos bool) Msg {
	m := Msg{From: n.id, Nick: nick, Chan: ch, Text: text, TS: time.Now().UnixMilli(), SOS: sos, U: u, To: to}
	m.Sig = hex.EncodeToString(ed25519.Sign(n.priv, payload(m)))
	m.ID = m.Sig[:24]
	return m
}

func verify(m *Msg) bool {
	if len(m.From) != 64 || len(m.Sig) != 128 || m.ID != m.Sig[:24] {
		return false
	}
	if (m.U != "" && !isHex64(m.U)) || (m.To != "" && !isHex64(m.To)) {
		return false
	}
	if len(m.Text) > 8000 || len(m.Nick) > 200 || len(m.Chan) > 100 {
		return false
	}
	pub, err1 := hex.DecodeString(m.From)
	sig, err2 := hex.DecodeString(m.Sig)
	if err1 != nil || err2 != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload(*m), sig)
}

func isHex64(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}

func loadKey(dir string) ed25519.PrivateKey {
	p := filepath.Join(dir, "key.hex")
	if b, err := os.ReadFile(p); err == nil {
		if seed, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(p, []byte(hex.EncodeToString(priv.Seed())), 0600)
	return priv
}

// ---------- message store / fanout ----------

func (n *Node) load() {
	f, err := os.OpenFile(filepath.Join(dataDir, "messages.jsonl"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("warn: no persistence: %v", err)
		return
	}
	n.logf = f
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var m Msg
		if json.Unmarshal(sc.Bytes(), &m) == nil && verify(&m) && !n.seen[m.ID] {
			n.seen[m.ID] = true
			n.msgs = append(n.msgs, m)
		}
	}
	if len(n.msgs) > maxHistory {
		n.msgs = n.msgs[len(n.msgs)-maxHistory:]
	}
	log.Printf("loaded %d messages", len(n.msgs))
}

var dataDir string

// add stores a new message and floods it. Returns false if already seen.
func (n *Node) add(m Msg, from *Peer) bool {
	n.mu.Lock()
	if n.seen[m.ID] {
		n.mu.Unlock()
		return false
	}
	n.seen[m.ID] = true
	n.msgs = append(n.msgs, m)
	if len(n.msgs) > maxHistory {
		n.msgs = n.msgs[len(n.msgs)-maxHistory:]
	}
	if n.logf != nil {
		b, _ := json.Marshal(m)
		n.logf.Write(append(b, '\n'))
	}
	subs := make([]chan Msg, 0, len(n.subs))
	for c := range n.subs {
		subs = append(subs, c)
	}
	peers := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		if p != from {
			peers = append(peers, p)
		}
	}
	n.mu.Unlock()
	for _, c := range subs {
		select {
		case c <- m:
		default:
		}
	}
	for _, p := range peers {
		mm := m
		go p.send(Frame{T: "msg", M: &mm})
	}
	return true
}

// seeWho records an online user and floods the presence (rate-limited per user).
func (n *Node) seeWho(u, nick string, ttl int, from *Peer, local bool) {
	n.mu.Lock()
	p := n.people[u]
	changed := p == nil || p.Nick != nick
	fresh := p == nil || time.Since(p.Refl) > 8*time.Second
	if p == nil {
		p = &Person{}
		n.people[u] = p
	}
	p.Nick, p.Seen = nick, time.Now()
	flood := local || fresh || changed
	if flood {
		p.Refl = time.Now()
	}
	var ps []*Peer
	for _, q := range n.peers {
		if q != from {
			ps = append(ps, q)
		}
	}
	n.mu.Unlock()
	if flood && ttl > 0 {
		for _, q := range ps {
			go q.send(Frame{T: "who", U: u, Nick: nick, TTL: ttl - 1})
		}
	}
}

func (n *Node) whoList() map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]string{}
	for u, p := range n.people {
		if time.Since(p.Seen) > 45*time.Second {
			delete(n.people, u)
			continue
		}
		out[u] = p.Nick
	}
	return out
}

func (n *Node) recent(k int) []Msg {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.msgs
	if len(s) > k {
		s = s[len(s)-k:]
	}
	return append([]Msg(nil), s...)
}

// ---------- peer management ----------

func okAddr(a string) bool {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func (n *Node) addKnown(a string) {
	if !okAddr(a) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.selfAddr[a] {
		return
	}
	if _, ok := n.known[a]; !ok {
		n.known[a] = 0
	}
}

func (n *Node) addrList() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	set := map[string]bool{}
	for _, p := range n.peers {
		set[p.addr] = true
	}
	for a := range n.known {
		set[a] = true
	}
	out := []string{}
	for a := range set {
		if !n.selfAddr[a] && len(out) < 64 {
			out = append(out, a)
		}
	}
	return out
}

func clip(s string, k int) string {
	r := []rune(s)
	if len(r) > k {
		r = r[:k]
	}
	return string(r)
}

func (n *Node) listen() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", n.meshPort))
	if err != nil {
		log.Fatalf("mesh listen: %v", err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go n.handle(c, false, "")
	}
}

func (n *Node) handle(c net.Conn, outbound bool, dialAddr string) {
	defer c.Close()
	p := &Peer{conn: c}
	if p.send(Frame{T: "hello", ID: n.id, Nick: n.nick, Port: n.meshPort}) != nil {
		return
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if !sc.Scan() {
		return
	}
	var h Frame
	if json.Unmarshal(sc.Bytes(), &h) != nil || h.T != "hello" || len(h.ID) != 64 {
		return
	}
	if h.ID == n.id { // dialed ourselves
		if outbound {
			n.mu.Lock()
			n.selfAddr[dialAddr] = true
			delete(n.known, dialAddr)
			n.mu.Unlock()
		}
		return
	}
	p.id, p.nick = h.ID, clip(h.Nick, 24)
	if outbound {
		p.addr, p.initiator = dialAddr, n.id
	} else {
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		p.addr, p.initiator = net.JoinHostPort(host, strconv.Itoa(h.Port)), h.ID
	}

	n.mu.Lock()
	if old, ok := n.peers[p.id]; ok {
		// both sides keep the link initiated by the lower id
		if p.initiator > old.initiator {
			if outbound {
				n.backoff[dialAddr] = time.Now().Add(2 * time.Minute)
			}
			n.mu.Unlock()
			return
		}
		old.conn.Close()
	}
	n.peers[p.id] = p
	if h.Port > 0 && !n.selfAddr[p.addr] {
		n.known[p.addr] = 0
	}
	n.mu.Unlock()

	log.Printf("peer up: %s (%s) %s", p.nick, p.id[:8], p.addr)
	defer func() {
		n.mu.Lock()
		if n.peers[p.id] == p {
			delete(n.peers, p.id)
		}
		n.mu.Unlock()
		log.Printf("peer down: %s (%s)", p.nick, p.id[:8])
	}()

	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if p.send(Frame{T: "ping"}) != nil {
					c.Close()
					return
				}
			}
		}
	}()

	p.send(Frame{T: "peers", Addrs: n.addrList()})
	for u, nk := range n.whoList() {
		p.send(Frame{T: "who", U: u, Nick: nk})
	}
	for _, m := range n.recent(syncCount) {
		mm := m
		if p.send(Frame{T: "msg", M: &mm}) != nil {
			return
		}
	}
	for {
		c.SetReadDeadline(time.Now().Add(50 * time.Second))
		if !sc.Scan() {
			return
		}
		var f Frame
		if json.Unmarshal(sc.Bytes(), &f) != nil {
			continue
		}
		switch f.T {
		case "msg":
			if f.M != nil && verify(f.M) {
				n.add(*f.M, p)
			}
		case "who":
			if isHex64(f.U) {
				n.seeWho(f.U, clip(f.Nick, 24), min(f.TTL, 8), p, false)
			}
		case "peers":
			for _, a := range f.Addrs {
				n.addKnown(a)
			}
		}
	}
}

func (n *Node) dialLoop() {
	for {
		n.mu.Lock()
		connected := map[string]bool{}
		for _, p := range n.peers {
			connected[p.addr] = true
		}
		var todo []string
		now := time.Now()
		for a := range n.known {
			if !connected[a] && !n.dialing[a] && !n.selfAddr[a] && now.After(n.backoff[a]) {
				todo = append(todo, a)
				n.dialing[a] = true
			}
		}
		n.mu.Unlock()
		for _, a := range todo {
			go n.dial(a)
		}
		time.Sleep(5 * time.Second)
	}
}

func (n *Node) dial(a string) {
	c, err := net.DialTimeout("tcp", a, 4*time.Second)
	if err != nil {
		n.mu.Lock()
		delete(n.dialing, a)
		if v, ok := n.known[a]; ok {
			n.known[a] = v + 1
			if v+1 > 40 && !n.pinned[a] {
				delete(n.known, a)
			}
		}
		n.mu.Unlock()
		return
	}
	n.handle(c, true, a)
	n.mu.Lock()
	delete(n.dialing, a)
	n.mu.Unlock()
}

func (n *Node) gossipLoop() {
	for {
		time.Sleep(30 * time.Second)
		addrs := n.addrList()
		n.mu.Lock()
		ps := make([]*Peer, 0, len(n.peers))
		for _, p := range n.peers {
			ps = append(ps, p)
		}
		n.mu.Unlock()
		for _, p := range ps {
			go p.send(Frame{T: "peers", Addrs: addrs})
		}
	}
}

// ---------- LAN discovery (UDP broadcast beacons) ----------

func broadcastAddrs() []net.IP {
	out := []net.IP{net.IPv4bcast}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || len(ipn.Mask) != 4 && len(ipn.Mask) != 16 {
				continue
			}
			ip4, mask := ipn.IP.To4(), ipn.Mask
			if len(mask) == 16 {
				mask = mask[12:]
			}
			b := make(net.IP, 4)
			for i := range b {
				b[i] = ip4[i] | ^mask[i]
			}
			out = append(out, b)
		}
	}
	return out
}

func (n *Node) discover(port int) {
	pc, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("warn: discovery disabled (udp %d busy: %v); use --peer", port, err)
		return
	}
	go func() {
		buf := make([]byte, 512)
		for {
			k, ra, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			parts := strings.Split(string(buf[:k]), "|")
			if len(parts) != 3 || parts[0] != "MESHv1" || parts[1] == n.id {
				continue
			}
			host, _, _ := net.SplitHostPort(ra.String())
			n.addKnown(net.JoinHostPort(host, parts[2]))
		}
	}()
	beacon := []byte(fmt.Sprintf("MESHv1|%s|%d", n.id, n.meshPort))
	for {
		for _, b := range broadcastAddrs() {
			pc.WriteTo(beacon, &net.UDPAddr{IP: b, Port: port})
		}
		time.Sleep(3 * time.Second)
	}
}

// ---------- HTTP API + UI ----------

var chanRe = regexp.MustCompile(`[^a-z0-9_-]`)

func cleanChan(s string) string {
	s = chanRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "")
	if s == "" {
		return "general"
	}
	return clip(s, 24)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (n *Node) serveHTTP() {
	sub, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		type pi struct{ ID, Nick, Addr string }
		n.mu.Lock()
		ps := []pi{}
		for _, p := range n.peers {
			ps = append(ps, pi{p.id[:8], p.nick, p.addr})
		}
		info := map[string]any{"id": n.id, "node": n.nick, "peers": ps, "known": len(n.known)}
		n.mu.Unlock()
		writeJSON(w, info)
	})

	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		h := n.recent(1000)
		sort.SliceStable(h, func(i, j int) bool { return h[i].TS < h[j].TS })
		writeJSON(w, h)
	})

	mux.HandleFunc("POST /api/send", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Nick, Chan, Text, U, To string
			SOS                     bool
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in) != nil ||
			(in.U != "" && !isHex64(in.U)) || (in.To != "" && !isHex64(in.To)) {
			http.Error(w, "bad request", 400)
			return
		}
		text, limit := strings.TrimSpace(in.Text), 2000
		if in.To != "" {
			limit = 6000 // ciphertext is larger
		}
		if text == "" || len([]rune(text)) > limit {
			http.Error(w, "bad text", 400)
			return
		}
		nick := clip(strings.TrimSpace(in.Nick), 24)
		if nick == "" {
			nick = "anon"
		}
		ch := cleanChan(in.Chan)
		if in.To != "" {
			ch, in.SOS = "dm", false
		} else if in.SOS {
			ch = "sos"
		}
		m := n.newMsg(nick, ch, text, in.U, in.To, in.SOS)
		n.add(m, nil)
		writeJSON(w, map[string]string{"id": m.ID})
	})

	mux.HandleFunc("POST /api/presence", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ U, Nick string }
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in) != nil || !isHex64(in.U) {
			http.Error(w, "bad request", 400)
			return
		}
		n.seeWho(in.U, clip(strings.TrimSpace(in.Nick), 24), 8, nil, true)
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("GET /api/people", func(w http.ResponseWriter, r *http.Request) {
		type pe struct {
			U    string `json:"u"`
			Nick string `json:"nick"`
		}
		out := []pe{}
		for u, nk := range n.whoList() {
			out = append(out, pe{u, nk})
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("GET /api/stream", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no streaming", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		ch := make(chan Msg, 64)
		n.mu.Lock()
		n.subs[ch] = true
		n.mu.Unlock()
		defer func() { n.mu.Lock(); delete(n.subs, ch); n.mu.Unlock() }()
		fmt.Fprint(w, ": hi\n\n")
		fl.Flush()
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case m := <-ch:
				b, _ := json.Marshal(m)
				fmt.Fprintf(w, "data: %s\n\n", b)
				fl.Flush()
			case <-t.C:
				fmt.Fprint(w, ": ping\n\n")
				fl.Flush()
			}
		}
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", n.httpPort), mux))
}

func main() {
	host, _ := os.Hostname()
	nick := flag.String("nick", host, "node name shown to other nodes")
	httpPort := flag.Int("http", 8080, "web UI port")
	meshPort := flag.Int("mesh", 9000, "mesh TCP port")
	disco := flag.Int("disco", 9999, "UDP discovery port (0 = off)")
	data := flag.String("data", "./data", "data dir (key + message log)")
	peers := flag.String("peer", "", "comma-separated bootstrap peers ip:port")
	flag.Parse()

	dataDir = *data
	os.MkdirAll(dataDir, 0700)
	priv := loadKey(dataDir)
	n := &Node{
		priv: priv, id: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
		nick: clip(*nick, 24), meshPort: *meshPort, httpPort: *httpPort,
		seen: map[string]bool{}, peers: map[string]*Peer{}, known: map[string]int{},
		pinned: map[string]bool{}, selfAddr: map[string]bool{}, dialing: map[string]bool{},
		backoff: map[string]time.Time{}, subs: map[chan Msg]bool{}, people: map[string]*Person{},
	}
	n.load()
	for _, a := range strings.Split(*peers, ",") {
		if a = strings.TrimSpace(a); a != "" {
			n.known[a], n.pinned[a] = 0, true
		}
	}
	go n.listen()
	go n.dialLoop()
	go n.gossipLoop()
	if *disco > 0 {
		go n.discover(*disco)
	}
	log.Printf("MeshLink node %q id=%s", n.nick, n.id[:8])
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			log.Printf("open on phones/laptops: http://%s:%d", ipn.IP, n.httpPort)
		}
	}
	n.serveHTTP()
}
