#!/bin/sh
# Cross-compile single-file binaries into ./dist
mkdir -p dist
for t in linux/amd64 linux/arm64 windows/amd64 darwin/arm64 darwin/amd64; do
  os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -ldflags "-s -w" -o dist/meshlink-$os-$arch$ext . && echo built $os/$arch
done
