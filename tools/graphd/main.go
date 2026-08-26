// Command graphd serves a live view of a Go module's package graph, with
// architecture rules checked on every rebuild.
package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"time"
)

func main() {
	dir := flag.String("dir", ".", "module root to watch")
	addr := flag.String("addr", "127.0.0.1:7717", "listen address")
	interval := flag.Duration("interval", 400*time.Millisecond, "filesystem poll interval")
	flag.Parse()

	root, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatal(err)
	}

	server := NewServer(root)

	// Watch calls Rebuild once at startup, then on every change.
	go Watch(root, *interval, server.Rebuild)

	log.Printf("watching %s", root)
	log.Printf("open http://%s", *addr)

	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		log.Fatal(err)
	}
}
