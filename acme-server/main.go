package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"acme-server/internal"
)

var (
	addr       = flag.String("addr", ":443", "The address to listen on")
	publicName = flag.String("public-name", "acme-v02.api.letsencrypt.org", "The public DNS name of this service")
	certFile   = flag.String("cert-file", "root-ca.pem", "The file where the root certificate should be written")
	ready      = flag.Bool("ready", false, "Exit successfully if cert-file exists")
)

func main() {
	flag.Parse()

	if *ready {
		if _, err := os.Stat(*certFile); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, err := internal.NewInMemoryACMEServer(*publicName, *addr, *certFile)
	if err != nil {
		log.Fatalf("NewInMemoryACMEServer: %v", err)
	}

	listener, err := s.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start InMemoryACMEServer: %v", err)
	}
	defer listener.Close()

	log.Printf("InMemory ACME server listening on %s", listener.Addr())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT)
	signal.Notify(ch, syscall.SIGTERM)
	sig := <-ch
	log.Printf("INF Received signal %d (%s)", sig, sig)
	cancel()
}
