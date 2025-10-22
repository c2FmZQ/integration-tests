package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

var (
	acmeHost = flag.String("acme-host", "doh.example.com", "The host name for which to get an ACME certificate.")
	domains  = flag.String("domains", "", "A comma-separated list of domain names to manage.")
)

type server struct {
	zones map[string]zone
	mu    sync.RWMutex
}

// memCache is an in-memory cache for autocert.
type memCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemCache() *memCache {
	return &memCache{
		data: make(map[string][]byte),
	}
}

func (m *memCache) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.data[key]; ok {
		return v, nil
	}
	return nil, autocert.ErrCacheMiss
}

func (m *memCache) Put(ctx context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = slices.Clone(data)
	return nil
}

func (m *memCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func main() {
	flag.Parse()
	s := &server{
		zones: make(map[string]zone),
	}
	for _, d := range strings.Split(*domains, ",") {
		if d == "" {
			continue
		}
		s.addZone(d)
	}

	m := &autocert.Manager{
		Cache:      newMemCache(),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*acmeHost),
		Email:      "doh@example.com",
	}

	// Main DoH server (HTTPS)
	dohMux := http.NewServeMux()
	dohMux.HandleFunc("/dns-query", s.handleDNSQuery)
	dohMux.HandleFunc("/client/v4/zones", s.handleZones)
	dohMux.HandleFunc("/client/v4/zones/", s.handleZone)

	// TODO(c-m-s): Add a separate server for the Cloudflare API so we don't
	// need to expose it on the public internet.
	httpServer := &http.Server{
		Addr:      ":443",
		Handler:   dohMux,
		TLSConfig: m.TLSConfig(),
	}

	log.Println("Starting DoH server on :443")
	if err := httpServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("ListenAndServeTLS: %v", err)
	}
}
