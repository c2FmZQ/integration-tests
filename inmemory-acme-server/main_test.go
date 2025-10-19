package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func TestAcmeChallengeWithMockServer(t *testing.T) {
	var err error
	var cacheDir string
	var cert *tls.Certificate

	// Create and start the InMemoryACMEServer
	s, err := NewInMemoryACMEServer("0", true) // Use dynamic port and test mode
	if err != nil {
		t.Fatalf("Failed to create InMemoryACMEServer: %v", err)
	}

	listener, caDir, err := s.Start()
	if err != nil {
		t.Fatalf("Failed to start InMemoryACMEServer: %v", err)
	}
	defer os.RemoveAll(caDir)

	actualPort := listener.Addr().(*net.TCPAddr).Port
	log.Printf("InMemory ACME server listening on :%d", actualPort)

	// Wait for the server to be ready (optional, as Start() already runs in goroutine)
	// This is more for ensuring the listener is truly ready
	var conn net.Conn
	for i := 0; i < 10; i++ {
		conn, err = net.DialTimeout("tcp", "localhost:"+strconv.Itoa(actualPort), 1*time.Second)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("InMemory ACME server did not become ready: %v", err)
	}

	// Create a temporary cache directory for autocert
	cacheDir, err = os.MkdirTemp("", "autocert-cache")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(cacheDir)

	// Configure autocert manager to use the running inmemory ACME server
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com"),
		Cache:      autocert.DirCache(cacheDir),
		Client: &acme.Client{
			DirectoryURL: "https://localhost:" + strconv.Itoa(actualPort) + "/acme",
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						if strings.HasPrefix(addr, "example.com:") {
							addr = "localhost:" + strconv.Itoa(actualPort)
						}
						return (&net.Dialer{}).DialContext(ctx, network, addr)
					},
				},
			},
		},
	}

	// Attempt to get a certificate
	cert, err = manager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "example.com",
	})
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected a certificate, got nil")
	}

	log.Println("Successfully obtained a certificate from inmemory ACME server.")

	defer listener.Close()

}
