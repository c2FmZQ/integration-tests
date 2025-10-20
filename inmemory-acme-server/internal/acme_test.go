package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func TestFullACMEFlow(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	caCertFile := filepath.Join(dir, "root-ca.pem")
	s, err := NewInMemoryACMEServer("localhost", "127.0.0.1:0", caCertFile)
	if err != nil {
		t.Fatalf("NewInMemoryACMEServer: %v", err)
	}
	listener, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer listener.Close()
	actualPort := listener.Addr().(*net.TCPAddr).Port
	t.Logf("Server started on port %d", actualPort)

	pool := x509.NewCertPool()
	for {
		b, err := os.ReadFile(caCertFile)
		if errors.Is(err, fs.ErrNotExist) || !pool.AppendCertsFromPEM(b) {
			t.Logf("Waiting for %q", caCertFile)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		break
	}

	directoryURL := fmt.Sprintf("https://localhost:%d/directory", actualPort)

	// Create a new account key
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate account key: %v", err)
	}

	// Create a new ACME client
	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: directoryURL,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			},
		},
	}

	t.Log("Create a new account")
	account := &acme.Account{
		Contact: []string{"mailto:test@example.com"},
	}
	_, err = client.Register(ctx, account, autocert.AcceptTOS)
	if err != nil {
		t.Fatalf("Failed to register account: %v", err)
	}

	t.Log("Create a new order")
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: "example.com"}})
	if err != nil {
		t.Fatalf("Failed to create order: %v", err)
	}

	// Handle each authorization
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("Failed to get authorization: %v", err)
		}

		// Find the http-01 challenge
		var challenge *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			t.Fatalf("No http-01 challenge found")
		}

		// Set up a local HTTP server to respond to the challenge
		challengeResponse, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			t.Fatalf("Failed to get challenge response: %v", err)
		}

		challengeMux := http.NewServeMux()
		challengeMux.HandleFunc("/.well-known/acme-challenge/"+challenge.Token, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(challengeResponse))
		})
		challengeListener, err := net.Listen("tcp", "127.0.0.1:8080")
		if err != nil {
			t.Fatalf("Failed to listen for challenge server: %v", err)
		}
		challengeServer := &http.Server{Handler: challengeMux}
		go func() {
			if err := challengeServer.Serve(challengeListener); err != http.ErrServerClosed {
				t.Logf("Challenge server error: %v", err)
			}
		}()
		defer challengeServer.Shutdown(ctx)

		// Tell the ACME server that we're ready for the challenge
		_, err = client.Accept(ctx, challenge)
		if err != nil {
			t.Fatalf("Failed to accept challenge: %v", err)
		}

		// Wait for the order to become ready
		_, err = client.WaitOrder(ctx, order.URI)
		if err != nil {
			t.Fatalf("Failed to wait for order: %v", err)
		}
	}

	// Create a certificate signing request (CSR)
	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CSR key: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &csrKey.PublicKey,
		Subject:            pkix.Name{CommonName: "example.org"},
		DNSNames:           []string{"example.org"},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, csrKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Finalize the order
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("Failed to finalize order: %v", err)
	}

	// We got a certificate!
	if len(der) == 0 {
		t.Fatal("Expected a certificate, got empty slice")
	}
	for i, raw := range der {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatalf("x509.ParseCertificate: %v", err)
		}
		t.Logf("Cert #%d %s", i, cert.Subject)
	}
}

func TestFullACMEFlowTLSALPN(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	caCertFile := filepath.Join(dir, "root-ca.pem")
	s, err := NewInMemoryACMEServer("localhost", "127.0.0.1:0", caCertFile)
	if err != nil {
		t.Fatalf("NewInMemoryACMEServer: %v", err)
	}
	listener, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer listener.Close()
	actualPort := listener.Addr().(*net.TCPAddr).Port
	t.Logf("Server started on port %d", actualPort)

	pool := x509.NewCertPool()
	for {
		b, err := os.ReadFile(caCertFile)
		if errors.Is(err, fs.ErrNotExist) || !pool.AppendCertsFromPEM(b) {
			t.Logf("Waiting for %q", caCertFile)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		break
	}

	directoryURL := fmt.Sprintf("https://localhost:%d/directory", actualPort)

	// Create a new account key
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate account key: %v", err)
	}

	// Create a new ACME client
	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: directoryURL,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			},
		},
	}

	t.Log("Create a new account")
	account := &acme.Account{
		Contact: []string{"mailto:test@example.com"},
	}
	_, err = client.Register(ctx, account, autocert.AcceptTOS)
	if err != nil {
		t.Fatalf("Failed to register account: %v", err)
	}

	t.Log("Create a new order")
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: "example.com"}})
	if err != nil {
		t.Fatalf("Failed to create order: %v", err)
	}

	// Handle each authorization
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("Failed to get authorization: %v", err)
		}

		// Find the tls-alpn-01 challenge
		var challenge *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "tls-alpn-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			t.Fatalf("No tls-alpn-01 challenge found")
		}

		// Set up a local TLS server to respond to the challenge
		cert, err := client.TLSALPN01ChallengeCert(challenge.Token, "example.com")
		if err != nil {
			t.Fatalf("Failed to get challenge certificate: %v", err)
		}
		challengeServer := &http.Server{
			Addr: "127.0.0.1:5001",
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"acme-tls/1"},
			},
		}
		go func() {
			if err := challengeServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				t.Logf("Challenge server error: %v", err)
			}
		}()
		defer challengeServer.Shutdown(ctx)

		// Tell the ACME server that we're ready for the challenge
		_, err = client.Accept(ctx, challenge)
		if err != nil {
			t.Fatalf("Failed to accept challenge: %v", err)
		}

		// Wait for the order to become ready
		_, err = client.WaitOrder(ctx, order.URI)
		if err != nil {
			t.Fatalf("Failed to wait for order: %v", err)
		}
	}

	// Create a certificate signing request (CSR)
	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CSR key: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &csrKey.PublicKey,
		Subject:            pkix.Name{CommonName: "example.com"},
		DNSNames:           []string{"example.com"},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, csrKey)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Finalize the order
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("Failed to finalize order: %v", err)
	}

	// We got a certificate!
	if len(der) == 0 {
		t.Fatal("Expected a certificate, got empty slice")
	}
	for i, raw := range der {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatalf("x509.ParseCertificate: %v", err)
		}
		t.Logf("Cert #%d %s", i, cert.Subject)
	}
}
