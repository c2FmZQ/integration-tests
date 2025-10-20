package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func TestFullACMEFlow(t *testing.T) {
	// Start the mock ACME server
	s, err := NewInMemoryACMEServer("0", true)
	if err != nil {
		t.Fatalf("Failed to create InMemoryACMEServer: %v", err)
	}
	listener, caDir, err := s.Start()
	if err != nil {
		t.Fatalf("Failed to start InMemoryACMEServer: %v", err)
	}
	defer os.RemoveAll(caDir)
	actualPort := listener.Addr().(*net.TCPAddr).Port
	directoryURL := "https://localhost:" + strconv.Itoa(actualPort) + "/directory"

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
					InsecureSkipVerify: true, // Trust the mock server's self-signed cert
				},
			},
		},
	}

	// Create a new account
	account := &acme.Account{
		Contact: []string{"mailto:test@example.com"},
	}
	_, err = client.Register(context.Background(), account, autocert.AcceptTOS)
	if err != nil {
		t.Fatalf("Failed to register account: %v", err)
	}

	// Create a new order
	order, err := client.AuthorizeOrder(context.Background(), []acme.AuthzID{{Type: "dns", Value: "example.com"}})
	if err != nil {
		t.Fatalf("Failed to create order: %v", err)
	}

	// Handle each authorization
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(context.Background(), authzURL)
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
		defer challengeServer.Shutdown(context.Background())

		// Tell the ACME server that we're ready for the challenge
		_, err = client.Accept(context.Background(), challenge)
		if err != nil {
			t.Fatalf("Failed to accept challenge: %v", err)
		}

		// Wait for the order to become ready
		_, err = client.WaitOrder(context.Background(), order.URI)
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
	der, _, err := client.CreateOrderCert(context.Background(), order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("Failed to finalize order: %v", err)
	}

	// We got a certificate!
	if len(der) == 0 {
		t.Fatal("Expected a certificate, got empty slice")
	}

	listener.Close()
}
