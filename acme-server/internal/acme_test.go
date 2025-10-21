package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

type keyType int

const (
	rsaKey keyType = iota
	ecdsaKey
)

func TestFullACMEFlowRSA_HTTP01(t *testing.T) {
	testFullACMEFlow(t, rsaKey, "http-01")
}

func TestFullACMEFlowECDSA_HTTP01(t *testing.T) {
	testFullACMEFlow(t, ecdsaKey, "http-01")
}

func TestFullACMEFlowRSA_TLSALPN01(t *testing.T) {
	testFullACMEFlow(t, rsaKey, "tls-alpn-01")
}

func TestFullACMEFlowECDSA_TLSALPN01(t *testing.T) {
	testFullACMEFlow(t, ecdsaKey, "tls-alpn-01")
}

func testFullACMEFlow(t *testing.T, kt keyType, challengeType string) {
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
	accountKey, err := generatePrivateKey(kt)
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

		// Find the challenge
		var challenge *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == challengeType {
				challenge = c
				break
			}
		}
		if challenge == nil {
			t.Fatalf("No %s challenge found", challengeType)
		}
		switch challengeType {
		case "http-01":
			// Set up a local HTTP server to respond to the challenge
			challengeResponse, err := client.HTTP01ChallengeResponse(challenge.Token)
			if err != nil {
				t.Fatalf("Failed to get challenge response: %v", err)
			}

			challengeMux := http.NewServeMux()
			challengeMux.HandleFunc("/.well-known/acme-challenge/"+challenge.Token, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(challengeResponse))
			})
			challengeListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to listen for challenge server: %v", err)
			}
			addressMapForTests["example.com:80"] = challengeListener.Addr().String()
			challengeServer := &http.Server{Handler: challengeMux}
			go func() {
				if err := challengeServer.Serve(challengeListener); err != http.ErrServerClosed {
					t.Logf("Challenge server error: %v", err)
				}
			}()
			defer challengeServer.Shutdown(ctx)
		case "tls-alpn-01":
			// Set up a local TLS server to respond to the challenge
			cert, err := client.TLSALPN01ChallengeCert(challenge.Token, "example.com")
			if err != nil {
				t.Fatalf("Failed to get challenge certificate: %v", err)
			}
			challengeListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to listen for challenge server: %v", err)
			}
			defer challengeListener.Close()
			challengeServer := &http.Server{
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{"acme-tls/1"},
				},
			}
			addressMapForTests["example.com:443"] = challengeListener.Addr().String()
			go func() {
				if err := challengeServer.ServeTLS(challengeListener, "", ""); err != http.ErrServerClosed {
					t.Logf("Challenge server error: %v", err)
				}
			}()
			defer challengeServer.Shutdown(ctx)
		}

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
	csrKey, err := generatePrivateKey(kt)
	if err != nil {
		t.Fatalf("Failed to generate CSR key: %v", err)
	}
	csr, err := createCSR(kt, csrKey, "example.com")
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

func generatePrivateKey(kt keyType) (crypto.Signer, error) {
	switch kt {
	case rsaKey:
		return rsa.GenerateKey(rand.Reader, 2048)
	case ecdsaKey:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("unknown key type: %d", kt)
	}
}

func createCSR(kt keyType, key crypto.Signer, commonName string, dnsNames ...string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: append(dnsNames, commonName),
	}
	switch kt {
	case rsaKey:
		template.SignatureAlgorithm = x509.SHA256WithRSA
	case ecdsaKey:
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	default:
		return nil, fmt.Errorf("unknown key type: %d", kt)
	}

	return x509.CreateCertificateRequest(rand.Reader, template, key)
}
