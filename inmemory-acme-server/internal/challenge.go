package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// validateChallenge validates the given challenge.
func (s *InMemoryACMEServer) validateChallenge(challenge *acmeChallenge, authzID string, identifierValue string, accountKey *jose.JSONWebKey) {
	switch challenge.Type {
	case "http-01":
		s.validateHTTP01Challenge(challenge, authzID, identifierValue, accountKey)
	case "tls-alpn-01":
		s.validateTLSALPN01Challenge(challenge, authzID, identifierValue, accountKey)
	}
}

// validateTLSALPN01Challenge validates a tls-alpn-01 challenge.
func (s *InMemoryACMEServer) validateTLSALPN01Challenge(challenge *acmeChallenge, authzID string, identifierValue string, accountKey *jose.JSONWebKey) {
	expectedKeyAuth, err := s.keyAuthorization(challenge.Token, accountKey)
	if err != nil {
		s.mu.Lock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:serverInternal", Detail: fmt.Sprintf("failed to generate key authorization: %v", err)}
		s.mu.Unlock()
		log.Printf("TLS-ALPN-01 challenge for %s failed: %v", identifierValue, err)
		return
	}

	// Create a TLS client to connect to the domain.
	log.Printf("validating tls-alpn-01 challenge for %s", identifierValue)
	dialer := &net.Dialer{}
	config := &tls.Config{
		NextProtos:         []string{"acme-tls/1"},
		ServerName:         identifierValue,
		InsecureSkipVerify: true, // We expect a self-signed certificate.
	}
	var conn *tls.Conn
	if identifierValue == "example.com" {
		conn, err = tls.DialWithDialer(dialer, "tcp", "127.0.0.1:5001", config)
	} else {
		conn, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(identifierValue, "443"), config)
	}
	log.Printf("tls-alpn-01 challenge for %s: tls dial done", identifierValue)
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:connection", Detail: fmt.Sprintf("failed to connect to client: %v", err)}
		log.Printf("TLS-ALPN-01 challenge for %s failed: %v", identifierValue, err)
		return
	}
	defer conn.Close()

	// Verify the certificate presented by the server.
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		s.mu.Lock()
		defer s.mu.Unlock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "no certificate presented"}
		log.Printf("TLS-ALPN-01 challenge for %s failed: no certificate presented", identifierValue)
		return
	}
	cert := certs[0]

	// The certificate must be self-signed.
	if cert.Issuer.String() != cert.Subject.String() {
		s.mu.Lock()
		defer s.mu.Unlock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "certificate not self-signed"}
		log.Printf("TLS-ALPN-01 challenge for %s failed: certificate not self-signed", identifierValue)
		return
	}

	// The certificate must contain the expected key authorization in an extension.
	// The OID for the acmeValidationV1 extension is 1.3.6.1.5.5.7.1.31.
	var found bool
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.5.5.7.1.31" {
			if string(ext.Value) != expectedKeyAuth {
				s.mu.Lock()
				defer s.mu.Unlock()
				challenge.Status = "invalid"
				challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "key authorization mismatch"}
				log.Printf("TLS-ALPN-01 challenge for %s failed: key authorization mismatch. Expected %s, got %s", identifierValue, expectedKeyAuth, string(ext.Value))
				return
			}
			found = true
			break
		}
	}
	if !found {
		s.mu.Lock()
		defer s.mu.Unlock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "acmeValidationV1 extension not found"}
		log.Printf("TLS-ALPN-01 challenge for %s failed: acmeValidationV1 extension not found", identifierValue)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	challenge.Status = "valid"
	log.Printf("TLS-ALPN-01 challenge for %s marked as valid", identifierValue)
	authz, ok := s.authz[authzID]
	if !ok {
		log.Printf("Authorization %s not found after validation check", authzID)
		return
	}
	authz.Status = "valid"
}

// validateHTTP01Challenge validates an http-01 challenge.
func (s *InMemoryACMEServer) validateHTTP01Challenge(challenge *acmeChallenge, authzID string, identifierValue string, accountKey *jose.JSONWebKey) {
	expectedKeyAuth, err := s.keyAuthorization(challenge.Token, accountKey)
	if err != nil {
		s.mu.Lock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:serverInternal", Detail: fmt.Sprintf("failed to generate key authorization: %v", err)}
		s.mu.Unlock()
		log.Printf("HTTP-01 challenge for %s failed: %v", identifierValue, err)
		return
	}

	// Simulate HTTP GET to client's domain
	log.Printf("validating http-01 challenge for %s", identifierValue)
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if identifierValue == "example.com" {
				return dialer.DialContext(ctx, network, "127.0.0.1:8080")
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	resp, err := client.Get(fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", identifierValue, challenge.Token))
	log.Printf("http-01 challenge for %s: http get done", identifierValue)
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:connection", Detail: fmt.Sprintf("failed to connect to client: %v", err)}
		log.Printf("HTTP-01 challenge for %s failed: %v", identifierValue, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.mu.Lock()
		defer s.mu.Unlock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: fmt.Sprintf("client returned status %d", resp.StatusCode)}
		log.Printf("HTTP-01 challenge for %s failed: client returned status %d", identifierValue, resp.StatusCode)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:serverInternal", Detail: fmt.Sprintf("failed to read response body: %v", err)}
		log.Printf("HTTP-01 challenge for %s failed: %v", identifierValue, err)
		return
	}

	if string(bodyBytes) != expectedKeyAuth {
		s.mu.Lock()
		defer s.mu.Unlock()
		challenge.Status = "invalid"
		challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "key authorization mismatch"}
		log.Printf("HTTP-01 challenge for %s failed: key authorization mismatch. Expected %s, got %s", identifierValue, expectedKeyAuth, string(bodyBytes))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	challenge.Status = "valid"
	log.Printf("HTTP-01 challenge for %s marked as valid", identifierValue)
	authz, ok := s.authz[authzID]
	if !ok {
		log.Printf("Authorization %s not found after validation check", authzID)
		return
	}
	authz.Status = "valid"
}
