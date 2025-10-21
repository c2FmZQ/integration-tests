package internal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
)

var addressMapForTests = map[string]string{}

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
	expectedKeyAuth, err := s.keyAuthorization(challenge.Token.String(), accountKey)
	if err != nil {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:serverInternal", "failed to generate key authorization: %v", err)
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
	addr := net.JoinHostPort(identifierValue, "443")
	if a, exists := addressMapForTests[addr]; exists {
		addr = a
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	log.Printf("tls-alpn-01 challenge for %s: tls dial done", identifierValue)
	if err != nil {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:connection", "failed to connect to client: %v", err)
		return
	}
	defer conn.Close()

	// Verify the certificate presented by the server.
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:unauthorized", "no certificate presented")
		return
	}
	cert := certs[0]

	// The certificate must be self-signed.
	if cert.Issuer.String() != cert.Subject.String() {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:unauthorized", "certificate not self-signed")
		return
	}

	// The certificate must contain the expected key authorization in an extension.
	// The OID for the acmeValidationV1 extension is 1.3.6.1.5.5.7.1.31.
	var found bool
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.5.5.7.1.31" {
			// The value of the extension is the SHA-256 digest of the key authorization.
			// https://tools.ietf.org/html/rfc8737#section-3
			keyAuthHash := sha256.Sum256([]byte(expectedKeyAuth))
			var presentedKeyAuth []byte
			if _, err := asn1.Unmarshal(ext.Value, &presentedKeyAuth); err != nil {
				s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:unauthorized", "failed to parse acmeValidationV1 extension: %v", err)
				return
			}

			if !bytes.Equal(presentedKeyAuth, keyAuthHash[:]) {
				s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:unauthorized", "key authorization mismatch. Expected %x, got %x", keyAuthHash[:], presentedKeyAuth)
				return
			}
			found = true
			break
		}
	}
	if !found {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:unauthorized", "acmeValidationV1 extension not found")
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

func (s *InMemoryACMEServer) failChallenge(challenge *acmeChallenge, identifierValue, problemType, detailFormat string, a ...interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge.Status = "invalid"
	detail := fmt.Sprintf(detailFormat, a...)
	challenge.Error = &Problem{Type: problemType, Detail: detail}
	log.Printf("%s challenge for %s failed: %s", strings.ToUpper(challenge.Type), identifierValue, detail)
}

// validateHTTP01Challenge validates an http-01 challenge.
func (s *InMemoryACMEServer) validateHTTP01Challenge(challenge *acmeChallenge, authzID string, identifierValue string, accountKey *jose.JSONWebKey) {
	expectedKeyAuth, err := s.keyAuthorization(challenge.Token.String(), accountKey)
	if err != nil {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:serverInternal", "failed to generate key authorization: %v", err)
		return
	}

	// Simulate HTTP GET to client's domain
	log.Printf("validating http-01 challenge for %s", identifierValue)
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if a, exists := addressMapForTests[addr]; exists {
				addr = a
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
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:connection", "failed to connect to client: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:unauthorized", "client returned status %d", resp.StatusCode)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:serverInternal", "failed to read response body: %v", err)
		return
	}

	if string(bodyBytes) != expectedKeyAuth {
		s.failChallenge(challenge, identifierValue, "urn:ietf:params:acme:error:unauthorized", "key authorization mismatch. Expected %s, got %s", expectedKeyAuth, string(bodyBytes))
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
