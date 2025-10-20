package internal

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"gopkg.in/square/go-jose.v2"
)

// generateNonce creates a new unique nonce.
func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// verifyJWSAndIssueNonce verifies the JWS signature and issues a new nonce.
func (s *InMemoryACMEServer) verifyJWSAndIssueNonce(w http.ResponseWriter, r *http.Request, expectedURL string) (*jose.JSONWebSignature, []byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request body: %w", err)
	}

	jws, err := jose.ParseSigned(string(body))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	nonce := jws.Signatures[0].Protected.Nonce
	if nonce == "" {
		return nil, nil, fmt.Errorf("JWS protected header missing nonce")
	}

	if _, ok := s.nonces[nonce]; !ok {
		return nil, nil, fmt.Errorf("invalid or re-used nonce")
	}
	delete(s.nonces, nonce)

	newNonce := generateNonce()
	s.nonces[newNonce] = true
	w.Header().Set("Replay-Nonce", newNonce)

	jwsURL, ok := jws.Signatures[0].Protected.ExtraHeaders["url"].(string)
	if !ok || jwsURL == "" {
		return nil, nil, fmt.Errorf("JWS protected header missing or invalid url")
	}
	jwsURL = strings.TrimPrefix(jwsURL, fmt.Sprintf("https://%s:%d", s.publicName, s.port))
	if jwsURL != expectedURL {
		return nil, nil, fmt.Errorf("JWS protected header url mismatch: expected %s, got %s", expectedURL, jwsURL)
	}

	return jws, body, nil
}

// findAccountByKey finds an account by its public key.
func (s *InMemoryACMEServer) findAccountByKey(key *jose.JSONWebKey) *acmeAccount {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		log.Printf("Error calculating thumbprint for key: %v", err)
		return nil
	}
	for _, acc := range s.accounts {
		accThumbprint, err := acc.Key.Thumbprint(crypto.SHA256)
		if err != nil {
			log.Printf("Error calculating thumbprint for account %s: %v", acc.ID, err)
			continue
		}
		if string(accThumbprint) == string(thumbprint) {
			return acc
		}
	}
	log.Printf("No matching account found")
	return nil
}
