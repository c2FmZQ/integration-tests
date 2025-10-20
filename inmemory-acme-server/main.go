package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
)

const acmeServerName = "acme-v02.api.letsencrypt.org"

type acmeAccount struct {
	ID        string
	Key       *jose.JSONWebKey
	Status    string
	Contact   []string
	CreatedAt time.Time
}

type acmeOrder struct {
	ID             string
	AccountID      string
	Status         string
	Expires        time.Time
	Identifiers    []AuthzID
	Authorizations []string // URLs to authorizations
	FinalizeURL    string
	CertificateURL string
	Error          *Problem
}

type acmeAuthorization struct {
	ID         string
	Identifier AuthzID
	Status     string
	Expires    time.Time
	Challenges []*acmeChallenge
	Wildcard   bool
}

type acmeChallenge struct {
	ID               string
	Type             string
	Status           string
	URL              string
	Token            string
	KeyAuthorization string
	Error            *Problem
}

type acmeCertificate struct {
	ID        string
	OrderID   string
	CertBytes []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// AuthzID represents an ACME identifier for authorization.
type AuthzID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Problem represents an ACME problem detail.
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
	Status int    `json:"status,omitempty"`
}

// InMemoryACMEServer encapsulates the state and handlers for the mock ACME server.
type InMemoryACMEServer struct {
	mu                    sync.Mutex
	accounts              map[string]*acmeAccount       // map[accountID]*acmeAccount
	orders                map[string]*acmeOrder         // map[orderID]*acmeOrder
	authz                 map[string]*acmeAuthorization // map[authzID]*acmeAuthorization
	challenges            map[string]*acmeChallenge     // map[token]*acmeChallenge
	certs                 map[string]*acmeCertificate   // map[certID]*acmeCertificate
	nextID                int
	testMode              bool
	directory             string
	port                  string
	listener              net.Listener
	caDir                 string
	caCert                *x509.Certificate
	caKey                 *rsa.PrivateKey
	currentAcmeServerName string
	nonces                map[string]bool
}

func NewInMemoryACMEServer(port string, testMode bool) (*InMemoryACMEServer, error) {
	return &InMemoryACMEServer{
		accounts:   make(map[string]*acmeAccount),
		orders:     make(map[string]*acmeOrder),
		authz:      make(map[string]*acmeAuthorization),
		challenges: make(map[string]*acmeChallenge),
		certs:      make(map[string]*acmeCertificate),
		nextID:     1,
		testMode:   testMode,
		port:       port,
		nonces:     make(map[string]bool),
	}, nil
}

// Start starts the HTTPS server for the MockACMEServer.
func (s *InMemoryACMEServer) Start() (net.Listener, string, error) {
	// 1. Listen to get the port.
	listener, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		return nil, "", fmt.Errorf("failed to listen on :%s: %w", s.port, err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	s.port = strconv.Itoa(actualPort)

	// 2. Set the server name.
	if s.testMode {
		s.currentAcmeServerName = "localhost"
	} else {
		s.currentAcmeServerName = acmeServerName
	}

	// 3. Generate CA
	caDir, err := os.MkdirTemp("", "inmemory-acme-ca")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp CA directory: %w", err)
	}
	s.caDir = caDir

	caCert, caKey, err := generateCA()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate CA: %w", err)
	}
	s.caCert = caCert
	s.caKey = caKey

	caFile, err := os.Create(filepath.Join(caDir, "inmemory-acme-ca.pem"))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create CA file: %w", err)
	}
	if err := pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw}); err != nil {
		return nil, "", fmt.Errorf("failed to write CA certificate: %w", err)
	}
	caFile.Close()

	// 4. Generate the server certificate using the correct name
	serverCert, serverKey, err := generateServerCert(s.caCert, s.caKey, s.currentAcmeServerName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// 5. Create the TLS certificate
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	// 6. Set up mux and http.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/new-nonce", s.newNonce)
	mux.HandleFunc("/acme/new-account", s.newAccount)
	mux.HandleFunc("/acme/new-order", s.newOrder)
	mux.HandleFunc("/acme/authz/", s.getAuthorization)
	mux.HandleFunc("/acme/challenge/", s.postChallenge)
	mux.HandleFunc("/acme/order/", s.getOrder)
	mux.HandleFunc("/acme/finalize/", s.finalizeOrder)
	mux.HandleFunc("/acme/cert/", s.getCertificate)
	mux.HandleFunc("/acme", s.directoryHandler)
	mux.HandleFunc("/directory", s.directoryHandler)

	server := &http.Server{
		Addr: ":" + s.port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			log.Printf("%s %s", req.Method, req.RequestURI)
			mux.ServeHTTP(w, req)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	// 7. Start the server
	go func() {
		if err := server.ServeTLS(listener, "", ""); err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	return listener, s.caDir, nil
}
func (s *InMemoryACMEServer) verifyJWSAndIssueNonce(w http.ResponseWriter, r *http.Request, expectedURL string) (*jose.JSONWebSignature, []byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request body: %w", err)
	}

	jws, err := jose.ParseSigned(string(body))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	log.Printf("JWS protected headers: %+v", jws.Signatures[0].Protected)

	nonce := jws.Signatures[0].Protected.Nonce
	if nonce == "" {
		return nil, nil, fmt.Errorf("JWS protected header missing nonce")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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
	if jwsURL != expectedURL {
		return nil, nil, fmt.Errorf("JWS protected header url mismatch: expected %s, got %s", expectedURL, jwsURL)
	}

	return jws, body, nil
}

func (s *InMemoryACMEServer) newNonce(w http.ResponseWriter, r *http.Request) {
	log.Printf("newNonce called for path: %s", r.URL.Path)

	s.mu.Lock()
	defer s.mu.Unlock()

	nonce := generateNonce()
	s.nonces[nonce] = true

	w.Header().Set("Replay-Nonce", nonce)
	w.WriteHeader(http.StatusOK)
}

// generateNonce creates a new unique nonce.
func generateNonce() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Failed to generate nonce: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *InMemoryACMEServer) newAccount(w http.ResponseWriter, r *http.Request) {
	log.Printf("newAccount called for path: %s", r.URL.Path)
	if r.Method == "HEAD" {
		s.newNonce(w, r)
		return
	}

	jws, _, err := s.verifyJWSAndIssueNonce(w, r, fmt.Sprintf("https://%s:%s/acme/new-account", s.currentAcmeServerName, s.port))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	payload, err := jws.Verify(jws.Signatures[0].Header.JSONWebKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		Contact              []string `json:"contact"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	account := &acmeAccount{
		ID:        fmt.Sprintf("%d", s.nextID),
		Key:       jws.Signatures[0].Header.JSONWebKey,
		Contact:   req.Contact,
		Status:    "valid",
		CreatedAt: time.Now(),
	}
	s.accounts[account.ID] = account
	s.nextID++

	w.Header().Set("Location", fmt.Sprintf("https://%s:%s/acme/acct/%s", s.currentAcmeServerName, s.port, account.ID))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(account)
}

func (s *InMemoryACMEServer) newOrder(w http.ResponseWriter, r *http.Request) {
	log.Printf("newOrder called for path: %s", r.URL.Path)
	s.mu.Lock()
	defer s.mu.Unlock()

	jws, _, err := s.verifyJWSAndIssueNonce(w, r, fmt.Sprintf("https://%s:%s/acme/new-order", s.currentAcmeServerName, s.port))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("New order request with KeyID: %s", jws.Signatures[0].Header.KeyID)
	var account *acmeAccount
	if jws.Signatures[0].Header.KeyID != "" {
		accountID := strings.TrimPrefix(jws.Signatures[0].Header.KeyID, fmt.Sprintf("https://%s:%s/acme/acct/", s.currentAcmeServerName, s.port))
		var ok bool
		account, ok = s.accounts[accountID]
		if !ok {
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
	} else {
		// If KeyID is not present, try to find account by JWK
		account = s.findAccountByKey(jws.Signatures[0].Header.JSONWebKey)
		if account == nil {
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
	}

	payload, err := jws.Verify(account.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		Identifiers []AuthzID `json:"identifiers"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	order := &acmeOrder{
		ID:             fmt.Sprintf("%d", s.nextID),
		AccountID:      account.ID,
		Status:         "pending",
		Expires:        time.Now().Add(10 * time.Minute),
		Identifiers:    req.Identifiers,
		Authorizations: []string{},
		FinalizeURL:    fmt.Sprintf("https://%s:%s/acme/finalize/%d", s.currentAcmeServerName, s.port, s.nextID),
	}
	s.orders[order.ID] = order
	s.nextID++

	for _, identifier := range req.Identifiers {
		authz := &acmeAuthorization{
			ID:         fmt.Sprintf("%d", s.nextID),
			Identifier: identifier,
			Status:     "pending", // Initially pending
			Expires:    time.Now().Add(10 * time.Minute),
			Challenges: []*acmeChallenge{},
			Wildcard:   false,
		}
		s.authz[authz.ID] = authz
		order.Authorizations = append(order.Authorizations, fmt.Sprintf("https://%s:%s/acme/authz/%s", s.currentAcmeServerName, s.port, authz.ID))
		s.nextID++

		for _, challengeType := range []string{"http-01"} { // Only offer http-01 for now
			challenge := &acmeChallenge{
				ID:     fmt.Sprintf("%d", s.nextID),
				Type:   challengeType,
				URL:    fmt.Sprintf("https://%s:%s/acme/challenge/%d", s.currentAcmeServerName, s.port, s.nextID),
				Token:  fmt.Sprintf("token-%d", s.nextID),
				Status: "pending",
			}
			s.challenges[challenge.URL] = challenge
			authz.Challenges = append(authz.Challenges, challenge)
			s.nextID++
		}
	}

	w.Header().Set("Location", fmt.Sprintf("https://%s:%s/acme/order/%s", s.currentAcmeServerName, s.port, order.ID))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(order)
}

func (s *InMemoryACMEServer) keyAuthorization(token string, key *jose.JSONWebKey) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, base64.RawURLEncoding.EncodeToString(thumbprint)), nil
}

func (s *InMemoryACMEServer) findAccountByKey(key *jose.JSONWebKey) *acmeAccount {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		log.Printf("Error calculating thumbprint for key: %v", err)
		return nil
	}
	log.Printf("Searching for account with thumbprint: %s", base64.RawURLEncoding.EncodeToString(thumbprint))
	for _, acc := range s.accounts {
		accThumbprint, err := acc.Key.Thumbprint(crypto.SHA256)
		if err != nil {
			log.Printf("Error calculating thumbprint for account %s: %v", acc.ID, err)
			continue
		}
		log.Printf("Account %s has thumbprint: %s", acc.ID, base64.RawURLEncoding.EncodeToString(accThumbprint))
		if string(accThumbprint) == string(thumbprint) {
			log.Printf("Found matching account: %s", acc.ID)
			return acc
		}
	}
	log.Printf("No matching account found")
	return nil
}

func (s *InMemoryACMEServer) getAuthorization(w http.ResponseWriter, r *http.Request) {
	log.Printf("getAuthorization called for path: %s", r.URL.Path)
	s.mu.Lock()
	defer s.mu.Unlock()

	authzID := strings.TrimPrefix(r.URL.Path, "/acme/authz/")
	authz, ok := s.authz[authzID]
	if !ok {
		http.Error(w, "authorization not found", http.StatusNotFound)
		return
	}

	log.Printf("Returning authorization: %+v", authz)
	for _, challenge := range authz.Challenges {
		log.Printf("Challenge: &{Type:%s URL:%s Token:%s Status:%s}", challenge.Type, challenge.URL, challenge.Token, challenge.Status)
	}

	json.NewEncoder(w).Encode(authz)
}

func (s *InMemoryACMEServer) postChallenge(w http.ResponseWriter, r *http.Request) {
	log.Printf("postChallenge called for path: %s", r.URL.Path)
	s.mu.Lock()
	defer s.mu.Unlock()

	jws, _, err := s.verifyJWSAndIssueNonce(w, r, r.URL.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	challenge, ok := s.challenges[r.URL.String()]
	if !ok {
		http.Error(w, "challenge not found", http.StatusNotFound)
		return
	}

	var authz *acmeAuthorization
	for _, a := range s.authz {
		for _, c := range a.Challenges {
			if c.URL == r.URL.String() {
				authz = a
				break
			}
		}
		if authz != nil {
			break
		}
	}

	if authz == nil {
		http.Error(w, "authorization not found", http.StatusInternalServerError)
		return
	}

	var account *acmeAccount
	for _, acc := range s.accounts {
		for _, order := range s.orders {
			if order.AccountID == acc.ID {
				for _, authzURL := range order.Authorizations {
					if strings.Contains(authzURL, authz.ID) {
						account = acc
						break
					}
				}
			}
			if account != nil {
				break
			}
		}
		if account != nil {
			break
		}
	}

	if account == nil {
		http.Error(w, "account not found for authorization", http.StatusInternalServerError)
		return
	}

	_, err = jws.Verify(account.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	challenge.Status = "processing"
	go s.validateChallenge(challenge, authz.ID, authz.Identifier.Value, account.Key)
	json.NewEncoder(w).Encode(challenge)
}

func (s *InMemoryACMEServer) validateChallenge(challenge *acmeChallenge, authzID string, identifierValue string, accountKey *jose.JSONWebKey) {
	switch challenge.Type {
	case "http-01":
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

		s.mu.Lock()
		defer s.mu.Unlock()

		// Re-fetch authz from the map to ensure we have the correct, current object
		authz, ok := s.authz[authzID]
		if !ok {
			log.Printf("Authorization %s not found after validation check", authzID)
			return
		}

		if err != nil {
			challenge.Status = "invalid"
			challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:connection", Detail: fmt.Sprintf("failed to connect to client: %v", err)}
			log.Printf("HTTP-01 challenge for %s failed: %v", identifierValue, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			challenge.Status = "invalid"
			challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: fmt.Sprintf("client returned status %d", resp.StatusCode)}
			log.Printf("HTTP-01 challenge for %s failed: client returned status %d", identifierValue, resp.StatusCode)
			return
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			challenge.Status = "invalid"
			challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:serverInternal", Detail: fmt.Sprintf("failed to read response body: %v", err)}
			log.Printf("HTTP-01 challenge for %s failed: %v", identifierValue, err)
			return
		}

		if string(bodyBytes) != expectedKeyAuth {
			challenge.Status = "invalid"
			challenge.Error = &Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "key authorization mismatch"}
			log.Printf("HTTP-01 challenge for %s failed: key authorization mismatch. Expected %s, got %s", identifierValue, expectedKeyAuth, string(bodyBytes))
			return
		}

		challenge.Status = "valid"
		log.Printf("HTTP-01 challenge for %s marked as valid", identifierValue)
		authz.Status = "valid"
	}
}

func (s *InMemoryACMEServer) getOrder(w http.ResponseWriter, r *http.Request) {
	log.Printf("getOrder called for path: %s", r.URL.Path)
	s.mu.Lock()
	defer s.mu.Unlock()

	orderID := strings.TrimPrefix(r.URL.Path, "/acme/order/")
	order, ok := s.orders[orderID]
	if !ok {
		http.Error(w, "order not found", http.StatusNotFound)
		return
	}

	// Update order status based on authorization statuses
	allValid := true
	oneInvalid := false
	for _, authzURL := range order.Authorizations {
		authzID := strings.TrimPrefix(authzURL, fmt.Sprintf("https://%s:%s/acme/authz/", s.currentAcmeServerName, s.port))
		authz, ok := s.authz[authzID]
		if !ok || authz.Status != "valid" {
			allValid = false
		}
		if ok && authz.Status == "invalid" {
			oneInvalid = true
			break
		}
	}
	if oneInvalid {
		order.Status = "invalid"
	} else if allValid {
		order.Status = "ready"
	}
	log.Printf("Returning order: %+v, CertificateURL: %s", order, order.CertificateURL)
	json.NewEncoder(w).Encode(order)
}

func (s *InMemoryACMEServer) finalizeOrder(w http.ResponseWriter, r *http.Request) {
	log.Printf("finalizeOrder called for path: %s", r.URL.Path)
	s.mu.Lock()
	defer s.mu.Unlock()

	orderID := strings.TrimPrefix(r.URL.Path, "/acme/finalize/")
	log.Printf("Finalizing order with ID: %s", orderID)
	order, ok := s.orders[orderID]
	if !ok {
		http.Error(w, "order not found", http.StatusNotFound)
		return
	}

	jws, _, err := s.verifyJWSAndIssueNonce(w, r, fmt.Sprintf("https://%s:%s/acme/finalize/%s", s.currentAcmeServerName, s.port, orderID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("finalizeOrder JWS KeyID: %s", jws.Signatures[0].Header.KeyID)
	var account *acmeAccount
	if jws.Signatures[0].Header.KeyID != "" {
		accountID := strings.TrimPrefix(jws.Signatures[0].Header.KeyID, fmt.Sprintf("https://%s:%s/acme/acct/", s.currentAcmeServerName, s.port))
		var ok bool
		account, ok = s.accounts[accountID]
		if !ok {
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
	} else {
		account = s.findAccountByKey(jws.Signatures[0].Header.JSONWebKey)
		if account == nil {
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
	}
	payload, err := jws.Verify(account.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	csrBytes, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}

	cert, err := issueCertificate(csr, s.caCert, s.caKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	order.Status = "valid"
	order.CertificateURL = fmt.Sprintf("https://%s:%s/acme/cert/%s", s.currentAcmeServerName, s.port, order.ID)

	acmeCert := &acmeCertificate{
		ID:        order.ID,
		OrderID:   order.ID,
		CertBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		IssuedAt:  time.Now(),
		ExpiresAt: cert.NotAfter,
	}
	s.certs[acmeCert.ID] = acmeCert

	log.Printf("Finalized order %s, CertificateURL set to: %s", order.ID, order.CertificateURL)

	w.Header().Set("Location", fmt.Sprintf("https://%s:%s/acme/order/%s", s.currentAcmeServerName, s.port, order.ID))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(order)
}

func (s *InMemoryACMEServer) getCertificate(w http.ResponseWriter, r *http.Request) {
	log.Printf("getCertificate called for path: %s", r.URL.Path)
	s.mu.Lock()
	defer s.mu.Unlock()

	certID := strings.TrimPrefix(r.URL.Path, "/acme/cert/")
	cert, ok := s.certs[certID]
	if !ok || cert.CertBytes == nil {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(cert.CertBytes)
}

func (s *InMemoryACMEServer) directoryHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("directoryHandler called for path: %s", r.URL.Path)
	dir := struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
		RevokeCert string `json:"revokeCert"`
		KeyChange  string `json:"keyChange"`
	}{
		NewNonce:   fmt.Sprintf("https://%s:%s/acme/new-nonce", s.currentAcmeServerName, s.port),
		NewAccount: fmt.Sprintf("https://%s:%s/acme/new-account", s.currentAcmeServerName, s.port),
		NewOrder:   fmt.Sprintf("https://%s:%s/acme/new-order", s.currentAcmeServerName, s.port),
		RevokeCert: fmt.Sprintf("https://%s:%s/acme/revoke-cert", s.currentAcmeServerName, s.port),
		KeyChange:  fmt.Sprintf("https://%s:%s/acme/key-change", s.currentAcmeServerName, s.port),
	}
	log.Printf("Encoding directory: %+v", dir)
	json.NewEncoder(w).Encode(dir)
}

func issueCertificate(csr *x509.CertificateRequest, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, error) {
	// Implements RFC 8555, Section 7.4.2 "Certificate Issuance"
	// https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.2
	// "The CA issues a certificate for the identifiers in the order, based on the CSR provided by the client."
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     csr.DNSNames,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	// This function generates a self-signed CA certificate for the mock ACME server.
	// While not directly specified in RFC 8555, a CA is a prerequisite for issuing certificates.
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Mock ACME Inc."},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caPrivKey, nil
}

func generateServerCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// This function generates a server certificate signed by the mock CA.
	// While not directly specified in RFC 8555, a server certificate is needed for the HTTPS server.
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Mock ACME Inc."},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{name},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	serverCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return serverCert, certPrivKey, nil
}

// main function is commented out because it is not needed for the library and unit tests.
// func main() {
// 	portFlag := flag.String("port", "443", "Port to listen on")
// 	testModeFlag := flag.Bool("test-mode", false, "Enable test mode (generate cert for localhost, use localhost in URLs)")
// 	flag.Parse()
//
// 	s, err := NewInMemoryACMEServer(*portFlag, *testModeFlag)
// 	if err != nil {
// 		log.Fatalf("Failed to create InMemoryACMEServer: %v", err)
// 	}
//
// 	listener, caDir, err := s.Start()
// 	if err != nil {
// 		log.Fatalf("Failed to start InMemoryACMEServer: %v", err)
// 	}
// 	defer listener.Close()
// 	defer os.RemoveAll(caDir)
//
// 	log.Printf("InMemory ACME server listening on %s", listener.Addr().String())
// 	select {} // Block forever to keep the server running
// }
