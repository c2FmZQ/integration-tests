package internal

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
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
)

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
	Status         string    `json:"Status"`
	Expires        time.Time `json:"Expires"`
	Identifiers    []AuthzID `json:"Identifiers"`
	Authorizations []string  `json:"Authorizations"`
	FinalizeURL    string    `json:"Finalize"`
	CertificateURL string    `json:"Certificate"`
	Error          *Problem  `json:"Error"`
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
	publicName string
	addr       string
	certFile   string

	mu         sync.Mutex
	accounts   map[string]*acmeAccount       // map[accountID]*acmeAccount
	orders     map[string]*acmeOrder         // map[orderID]*acmeOrder
	authz      map[string]*acmeAuthorization // map[authzID]*acmeAuthorization
	challenges map[string]*acmeChallenge     // map[token]*acmeChallenge
	certs      map[string]*acmeCertificate   // map[certID]*acmeCertificate
	nextID     int
	listener   net.Listener
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	nonces     map[string]bool
	port       int
}

func NewInMemoryACMEServer(publicName, addr, certFile string) (*InMemoryACMEServer, error) {
	return &InMemoryACMEServer{
		publicName: publicName,
		addr:       addr,
		certFile:   certFile,
		accounts:   make(map[string]*acmeAccount),
		orders:     make(map[string]*acmeOrder),
		authz:      make(map[string]*acmeAuthorization),
		challenges: make(map[string]*acmeChallenge),
		certs:      make(map[string]*acmeCertificate),
		nextID:     1,
		nonces:     make(map[string]bool),
	}, nil
}

// Start starts the HTTPS server for the MockACMEServer.
func (s *InMemoryACMEServer) Start(ctx context.Context) (net.Listener, error) {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("net.Listen(%q): %w", s.addr, err)
	}
	s.port = listener.Addr().(*net.TCPAddr).Port

	caCert, caKey, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	s.caCert = caCert
	s.caKey = caKey

	caFile, err := os.Create(s.certFile)
	if err != nil {
		return nil, fmt.Errorf("Create cert file: %w", err)
	}
	if err := pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw}); err != nil {
		return nil, fmt.Errorf("Write cert file: %w", err)
	}
	if err := caFile.Close(); err != nil {
		return nil, fmt.Errorf("Close cert file: %v", err)
	}

	serverCert, serverKey, err := generateServerCert(s.caCert, s.caKey, s.publicName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

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
		Addr: s.addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			log.Printf("%s %s", req.Method, req.RequestURI)
			mux.ServeHTTP(w, req)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	go func() {
		if err := server.ServeTLS(listener, "", ""); !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		server.Close()
	}()

	return listener, nil
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

func (s *InMemoryACMEServer) newNonce(w http.ResponseWriter, r *http.Request) {
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
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *InMemoryACMEServer) newAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		s.newNonce(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	jws, _, err := s.verifyJWSAndIssueNonce(w, r, "/acme/new-account")
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

	account := &acmeAccount{
		ID:        fmt.Sprintf("%d", s.nextID),
		Key:       jws.Signatures[0].Header.JSONWebKey,
		Contact:   req.Contact,
		Status:    "valid",
		CreatedAt: time.Now(),
	}
	s.accounts[account.ID] = account
	s.nextID++

	w.Header().Set("Location", fmt.Sprintf("https://%s:%d/acme/acct/%s", s.publicName, s.port, account.ID))
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(account)
}

func (s *InMemoryACMEServer) newOrder(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jws, _, err := s.verifyJWSAndIssueNonce(w, r, "/acme/new-order")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var account *acmeAccount
	if jws.Signatures[0].Header.KeyID != "" {
		accountID := strings.TrimPrefix(jws.Signatures[0].Header.KeyID, fmt.Sprintf("https://%s:%d/acme/acct/", s.publicName, s.port))
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
		FinalizeURL:    fmt.Sprintf("https://%s:%d/acme/finalize/%d", s.publicName, s.port, s.nextID),
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
		order.Authorizations = append(order.Authorizations, fmt.Sprintf("https://%s:%d/acme/authz/%s", s.publicName, s.port, authz.ID))
		s.nextID++

		for _, challengeType := range []string{"http-01"} { // Only offer http-01 for now
			challenge := &acmeChallenge{
				ID:     fmt.Sprintf("%d", s.nextID),
				Type:   challengeType,
				URL:    fmt.Sprintf("https://%s:%d/acme/challenge/%d", s.publicName, s.port, s.nextID),
				Token:  fmt.Sprintf("token-%d", s.nextID),
				Status: "pending",
			}
			s.challenges[challenge.URL] = challenge
			authz.Challenges = append(authz.Challenges, challenge)
			s.nextID++
		}
	}

	w.Header().Set("Location", fmt.Sprintf("https://%s:%d/acme/order/%s", s.publicName, s.port, order.ID))
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

func (s *InMemoryACMEServer) getAuthorization(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	authzID := strings.TrimPrefix(r.URL.Path, "/acme/authz/")
	authz, ok := s.authz[authzID]
	if !ok {
		http.Error(w, "authorization not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(authz)
}

func (s *InMemoryACMEServer) postChallenge(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jws, _, err := s.verifyJWSAndIssueNonce(w, r, r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("https://%s:%d%s", s.publicName, s.port, r.URL.Path)
	challenge, ok := s.challenges[key]
	if !ok {
		http.Error(w, "challenge not found", http.StatusNotFound)
		return
	}

	var authz *acmeAuthorization
	for _, a := range s.authz {
		for _, c := range a.Challenges {
			if c.URL == key {
				authz = a
				break
			}
		}
		if authz != nil {
			break
		}
	}

	if authz == nil {
		log.Print("postChallenge: authorization not found")
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
		log.Print("postChallenge: account not found for authorization")
		http.Error(w, "account not found for authorization", http.StatusInternalServerError)
		return
	}

	_, err = jws.Verify(account.Key)
	if err != nil {
		log.Printf("postChallenge jws.Verify: %v", err)
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
		authzID := strings.TrimPrefix(authzURL, fmt.Sprintf("https://%s:%d/acme/authz/", s.publicName, s.port))
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
	json.NewEncoder(w).Encode(order)
}

func (s *InMemoryACMEServer) finalizeOrder(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	orderID := strings.TrimPrefix(r.URL.Path, "/acme/finalize/")
	order, ok := s.orders[orderID]
	if !ok {
		http.Error(w, "order not found", http.StatusNotFound)
		return
	}

	jws, _, err := s.verifyJWSAndIssueNonce(w, r, fmt.Sprintf("/acme/finalize/%s", orderID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var account *acmeAccount
	if jws.Signatures[0].Header.KeyID != "" {
		accountID := strings.TrimPrefix(jws.Signatures[0].Header.KeyID, fmt.Sprintf("https://%s:%d/acme/acct/", s.publicName, s.port))
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
	order.CertificateURL = fmt.Sprintf("https://%s:%d/acme/cert/%s", s.publicName, s.port, order.ID)

	acmeCert := &acmeCertificate{
		ID:        order.ID,
		OrderID:   order.ID,
		CertBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		IssuedAt:  time.Now(),
		ExpiresAt: cert.NotAfter,
	}
	s.certs[acmeCert.ID] = acmeCert

	w.Header().Set("Location", fmt.Sprintf("https://%s:%d/acme/order/%s", s.publicName, s.port, order.ID))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(order)
}

func (s *InMemoryACMEServer) getCertificate(w http.ResponseWriter, r *http.Request) {
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
	dir := struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
		RevokeCert string `json:"revokeCert"`
		KeyChange  string `json:"keyChange"`
	}{
		NewNonce:   fmt.Sprintf("https://%s:%d/acme/new-nonce", s.publicName, s.port),
		NewAccount: fmt.Sprintf("https://%s:%d/acme/new-account", s.publicName, s.port),
		NewOrder:   fmt.Sprintf("https://%s:%d/acme/new-order", s.publicName, s.port),
		RevokeCert: fmt.Sprintf("https://%s:%d/acme/revoke-cert", s.publicName, s.port),
		KeyChange:  fmt.Sprintf("https://%s:%d/acme/key-change", s.publicName, s.port),
	}
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
