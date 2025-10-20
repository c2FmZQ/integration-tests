package internal

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// newNonce is the handler for the new-nonce endpoint.
func (s *InMemoryACMEServer) newNonce(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nonce := generateNonce()
	s.nonces[nonce] = true

	w.Header().Set("Replay-Nonce", nonce)
	w.WriteHeader(http.StatusOK)
}

// newAccount is the handler for the new-account endpoint.
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

// newOrder is the handler for the new-order endpoint.
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

		for _, challengeType := range []string{"http-01", "tls-alpn-01"} {
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

// getAuthorization is the handler for the authz endpoint.
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

// postChallenge is the handler for the challenge endpoint.
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

// getOrder is the handler for the order endpoint.
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

// finalizeOrder is the handler for the finalize endpoint.
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

	// Validate that the CSR identifiers match the order identifiers.
	// https://tools.ietf.org/html/rfc8555#section-7.4
	csrIdentifiers := getCSRIdentifiers(csr)
	orderIdentifiers := getOrderIdentifiers(order)
	if !identifiersMatch(csrIdentifiers, orderIdentifiers) {
		http.Error(w, "CSR identifiers do not match order identifiers", http.StatusForbidden)
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

// getCertificate is the handler for the cert endpoint.
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

// directoryHandler is the handler for the directory endpoint.
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

// getCSRIdentifiers extracts all unique identifiers from a CSR.
func getCSRIdentifiers(csr *x509.CertificateRequest) []string {
	idMap := make(map[string]struct{})
	if csr.Subject.CommonName != "" {
		idMap[csr.Subject.CommonName] = struct{}{}
	}
	for _, name := range csr.DNSNames {
		idMap[name] = struct{}{}
	}
	identifiers := make([]string, 0, len(idMap))
	for id := range idMap {
		identifiers = append(identifiers, id)
	}
	return identifiers
}

// getOrderIdentifiers extracts all identifiers from an ACME order.
func getOrderIdentifiers(order *acmeOrder) []string {
	var identifiers []string
	for _, id := range order.Identifiers {
		identifiers = append(identifiers, id.Value)
	}
	return identifiers
}

// identifiersMatch checks if two slices of identifiers are exactly the same.
func identifiersMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int)
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		if _, ok := m[v]; !ok {
			return false
		}
		m[v]--
		if m[v] == 0 {
			delete(m, v)
		}
	}
	return len(m) == 0
}
