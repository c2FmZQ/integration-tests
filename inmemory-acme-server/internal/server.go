package internal

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

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

// NewInMemoryACMEServer creates a new InMemoryACMEServer.
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
		caFile.Close()
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
