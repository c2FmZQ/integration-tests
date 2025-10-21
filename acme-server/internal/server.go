package internal

import (
	"context"
	"crypto"
	"crypto/ecdsa"
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
	listener   net.Listener
	caCerts    map[keyType]*x509.Certificate
	caKeys     map[keyType]crypto.Signer
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
		nonces:     make(map[string]bool),
		caCerts:    make(map[keyType]*x509.Certificate),
		caKeys:     make(map[keyType]crypto.Signer),
	}, nil
}

// Start starts the HTTPS server for the MockACMEServer.
func (s *InMemoryACMEServer) Start(ctx context.Context) (net.Listener, error) {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("net.Listen(%q): %w", s.addr, err)
	}
	s.port = listener.Addr().(*net.TCPAddr).Port

	for _, kt := range []keyType{rsaKey, ecdsaKey} {
		caCert, caKey, err := generateCA(kt)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", err)
		}
		s.caCerts[kt] = caCert
		s.caKeys[kt] = caKey
	}

	caFile, err := os.Create(s.certFile)
	if err != nil {
		return nil, fmt.Errorf("Create cert file: %w", err)
	}
	defer caFile.Close()
	for _, cert := range s.caCerts {
		if err := pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, fmt.Errorf("Write cert file: %w", err)
		}
	}

	serverCert, serverKey, err := generateServerCert(s.caCerts[ecdsaKey], s.caKeys[ecdsaKey], s.publicName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	serverKeyBytes, err := marshalPrivateKey(serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal server key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyBytes}),
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

func marshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(k)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}
