package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type keyType int

const (
	rsaKey keyType = iota
	ecdsaKey
)

// keyAuthorization creates the key authorization string for a given token and account key.
func (s *InMemoryACMEServer) keyAuthorization(token string, key *jose.JSONWebKey) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, base64.RawURLEncoding.EncodeToString(thumbprint)), nil
}

// issueCertificate issues a certificate for the given CSR, signed by the CA.
func issueCertificate(csr *x509.CertificateRequest, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, error) {
	// Implements RFC 8555, Section 7.4.2 "Certificate Issuance"
	// https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.2
	// "The CA issues a certificate for the identifiers in the order, based on the CSR provided by the client."
	subjectKeyId, err := calculateSubjectKeyId(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		SubjectKeyId: subjectKeyId,
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

// generateCA generates a self-signed CA certificate and private key.
func generateCA(kt keyType) (*x509.Certificate, crypto.Signer, error) {
	// This function generates a self-signed CA certificate for the mock ACME server.
	// While not directly specified in RFC 8555, a CA is a prerequisite for issuing certificates.
	caPrivKey, err := generatePrivateKey(kt)
	if err != nil {
		return nil, nil, err
	}

	pubKey := caPrivKey.Public()

	subjectKeyId, err := calculateSubjectKeyId(pubKey)
	if err != nil {
		return nil, nil, err
	}
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mock ACME Inc."},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          subjectKeyId,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caPrivKey, nil
}

// generateServerCert generates a server certificate signed by the mock CA.
func generateServerCert(caCert *x509.Certificate, caKey crypto.Signer, name string) (*x509.Certificate, crypto.Signer, error) {
	// This function generates a server certificate signed by the mock CA.
	// While not directly specified in RFC 8555, a server certificate is needed for the HTTPS server.
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	subjectKeyId, err := calculateSubjectKeyId(&certPrivKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mock ACME Inc."},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: subjectKeyId,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{name},
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

func calculateSubjectKeyId(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(spki)
	return hash[:], nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	return serialNumber, nil
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
