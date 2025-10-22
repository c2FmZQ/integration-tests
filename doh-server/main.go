package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/c2FmZQ/ech/dns"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	m := &autocert.Manager{
		Cache:      autocert.DirCache("/tmp/doh-server-certs"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("doh.example.com"),
	}
	if dirURL := os.Getenv("ACME_DIRECTORY_URL"); dirURL != "" {
		rootCABytes, err := os.ReadFile(os.Getenv("ACME_ROOT_CA"))
		if err != nil {
			log.Fatalf("failed to read root CA: %v", err)
		}
		certs := x509.NewCertPool()
		if ok := certs.AppendCertsFromPEM(rootCABytes); !ok {
			log.Fatal("failed to parse root certificate")
		}
		m.Client = &acme.Client{
			DirectoryURL: dirURL,
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: certs,
					},
					ForceAttemptHTTP2: true,
				},
			},
		}
	}

	http.HandleFunc("/dns-query", handleDNSQuery)
	server := &http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			GetCertificate: m.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
		},
	}

	log.Println("Starting DoH server on :443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("ListenAndServeTLS: %v", err)
	}
}

func handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	msg, err := dns.DecodeMessage(body)
	if err != nil {
		http.Error(w, "Failed to decode DNS message", http.StatusBadRequest)
		return
	}

	if len(msg.Question) == 0 {
		http.Error(w, "No questions in DNS message", http.StatusBadRequest)
		return
	}

	response := new(dns.Message)
	response.ID = msg.ID
	response.QR = 1
	response.OpCode = msg.OpCode
	response.RD = msg.RD
	response.RA = 1
	response.Question = msg.Question

	for _, question := range msg.Question {
		if question.Type == dns.RRType("HTTPS") {
			log.Printf("Received HTTPS query for %s", question.Name)
			ips, err := net.LookupIP(strings.TrimRight(question.Name, "."))
			if err != nil {
				log.Printf("Failed to resolve %s: %v", question.Name, err)
				response.RCode = 2 // SERVFAIL
				continue
			}
			if len(ips) == 0 {
				response.RCode = 3 // NXDOMAIN
				continue
			}

			response.RCode = 0 // NOERROR
			var answer dns.RR
			answer.Name = question.Name
			answer.Type = dns.RRType("HTTPS")
			answer.Class = question.Class
			answer.TTL = 3600
			httpsRR := dns.HTTPS{
				Priority: 1,
				Target:   ".",
			}
			for _, ip := range ips {
				if ip.To4() != nil {
					httpsRR.IPv4Hint = append(httpsRR.IPv4Hint, ip.To4())
				} else {
					httpsRR.IPv6Hint = append(httpsRR.IPv6Hint, ip)
				}
			}
			answer.Data = httpsRR
			response.Answer = append(response.Answer, answer)
		}
	}

	packed := response.Bytes()
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}
