package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/c2FmZQ/ech/dns"
	"golang.org/x/crypto/acme/autocert"
)

// memCache is an in-memory cache for autocert.
type memCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemCache() *memCache {
	return &memCache{
		data: make(map[string][]byte),
	}
}

func (m *memCache) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.data[key]; ok {
		return v, nil
	}
	return nil, autocert.ErrCacheMiss
}

func (m *memCache) Put(ctx context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = slices.Clone(data)
	return nil
}

func (m *memCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func main() {
	m := &autocert.Manager{
		Cache:      newMemCache(),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("doh.example.com"),
		Email:      "doh@example.com",
	}

	// Main DoH server (HTTPS)
	dohMux := http.NewServeMux()
	dohMux.HandleFunc("/dns-query", handleDNSQuery)
	server := &http.Server{
		Addr:      ":443",
		Handler:   dohMux,
		TLSConfig: m.TLSConfig(),
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
		switch question.Type {
		case dns.RRType("A"):
			log.Printf("Received A query for %s", question.Name)
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
			for _, ip := range ips {
				if ip.To4() != nil {
					var answer dns.RR
					answer.Name = question.Name
					answer.Type = dns.RRType("A")
					answer.Class = question.Class
					answer.TTL = 3600
					answer.Data = ip.To4()
					response.Answer = append(response.Answer, answer)
				}
			}
		case dns.RRType("AAAA"):
			log.Printf("Received AAAA query for %s", question.Name)
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
			for _, ip := range ips {
				if ip.To4() == nil {
					var answer dns.RR
					answer.Name = question.Name
					answer.Type = dns.RRType("AAAA")
					answer.Class = question.Class
					answer.TTL = 3600
					answer.Data = ip
					response.Answer = append(response.Answer, answer)
				}
			}
		case dns.RRType("CNAME"):
			log.Printf("Received CNAME query for %s", question.Name)
			cname, err := net.LookupCNAME(strings.TrimRight(question.Name, "."))
			if err != nil {
				log.Printf("Failed to resolve %s: %v", question.Name, err)
				response.RCode = 2 // SERVFAIL
				continue
			}
			if cname == "" {
				response.RCode = 3 // NXDOMAIN
				continue
			}
			response.RCode = 0 // NOERROR
			var answer dns.RR
			answer.Name = question.Name
			answer.Type = dns.RRType("CNAME")
			answer.Class = question.Class
			answer.TTL = 3600
			answer.Data = cname
			response.Answer = append(response.Answer, answer)
		case dns.RRType("HTTPS"):
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
			answer.Data = httpsRR
			response.Answer = append(response.Answer, answer)
			for _, ip := range ips {
				var answer dns.RR
				answer.Name = question.Name
				answer.Class = question.Class
				answer.TTL = 3600
				if four := ip.To4(); four != nil {
					answer.Type = dns.RRType("A")
					answer.Data = four
				} else {
					answer.Type = dns.RRType("AAAA")
					answer.Data = ip
				}
				response.Answer = append(response.Answer, answer)
			}
		}
	}

	packed := response.Bytes()
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}
