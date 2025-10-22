package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/c2FmZQ/ech/dns"
)

func (s *server) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
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
			s.handleAQuery(response, question)
		case dns.RRType("AAAA"):
			s.handleAAAAQuery(response, question)
		case dns.RRType("CNAME"):
			s.handleCNAMEQuery(response, question)
		case dns.RRType("HTTPS"):
			s.handleHTTPSQuery(response, question)
		}
	}

	packed := response.Bytes()
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func (s *server) handleAQuery(response *dns.Message, question dns.Question) {
	log.Printf("Received A query for %s", question.Name)
	ips, err := net.LookupIP(strings.TrimRight(question.Name, "."))
	if err != nil {
		log.Printf("Failed to resolve %s: %v", question.Name, err)
		response.RCode = 2 // SERVFAIL
		return
	}
	if len(ips) == 0 {
		response.RCode = 3 // NXDOMAIN
		return
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
}

func (s *server) handleAAAAQuery(response *dns.Message, question dns.Question) {
	log.Printf("Received AAAA query for %s", question.Name)
	ips, err := net.LookupIP(strings.TrimRight(question.Name, "."))
	if err != nil {
		log.Printf("Failed to resolve %s: %v", question.Name, err)
		response.RCode = 2 // SERVFAIL
		return
	}
	if len(ips) == 0 {
		response.RCode = 3 // NXDOMAIN
		return
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
}

func (s *server) handleCNAMEQuery(response *dns.Message, question dns.Question) {
	log.Printf("Received CNAME query for %s", question.Name)
	cname, err := net.LookupCNAME(strings.TrimRight(question.Name, "."))
	if err != nil {
		log.Printf("Failed to resolve %s: %v", question.Name, err)
		response.RCode = 2 // SERVFAIL
		return
	}
	if cname == "" {
		response.RCode = 3 // NXDOMAIN
		return
	}
	response.RCode = 0 // NOERROR
	var answer dns.RR
	answer.Name = question.Name
	answer.Type = dns.RRType("CNAME")
	answer.Class = question.Class
	answer.TTL = 3600
	answer.Data = cname
	response.Answer = append(response.Answer, answer)
}

func (s *server) handleHTTPSQuery(response *dns.Message, question dns.Question) {
	log.Printf("Received HTTPS query for %s", question.Name)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, z := range s.zones {
		if strings.HasSuffix(question.Name, z.Name) {
			for _, rec := range z.Records {
				if rec.Name == question.Name {
					var answer dns.RR
				answer.Name = question.Name
				answer.Type = dns.RRType("HTTPS")
				answer.Class = question.Class
				answer.TTL = 3600
				httpsRR := dns.HTTPS{
					Priority: 1,
					Target:   ".",
				}
				parts := strings.Split(rec.Data.Value, " ")
				for _, part := range parts {
					if strings.HasPrefix(part, "alpn=") {
						httpsRR.ALPN = strings.Split(strings.Trim(part[5:], "\""), ",")
					}
					if strings.HasPrefix(part, "ech=") {
						httpsRR.ECH = []byte(strings.Trim(part[4:], "\""))
					}
				}
				answer.Data = httpsRR
				response.Answer = append(response.Answer, answer)
				return
				}
			}
		}
	}

	ips, err := net.LookupIP(strings.TrimRight(question.Name, "."))
	if err != nil {
		log.Printf("Failed to resolve %s: %v", question.Name, err)
		response.RCode = 2 // SERVFAIL
		return
	}
	if len(ips) == 0 {
		response.RCode = 3 // NXDOMAIN
		return
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
