package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type zone struct {
	ID      string
	Name    string
	Records map[string]record
}

type record struct {
	ID   string
	Name string
	Data httpsData
}

type httpsData struct {
	Priority int    `json:"priority"`
	Target   string `json:"target"`
	Value    string `json:"value"`
}

func (s *server) addZone(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := record{
		ID:   uuid.New().String(),
		Name: name,
		Data: httpsData{
			Priority: 1,
			Target:   ".",
			Value:    "alpn=\"h2\"",
		},
	}
	z := zone{
		ID:      uuid.New().String(),
		Name:    name,
		Records: map[string]record{rec.ID: rec},
	}
	s.zones[name] = z
	log.Printf("Added zone %s", name)
}

func (s *server) handleZones(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	z, ok := s.zones[name]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}{
		Success: true,
		Result: []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{
			{
				ID:   z.ID,
				Name: z.Name,
			},
		},
	})
}

func (s *server) handleZone(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	zoneID := parts[3]
	var z *zone
	for i := range s.zones {
		zone := s.zones[i]
		if zone.ID == zoneID {
			z = &zone
			break
		}
	}
	if z.ID == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if len(parts) == 4 {
		// This is a request for the zone itself.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Success bool `json:"success"`
			Result  struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}{
			Success: true,
			Result: struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{
				ID:   z.ID,
				Name: z.Name,
			},
		})
		return
	}

	if len(parts) > 4 && parts[4] == "dns_records" {
		if len(parts) == 5 {
			// This is a request for the list of records.
			var records []record
			for _, rec := range z.Records {
				records = append(records, rec)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(struct {
				Success bool     `json:"success"`
				Result  []record `json:"result"`
			}{
				Success: true,
				Result:  records,
			})
			return
		}
		if len(parts) == 6 {
			// This is a request for a specific record.
			recordID := parts[5]
			rec, ok := z.Records[recordID]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if r.Method == http.MethodPatch {
				var req struct {
					Data httpsData `json:"data"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				rec.Data = req.Data
				s.mu.RUnlock()
				s.mu.Lock()
				z.Records[recordID] = rec
				s.mu.Unlock()
				s.mu.RLock()
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(struct {
				Success bool   `json:"success"`
				Result  record `json:"result"`
			}{
				Success: true,
				Result:  rec,
			})
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}
