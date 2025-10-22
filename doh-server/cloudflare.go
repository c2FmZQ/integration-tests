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

func (s *server) addZone(name string, hosts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make(map[string]record)
	for _, h := range hosts {
		rec := record{
			ID:   uuid.New().String(),
			Name: h,
			Data: httpsData{
				Priority: 1,
				Target:   ".",
				Value:    "alpn=\"h2\"",
			},
		}
		records[rec.ID] = rec
	}
	z := zone{
		ID:      uuid.New().String(),
		Name:    name,
		Records: records,
	}
	s.zones[name] = z
	s.zoneIDs[z.ID] = name
	log.Printf("Added zone %s [%s]  with hosts %v", name, z.ID, hosts)
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
	const prefix = "/client/v4/zones/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "unexpected path prefix", http.StatusNotFound)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) < 1 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	zoneID := parts[0]
	zoneName, ok := s.zoneIDs[zoneID]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	z := s.zones[zoneName]
	if len(parts) == 1 {
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

	if len(parts) > 1 && parts[1] == "dns_records" {
		if len(parts) == 2 {
			// This is a request for the list of records.
			var records []record
			name := r.URL.Query().Get("name")
			for _, rec := range z.Records {
				if name == "" || rec.Name == name {
					records = append(records, rec)
				}
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
		if len(parts) == 3 {
			// This is a request for a specific record.
			recordID := parts[2]
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
				s.mu.RUnlock()
				s.mu.Lock()
				rec.Data = req.Data
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
