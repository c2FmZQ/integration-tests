package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudflareAPI(t *testing.T) {
	s := &server{
		zones:   make(map[string]zone),
		zoneIDs: make(map[string]string),
	}
	s.addZone("example.com", []string{"www.example.com"})

	// Test GET /client/v4/zones
	req, err := http.NewRequest("GET", "/client/v4/zones?name=example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(s.handleZones)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var zonesResp struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&zonesResp); err != nil {
		t.Fatal(err)
	}
	if !zonesResp.Success {
		t.Errorf("expected success")
	}
	if len(zonesResp.Result) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zonesResp.Result))
	}
	if zonesResp.Result[0].Name != "example.com" {
		t.Errorf("expected zone name example.com, got %s", zonesResp.Result[0].Name)
	}
	zoneID := zonesResp.Result[0].ID

	// Test GET /client/v4/zones/:id/dns_records
	req, err = http.NewRequest("GET", "/client/v4/zones/"+zoneID+"/dns_records", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(s.handleZone)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var recordsResp struct {
		Success bool     `json:"success"`
		Result  []record `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&recordsResp); err != nil {
		t.Fatal(err)
	}
	if !recordsResp.Success {
		t.Errorf("expected success")
	}
	if len(recordsResp.Result) != 1 {
		t.Errorf("expected 1 record, got %d", len(recordsResp.Result))
	}
	recordID := recordsResp.Result[0].ID

	// Test PATCH /client/v4/zones/:id/dns_records/:id
	var patchReq struct {
		Data httpsData `json:"data"`
	}
	patchReq.Data.Value = "alpn=\"h3\""
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(patchReq); err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequest("PATCH", "/client/v4/zones/"+zoneID+"/dns_records/"+recordID, &buf)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(s.handleZone)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	var patchResp struct {
		Success bool   `json:"success"`
		Result  record `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&patchResp); err != nil {
		t.Fatal(err)
	}
	if !patchResp.Success {
		t.Errorf("expected success")
	}
	if patchResp.Result.Data.Value != "alpn=\"h3\"" {
		t.Errorf("expected record value to be alpn=\"h3\", got %s", patchResp.Result.Data.Value)
	}

	// Test that the change was persisted.
	req, err = http.NewRequest("GET", "/client/v4/zones/"+zoneID+"/dns_records", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(s.handleZone)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	if err := json.NewDecoder(rr.Body).Decode(&recordsResp); err != nil {
		t.Fatal(err)
	}
	if !recordsResp.Success {
		t.Errorf("expected success")
	}
	if len(recordsResp.Result) != 1 {
		t.Errorf("expected 1 record, got %d", len(recordsResp.Result))
	}
	if recordsResp.Result[0].Data.Value != "alpn=\"h3\"" {
		t.Errorf("expected record value to be alpn=\"h3\", got %s", recordsResp.Result[0].Data.Value)
	}
}
