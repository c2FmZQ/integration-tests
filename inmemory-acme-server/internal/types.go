package internal

import (
	"time"

	"gopkg.in/square/go-jose.v2"
)

type acmeAccount struct {
	ID        string
	Key       *jose.JSONWebKey
	Status    string
	Contact   []string
	CreatedAt time.Time
}

type acmeOrder struct {
	ID             string
	AccountID      string
	Status         string    `json:"Status"`
	Expires        time.Time `json:"Expires"`
	Identifiers    []AuthzID `json:"Identifiers"`
	Authorizations []string  `json:"Authorizations"`
	FinalizeURL    string    `json:"Finalize"`
	CertificateURL string    `json:"Certificate"`
	Error          *Problem  `json:"Error"`
}

type acmeAuthorization struct {
	ID         string
	Identifier AuthzID
	Status     string
	Expires    time.Time
	Challenges []*acmeChallenge
	Wildcard   bool
}

type acmeChallenge struct {
	ID               string
	Type             string
	Status           string
	URL              string
	Token            string
	KeyAuthorization string
	Error            *Problem
}

type acmeCertificate struct {
	ID        string
	OrderID   string
	CertBytes []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// AuthzID represents an ACME identifier for authorization.
type AuthzID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Problem represents an ACME problem detail.
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
	Status int    `json:"status,omitempty"`
}
