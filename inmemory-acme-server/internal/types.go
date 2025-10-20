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
	ID             string    `json:"-"`
	AccountID      string    `json:"-"`
	Status         string    `json:"status"`
	Expires        time.Time `json:"expires"`
	Identifiers    []AuthzID `json:"identifiers"`
	Authorizations []string  `json:"authorizations"`
	FinalizeURL    string    `json:"finalize"`
	CertificateURL string    `json:"certificate,omitempty"`
	Error          *Problem  `json:"error,omitempty"`
}

type acmeAuthorization struct {
	ID         string           `json:"-"`
	Identifier AuthzID          `json:"identifier"`
	Status     string           `json:"status"`
	Expires    time.Time        `json:"expires"`
	Challenges []*acmeChallenge `json:"challenges"`
	Wildcard   bool             `json:"wildcard"`
}

type acmeChallenge struct {
	ID               string   `json:"-"`
	Type             string   `json:"type"`
	Status           string   `json:"status"`
	URL              string   `json:"url"`
	Token            string   `json:"token"`
	KeyAuthorization string   `json:"keyAuthorization"`
	Error            *Problem `json:"error,omitempty"`
}

type acmeCertificate struct {
	ID        string    `json:"-"`
	OrderID   string    `json:"orderId"`
	CertBytes []byte    `json:"certBytes"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
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
