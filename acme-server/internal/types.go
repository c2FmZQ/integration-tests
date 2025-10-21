package internal

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

type acmeAccount struct {
	ID        uuid.UUID
	Key       *jose.JSONWebKey
	Status    string
	Contact   []string
	CreatedAt time.Time
}

type acmeOrder struct {
	ID             uuid.UUID `json:"-"`
	AccountID      uuid.UUID `json:"-"`
	Status         string    `json:"status"`
	Expires        time.Time `json:"expires"`
	Identifiers    []AuthzID `json:"identifiers"`
	Authorizations []string  `json:"authorizations"`
	FinalizeURL    string    `json:"finalize"`
	CertificateURL string    `json:"certificate,omitempty"`
	Error          *Problem  `json:"error,omitempty"`
}

type acmeAuthorization struct {
	ID         uuid.UUID        `json:"-"`
	Identifier AuthzID          `json:"identifier"`
	Status     string           `json:"status"`
	Expires    time.Time        `json:"expires"`
	Challenges []*acmeChallenge `json:"challenges"`
	Wildcard   bool             `json:"wildcard"`
}

type acmeChallenge struct {
	ID               uuid.UUID `json:"-"`
	Type             string    `json:"type"`
	Status           string    `json:"status"`
	URL              string    `json:"url"`
	Token            uuid.UUID `json:"token"`
	KeyAuthorization string    `json:"keyAuthorization"`
	Error            *Problem  `json:"error,omitempty"`
}

type acmeCertificate struct {
	ID        uuid.UUID `json:"-"`
	OrderID   uuid.UUID `json:"orderId"`
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
