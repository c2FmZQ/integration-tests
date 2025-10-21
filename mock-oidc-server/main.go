package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

var (
	addr = flag.String("addr", ":8080", "Listen address")
)

var (
	identities = []string{
		"alice@example.com",
		"bob@example.com",
		"charlie@example.com",
	}
	clients = map[string]string{
		"CLIENTID": "CLIENTSECRET",
	}
)

type authRequest struct {
	RedirectURI string
	State       string
}

var (
	authRequests      = make(map[string]authRequest)
	authRequestsMutex sync.Mutex

	authCodes      = make(map[string]string)
	authCodesMutex sync.Mutex

	privateKey *rsa.PrivateKey
	publicKey  *jose.JSONWebKey
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}

func run() error {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	publicKey = &jose.JSONWebKey{Key: &privateKey.PublicKey, Algorithm: "RS256", KeyID: "1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", wellKnownHandler)
	mux.HandleFunc("/authorization", authorizationHandler)
	mux.HandleFunc("/auth-callback", authCallbackHandler)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/jwks", jwksHandler)

	log.Printf("Listening on %s", *addr)
	return http.ListenAndServe(*addr, mux)
}

func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"issuer":                 "http://mock-oidc-server.local:8080",
		"authorization_endpoint": "http://mock-oidc-server.local:8080/authorization",
		"token_endpoint":         "http://mock-oidc-server.local:8080/token",
		"jwks_uri":               "http://mock-oidc-server.local:8080/jwks",
	})
}

func authorizationHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("OIDC: %s %s", r.Method, r.RequestURI)
	reqID := newID()
	authRequestsMutex.Lock()
	authRequests[reqID] = authRequest{
		RedirectURI: r.FormValue("redirect_uri"),
		State:       r.FormValue("state"),
	}
	authRequestsMutex.Unlock()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h1>Select Identity</h1>`)
	for _, id := range identities {
		fmt.Fprintf(w, `<p><a class="user-id-link" href="/auth-callback?req_id=%s&user=%s">%s</a></p>`, reqID, id, id)
	}
}

func authCallbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("OIDC: %s %s", r.Method, r.RequestURI)
	reqID := r.FormValue("req_id")
	user := r.FormValue("user")

	authRequestsMutex.Lock()
	req, ok := authRequests[reqID]
	delete(authRequests, reqID)
	authRequestsMutex.Unlock()

	if !ok {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	code := newID()
	authCodesMutex.Lock()
	authCodes[code] = user
	authCodesMutex.Unlock()

	redirectURL, _ := url.Parse(req.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", req.State)
	redirectURL.RawQuery = q.Encode()

	out := redirectURL.String()
	log.Printf("OIDC redirect to %s", out)
	http.Redirect(w, r, out, http.StatusFound)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("OIDC: %s %s", r.Method, r.RequestURI)
	r.ParseForm()
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if secret, ok := clients[clientID]; !ok || secret != clientSecret {
		http.Error(w, "invalid client", http.StatusUnauthorized)
		return
	}

	authCodesMutex.Lock()
	user, ok := authCodes[code]
	delete(authCodes, code)
	authCodesMutex.Unlock()

	if !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	claims := jwt.MapClaims{
		"iss":   "http://mock-oidc-server.local:8080",
		"sub":   user,
		"aud":   clientID,
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
		"email": user,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "1"
	idToken, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "mock-access-token",
		"token_type":   "Bearer",
		"id_token":     idToken,
	})
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("OIDC: %s %s", r.Method, r.RequestURI)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{*publicKey},
	})
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
