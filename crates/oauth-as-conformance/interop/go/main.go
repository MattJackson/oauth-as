// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson
//
// THIRD-PARTY CLIENT DRIVE, second judge.
//
// Everything protocol-shaped here is decided by golang.org/x/oauth2 (pinned exactly in go.mod),
// which is written and maintained by the Go project and has no relationship to this repository or
// to the Rust `oauth2` crate the rest of this harness drives. It builds the requests, parses the
// responses, runs the RFC 8628 poll loop (including its own reading of authorization_pending and
// slow_down), and decides for itself whether what came back is a usable token.
//
// This file adds only the assertions that library cannot make on its own, each with the section
// that settles it, plus the two things it has no opinion about: RFC 9207 `iss` on the
// authorization response, and RFC 6749 s4.4.3's prohibition on a refresh token in a client
// credentials response.
//
// It covers two grants the Rust client drive does NOT: client credentials, and the refresh grant
// with rotation. That is the point of a second judge; a second opinion on the same question is
// worth less than a first opinion on a new one.
//
// It also covers RFC 7523 private_key_jwt client authentication with RS256 and EdDSA — the Rust
// drive interops on ES256 only. The assertion is hand-assembled and signed with Go's stdlib
// crypto/rsa (PKCS#1 v1.5 + SHA-256) and crypto/ed25519 (raw 64-byte), no third-party JWT library,
// over the pinned RFC 7515 A.2 / RFC 8037 A.4 keypairs whose public halves the AS registers. Each
// algorithm is judged twice: a valid assertion must be accepted and a one-byte-tampered signature
// must be rejected as invalid_client, so a broken or absent verifier cannot pass either check.
//
// FAILS LOUDLY, never skips: with no OAUTH_AS_BASE_URL it exits 2 rather than reporting success.
// Run it through scripts/oauth-interop.sh, whose --selftest proves it can go RED first.
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	publicClientID       = "conformance-public"
	publicRedirectURI    = "http://127.0.0.1:8917/cb"
	confidentialClientID = "conformance-confidential"
	confidentialSecret   = "conformance-secret-0123456789abcdef"

	// RFC 7521 s4.2: the client_assertion_type for a JWT bearer assertion.
	jwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// The two RFC 7523 private_key_jwt fixture clients (see conformance_server.rs). Their
	// registered PUBLIC keys are the RFC 7515 A.2 (RSA) and RFC 8037 A.4 (Ed25519) vectors; this
	// judge holds the matching PRIVATE halves below and signs with Go's own stdlib crypto, so the
	// AS's rsa / ed25519-dalek verifiers are being judged by an independent implementation.
	pkjwtRS256ClientID = "conformance-pkjwt-rs256"
	pkjwtRS256Kid      = "conformance-rs256-1"
	pkjwtEdDSAClientID = "conformance-pkjwt-eddsa"
	pkjwtEdDSAKid      = "conformance-eddsa-1"
)

// RFC 7515 appendix A.2 RSA private key (base64urlUInt members). e is AQAB = 65537. The AS holds
// only n and e; these private members never leave the client, exactly as private_key_jwt intends.
const (
	rs256N = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
	rs256D = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
	rs256P = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
	rs256Q = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"

	// RFC 8037 appendix A.4 Ed25519 32-byte private seed `d`. The public `x` is the AS's registered
	// key; NewKeyFromSeed derives the full private key from this seed.
	eddsaD = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
)

type metadata struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
}

var failures int

func check(name string, err error) {
	if err != nil {
		fmt.Printf("FAIL  %s: %v\n", name, err)
		failures++
		return
	}
	fmt.Printf("ok    %s\n", name)
}

func noRedirect() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func main() {
	base := strings.TrimRight(os.Getenv("OAUTH_AS_BASE_URL"), "/")
	if base == "" {
		fmt.Fprintln(os.Stderr, "OAUTH_AS_BASE_URL is not set; refusing to pass vacuously")
		os.Exit(2)
	}
	ctx := context.Background()
	hc := noRedirect()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, hc)

	meta, err := fetchMetadata(hc, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot fetch RFC 8414 metadata: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("discovered issuer %s\n", meta.Issuer)

	check("device flow (RFC 8628), judged by golang.org/x/oauth2", deviceFlow(ctx, hc, meta))
	tok, err := authCodePKCE(ctx, hc, meta)
	check("authorization code + PKCE S256, judged by golang.org/x/oauth2", err)
	if err == nil {
		check("refresh token grant (RFC 6749 s6), judged by golang.org/x/oauth2", refresh(ctx, meta, tok))
	}
	check("client credentials (RFC 6749 s4.4), judged by golang.org/x/oauth2/clientcredentials",
		clientCreds(ctx, meta))

	// The RS256/EdDSA half of the second-judge story: hand-assembled RFC 7523 private_key_jwt
	// assertions signed by Go's stdlib crypto, verified by this crate's rsa / ed25519-dalek. Each
	// step proves BOTH that a valid assertion is accepted and that a one-byte-tampered signature is
	// rejected, so the check cannot pass vacuously if verification were absent.
	check("private_key_jwt RS256 (RFC 7523), signed by Go crypto/rsa PKCS#1v1.5+SHA-256",
		privateKeyJWT(hc, meta, rs256Client()))
	check("private_key_jwt EdDSA (RFC 7523), signed by Go crypto/ed25519",
		privateKeyJWT(hc, meta, eddsaClient()))

	if failures > 0 {
		fmt.Printf("\n%d interop check(s) FAILED\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nall interop checks passed")
}

func fetchMetadata(hc *http.Client, base string) (*metadata, error) {
	resp, err := hc.Get(base + "/.well-known/oauth-authorization-server")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("metadata returned %d", resp.StatusCode)
	}
	var m metadata
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	if m.TokenEndpoint == "" || m.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("metadata missing required endpoints")
	}
	return &m, nil
}

func cfg(meta *metadata, clientID, secret, redirect string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: secret,
		RedirectURL:  redirect,
		Endpoint: oauth2.Endpoint{
			AuthURL:       meta.AuthorizationEndpoint,
			TokenURL:      meta.TokenEndpoint,
			DeviceAuthURL: meta.DeviceAuthorizationEndpoint,
		},
	}
}

func deviceFlow(ctx context.Context, hc *http.Client, meta *metadata) error {
	if meta.DeviceAuthorizationEndpoint == "" {
		return fmt.Errorf("metadata advertises no device_authorization_endpoint")
	}
	c := cfg(meta, publicClientID, "", "")
	da, err := c.DeviceAuth(ctx)
	if err != nil {
		return fmt.Errorf("x/oauth2 rejected the RFC 8628 s3.2 device authorization response: %w", err)
	}
	if da.UserCode == "" || da.VerificationURI == "" || da.DeviceCode == "" {
		return fmt.Errorf("device authorization response parsed but incomplete: %+v", da)
	}
	form := url.Values{"user_code": {da.UserCode}}
	resp, err := hc.PostForm(da.VerificationURI, form)
	if err != nil {
		return fmt.Errorf("approving the user_code: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("seeded AS refused the user_code approval: %d", resp.StatusCode)
	}
	pollCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	tok, err := c.DeviceAccessToken(pollCtx, da)
	if err != nil {
		return fmt.Errorf("x/oauth2 rejected the device token exchange: %w", err)
	}
	if !tok.Valid() {
		return fmt.Errorf("x/oauth2 considers the issued token invalid")
	}
	if tok.TokenType != "Bearer" {
		return fmt.Errorf("token_type was %q, RFC 6749 s5.1 / RFC 6750 expects Bearer", tok.TokenType)
	}
	return nil
}

func authCodePKCE(ctx context.Context, hc *http.Client, meta *metadata) (*oauth2.Token, error) {
	c := cfg(meta, publicClientID, "", publicRedirectURI)
	verifier := oauth2.GenerateVerifier()
	state := "go-interop-state"
	authURL := c.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	resp, err := hc.Get(authURL)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("seeded AS must auto-approve with a redirect, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, fmt.Errorf("Location header is not a URL: %w", err)
	}
	q := loc.Query()
	if q.Get("state") != state {
		return nil, fmt.Errorf("state not echoed unmodified (RFC 6749 s4.1.2): %q", q.Get("state"))
	}
	if q.Get("iss") != meta.Issuer {
		return nil, fmt.Errorf("RFC 9207 iss was %q, metadata issuer is %q", q.Get("iss"), meta.Issuer)
	}
	code := q.Get("code")
	if code == "" {
		return nil, fmt.Errorf("no code in the authorization response")
	}
	tok, err := c.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("x/oauth2 rejected the token response: %w", err)
	}
	if !tok.Valid() {
		return nil, fmt.Errorf("x/oauth2 considers the issued token invalid")
	}
	if tok.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh_token issued to a client registered for refresh")
	}
	return tok, nil
}

func refresh(ctx context.Context, meta *metadata, tok *oauth2.Token) error {
	c := cfg(meta, publicClientID, "", publicRedirectURI)
	stale := &oauth2.Token{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       time.Now().Add(-time.Hour),
	}
	fresh, err := c.TokenSource(ctx, stale).Token()
	if err != nil {
		return fmt.Errorf("x/oauth2 rejected the refresh response: %w", err)
	}
	if !fresh.Valid() {
		return fmt.Errorf("refreshed token is not valid per x/oauth2")
	}
	if fresh.AccessToken == tok.AccessToken {
		return fmt.Errorf("refresh returned the same access token")
	}
	if fresh.RefreshToken == tok.RefreshToken {
		return fmt.Errorf("refresh did not rotate the refresh token (OAuth 2.1 s6.1)")
	}
	return nil
}

func clientCreds(ctx context.Context, meta *metadata) error {
	c := &clientcredentials.Config{
		ClientID:     confidentialClientID,
		ClientSecret: confidentialSecret,
		TokenURL:     meta.TokenEndpoint,
	}
	tok, err := c.Token(ctx)
	if err != nil {
		return fmt.Errorf("x/oauth2 clientcredentials rejected the response: %w", err)
	}
	if !tok.Valid() {
		return fmt.Errorf("x/oauth2 considers the client-credentials token invalid")
	}
	if tok.RefreshToken != "" {
		return fmt.Errorf("RFC 6749 s4.4.3: a client credentials response MUST NOT include a refresh token")
	}
	return nil
}

// A private_key_jwt client this judge can authenticate as: its registered algorithm, key id, the
// client id it must name as iss/sub, and a signer over the JWS Signing Input built from Go stdlib
// crypto only (no third-party JWT library). `alg` is the JOSE header value.
type pkjwtClient struct {
	name     string
	alg      string
	kid      string
	clientID string
	sign     func(signingInput []byte) ([]byte, error)
}

// b64uInt decodes an RFC 7518 base64urlUInt member into a big.Int.
func b64uInt(s string) *big.Int {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("pinned RFC key material is not base64url: %v", err))
	}
	return new(big.Int).SetBytes(b)
}

func rs256Client() pkjwtClient {
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: b64uInt(rs256N), E: 65537}, // e = AQAB
		D:         b64uInt(rs256D),
		Primes:    []*big.Int{b64uInt(rs256P), b64uInt(rs256Q)},
	}
	priv.Precompute()
	if err := priv.Validate(); err != nil {
		panic(fmt.Sprintf("RFC 7515 A.2 RSA private key failed validation: %v", err))
	}
	return pkjwtClient{
		name:     "RS256",
		alg:      "RS256",
		kid:      pkjwtRS256Kid,
		clientID: pkjwtRS256ClientID,
		sign: func(signingInput []byte) ([]byte, error) {
			// RS256 = RSASSA-PKCS1-v1_5 over SHA-256 (RFC 7518 s3.3): sign the digest, not the input.
			digest := sha256.Sum256(signingInput)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		},
	}
}

func eddsaClient() pkjwtClient {
	seed, err := base64.RawURLEncoding.DecodeString(eddsaD)
	if err != nil || len(seed) != ed25519.SeedSize {
		panic(fmt.Sprintf("RFC 8037 A.4 Ed25519 seed is not %d base64url bytes: %v", ed25519.SeedSize, err))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return pkjwtClient{
		name:     "EdDSA",
		alg:      "EdDSA",
		kid:      pkjwtEdDSAKid,
		clientID: pkjwtEdDSAClientID,
		sign: func(signingInput []byte) ([]byte, error) {
			// EdDSA over Ed25519 (RFC 8037 s3.1): a raw 64-byte signature over the input itself.
			return ed25519.Sign(priv, signingInput), nil
		},
	}
}

// assemble builds the compact JWS client assertion for `c` against `tokenEndpoint`. `tamper`, when
// set, flips one signature byte so the AS must reject it. base64url is RFC 7515 URL-safe, no pad.
func assemble(c pkjwtClient, tokenEndpoint string, tamper bool) (string, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	header, err := json.Marshal(map[string]string{"alg": c.alg, "typ": "JWT", "kid": c.kid})
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims, err := json.Marshal(map[string]any{
		"iss": c.clientID, // RFC 7523 s3(1): the client is its own issuer.
		"sub": c.clientID, // RFC 7523 s3(2): and its own subject.
		"aud": tokenEndpoint,
		"exp": now.Add(2 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": fmt.Sprintf("go-interop-%s-%d", c.alg, now.UnixNano()),
	})
	if err != nil {
		return "", err
	}
	signingInput := b64(header) + "." + b64(claims)
	sig, err := c.sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	if tamper {
		// Flip one bit of one byte: still the right length, no longer a valid signature.
		sig[len(sig)-1] ^= 0x01
	}
	return signingInput + "." + b64(sig), nil
}

// postAssertion sends grant_type=client_credentials authenticated by the private_key_jwt assertion.
func postAssertion(hc *http.Client, tokenEndpoint, clientID, assertion string) (*http.Response, map[string]any, error) {
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {jwtBearerAssertionType},
		"client_assertion":      {assertion},
	}
	resp, err := hc.PostForm(tokenEndpoint, form)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	var body map[string]any
	// A token response and an RFC 6749 s5.2 error are both JSON; a decode failure is itself a fault.
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return resp, nil, fmt.Errorf("token endpoint did not return JSON (status %d): %w", resp.StatusCode, err)
	}
	return resp, body, nil
}

func privateKeyJWT(hc *http.Client, meta *metadata, c pkjwtClient) error {
	// ACCEPT: a valid assertion must yield a usable token (the RS256/EdDSA signature verified).
	valid, err := assemble(c, meta.TokenEndpoint, false)
	if err != nil {
		return fmt.Errorf("building the %s assertion: %w", c.name, err)
	}
	resp, body, err := postAssertion(hc, meta.TokenEndpoint, c.clientID, valid)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AS rejected a VALID %s private_key_jwt assertion: status %d, body %v",
			c.name, resp.StatusCode, body)
	}
	if at, _ := body["access_token"].(string); at == "" {
		return fmt.Errorf("AS returned 200 to the %s assertion but no access_token: %v", c.name, body)
	}
	if tt, _ := body["token_type"].(string); !strings.EqualFold(tt, "bearer") {
		return fmt.Errorf("%s token_type was %q, RFC 6749 s5.1 / RFC 6750 expects Bearer", c.name, tt)
	}

	// RED-PROOF / REJECT: one flipped signature byte must be refused as invalid_client. Without
	// this, an AS that never checked the signature would pass the ACCEPT half above vacuously.
	tampered, err := assemble(c, meta.TokenEndpoint, true)
	if err != nil {
		return fmt.Errorf("building the tampered %s assertion: %w", c.name, err)
	}
	resp, body, err = postAssertion(hc, meta.TokenEndpoint, c.clientID, tampered)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return fmt.Errorf("AS ACCEPTED a %s assertion with a tampered signature (status 200): %v",
			c.name, body)
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("tampered %s assertion: RFC 6749 s5.2 expects 400/401, got %d", c.name, resp.StatusCode)
	}
	if code, _ := body["error"].(string); code != "invalid_client" {
		return fmt.Errorf("tampered %s assertion: RFC 6749 s5.2 expects error=invalid_client, got %q (%v)",
			c.name, code, body)
	}
	return nil
}
