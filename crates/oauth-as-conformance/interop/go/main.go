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
// FAILS LOUDLY, never skips: with no OAUTH_AS_BASE_URL it exits 2 rather than reporting success.
// Run it through scripts/oauth-interop.sh, whose --selftest proves it can go RED first.
package main

import (
	"context"
	"encoding/json"
	"fmt"
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
