/*
Copyright 2026 The Kubermatic Kubernetes Platform contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
)

// TestAudienceTrusted covers the pure audience-matching logic used by
// OpenIDClient.Verify. It's the primary regression test for a bug where
// id_tokens minted by the dashboard's OIDC issuer client (used by the
// login/callback flow in pkg/handler/v2/authflow) were rejected by the
// authenticator verifier used for every other API request, because the two
// clients have different, and legitimately different, client IDs. Users were
// bounced straight back to the login page right after a successful login.
func TestAudienceTrusted(t *testing.T) {
	tests := []struct {
		name             string
		aud              []string
		clientID         string
		trustedAudiences []string
		want             bool
	}{
		{
			name:     "matches primary client ID",
			aud:      []string{"kubermatic"},
			clientID: "kubermatic",
			want:     true,
		},
		{
			name:             "matches a trusted audience",
			aud:              []string{"kubermaticIssuer"},
			clientID:         "kubermatic",
			trustedAudiences: []string{"kubermaticIssuer"},
			want:             true,
		},
		{
			name:             "matches neither primary nor trusted",
			aud:              []string{"someOtherClient"},
			clientID:         "kubermatic",
			trustedAudiences: []string{"kubermaticIssuer"},
			want:             false,
		},
		{
			name:     "no trusted audiences configured and aud mismatches",
			aud:      []string{"kubermaticIssuer"},
			clientID: "kubermatic",
			want:     false,
		},
		{
			name:             "empty audience never matches",
			aud:              nil,
			clientID:         "kubermatic",
			trustedAudiences: []string{"kubermaticIssuer"},
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audienceTrusted(tt.aud, tt.clientID, tt.trustedAudiences)
			if got != tt.want {
				t.Errorf("audienceTrusted(%v, %q, %v) = %v, want %v", tt.aud, tt.clientID, tt.trustedAudiences, got, tt.want)
			}
		})
	}
}

// testOIDCProvider is a minimal, self-signed OIDC provider serving discovery
// and JWKS documents, used to exercise OpenIDClient.Verify against a real
// go-oidc verifier instead of a fake one.
type testOIDCProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	p := &testOIDCProvider{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                p.server.URL,
			"authorization_endpoint":                p.server.URL + "/auth",
			"token_endpoint":                        p.server.URL + "/token",
			"jwks_uri":                              p.server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: "sig"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// signIDToken mints a compact RS256-signed JWT with the given audience and
// extra claims (e.g. "email"), issued by this test provider.
func (p *testOIDCProvider) signIDToken(t *testing.T, audience []string, extra map[string]interface{}) string {
	t.Helper()

	signerKey := jose.JSONWebKey{Key: p.key, KeyID: p.kid, Algorithm: "RS256", Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signerKey}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	claims := jwt.Claims{
		Issuer:   p.server.URL,
		Subject:  "test-subject",
		Audience: jwt.Audience(audience),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	raw, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		t.Fatalf("failed to sign id_token: %v", err)
	}
	return raw
}

// TestOpenIDClientVerify_AudienceMismatch is the end-to-end regression test:
// it exercises the real go-oidc verifier (unlike the fakeVerifier used in
// pkg/handler/v2/authflow tests) to prove that OpenIDClient.Verify accepts an
// id_token whose audience is the issuer client, as long as it's configured as
// a TrustedAudience, while still rejecting unrelated audiences.
func TestOpenIDClientVerify_AudienceMismatch(t *testing.T) {
	const (
		authenticatorClientID = "kubermatic"
		issuerClientID        = "kubermaticIssuer"
	)

	provider := newTestOIDCProvider(t)

	tests := []struct {
		name             string
		tokenAudience    []string
		trustedAudiences []string
		wantErr          bool
	}{
		{
			name:          "token issued to the authenticator client is accepted",
			tokenAudience: []string{authenticatorClientID},
			wantErr:       false,
		},
		{
			name:          "token issued to the issuer client is rejected without TrustedAudiences (pre-fix behavior)",
			tokenAudience: []string{issuerClientID},
			wantErr:       true,
		},
		{
			name:             "token issued to the issuer client is accepted once trusted",
			tokenAudience:    []string{issuerClientID},
			trustedAudiences: []string{issuerClientID},
			wantErr:          false,
		},
		{
			name:             "token issued to an unrelated client is still rejected",
			tokenAudience:    []string{"someOtherClient"},
			trustedAudiences: []string{issuerClientID},
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &authtypes.OIDCConfiguration{
				URL:              provider.server.URL,
				ClientID:         authenticatorClientID,
				TrustedAudiences: tt.trustedAudiences,
			}

			client, err := NewOpenIDClient(cfg, "", NewHeaderBearerTokenExtractor("Authorization"), nil)
			if err != nil {
				t.Fatalf("failed to create OpenID client: %v", err)
			}

			token := provider.signIDToken(t, tt.tokenAudience, map[string]interface{}{"email": "user@example.com"})

			_, err = client.Verify(context.Background(), token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
