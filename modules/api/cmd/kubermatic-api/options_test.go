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

package main

import (
	"reflect"
	"testing"
)

// TestTrustedAudiencesFor guards against a regression where the dashboard
// login flow (pkg/handler/v2/authflow) mints id_tokens against the issuer
// OIDC client, but the authenticator verifier used for every other API
// request only accepted the authenticator client's audience. Whenever the
// two clients differed (the common, documented setup), users were bounced
// straight back to the login page right after a successful login.
func TestTrustedAudiencesFor(t *testing.T) {
	tests := []struct {
		name                  string
		authenticatorClientID string
		issuerClientID        string
		want                  []string
	}{
		{
			name:                  "issuer and authenticator clients differ",
			authenticatorClientID: "kubermatic",
			issuerClientID:        "kubermaticIssuer",
			want:                  []string{"kubermaticIssuer"},
		},
		{
			name:                  "issuer and authenticator clients are the same",
			authenticatorClientID: "kubermatic",
			issuerClientID:        "kubermatic",
			want:                  nil,
		},
		{
			name:                  "issuer client not configured",
			authenticatorClientID: "kubermatic",
			issuerClientID:        "",
			want:                  nil,
		},
		{
			name:                  "neither client configured",
			authenticatorClientID: "",
			issuerClientID:        "",
			want:                  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trustedAudiencesFor(tt.authenticatorClientID, tt.issuerClientID)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("trustedAudiencesFor(%q, %q) = %v, want %v", tt.authenticatorClientID, tt.issuerClientID, got, tt.want)
			}
		})
	}
}
