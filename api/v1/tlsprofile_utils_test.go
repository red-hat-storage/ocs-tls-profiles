/*
Copyright 2026 Red Hat OpenShift Data Foundation.

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

package v1

import (
	"crypto/tls"
	"testing"
)

// cfg is a shorthand to build a TLSConfig distinguishable by version alone.
func cfg(v TLSProtocolVersion) TLSConfig {
	return TLSConfig{Version: v}
}

// rule builds a TLSProfileRules with the given selectors and config.
func rule(config TLSConfig, selectors ...string) TLSProfileRules {
	s := make([]Selector, len(selectors))
	for i, sel := range selectors {
		s[i] = Selector(sel)
	}
	return TLSProfileRules{Selectors: s, Config: config}
}

// profile wraps rules into a TLSProfile.
func profile(rules ...TLSProfileRules) *TLSProfile {
	return &TLSProfile{Spec: TLSProfileSpec{Rules: rules}}
}

var (
	cfgExact    = cfg(VersionTLS1_3)
	cfgDomain   = cfg(VersionTLS1_2)
	cfgCatchAll = cfg(VersionTLS1_3)
)

func TestGetConfigForServer(t *testing.T) {
	tests := []struct {
		name    string
		profile *TLSProfile
		domain  string
		server  string
		wantNil bool
		wantCfg *TLSConfig
	}{
		{
			name:    "nil profile",
			profile: nil,
			domain:  "example.com", server: "s3",
			wantNil: true,
		},
		{
			name:    "empty rules",
			profile: profile(),
			domain:  "example.com", server: "s3",
			wantNil: true,
		},
		{
			name: "exact domain/server match",
			profile: profile(
				rule(cfgExact, "example.com/s3"),
				rule(cfgDomain, "example.com"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "domain match when no domain/server rule",
			profile: profile(
				rule(cfgDomain, "example.com"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgDomain,
		},
		{
			name: "catchall fallback when no domain or domain/server rule",
			profile: profile(
				rule(cfgCatchAll, "*"),
			),
			domain: "two.com", server: "s3",
			wantCfg: &cfgCatchAll,
		},
		{
			name: "unmatched domain falls back to catchall",
			profile: profile(
				rule(cfgDomain, "example.com"),
				rule(cfgCatchAll, "*"),
			),
			domain: "two.com", server: "s3",
			wantCfg: &cfgCatchAll,
		},
		{
			name: "no match at any level returns nil",
			profile: profile(
				rule(cfgDomain, "example.com"),
			),
			domain: "two.com", server: "s3",
			wantNil: true,
		},
		{
			name: "domain/server beats domain",
			profile: profile(
				rule(cfgExact, "example.com/s3"),
				rule(cfgDomain, "example.com"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "domain beats catchall",
			profile: profile(
				rule(cfgDomain, "example.com"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "",
			wantCfg: &cfgDomain,
		},
		{
			name: "domain/server beats catchall skipping domain level",
			profile: profile(
				rule(cfgExact, "example.com/s3"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "rule with mixed selectors [* example.com] - query example.com returns domain match",
			profile: profile(
				rule(cfgDomain, "*", "example.com"),
			),
			domain: "example.com", server: "",
			wantCfg: &cfgDomain,
		},
		{
			name: "rule with mixed selectors [* example.com] - unmatched domain falls back to *",
			profile: profile(
				rule(cfgCatchAll, "*", "example.com"),
			),
			domain: "two.com", server: "",
			wantCfg: &cfgCatchAll,
		},
		{
			name: "ambiguous: two rules both claim same domain with different configs",
			profile: profile(
				rule(cfgDomain, "example.com"),
				rule(cfgExact, "example.com"),
			),
			domain: "example.com", server: "",
			wantNil: true,
		},
		{
			name: "duplicate selector across different rules is ambiguous even if configs match",
			profile: profile(
				rule(cfgDomain, "example.com"),
				rule(cfgDomain, "example.com"),
			),
			domain: "example.com", server: "",
			wantNil: true,
		},
		{
			name: "ambiguous: two rules both claim *",
			profile: profile(
				rule(cfgCatchAll, "*"),
				rule(cfgDomain, "*"),
			),
			domain: "two.com", server: "",
			wantNil: true,
		},
		{
			name: "ambiguous at domain/server level; does not fall through",
			profile: profile(
				rule(cfgExact, "example.com/s3"),
				rule(cfgDomain, "example.com/s3"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "s3",
			wantNil: true,
		},
		{
			name: "one rule with multiple selectors matches at domain/server level",
			profile: profile(
				rule(cfgExact, "example.com/s3", "example.com/s3"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "empty server skips domain/server bucket",
			profile: profile(
				rule(cfgDomain, "example.com"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "",
			wantCfg: &cfgDomain,
		},
		{
			name: "empty domain skips domain and domain/server buckets",
			profile: profile(
				rule(cfgCatchAll, "*"),
			),
			domain: "", server: "",
			wantCfg: &cfgCatchAll,
		},

		// glob selectors
		{
			name: "wildcard domain matches subdomain",
			profile: profile(
				rule(cfgDomain, "*.example.com"),
			),
			domain: "foo.example.com", server: "",
			wantCfg: &cfgDomain,
		},
		{
			name: "wildcard domain does not match base domain",
			profile: profile(
				rule(cfgDomain, "*.example.com"),
			),
			domain: "example.com", server: "",
			wantNil: true,
		},
		{
			name: "exact domain beats wildcard domain",
			profile: profile(
				rule(cfgExact, "foo.example.com"),
				rule(cfgDomain, "*.example.com"),
			),
			domain: "foo.example.com", server: "",
			wantCfg: &cfgExact,
		},
		{
			name: "wildcard domain beats catchall",
			profile: profile(
				rule(cfgDomain, "*.example.com"),
				rule(cfgCatchAll, "*"),
			),
			domain: "foo.example.com", server: "",
			wantCfg: &cfgDomain,
		},
		{
			name: "more specific wildcard beats less specific wildcard",
			profile: profile(
				rule(cfgExact, "*.foo.example.com"),
				rule(cfgDomain, "*.example.com"),
			),
			domain: "bar.foo.example.com", server: "",
			wantCfg: &cfgExact,
		},
		{
			name: "wildcard domain with server matches",
			profile: profile(
				rule(cfgExact, "*.example.com/s3"),
			),
			domain: "foo.example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "wildcard domain/server beats wildcard domain",
			profile: profile(
				rule(cfgExact, "*.example.com/s3"),
				rule(cfgDomain, "*.example.com"),
			),
			domain: "foo.example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "wildcard domain/server does not match different server",
			profile: profile(
				rule(cfgExact, "*.example.com/s3"),
				rule(cfgCatchAll, "*"),
			),
			domain: "foo.example.com", server: "s3",
			wantCfg: &cfgCatchAll,
		},
		{
			name: "exact domain beats wildcard domain/server for short domain",
			profile: profile(
				rule(cfgExact, "x.io"),
				rule(cfgDomain, "*.io/s3"),
			),
			domain: "x.io", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "ambiguous wildcard domains at same specificity",
			profile: profile(
				rule(cfgExact, "*.example.com"),
				rule(cfgDomain, "*.example.com"),
			),
			domain: "foo.example.com", server: "",
			wantNil: true,
		},

		// */server selectors
		{
			name: "*/server matches any domain with that server",
			profile: profile(
				rule(cfgExact, "*/s3"),
			),
			domain: "any.example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "*/server does not match different server",
			profile: profile(
				rule(cfgExact, "*/s3"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgCatchAll,
		},
		{
			name: "*/server beats catchall",
			profile: profile(
				rule(cfgExact, "*/s3"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "exact domain beats */server",
			profile: profile(
				rule(cfgExact, "example.com"),
				rule(cfgDomain, "*/s3"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgExact,
		},
		{
			name: "wildcard domain beats */server",
			profile: profile(
				rule(cfgExact, "*.example.com"),
				rule(cfgDomain, "*/s3"),
			),
			domain: "foo.example.com", server: "s3",
			wantCfg: &cfgExact,
		},

		// invalid selector forms are ignored
		{
			name: "leading slash selector is ignored",
			profile: profile(
				rule(cfgExact, "/s3"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "s3",
			wantCfg: &cfgCatchAll,
		},
		{
			name: "trailing slash selector is ignored",
			profile: profile(
				rule(cfgExact, "example.com/"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "",
			wantCfg: &cfgCatchAll,
		},
		{
			name: "bare wildcard without dot or slash is ignored",
			profile: profile(
				rule(cfgExact, "*example.com"),
				rule(cfgCatchAll, "*"),
			),
			domain: "example.com", server: "",
			wantCfg: &cfgCatchAll,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := GetConfigForServer(tc.profile, tc.domain, tc.server)
			if tc.wantNil {
				if ok || got != nil {
					t.Fatalf("want nil,false; got %+v,%v", got, ok)
				}
				return
			}
			if !ok || got == nil {
				t.Fatalf("want config %+v; got nil,false", tc.wantCfg)
			}
			if got.Version != tc.wantCfg.Version {
				t.Fatalf("want version %q; got %q", tc.wantCfg.Version, got.Version)
			}
		})
	}
}

func TestValidateTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   *TLSConfig
		wantErr bool
	}{
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
		{
			name: "TLS 1.2 valid ciphers and groups",
			input: &TLSConfig{
				Version: VersionTLS1_2,
				Ciphers: []TLSCipherSuite{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				Groups:  []TLSGroupName{"secp256r1", "X25519"},
			},
		},
		{
			name: "TLS 1.3 valid ciphers and groups including hybrid",
			input: &TLSConfig{
				Version: VersionTLS1_3,
				Ciphers: []TLSCipherSuite{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				Groups:  []TLSGroupName{"secp256r1", "X25519MLKEM768"},
			},
		},
		{
			name: "TLS 1.2 cipher rejected for TLS 1.3",
			input: &TLSConfig{
				Version: VersionTLS1_3,
				Ciphers: []TLSCipherSuite{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				Groups:  []TLSGroupName{"secp256r1"},
			},
			wantErr: true,
		},
		{
			name: "TLS 1.3 cipher rejected for TLS 1.2",
			input: &TLSConfig{
				Version: VersionTLS1_2,
				Ciphers: []TLSCipherSuite{"TLS_AES_128_GCM_SHA256"},
				Groups:  []TLSGroupName{"secp256r1"},
			},
			wantErr: true,
		},
		{
			name: "hybrid group rejected for TLS 1.2",
			input: &TLSConfig{
				Version: VersionTLS1_2,
				Ciphers: []TLSCipherSuite{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				Groups:  []TLSGroupName{"X25519MLKEM768"},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTLSConfig(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error; got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("want no error; got %v", err)
			}
		})
	}
}

func TestGetGoTLSConfig(t *testing.T) {
	tests := []struct {
		name  string
		input *TLSConfig
		check func(*testing.T, *tls.Config)
	}{
		{
			name: "TLS 1.2 ciphers and groups",
			input: &TLSConfig{
				Version: VersionTLS1_2,
				Ciphers: []TLSCipherSuite{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				Groups:  []TLSGroupName{"secp256r1", "X25519"},
			},
			check: func(t *testing.T, c *tls.Config) {
				if c.MinVersion != tls.VersionTLS12 || c.MaxVersion != tls.VersionTLS12 {
					t.Fatalf("want TLS12 min/max; got %x/%x", c.MinVersion, c.MaxVersion)
				}
				if len(c.CipherSuites) != 2 {
					t.Fatalf("want 2 ciphers; got %d", len(c.CipherSuites))
				}
				if len(c.CurvePreferences) != 2 {
					t.Fatalf("want 2 groups; got %d", len(c.CurvePreferences))
				}
			},
		},
		{
			name: "TLS 1.3 ciphers and groups including hybrid",
			input: &TLSConfig{
				Version: VersionTLS1_3,
				Ciphers: []TLSCipherSuite{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				Groups:  []TLSGroupName{"secp256r1", "X25519MLKEM768"},
			},
			check: func(t *testing.T, c *tls.Config) {
				if c.MinVersion != tls.VersionTLS13 || c.MaxVersion != tls.VersionTLS13 {
					t.Fatalf("want TLS13 min/max; got %x/%x", c.MinVersion, c.MaxVersion)
				}
				if len(c.CipherSuites) != 2 {
					t.Fatalf("want 2 ciphers; got %d", len(c.CipherSuites))
				}
				if len(c.CurvePreferences) != 2 {
					t.Fatalf("want 2 groups; got %d", len(c.CurvePreferences))
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GetGoTLSConfig(tc.input)
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestOpenSSLConfigFrom(t *testing.T) {
	tests := []struct {
		name        string
		input       *tls.Config
		wantNil     bool
		wantProto   string
		wantCiphers []string
		wantGroups  []string
	}{
		{
			name:    "nil input",
			input:   nil,
			wantNil: true,
		},
		{
			name:    "unknown version returns nil",
			input:   &tls.Config{MinVersion: tls.VersionTLS10},
			wantNil: true,
		},
		{
			name: "TLS 1.2 with ciphers and groups",
			input: &tls.Config{
				MinVersion:       tls.VersionTLS12,
				CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
				CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
			},
			wantProto:   "TLSv1.2",
			wantCiphers: []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"},
			wantGroups:  []string{"prime256v1", "x25519"},
		},
		{
			name: "TLS 1.3 with ciphers and groups",
			input: &tls.Config{
				MinVersion:       tls.VersionTLS13,
				CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
				CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519MLKEM768},
			},
			wantProto:   "TLSv1.3",
			wantCiphers: []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
			wantGroups:  []string{"prime256v1", "X25519MLKEM768"},
		},
		{
			name: "empty ciphers and groups",
			input: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			wantProto:   "TLSv1.2",
			wantCiphers: nil,
			wantGroups:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := OpenSSLConfigFrom(tc.input)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("want nil; got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("want result; got nil")
			}
			if got.Protocol != tc.wantProto {
				t.Fatalf("want protocol %q; got %q", tc.wantProto, got.Protocol)
			}
			if len(got.Ciphers) != len(tc.wantCiphers) {
				t.Fatalf("want ciphers %v; got %v", tc.wantCiphers, got.Ciphers)
			}
			for i, c := range tc.wantCiphers {
				if got.Ciphers[i] != c {
					t.Fatalf("cipher[%d]: want %q; got %q", i, c, got.Ciphers[i])
				}
			}
			if len(got.Groups) != len(tc.wantGroups) {
				t.Fatalf("want groups %v; got %v", tc.wantGroups, got.Groups)
			}
			for i, g := range tc.wantGroups {
				if got.Groups[i] != g {
					t.Fatalf("group[%d]: want %q; got %q", i, g, got.Groups[i])
				}
			}
		})
	}
}
