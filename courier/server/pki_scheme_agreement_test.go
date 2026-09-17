// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/courier/server/config"
)

// newPKIWorkerWithDefaultClient used to derive its PKI signature scheme (and
// so its wire ceiling) solely from the first-listed authority, on the
// unenforced assumption that every authority uses the same scheme. This
// proves a mismatched peer set is now rejected with a clear error at
// construction, instead of silently under-estimating the ceiling for the
// authority that was not consulted.
func TestNewPKIWorkerWithDefaultClientRejectsSchemeMismatch(t *testing.T) {
	srv := &Server{
		cfg: &config.Config{
			WireKEMScheme: "x25519",
			PKI: &config.PKI{
				Voting: &config.Voting{
					Authorities: []*vConfig.Authority{
						{Identifier: "auth1", PKISignatureScheme: "Ed25519"},
						{Identifier: "auth2", PKISignatureScheme: "Ed25519 Sphincs+"},
					},
				},
			},
		},
	}

	_, err := newPKIWorkerWithDefaultClient(srv, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "do not agree")
}

// A uniform peer set is unaffected: construction proceeds past the scheme
// check (it fails later, on dialing the fake addresses, which this test does
// not need to reach; it only needs to prove the mismatch check did not
// itself reject an agreeing peer set).
func TestNewPKIWorkerWithDefaultClientAcceptsUniformScheme(t *testing.T) {
	srv := &Server{
		cfg: &config.Config{
			WireKEMScheme: "x25519",
			PKI: &config.PKI{
				Voting: &config.Voting{
					Authorities: []*vConfig.Authority{
						{Identifier: "auth1", PKISignatureScheme: "Ed25519"},
						{Identifier: "auth2", PKISignatureScheme: "Ed25519"},
					},
				},
			},
		},
	}

	_, err := newPKIWorkerWithDefaultClient(srv, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "do not agree")
}
