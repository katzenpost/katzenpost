// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package config

// DefaultPKISignatureScheme is the PKI signature scheme used when none is
// configured. SPHINCS+ hybridized with Ed25519 is the default for its
// conservative, hash-based assumptions at the PKI trust root; operators may
// select a different registered scheme.
const DefaultPKISignatureScheme = "Ed25519 Sphincs+"
