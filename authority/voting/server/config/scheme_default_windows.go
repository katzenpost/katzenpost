// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package config

// Windows has no cgo-free Sphincs+ build, so the default is plain Ed25519.
const DefaultPKISignatureScheme = "Ed25519"
