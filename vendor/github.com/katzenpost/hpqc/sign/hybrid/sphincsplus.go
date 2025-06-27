//go:build !windows
// +build !windows

// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"github.com/katzenpost/circl/sign/ed448"

	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

var Ed25519Sphincs = New("Ed25519 Sphincs+", ed25519.Scheme(), sphincsplus.Scheme())
var Ed448Sphincs = New("Ed448-Sphincs+", ed448.Scheme(), sphincsplus.Scheme())
