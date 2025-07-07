//go:build windows

// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import "github.com/katzenpost/hpqc/sign"

var Ed25519Sphincs sign.Scheme = nil
var Ed448Sphincs sign.Scheme = nil
