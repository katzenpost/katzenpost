// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build noprometheus
// +build noprometheus

package handshakeinstrument

import "time"

// HandshakeFailure is a no-op when the noprometheus build tag is set.
func HandshakeFailure(direction, state string) {}

// HandshakeDuration is a no-op when the noprometheus build tag is set.
func HandshakeDuration(direction, result string, d time.Duration) {}

// IncomingPeerValidationFailure is a no-op when the noprometheus build tag is set.
func IncomingPeerValidationFailure(reason string) {}

// IncomingRefusedNoPKIDoc is a no-op when the noprometheus build tag is set.
func IncomingRefusedNoPKIDoc() {}

// OutgoingDialFailure is a no-op when the noprometheus build tag is set.
func OutgoingDialFailure(reason string) {}
