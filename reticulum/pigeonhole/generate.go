//go:generate go run build.go

// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package pigeonhole holds the trunnel schema and generated Go bindings
// for the rnsClient ↔ rnsCourier wire over Reticulum.
//
// The schema is intentionally minimal: only cached_courier_envelope is
// defined here. All other Pigeonhole protocol types are reused from
// the existing github.com/katzenpost/katzenpost/pigeonhole package,
// because the wire to replicas is binary-compatible.
//
// To regenerate trunnel_messages.go from the schema:
//
//	go generate ./reticulum/pigeonhole/...
package pigeonhole
