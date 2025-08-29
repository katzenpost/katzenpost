//go:generate go run build.go

// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package pigeonhole contains trunnel message definitions and generation.
//
// To regenerate the trunnel message types, run:
//   go generate ./pigeonhole/...
//
// This will:
// 1. Read pigeonhole_messages.trunnel schema
// 2. Generate Go code using the trunnel binary
// 3. Output trunnel_messages.go in pigeonhole/
//
// The generated types provide fixed binary encoding with predictable
// overhead, simplifying pigeonhole geometry calculations by eliminating
// dynamic overhead measurements completely.

package pigeonhole
