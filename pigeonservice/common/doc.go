// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package common is what pigeonhole services, the voucher router and the
// service directory share: the Pigeonhole box operations over the thin
// client, canonical CBOR and the reply status codes, service and plugin
// keys with the MAC on requests between them, and the ServiceDescriptor
// that names a service by its NIKE public key and the routers it holds a
// link with.
//
// The contact voucher protocol and the router that relays sealed vouchers
// are in voucher_router; the directory services advertise in and clients
// look them up in is in discovery. The framework for writing a service,
// and the services themselves, live in the pigeonhole_protocols module.
package common
