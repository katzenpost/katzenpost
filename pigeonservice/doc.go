// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package pigeonservice is a framework for services that speak only
// Pigeonhole, and the wire types of the two mixnet services that connect
// clients to them.
//
// A pigeonhole service is known by its ServiceDescriptor: a NIKE public key,
// whose hash is the service's identity, and the voucher routers it holds a
// link with. A client reaches a service with the contact voucher protocol. It
// mints a voucher, seals it to the service's public key with hpqc
// protocols/box, and hands the sealed voucher to one of the service's voucher
// routers over Sphinx. The router cannot open it; it forwards the ciphertext
// over its Pigeonhole link to the service, which opens it, inducts the
// client, and so establishes a two-way Pigeonhole session.
//
// Services advertise their descriptors through an Advertiser, and clients
// find them through a Discoverer. The service directory, a mixnet service,
// is the first implementation of both.
package pigeonservice
