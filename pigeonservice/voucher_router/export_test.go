// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router

import "time"

// Inductions reports the registrations being inducted and the services
// with vouchers pending an induction.
func (r *Router) Inductions() (registering, pending int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.registering), len(r.pending)
}

// SetNow replaces the clock leases are judged by.
func (r *Router) SetNow(now func() time.Time) { r.clock.Store(&now) }

// Sweep forgets expired links and leases now.
func (r *Router) Sweep() { r.sweep() }

// Leases counts the services the router remembers, linked or not.
func (r *Router) Leases() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.leases)
}
