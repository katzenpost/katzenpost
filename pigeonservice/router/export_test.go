// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package router

// Inductions reports the registrations being inducted and the services
// with vouchers pending an induction.
func (r *Router) Inductions() (registering, pending int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.registering), len(r.pending)
}
