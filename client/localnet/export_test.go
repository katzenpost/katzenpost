// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package localnet

import "time"

// DropGatewayLinks closes every client link at the gateway, as the
// daemon's read idle timeout does on a slow runner, and reports whether a
// new link replaced them within timeout.
func (n *Network) DropGatewayLinks(timeout time.Duration) bool {
	n.gw.mu.Lock()
	dropped := make(map[*clientConn]bool)
	for _, c := range n.gw.clients {
		c.w.Close()
		dropped[c] = true
	}
	n.gw.mu.Unlock()

	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		n.gw.mu.Lock()
		for _, c := range n.gw.clients {
			if !dropped[c] {
				n.gw.mu.Unlock()
				return true
			}
		}
		n.gw.mu.Unlock()
	}
	return false
}
