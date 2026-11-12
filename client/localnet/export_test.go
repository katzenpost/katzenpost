// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package localnet

// DropGatewayLinks closes every client link at the gateway, as the
// daemon's read idle timeout does on a slow runner.
func (n *Network) DropGatewayLinks() {
	n.gw.mu.Lock()
	defer n.gw.mu.Unlock()
	for _, c := range n.gw.clients {
		c.w.Close()
	}
}
