// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import "os"

func HostSocketPath(fallback string) (string, bool) {
	socket := os.Getenv(PluginSocketEnv)
	if os.Getenv(PluginProtocolEnv) != PluginProtocol || socket == "" {
		return fallback, false
	}
	return socket, true
}
