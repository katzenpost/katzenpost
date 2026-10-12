// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"os"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	PluginPayloadLengthEnv = "KATZENPOST_PLUGIN_USER_FORWARD_PAYLOAD_LENGTH"
	PluginGeometryEnv      = "KATZENPOST_PLUGIN_SPHINX_GEOMETRY"
)

type Host struct {
	UserForwardPayloadLength int
	Geometry                 *geo.Geometry
}

func HostSocketPath(fallback string) (string, bool) {
	socket := os.Getenv(PluginSocketEnv)
	if os.Getenv(PluginProtocolEnv) != PluginProtocol || socket == "" {
		return fallback, false
	}
	return socket, true
}

func HostInfo() (*Host, error) {
	return new(Host), nil
}
