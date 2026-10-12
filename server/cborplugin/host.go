// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"

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
	h := new(Host)
	if v := os.Getenv(PluginPayloadLengthEnv); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("cborplugin: bad %s %q", PluginPayloadLengthEnv, v)
		}
		h.UserForwardPayloadLength = n
	}
	if v := os.Getenv(PluginGeometryEnv); v != "" {
		cfg := new(geo.Config)
		if _, err := toml.Decode(v, cfg); err != nil || cfg.SphinxGeometry == nil {
			return nil, fmt.Errorf("cborplugin: bad %s: %v", PluginGeometryEnv, err)
		}
		h.Geometry = cfg.SphinxGeometry
	}
	return h, nil
}

func hostGeometryEnv(g *geo.Geometry) ([]string, error) {
	if g == nil {
		return nil, nil
	}
	blob, err := g.Marshal()
	if err != nil {
		return nil, err
	}
	return []string{
		PluginPayloadLengthEnv + "=" + strconv.Itoa(g.UserForwardPayloadLength),
		PluginGeometryEnv + "=" + string(blob),
	}, nil
}
