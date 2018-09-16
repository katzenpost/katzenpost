// interface.go - Katzenpost plugin interface.
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package plugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"github.com/katzenpost/server/plugin/proto"
	"google.golang.org/grpc"
)

const (
	// KaetzchenPluginProtocolVersion is the version number
	// of this plugin system which we will iterate upon making
	// breaking changes so that we can invalidate old plugins.
	KaetzchenPluginProtocolVersion = 1
)

// Handshake is a common handshake that is shared by plugin and host.
// Plugin usage of this is optional and is supported by the golang
// plugin implementations that use the go-plugin package.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  KaetzchenPluginProtocolVersion,
	MagicCookieKey:   "KAETZCHEN_PLUGIN",
	MagicCookieValue: "meow",
}

// KaetzchenService is the name of our Kaetzchen plugins
// which is used by the gRPC generated code.
var KaetzchenService = "kaetzchen"

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	KaetzchenService: &KaetzchenPlugin{},
}

// KaetzchenPluginInterface is the interface that we expose for external
// plugins to implement. This is similar to the internal Kaetzchen
// interface defined in:
// github.com/katzenpost/server/internal/provider/kaetzchen/kaetzchen.go
type KaetzchenPluginInterface interface {
	// OnRequest is the method that is called when the Provider receives
	// a request desgined for a particular agent. The caller will handle
	// extracting the payload component of the message
	OnRequest(id uint64, request []byte, hasSURB bool) ([]byte, error)

	// Parameters returns the agent's paramenters for publication in
	// the Provider's descriptor.
	Parameters() (map[string]string, error)
}

// KaetzchenPlugin is the implementation of plugin.Plugin so we can
// serve/consume this. We also implement GRPCPlugin so that this
// plugin can be served over gRPC.
type KaetzchenPlugin struct {
	plugin.NetRPCUnsupportedPlugin

	// Impl is the concrete implementation, written in Go.
	// This is only used for plugins that are written in Go.
	Impl KaetzchenPluginInterface
}

// GRPCServer registers this plugin for serving with the given gRPC server.
func (p *KaetzchenPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterKaetzchenServer(s, &GRPCServer{
		Impl: p.Impl,
	})
	return nil
}

// GRPCClient returns the interface implementation for the plugin being served
// over gRPC. The provided context will be canceled by go-plugin in the event
// of the plugin process exiting.
func (p *KaetzchenPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{
		client: proto.NewKaetzchenClient(c),
	}, nil
}

var _ plugin.GRPCPlugin = &KaetzchenPlugin{}
