// SPDX-License-Identifier: AGPL-3.0-only

package outgoing

import (
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/katzenpost/katzenpost/server/config"
)

func dialAddresses(cfg *config.Server, dst *cpki.MixDescriptor) []string {
	order := cfg.InternalTransports
	if order == nil {
		order = cpki.InternalTransports
	}
	var addrs []string
	for _, t := range order {
		addrs = append(addrs, dst.Addresses[t]...)
	}
	return retry.FilterByLocalAddresses(cfg.Addresses, addrs)
}
