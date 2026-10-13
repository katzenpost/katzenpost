// SPDX-License-Identifier: AGPL-3.0-only

package outgoing

import (
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/katzenpost/katzenpost/server/config"
)

func dialAddresses(cfg *config.Server, dst *cpki.MixDescriptor) []string {
	var addrs []string
	for _, t := range cpki.InternalTransports {
		addrs = append(addrs, dst.Addresses[t]...)
	}
	return retry.FilterByLocalAddresses(cfg.Addresses, addrs)
}
