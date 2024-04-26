// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

// ServiceDescriptor describe a mixnet Provider-side service.
type ServiceDescriptor struct {
	// RecipientQueueID is the service name or queue ID.
	RecipientQueueID []byte
	// Provider name.
	MixDescriptor *cpki.MixDescriptor
}

// FindServices is a helper function for finding Provider-side services in the PKI document.
func FindServices(capability string, doc *cpki.Document) []*ServiceDescriptor {
	if doc == nil {
		panic("pki doc is nil")
	}
	services := []*ServiceDescriptor{}
	for _, provider := range doc.Providers {
		for cap := range provider.Kaetzchen {
			if cap == capability {
				serviceID := &ServiceDescriptor{
					RecipientQueueID: []byte(provider.Kaetzchen[cap]["endpoint"].(string)),
					MixDescriptor:    provider,
				}
				services = append(services, serviceID)
			}
		}
	}
	return services
}
