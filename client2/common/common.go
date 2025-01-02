// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"fmt"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

// ServiceDescriptor describe a mixnet Gateway-side service.
type ServiceDescriptor struct {
	// RecipientQueueID is the service name or queue ID.
	RecipientQueueID []byte
	// Gateway name.
	MixDescriptor *cpki.MixDescriptor
}

// FindServices is a helper function for finding Gateway-side services in the PKI document.
func FindServices(capability string, doc *cpki.Document) []*ServiceDescriptor {
	fmt.Printf("FindServices: capability -> %s\n", capability)
	fmt.Printf("PKI DOC: %s\n", doc.String())

	if doc == nil {
		panic("pki doc is nil")
	}
	services := []*ServiceDescriptor{}
	fmt.Printf("num service nodes %d\n", len(doc.ServiceNodes))
	for _, provider := range doc.ServiceNodes {
		for cap := range provider.Kaetzchen {
			fmt.Printf("comparing caps %s and %s\n", cap, capability)
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
