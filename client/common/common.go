// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"github.com/katzenpost/hpqc/rand"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
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
	if doc == nil {
		panic("pki doc is nil")
	}
	services := []*ServiceDescriptor{}
	for _, provider := range doc.ServiceNodes {
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

func NewSURBID() *[constants.SURBIDLength]byte {
	id := new([constants.SURBIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}
