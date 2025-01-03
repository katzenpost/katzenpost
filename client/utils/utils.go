// utils.go - Katzenpost client utilities.
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

package utils

import (
	"fmt"

	"github.com/katzenpost/katzenpost/core/pki"
)

// ServiceDescriptor describe a mixnet Provider-side service.
type ServiceDescriptor struct {
	// Name of the service.
	Name string
	// Provider name.
	Provider string
}

// FindServices is a helper function for finding Provider-side services in the PKI document.
func FindServices(capability string, doc *pki.Document) []ServiceDescriptor {
	if doc == nil {
		panic("pki doc is nil")
	}

	fmt.Printf("FindServices: capability -> %s\n", capability)
	fmt.Printf("PKI DOC: %s\n", doc.String())
	fmt.Println("AFTER printing PKI doc")
	fmt.Printf("num service nodes %d\n", len(doc.ServiceNodes))

	services := []ServiceDescriptor{}
	for _, provider := range doc.ServiceNodes {
		fmt.Println("meOW")
		if provider == nil {
			panic("provider is nil")
		}
		fmt.Printf("service node %s\n", provider.Name)
		fmt.Printf("number of services on service node: %d", len(provider.Kaetzchen))
		for cap := range provider.Kaetzchen {
			fmt.Printf("comparing caps %s and %s\n", cap, capability)
			if cap == capability {
				fmt.Println("equal")
				serviceID := ServiceDescriptor{
					Name:     provider.Kaetzchen[cap]["endpoint"].(string),
					Provider: provider.Name,
				}
				services = append(services, serviceID)
			} else {
				fmt.Println("not equal")
			}
		}
	}
	return services
}
