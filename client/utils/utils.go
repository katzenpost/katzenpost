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
	services := []ServiceDescriptor{}
	for _, provider := range doc.ServiceNodes {
		for cap := range provider.Services {
			if cap == capability {
				serviceID := ServiceDescriptor{
					Name:     provider.Services[cap]["endpoint"].(string),
					Provider: provider.Name,
				}
				services = append(services, serviceID)
			}
		}
	}
	return services
}
