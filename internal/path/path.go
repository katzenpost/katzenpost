// path.go - Path selection routines.
// Copyright (C) 2017  Yawning Angel.
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

// Package path provides routines for path selection.
package path

import (
	"fmt"
	"math/rand"

	"github.com/katzenpost/core/pki"
)

// New returns a newly constructed path as a vector of node descriptors,
// including the descriptors for the source and destination providers.
func New(rng *rand.Rand, doc *pki.Document, source, destination string) ([]*pki.MixDescriptor, error) {
	p := make([]*pki.MixDescriptor, 0, 2+len(doc.Topology))

	srcProvider, err := doc.GetProvider(source)
	if err != nil {
		return nil, fmt.Errorf("path: failed to find source Provider: %v", err)
	}
	p = append(p, srcProvider)

	for i, nodes := range doc.Topology {
		if len(nodes) == 0 {
			return nil, fmt.Errorf("path: layer %v has no nodes", i)
		}
		p = append(p, nodes[rand.Intn(len(nodes))])
	}

	dstProvider, err := doc.GetProvider(destination)
	if err != nil {
		return nil, fmt.Errorf("path: failed to find destination Provider: %v", err)
	}
	p = append(p, dstProvider)

	return p, nil
}
