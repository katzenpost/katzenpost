//go:build ctidh1024
// +build ctidh1024

// ctidh1024_benchmark_test.go - Sphinx Packet Format benchmarks.
// Copyright (C) 2022 David Stainton.
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

package sphinx

import (
	"testing"

	ctidhnike "github.com/katzenpost/katzenpost/core/crypto/nike/ctidh"
)

func BenchmarkCtidh1024SphinxUnwrap(b *testing.B) {
	benchmarkSphinxUnwrap(b, ctidhnike.NewCtidhNike())
}
