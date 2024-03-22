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

	"github.com/katzenpost/hpqc/kem/adapter"
	ctidh "github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
)

func BenchmarkCtidh1024SphinxUnwrap(b *testing.B) {
	if ctidh.Scheme() == nil {
		panic("ctidh.CTIDH1024Scheme is NIL")
	}
	benchmarkSphinxUnwrap(b, ctidh.Scheme())
}

func BenchmarkKEMSphinxUnwrapCTIDH1024(b *testing.B) {
	benchmarkKEMSphinxUnwrap(b, adapter.FromNIKE(ctidh.Scheme()))
}
