// The MIT License (MIT)
//
// Copyright (c) 2021 Yawning Angel.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Package toolchain enforces the minimum supported toolchain.
package toolchain

// This is enforced so that I can consolidate build constraints
// instead of keeping track of exactly when each 64-bit target got
// support for SSA doing the right thing for bits.Add64/bits.Mul64.
//
// If you absolutely must get this working on older Go versions,
// the 64-bit codepath is safe (and performant) as follows:
//
//  * 1.12 - amd64 (all other targets INSECURE due to vartime fallback)
//  * 1.13 - arm64, ppcle, ppc64
//  * 1.14 - s390x
//
//  * riscv64 became fast during 1.19, not shipped yet
//
// Last updated: Go 1.19 (src/cmd/compile/internal/ssagen/ssa.go)
var _ = __SOFTWARE_REQUIRES_GO_VERSION_1_18__
