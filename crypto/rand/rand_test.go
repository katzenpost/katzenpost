// rand_test.go - Random number tests.
// Copyright (C) 2016  Yawning Angel.
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

package rand

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"testing"
)

func tryRandomRead(n int) error {
	b := make([]byte, n)
	rd, err := io.ReadFull(Reader, b)
	if err != nil {
		return err
	}
	if rd != len(b) {
		return fmt.Errorf("truncated read: %v", rd)
	}

	// Statistical test...
	var zipBuf bytes.Buffer
	zipper := zlib.NewWriter(&zipBuf)
	zipper.Write(b[:])
	zipper.Close()

	errorThresh := int(float32(len(b)) * 0.95)
	if zipBuf.Len()-16 < errorThresh {
		return fmt.Errorf("random data noticably compressed????: %v", zipBuf.Len())
	}
	return nil
}

func TestImprovedSyscallRand(t *testing.T) {
	if !usingImprovedSyscallEntropy {
		t.Skip("Improved (non-broken) syscall entropy not supported")
	}

	// Short read.
	if err := tryRandomRead(256); err != nil {
		t.Errorf("short: %v", err)
	}

	// Large read.
	if err := tryRandomRead(1024); err != nil {
		t.Errorf("large: %v", err)
	}
}
