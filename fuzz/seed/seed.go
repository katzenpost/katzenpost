//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package seed

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
)

var exportDir = os.Getenv("FUZZ_EXPORT_DIR")

func Export(args ...[]byte) bool {
	if exportDir == "" {
		return false
	}
	var buf []byte
	for _, a := range args {
		if len(a) == 0 {
			continue
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(a)))
		buf = append(buf, n[:]...)
		buf = append(buf, a...)
	}
	if len(buf) > 0 {
		sum := sha1.Sum(buf)
		_ = os.WriteFile(filepath.Join(exportDir, hex.EncodeToString(sum[:])), buf, 0o644)
	}
	return true
}
