package hash

import (
	"encoding"

	"golang.org/x/crypto/blake2b"
)

const HashSize = blake2b.Size256

func Sum256(data []byte) [blake2b.Size256]byte {
	return blake2b.Sum256(data)
}

func Sum256From(key encoding.BinaryMarshaler) [blake2b.Size256]byte {
	blob, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return blake2b.Sum256(blob)
}
