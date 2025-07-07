/* Copyright (c) 2017, Google Inc.
 *
 * This code was written to support development of BoringSSL and thus is
 * considered part of BoringSSL and under the same license.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

package gcmsiv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var verbose = false

func log(msg string, data []byte) {
	const lineWidth = 60
	if len(msg)+2+2*16 > lineWidth {
		panic("cannot log with message " + msg)
	}
	fmt.Printf("%s =", msg)
	if len(data) == 0 {
		fmt.Printf("\n")
		return
	}

	written := len(msg) + 2

	for len(data) > 0 {
		padding := lineWidth - (written + 2*16)
		for i := 0; i < padding; i++ {
			fmt.Printf(" ")
		}

		todo := data
		if len(todo) > 16 {
			todo = todo[:16]
		}
		fmt.Printf("%x\n", todo)
		written = 0

		data = data[len(todo):]
	}
}

// fieldElement represents a binary polynomial. The elements are in
// little-endian order, i.e the polynomial 'x' would be {1, 0, 0, 0}.
type fieldElement [4]uint64

var (
	// irreduciblePolynomial is the irreducable polynomial that defines the
	// field in which POLYVAL operates.
	irreduciblePolynomial = fieldElement([4]uint64{
		1, 0xc200000000000000, 1, 0,
	})
	// xMinus128 is the representation of x^-128.
	xMinus128 = fieldElement([4]uint64{
		1, 0x9204000000000000, 0, 0,
	})
)

// fieldElementFromBytes converts 16 bytes into a field element.
func fieldElementFromBytes(bytes []byte) fieldElement {
	return fieldElement([4]uint64{
		binary.LittleEndian.Uint64(bytes[:8]),
		binary.LittleEndian.Uint64(bytes[8:16]),
		0,
		0,
	})
}

func fieldElementFromSage(varName, in string) fieldElement {
	var ret fieldElement
	prefix := varName + "^"

	parts := strings.Split(in, " + ")
	for _, p := range parts {
		if p == "1" {
			ret.set(0)
			continue
		}
		if p == "x" {
			ret.set(1)
			continue
		}

		if !strings.HasPrefix(p, prefix) {
			panic(fmt.Sprintf("found %q in Sage string, but expected prefix %q", p, prefix))
		}
		p = p[len(prefix):]
		i, err := strconv.Atoi(p)
		if err != nil {
			panic(fmt.Sprintf("failed to parse %q in Sage string: %s", p, err))
		}
		ret.set(uint(i))
	}

	return ret
}

// fitsIn128Bits returns true if the top 128 bits of f are all zero. (And thus
// the value itself fits in 128 bits.)
func (f fieldElement) fitsIn128Bits() bool {
	return f[2] == 0 && f[3] == 0
}

// Bytes returns f as a 16-byte string. It requires that f fit into 128 bits.
func (f fieldElement) Bytes() (ret [16]byte) {
	if !f.fitsIn128Bits() {
		panic("Bytes argument out of range")
	}

	binary.LittleEndian.PutUint64(ret[:8], f[0])
	binary.LittleEndian.PutUint64(ret[8:], f[1])

	return ret
}

func (f fieldElement) SageString(varName string) string {
	if !f.fitsIn128Bits() {
		panic("unsupported")
	}

	ret := ""
	for i := uint(0); i < 128; i++ {
		if f.coefficient(i) {
			if len(ret) > 0 {
				ret += " + "
			}
			if i == 0 {
				ret += "1"
			} else {
				ret += varName + "^" + strconv.Itoa(int(i))
			}
		}
	}

	return ret
}

func (f fieldElement) String() string {
	if f.fitsIn128Bits() {
		return fmt.Sprintf("%016x%016x", f[1], f[0])
	} else {
		return fmt.Sprintf("%016x%016x%016x%016x",
			f[3], f[2], f[1], f[0])
	}
}

// coefficient returns the coefficient of x^i in f.
func (f fieldElement) coefficient(i uint) bool {
	return (f[(i/64)]>>(i&63))&1 == 1
}

// set sets the coefficient of x^i, in f, to 1.
func (f *fieldElement) set(i uint) {
	f[(i / 64)] |= 1 << (i & 63)
}

// leftShift returns f times x^i.
func (f fieldElement) leftShift(i uint) (result fieldElement) {
	// 0 <= i < 128
	if i < 64 {
		copy(result[:], f[:])
	} else if i < 128 {
		result[1] = f[0]
		result[2] = f[1]
		result[3] = f[2]
		i -= 64
	} else {
		panic("leftShift argument out of range")
	}

	result[3] = result[3]<<i | result[2]>>(64-i)
	result[2] = result[2]<<i | result[1]>>(64-i)
	result[1] = result[1]<<i | result[0]>>(64-i)
	result[0] = result[0] << i

	return result
}

func (a fieldElement) add(b fieldElement) (result fieldElement) {
	result[0] = a[0] ^ b[0]
	result[1] = a[1] ^ b[1]
	result[2] = a[2] ^ b[2]
	result[3] = a[3] ^ b[3]
	return result
}

func (a fieldElement) mul(b fieldElement) fieldElement {
	var product fieldElement

	if !a.fitsIn128Bits() || !b.fitsIn128Bits() {
		panic("mul argument out of range")
	}

	for i := uint(0); i < 128; i++ {
		if b.coefficient(127 - i) {
			shifted := a.leftShift(127 - i)
			for i := range product {
				product[i] ^= shifted[i]
			}
		}
	}

	// Reduce modulo the irreducable polynomial that defines the field.
	for i := uint(0); i < 128; i++ {
		if product.coefficient(255 - i) {
			shifted := irreduciblePolynomial.leftShift(127 - i)
			product = product.add(shifted)
		}
	}

	if !product.fitsIn128Bits() {
		panic("internal error")
	}

	return product
}

func (a fieldElement) dot(b fieldElement) fieldElement {
	return a.mul(b).mul(xMinus128)
}

func polyval(hBytes [16]byte, input []byte) [16]byte {
	if len(input)%16 != 0 {
		panic("polyval input not a multiple of the block size")
	}

	h := fieldElementFromBytes(hBytes[:])
	var s fieldElement

	powers := h
	var powersTable [16 * 8]byte
	for i := 0; i < 8; i++ {
		bytes := powers.Bytes()
		copy(powersTable[i*16:], bytes[:])
		powers = powers.dot(h)
	}

	for len(input) > 0 {
		x := fieldElementFromBytes(input[:16])
		input = input[16:]

		s = s.add(x).dot(h)
	}

	return s.Bytes()
}

const (
	maxPlaintextLen  = 1 << 36
	maxCiphertextLen = maxPlaintextLen + 16
	maxADLen         = (1 << 61) - 1
)

type GCMSIV struct {
	hBytes   [16]byte
	block    cipher.Block
	is256Bit bool
	key      [32]byte
}

func (GCMSIV) NonceSize() int {
	return 16
}

func (GCMSIV) Overhead() int {
	return 16
}

func NewGCMSIV(key []byte) (*GCMSIV, error) {
	var block cipher.Block
	var err error
	is256Bit := false

	switch len(key) {
	case 32:
		is256Bit = true
		fallthrough

	case 16:
		if block, err = aes.NewCipher(key); err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("gcmsiv: bad key length: " + strconv.Itoa(len(key)))
	}

	ret := &GCMSIV{
		block:    block,
		is256Bit: is256Bit,
	}
	copy(ret.key[:], key)

	return ret, nil
}

func appendU64(a []byte, val int) []byte {
	var valBytes [8]byte
	binary.LittleEndian.PutUint64(valBytes[:], uint64(val))
	return append(a, valBytes[:]...)
}

func (ctx *GCMSIV) deriveRecordKeys(nonce []byte) (block cipher.Block, hashKey [16]byte) {
	var counter [16]byte
	copy(counter[4:], nonce)

	var ciphertextBlocks [16 * 6]byte
	numBlocks := 4
	if ctx.is256Bit {
		numBlocks = 6
	}

	for j := 0; j < numBlocks; j++ {
		counter[0] = byte(j)
		ctx.block.Encrypt(ciphertextBlocks[16*j:], counter[:])
	}

	copy(hashKey[:], ciphertextBlocks[:8])
	copy(hashKey[8:], ciphertextBlocks[1*16:1*16+8])

	if verbose {
		log("Record authentication key", hashKey[:])
	}

	var encryptionKey [32]byte
	copy(encryptionKey[:], ciphertextBlocks[2*16:2*16+8])
	copy(encryptionKey[8:], ciphertextBlocks[3*16:3*16+8])

	var err error
	if ctx.is256Bit {
		copy(encryptionKey[16:], ciphertextBlocks[4*16:4*16+8])
		copy(encryptionKey[24:], ciphertextBlocks[5*16:5*16+8])
		if verbose {
			log("Record encryption key", encryptionKey[:])
		}
		block, err = aes.NewCipher(encryptionKey[:])
	} else {
		if verbose {
			log("Record encryption key", encryptionKey[:16])
		}
		block, err = aes.NewCipher(encryptionKey[:16])
	}

	if err != nil {
		panic(err)
	}

	return block, hashKey
}

func calculateTag(additionalData, plaintext []byte, nonce []byte, hashKey [16]byte, block cipher.Block) [16]byte {
	input := make([]byte, 0, len(additionalData)+len(plaintext)+48)

	input = append(input, additionalData...)
	for len(input)%16 != 0 {
		input = append(input, 0)
	}

	input = append(input, plaintext...)
	for len(input)%16 != 0 {
		input = append(input, 0)
	}

	input = appendU64(input, len(additionalData)*8)
	input = appendU64(input, len(plaintext)*8)

	if verbose {
		log("POLYVAL input", input)
	}

	S_s := polyval(hashKey, input)
	if verbose {
		log("POLYVAL result", S_s[:])
	}
	for i, b := range nonce {
		S_s[i] ^= b
	}
	if verbose {
		log("POLYVAL result XOR nonce", S_s[:])
	}
	S_s[15] &= 0x7f
	if verbose {
		log("... and masked", S_s[:])
	}
	block.Encrypt(S_s[:], S_s[:])
	if verbose {
		log("Tag", S_s[:])
	}

	return S_s
}

func cryptBytes(dst, src, initCtr []byte, block cipher.Block) []byte {
	var ctrBlock, keystreamBlock [16]byte
	copy(ctrBlock[:], initCtr)
	ctrBlock[15] |= 0x80
	if verbose {
		log("Initial counter", ctrBlock[:])
	}

	for ctr := binary.LittleEndian.Uint32(ctrBlock[:]); len(src) > 0; ctr += 1 {
		binary.LittleEndian.PutUint32(ctrBlock[:], ctr)
		block.Encrypt(keystreamBlock[:], ctrBlock[:])

		plaintextBlock := src

		if len(plaintextBlock) > 16 {
			plaintextBlock = plaintextBlock[:16]
		}
		src = src[len(plaintextBlock):]

		for i := range plaintextBlock {
			dst = append(dst, plaintextBlock[i]^keystreamBlock[i])
		}
	}

	return dst
}

func (ctx *GCMSIV) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if verbose {
		log(fmt.Sprintf("Plaintext (%d bytes)", len(plaintext)), plaintext)
		log(fmt.Sprintf("AAD (%d bytes)", len(additionalData)), additionalData)

		var key []byte
		if ctx.is256Bit {
			key = ctx.key[:]
		} else {
			key = ctx.key[:16]
		}
		log("Key", key)
		log("Nonce", nonce)
	}

	if len(plaintext) > maxPlaintextLen {
		panic("gcmsiv: plaintext too large")
	}

	if len(additionalData) > maxADLen {
		panic("gcmsiv: additional data too large")
	}

	block, hashKey := ctx.deriveRecordKeys(nonce)
	tag := calculateTag(additionalData, plaintext, nonce, hashKey, block)
	dst = cryptBytes(dst, plaintext, tag[:], block)
	dst = append(dst, tag[:]...)
	if verbose {
		log(fmt.Sprintf("Result (%d bytes)", len(dst)), dst)
		fmt.Printf("\n\n")
	}
	return dst
}

func (ctx GCMSIV) Open(dst, nonce, ciphertext, additionalData []byte) (out []byte, err error) {
	if len(additionalData) > maxADLen {
		return nil, errors.New("gcmsiv: bad ciphertext length")
	}

	if len(ciphertext) < 16 || len(ciphertext) > maxCiphertextLen {
		return nil, errors.New("gcmsiv: bad ciphertext length")
	}

	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	initialDstLen := len(dst)
	block, hashKey := ctx.deriveRecordKeys(nonce)
	dst = cryptBytes(dst, ciphertext, tag, block)
	calculatedTag := calculateTag(additionalData, dst[initialDstLen:], nonce, hashKey, block)
	if subtle.ConstantTimeCompare(calculatedTag[:], tag) != 1 {
		return nil, errors.New("gcmsiv: decryption failure")
	}

	return dst, nil
}
