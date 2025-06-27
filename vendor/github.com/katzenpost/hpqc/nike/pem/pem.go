// SPDX-FileCopyrightText: Copyright (c) 2023-2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pem

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/util"
)

// ToPublicPEMString converts a public key to its PEM-encoded string representation.
func ToPublicPEMString(key nike.PublicKey, scheme nike.Scheme) string {
	return string(ToPublicPEMBytes(key, scheme))
}

// ToPublicPEMBytes converts a public key to its PEM-encoded byte slice.
func ToPublicPEMBytes(key nike.PublicKey, scheme nike.Scheme) []byte {
	return toPEMBytes(key, fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(scheme.Name())))
}

// PublicKeyToFile writes a public key to a file in PEM format.
func PublicKeyToFile(filename string, key nike.PublicKey, scheme nike.Scheme) error {
	return writePEMToFile(filename, ToPublicPEMBytes(key, scheme))
}

// FromPublicPEMString parses a PEM-encoded public key string.
func FromPublicPEMString(data string, scheme nike.Scheme) (nike.PublicKey, error) {
	return FromPublicPEMBytes([]byte(data), scheme)
}

// FromPublicPEMBytes parses a PEM-encoded public key byte slice.
func FromPublicPEMBytes(data []byte, scheme nike.Scheme) (nike.PublicKey, error) {
	blk, err := decodePEMBlock(data, fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(scheme.Name())))
	if err != nil {
		return nil, err
	}
	return scheme.UnmarshalBinaryPublicKey(blk.Bytes)
}

// FromPublicPEMFile reads and parses a public key from a PEM-encoded file.
func FromPublicPEMFile(filename string, scheme nike.Scheme) (nike.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %w", err)
	}
	return FromPublicPEMBytes(data, scheme)
}

// ToPrivatePEMString converts a private key to its PEM-encoded string representation.
func ToPrivatePEMString(key nike.PrivateKey, scheme nike.Scheme) string {
	return string(ToPrivatePEMBytes(key, scheme))
}

// ToPrivatePEMBytes converts a private key to its PEM-encoded byte slice.
func ToPrivatePEMBytes(key nike.PrivateKey, scheme nike.Scheme) []byte {
	return toPEMBytes(key, fmt.Sprintf("%s PRIVATE KEY", strings.ToUpper(scheme.Name())))
}

// PrivateKeyToFile writes a private key to a file in PEM format.
func PrivateKeyToFile(filename string, key nike.PrivateKey, scheme nike.Scheme) error {
	return writePEMToFile(filename, ToPrivatePEMBytes(key, scheme))
}

// FromPrivatePEMString parses a PEM-encoded private key string.
func FromPrivatePEMString(data string, scheme nike.Scheme) (nike.PrivateKey, error) {
	return FromPrivatePEMBytes([]byte(data), scheme)
}

// FromPrivatePEMBytes parses a PEM-encoded private key byte slice.
func FromPrivatePEMBytes(data []byte, scheme nike.Scheme) (nike.PrivateKey, error) {
	blk, err := decodePEMBlock(data, fmt.Sprintf("%s PRIVATE KEY", strings.ToUpper(scheme.Name())))
	if err != nil {
		return nil, err
	}
	return scheme.UnmarshalBinaryPrivateKey(blk.Bytes)
}

// FromPrivatePEMFile reads and parses a private key from a PEM-encoded file.
func FromPrivatePEMFile(filename string, scheme nike.Scheme) (nike.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %w", err)
	}
	return FromPrivatePEMBytes(data, scheme)
}

// Helper Functions

// toPEMBytes serializes a key to a PEM-encoded byte slice.
func toPEMBytes(key nike.Key, keyType string) []byte {
	blob, err := key.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("failed to marshal key: %v", err))
	}
	if util.CtIsZero(blob) {
		panic(fmt.Sprintf("attempted to serialize a scrubbed key: %s", keyType))
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: blob,
	})
}

// decodePEMBlock decodes a PEM block and verifies its type.
func decodePEMBlock(data []byte, expectedType string) (*pem.Block, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, fmt.Errorf("failed to decode PEM block of type %s", expectedType)
	}
	if strings.ToUpper(blk.Type) != expectedType {
		return nil, fmt.Errorf("PEM block type mismatch: got %s, want %s", blk.Type, expectedType)
	}
	return blk, nil
}

// writePEMToFile writes PEM-encoded data to a file securely.
func writePEMToFile(filename string, pemData []byte) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(pemData); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}
	return nil
}
