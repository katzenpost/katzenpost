// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"bytes"
	"errors"
	"io"
)

const (
	oggHeaderLen   = 27
	oggInitPackets = 2
)

var errNotOgg = errors.New("kp-fa: input is not an Ogg stream")

func readPage(r io.Reader) ([]byte, error) {
	hdr := make([]byte, oggHeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if !bytes.Equal(hdr[:4], []byte("OggS")) || hdr[4] != 0 {
		return nil, errNotOgg
	}
	lacing := make([]byte, hdr[26])
	if _, err := io.ReadFull(r, lacing); err != nil {
		return nil, noEOF(err)
	}
	n := 0
	for _, l := range lacing {
		n += int(l)
	}
	page := make([]byte, oggHeaderLen+len(lacing)+n)
	copy(page, hdr)
	copy(page[oggHeaderLen:], lacing)
	if _, err := io.ReadFull(r, page[oggHeaderLen+len(lacing):]); err != nil {
		return nil, noEOF(err)
	}
	return page, nil
}

func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func packetsEnded(page []byte) int {
	n := 0
	for _, l := range page[oggHeaderLen : oggHeaderLen+int(page[26])] {
		if l < 255 {
			n++
		}
	}
	return n
}

func readInit(r io.Reader) ([]byte, error) {
	var init []byte
	for packets := 0; packets < oggInitPackets; {
		page, err := readPage(r)
		if err != nil {
			return nil, noEOF(err)
		}
		init = append(init, page...)
		packets += packetsEnded(page)
	}
	return init, nil
}
