// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	frameVersion  = 1
	frameOverhead = 4
	noSync        = 0xffff
	codecOpus     = "audio/ogg; codecs=opus"
)

const (
	kindHeader byte = iota
	kindData
	kindEnd
)

var errShortFrame = errors.New("kp-fa: frame too short")

type frame struct {
	kind byte
	sync uint16
	body []byte
}

func (f frame) marshal() []byte {
	b := make([]byte, frameOverhead, frameOverhead+len(f.body))
	b[0] = frameVersion
	b[1] = f.kind
	binary.BigEndian.PutUint16(b[2:], f.sync)
	return append(b, f.body...)
}

func unmarshalFrame(b []byte) (frame, error) {
	if len(b) < frameOverhead {
		return frame{}, errShortFrame
	}
	if b[0] != frameVersion {
		return frame{}, fmt.Errorf("kp-fa: frame version %d", b[0])
	}
	f := frame{kind: b[1], sync: binary.BigEndian.Uint16(b[2:]), body: b[frameOverhead:]}
	if f.kind > kindEnd {
		return frame{}, fmt.Errorf("kp-fa: frame kind %d", f.kind)
	}
	if f.sync != noSync && int(f.sync) >= len(f.body) {
		return frame{}, fmt.Errorf("kp-fa: sync %d past body of %d", f.sync, len(f.body))
	}
	return f, nil
}

func headerBody(codec string, init []byte) []byte {
	b := append([]byte{byte(len(codec))}, codec...)
	return append(b, init...)
}

func parseHeaderBody(b []byte) (string, []byte, error) {
	if len(b) == 0 || len(b) < 1+int(b[0]) {
		return "", nil, errShortFrame
	}
	n := 1 + int(b[0])
	return string(b[1:n]), b[n:], nil
}
