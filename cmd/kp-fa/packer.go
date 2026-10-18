// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

type packer struct {
	capacity int
	body     []byte
	sync     uint16
}

func newPacker(capacity int) *packer {
	return &packer{capacity: capacity, sync: noSync}
}

func (p *packer) add(page []byte) [][]byte {
	var out [][]byte
	if p.sync == noSync {
		p.sync = uint16(len(p.body))
	}
	for len(page) > 0 {
		n := min(p.capacity-len(p.body), len(page))
		p.body = append(p.body, page[:n]...)
		page = page[n:]
		if len(p.body) == p.capacity {
			out = append(out, p.flush())
		}
	}
	return out
}

func (p *packer) flush() []byte {
	if len(p.body) == 0 {
		return nil
	}
	b := frame{kind: kindData, sync: p.sync, body: p.body}.marshal()
	p.body = nil
	p.sync = noSync
	return b
}
