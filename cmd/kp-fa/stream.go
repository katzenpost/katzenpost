// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/sync/errgroup"
)

var errStalled = errors.New("the broadcaster has gone off the air")

func send(r io.Reader, maxPlaintext, windowSize int, write func(uint64, []byte) error, published func()) error {
	init, err := readInit(r)
	if err != nil {
		return err
	}
	header := frame{kind: kindHeader, sync: noSync, body: headerBody(codecOpus, init)}.marshal()
	if len(header) > maxPlaintext {
		return fmt.Errorf("kp-fa: Ogg headers of %d bytes exceed one box", len(init))
	}
	if err := write(0, header); err != nil {
		return err
	}
	published()
	g, failed := errgroup.WithContext(context.Background())
	g.SetLimit(windowSize)
	p := newPacker(maxPlaintext - frameOverhead)
	k := uint64(1)
	dispatch := func(b []byte) bool {
		if failed.Err() != nil {
			return false
		}
		i := k
		k++
		g.Go(func() error { return write(i, b) })
		return true
	}
	var readErr error
	for {
		page, err := readPage(r)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
		for _, b := range p.add(page) {
			if !dispatch(b) {
				return g.Wait()
			}
		}
	}
	if b := p.flush(); b != nil {
		dispatch(b)
	}
	if err := g.Wait(); err != nil {
		return err
	}
	if err := write(k, frame{kind: kindEnd, sync: noSync}.marshal()); err != nil {
		return err
	}
	return readErr
}

type result struct {
	b   []byte
	err error
}

func ordered(ctx context.Context, windowSize int, start uint64, stall time.Duration, read func(context.Context, uint64) ([]byte, error)) func() ([]byte, error) {
	slots := make(chan chan result, windowSize)
	go func() {
		defer close(slots)
		for k := start; ; k++ {
			ch := make(chan result, 1)
			select {
			case slots <- ch:
			case <-ctx.Done():
				return
			}
			go func(k uint64) {
				b, err := read(ctx, k)
				ch <- result{b, err}
			}(k)
		}
	}()
	return func() ([]byte, error) {
		ch, ok := <-slots
		if !ok {
			return nil, ctx.Err()
		}
		t := time.NewTimer(stall)
		defer t.Stop()
		select {
		case r := <-ch:
			return r.b, r.err
		case <-t.C:
			return nil, fmt.Errorf("no new audio for %s: %w", stall, errStalled)
		}
	}
}

func play(w io.Writer, init []byte, next func() ([]byte, error)) error {
	if _, err := w.Write(init); err != nil {
		return err
	}
	synced := false
	for {
		b, err := next()
		if err != nil {
			return err
		}
		f, err := unmarshalFrame(b)
		if err != nil {
			return err
		}
		switch f.kind {
		case kindEnd:
			return nil
		case kindData:
		default:
			return fmt.Errorf("kp-fa: unexpected frame kind %d in stream", f.kind)
		}
		body := f.body
		if !synced {
			if f.sync == noSync {
				continue
			}
			synced = true
			body = body[f.sync:]
		}
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
}

func stoppable(ctx context.Context, r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		_, err := io.Copy(pw, r)
		pw.CloseWithError(err)
	}()
	context.AfterFunc(ctx, func() { pw.Close() })
	return pr
}
