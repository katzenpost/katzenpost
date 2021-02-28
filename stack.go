// SPDX-License-Identifier: Unlicense OR MIT
/*
these methods were implemented by Elias Naur <mail@eliasnaur.com>
for the scatter.im project https://git.sr.ht/~eliasnaur/scatter
*/
package main

import (
	"image"
	"math"
	"time"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"image/color"
)

type pageStack struct {
	pages    []Page
	stopChan chan<- struct{}
}

type Page interface {
	Start(stop <-chan struct{})
	Event(gtx layout.Context) interface{}
	Layout(gtx layout.Context) layout.Dimensions
}

type Background struct {
	Color  color.NRGBA
	Radius unit.Value
	Inset  layout.Inset
}

type clipCircle struct {
}

func (cc *clipCircle) Layout(gtx layout.Context, w layout.Widget) layout.Dimensions {
	macro := op.Record(gtx.Ops)
	dims := w(gtx)
	call := macro.Stop()
	max := dims.Size.X
	if dy := dims.Size.Y; dy > max {
		max = dy
	}
	szf := float32(max)
	rr := szf * .5
	defer op.Save(gtx.Ops).Load()
	clip.RRect{
		Rect: f32.Rectangle{Max: f32.Point{X: szf, Y: szf}},
		NE:   rr, NW: rr, SE: rr, SW: rr,
	}.Add(gtx.Ops)
	call.Add(gtx.Ops)
	return dims
}

func (b *Background) Layout(gtx layout.Context, w layout.Widget) layout.Dimensions {
	macro := op.Record(gtx.Ops)
	dims := b.Inset.Layout(gtx, w)
	call := macro.Stop()
	defer op.Save(gtx.Ops).Load()
	size := dims.Size
	width, height := float32(size.X), float32(size.Y)
	if r := float32(gtx.Px(b.Radius)); r > 0 {
		if r > width/2 {
			r = width / 2
		}
		if r > height/2 {
			r = height / 2
		}
		clip.RRect{
			Rect: f32.Rectangle{Max: f32.Point{
				X: width, Y: height,
			}}, NW: r, NE: r, SW: r, SE: r,
		}.Add(gtx.Ops)
	}
	paint.FillShape(gtx.Ops, b.Color, clip.Rect(image.Rectangle{Max: size}).Op())
	call.Add(gtx.Ops)
	return dims
}

type Transition struct {
	prev, page Page
	reverse    bool
	time       time.Time
}

type BackEvent struct{}

type fill struct {
	color color.NRGBA
}

type icon struct {
	src  []byte
	size unit.Value

	// Cached values.
	op      paint.ImageOp
	imgSize int
}

func rgb(c uint32) color.NRGBA {
	return argb((0xff << 24) | c)
}

func argb(c uint32) color.NRGBA {
	return color.NRGBA{A: uint8(c >> 24), R: uint8(c >> 16), G: uint8(c >> 8), B: uint8(c)}
}

func (f fill) Layout(gtx layout.Context) layout.Dimensions {
	cs := gtx.Constraints
	d := cs.Min
	paint.FillShape(gtx.Ops, f.color, clip.Rect(image.Rectangle{Max: d}).Op())
	return layout.Dimensions{Size: d, Baseline: d.Y}
}

func (t *Transition) Start(stop <-chan struct{}) {
	t.page.Start(stop)
}

func (t *Transition) Event(gtx layout.Context) interface{} {
	return t.page.Event(gtx)
}

func (t *Transition) Layout(gtx layout.Context) layout.Dimensions {
	defer op.Save(gtx.Ops).Load()
	prev, page := t.prev, t.page
	if prev != nil {
		if t.reverse {
			prev, page = page, prev
		}
		now := gtx.Now
		if t.time.IsZero() {
			t.time = now
		}
		prev.Layout(gtx)
		cs := gtx.Constraints
		size := layout.FPt(cs.Max)
		max := float32(math.Sqrt(float64(size.X*size.X + size.Y*size.Y)))
		progress := float32(now.Sub(t.time).Seconds()) * 3
		progress = progress * progress // Accelerate
		if progress >= 1 {
			// Stop animation when complete.
			t.prev = nil
		}
		if t.reverse {
			progress = 1 - progress
		}
		diameter := progress * max
		radius := diameter / 2
		op.InvalidateOp{}.Add(gtx.Ops)
		center := size.Mul(.5)
		clipCenter := f32.Point{X: diameter / 2, Y: diameter / 2}
		off := f32.Affine2D{}.Offset(center.Sub(clipCenter))
		op.Affine(off).Add(gtx.Ops)
		clip.RRect{
			Rect: f32.Rectangle{Max: f32.Point{X: diameter, Y: diameter}},
			NE:   radius, NW: radius, SE: radius, SW: radius,
		}.Add(gtx.Ops)
		op.Affine(off.Invert()).Add(gtx.Ops)
		fill{rgb(0xffffff)}.Layout(gtx)
	}
	return page.Layout(gtx)
}

func (s *pageStack) Len() int {
	return len(s.pages)
}

func (s *pageStack) Current() Page {
	return s.pages[len(s.pages)-1]
}

func (s *pageStack) Pop() {
	s.stop()
	i := len(s.pages) - 1
	prev := s.pages[i]
	s.pages[i] = nil
	s.pages = s.pages[:i]
	if len(s.pages) > 0 {
		s.pages[i-1] = &Transition{
			reverse: true,
			prev:    prev,
			page:    s.Current(),
		}
		s.start()
	}
}

func (s *pageStack) start() {
	stop := make(chan struct{})
	s.stopChan = stop
	s.Current().Start(stop)
}

func (s *pageStack) Swap(p Page) {
	prev := s.pages[len(s.pages)-1]
	s.pages[len(s.pages)-1] = &Transition{
		prev: prev,
		page: p,
	}
	s.start()
}

func (s *pageStack) Push(p Page) {
	if s.stopChan != nil {
		s.stop()
	}
	if len(s.pages) > 0 {
		p = &Transition{
			prev: s.Current(),
			page: p,
		}
	}
	s.pages = append(s.pages, p)
	s.start()
}

func (s *pageStack) stop() {
	close(s.stopChan)
	s.stopChan = nil
}

func (s *pageStack) Clear(p Page) {
	for len(s.pages) > 0 {
		s.Pop()
	}
	s.Push(p)
}
