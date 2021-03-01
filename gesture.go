package main

import (
	"time"

	"gioui.org/f32"
	"gioui.org/io/event"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/op"
)

// Add multiple buttons support to gesture.Click

// The duration is somewhat arbitrary.
const doubleClickDuration = 200 * time.Millisecond

// Click detects click gestures in the form
// of ClickEvents.
type Click struct {
	// clickedAt is the timestamp at which
	// the last click occurred.
	clickedAt time.Duration
	// clicks is incremented if successive clicks
	// are performed within a fixed duration.
	clicks int
	// pressed tracks whether the pointer is pressed.
	pressed pointer.Buttons
	// entered tracks whether the pointer is inside the gesture.
	entered bool
	// pid is the pointer.ID.
	pid pointer.ID
}

type ClickState uint8

// ClickEvent represent a click action, either a
// TypePress for the beginning of a click or a
// TypeClick for a completed click.
type ClickEvent struct {
	Type      ClickType
	Position  f32.Point
	Source    pointer.Source
	Modifiers key.Modifiers
	Buttons   pointer.Buttons
	// NumClicks records successive clicks occurring
	// within a short duration of each other.
	NumClicks int
}

type ClickType uint8

const (
	// TypePress is reported for the first pointer
	// press.
	TypePress ClickType = iota
	// TypeClick is reported when a click action
	// is complete.
	TypeClick
	// TypeCancel is reported when the gesture is
	// cancelled.
	TypeCancel
)

// Add the handler to the operation list to receive click events.
func (c *Click) Add(ops *op.Ops) {
	op := pointer.InputOp{
		Tag:   c,
		Types: pointer.Press | pointer.Release | pointer.Enter | pointer.Leave,
	}
	op.Add(ops)
}

// Hovered returns whether a pointer is inside the area.
func (c *Click) Hovered() bool {
	return c.entered
}

// Pressed returns whether a pointer is pressing.
func (c *Click) Pressed(button pointer.Buttons) bool {
	return c.pressed.Contain(button)
}

// Events returns the next click event, if any.
func (c *Click) Events(q event.Queue) []ClickEvent {
	var events []ClickEvent
	for _, evt := range q.Events(c) {
		e, ok := evt.(pointer.Event)
		if !ok {
			continue
		}
		switch e.Type {
		case pointer.Release:
			if c.pid != e.PointerID {
				break
			}
			b := c.pressed ^ e.Buttons
			c.pressed = e.Buttons
			if c.entered {
				if e.Time-c.clickedAt < doubleClickDuration {
					c.clicks++
				} else {
					c.clicks = 1
				}
				c.clickedAt = e.Time
				events = append(events, ClickEvent{Type: TypeClick, Position: e.Position, Source: e.Source, Buttons: b, Modifiers: e.Modifiers, NumClicks: c.clicks})
			} else {
				events = append(events, ClickEvent{Type: TypeCancel, Buttons: b})
			}
		case pointer.Cancel:
			b := e.Buttons ^ c.pressed
			wasPressed := c.pressed.Contain(b)
			c.pressed = e.Buttons
			c.entered = false
			if wasPressed {
				events = append(events, ClickEvent{Type: TypeCancel, Buttons: b})
			}
		case pointer.Press:
			if c.pressed == e.Buttons {
				break
			}
			if !c.entered {
				c.pid = e.PointerID
			}
			if c.pid != e.PointerID {
				break
			}
			c.pressed = e.Buttons
			events = append(events, ClickEvent{Type: TypePress, Position: e.Position, Source: e.Source, Buttons: e.Buttons, Modifiers: e.Modifiers})
		case pointer.Leave:
			if !c.pressed.Contain(c.pressed ^ e.Buttons) {
				c.pid = e.PointerID
			}
			if c.pid == e.PointerID {
				c.entered = false
			}
		case pointer.Enter:
			if !c.pressed.Contain(c.pressed ^ e.Buttons) {
				c.pid = e.PointerID
			}
			if c.pid == e.PointerID {
				c.entered = true
			}
		}
	}
	return events
}

func (ClickEvent) ImplementsEvent() {}
