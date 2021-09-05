package main

import (
	"gioui.org/layout"
	"gioui.org/widget/material"
	"github.com/katzenpost/katzenpost/catshadow"
)

type connectingPage struct {
	result chan interface{}
}

func (p *connectingPage) Layout(gtx layout.Context) layout.Dimensions {
	bg := Background{
		Color: th.Bg,
		Inset: layout.Inset{},
	}

	return bg.Layout(gtx, func(gtx C) D { return layout.Center.Layout(gtx, material.Caption(th, "Stand by... connecting").Layout) })
}

func (p *connectingPage) Start(stop <-chan struct{}) {
}

type connectError struct {
	err error
}

type connectSuccess struct {
	client *catshadow.Client
}

func (p *connectingPage) Event(gtx layout.Context) interface{} {
	select {
	case r := <-p.result:
		switch r := r.(type) {
		case error:
			return connectError{err: r}
		case *catshadow.Client:
			return connectSuccess{client: r}
		}
	default:
	}
	return nil
}

func newConnectingPage(result chan interface{}) *connectingPage {
	p := new(connectingPage)
	p.result = result
	return p
}
