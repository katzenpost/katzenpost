package main
import (

	"gioui.org/widget"
	"gioui.org/layout"
	"gioui.org/widget/material"
)
// EditContactPage is the page for adding a new contact
type EditContactPage struct {
	nickname string
	avatar *widget.Clickable
	clear  *widget.Clickable
	expiry *widget.Clickable
	rename *widget.Clickable
	remove *widget.Clickable
	//avatar // select an avatar image
}

// Layout returns the contact options menu
func (p *EditContactPage) Layout(gtx layout.Context) layout.Dimensions {
	bg := Background{
		Color: th.Bg,
		Inset: layout.Inset{},
	}

	return bg.Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.End}.Layout(gtx,
			layout.Flexed(1, func(gtx C) D { return layout.Center.Layout(gtx, material.Button(th, p.avatar, "Choose avatar").Layout) }),
			layout.Flexed(1, func(gtx C) D { return layout.Center.Layout(gtx, material.Button(th, p.clear, "Clear message history").Layout) }),
			layout.Flexed(1, func(gtx C) D { return layout.Center.Layout(gtx, material.Button(th, p.expiry, "Set message lifetime").Layout) }),
			layout.Flexed(1, func(gtx C) D { return layout.Center.Layout(gtx, material.Button(th, p.rename, "Rename contact").Layout) }),
			layout.Flexed(1, func(gtx C) D { return layout.Center.Layout(gtx, material.Button(th, p.remove, "Remove contact").Layout) }),
		)
	})
}

type EditContactComplete struct {
	nickname string
}
// Event catches the widget submit events and calls catshadow.NewContact
func (p *EditContactPage) Event(gtx layout.Context) interface{} {
	if p.avatar.Clicked() {
		// TODO. avatar selection
	}
	if p.clear.Clicked() {
		// TODO: add clear history method to catshadow
	}
	if p.expiry.Clicked() {
		// TODO: add message expiry configuration to catshadow
	}
	if p.rename.Clicked() {
		// TODO: add contact renaming to catshadow
	}
	if p.remove.Clicked() {
		// TODO: confirmation dialog
		catshadowClient.RemoveContact(p.nickname)
		return EditContactComplete{nickname: p.nickname}
	}
	return nil
}

func (p *EditContactPage) Start(stop <-chan struct{}) {
}

func newEditContactPage(contact string) *EditContactPage {
	p := &EditContactPage{}
	p.nickname = contact
	p.avatar = &widget.Clickable{}
	p.clear  = &widget.Clickable{}
	p.expiry = &widget.Clickable{}
	p.rename = &widget.Clickable{}
	p.remove = &widget.Clickable{}
	return p
}


