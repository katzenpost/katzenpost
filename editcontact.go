package main

import (
	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// EditContactPage is the page for adding a new contact
type EditContactPage struct {
	nickname string
	back     *widget.Clickable
	avatar   *widget.Clickable
	clear    *widget.Clickable
	expiry   *widget.Clickable
	rename   *widget.Clickable
	remove   *widget.Clickable
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
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Baseline}.Layout(gtx,
					layout.Rigid(material.Button(th, p.back, "<").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
					layout.Rigid(material.H6(th, "Edit Contact").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout))
			}),
			layout.Flexed(1, func(gtx C) D {
				return layout.Center.Layout(gtx, material.Button(th, p.avatar, "Choose Avatar").Layout)
			}),
			layout.Flexed(1, func(gtx C) D {
				return layout.Center.Layout(gtx, material.Button(th, p.clear, "Clear History").Layout)
			}),
			//layout.Flexed(1, func(gtx C) D {
			//	return layout.Center.Layout(gtx, material.Button(th, p.expiry, "Set message lifetime").Layout)
			//}),
			//
			layout.Flexed(1, func(gtx C) D {
				return layout.Center.Layout(gtx, material.Button(th, p.rename, "Rename Contact").Layout)
			}),
			layout.Flexed(1, func(gtx C) D {
				return layout.Center.Layout(gtx, material.Button(th, p.remove, "Delete Contact").Layout)
			}))
	})
}

type EditContactComplete struct {
	nickname string
}

type ChooseAvatar struct {
	nickname string
}

type RenameContact struct {
	nickname string
}

// Event catches the widget submit events and calls catshadow.NewContact
func (p *EditContactPage) Event(gtx layout.Context) interface{} {
	if p.back.Clicked() {
		return BackEvent{}
	}
	if p.avatar.Clicked() {
		return ChooseAvatar{nickname: p.nickname}
	}
	if p.clear.Clicked() {
		// TODO: confirmation dialog
		catshadowClient.WipeConversation(p.nickname)
		return EditContactComplete{nickname: p.nickname}
	}
	if p.expiry.Clicked() {
		// TODO: add message expiry configuration to catshadow
	}
	if p.rename.Clicked() {
		return RenameContact{nickname: p.nickname}
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
	p.back = &widget.Clickable{}
	p.avatar = &widget.Clickable{}
	p.clear = &widget.Clickable{}
	p.expiry = &widget.Clickable{}
	p.rename = &widget.Clickable{}
	p.remove = &widget.Clickable{}
	return p
}
