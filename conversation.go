package main

import (
	"github.com/katzenpost/catshadow"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

var (
	messageList  = &layout.List{Axis: layout.Vertical, ScrollToEnd: true}
	messageField = &widget.Editor{SingleLine: true}
)

type conversationPage struct {
	nickname string
	edit     *widget.Clickable
	compose  *widget.Editor
	send     *widget.Clickable
	back     *widget.Clickable
}

func (c *conversationPage) Start(stop <-chan struct{}) {
}

type MessageSent struct {
	nickname string
	msgId    catshadow.MessageID
}

type EditContact struct {
	nickname string
}

func (c *conversationPage) Event(gtx layout.Context) interface{} {
	// receive keystroke to editor panel
	for _, ev := range c.compose.Events() {
		switch ev.(type) {
		case widget.SubmitEvent:
			c.send.Click()
		}
	}
	if c.send.Clicked() {
		msg := c.compose.Text()
		c.compose.SetText("")
		msgId := catshadowClient.SendMessage(c.nickname, []byte(msg))
		return MessageSent{nickname: c.nickname, msgId: msgId}
	}
	if c.edit.Clicked() {
		return EditContact{nickname: c.nickname}
	}
	if c.back.Clicked() {
		return BackEvent{}
	}

	return nil
}

func layoutMessage(gtx C, msg *catshadow.Message) D {
	ts := msg.Timestamp.Round(1 * time.Minute).Format(time.RFC822)

	status := ""
	if msg.Outbound == true {
		status = "queued"
		if msg.Sent {
			status = "sent"
		}
		if msg.Delivered {
			status = "delivered"
		}
	}

	return layout.Flex{Axis: layout.Vertical, Alignment: layout.End, Spacing: layout.SpaceBetween}.Layout(gtx,
		layout.Rigid(material.Body1(th, string(msg.Plaintext)).Layout),
		layout.Rigid(func(gtx C) D {
			in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
			return in.Layout(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.End, Spacing: layout.SpaceBetween}.Layout(gtx,
					layout.Rigid(material.Body2(th, ts).Layout),
					layout.Rigid(material.Body2(th, status).Layout),
				)
			})
		}),
	)
}

func (c *conversationPage) Layout(gtx layout.Context) layout.Dimensions {
	contact := catshadowClient.GetContacts()[c.nickname]
	messages := catshadowClient.GetSortedConversation(c.nickname)
	c.compose.Focus()
	bgl := Background{
		Color: th.Bg,
		Inset: layout.Inset{Top: unit.Dp(0), Bottom: unit.Dp(0), Left: unit.Dp(0), Right: unit.Dp(0)},
	}

	return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return bgl.Layout(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Baseline}.Layout(gtx,
					layout.Rigid(material.Button(th, c.back, "<").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
					layout.Rigid(material.Button(th, c.edit, c.nickname).Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
				)
			},
			)
		}),
		layout.Flexed(2, func(gtx C) D {
			return bgl.Layout(gtx, func(ctx C) D {
				if len(messages) == 0 {
					return fill{th.Bg}.Layout(ctx)
				}
				return messageList.Layout(gtx, len(messages), func(gtx C, i int) layout.Dimensions {
					bgSender := Background{
						Color:  th.ContrastBg,
						Inset:  layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(8), Right: unit.Dp(12)},
						Radius: unit.Dp(10),
					}
					bgReceiver := Background{
						Color:  th.ContrastFg,
						Inset:  layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(8)},
						Radius: unit.Dp(10),
					}
					if messages[i].Outbound {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
							layout.Flexed(1, fill{th.Bg}.Layout),
							layout.Flexed(5, func(gtx C) D {
								return bgSender.Layout(gtx, func(gtx C) D {
									return layoutMessage(gtx, messages[i])
								})
							}),
						)
					} else {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
							layout.Flexed(5, func(gtx C) D {
								return bgReceiver.Layout(gtx, func(gtx C) D {
									return layoutMessage(gtx, messages[i])
								})
							}),
							layout.Flexed(1, fill{th.Bg}.Layout),
						)
					}
				})
			})
		}),
		layout.Rigid(func(gtx C) D {
			bg := Background{
				Color: th.ContrastBg,
				Inset: layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(0), Left: unit.Dp(12), Right: unit.Dp(12)},
			}
			if contact.IsPending {
				return bg.Layout(gtx, material.Caption(th, "Contact pending key exchange").Layout)
			}
			return bg.Layout(gtx, material.Editor(th, c.compose, ">").Layout)
		}),
	)
}

func newConversationPage(nickname string) *conversationPage {
	return &conversationPage{nickname: nickname,
		compose: &widget.Editor{SingleLine: true, Submit: true},
		back:    &widget.Clickable{},
		send:    &widget.Clickable{},
		edit:    &widget.Clickable{}}
}
