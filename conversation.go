package main

import (
	"github.com/hako/durafmt"
	"github.com/katzenpost/catshadow"
	"strings"
	"time"

	"gioui.org/io/clipboard"
	"gioui.org/io/pointer"
	"image"

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
	nickname       string
	edit           *widget.Clickable
	compose        *widget.Editor
	send           *widget.Clickable
	back           *widget.Clickable
	cancel         *Click
	msgcopy        *widget.Clickable
	msgdetails     *widget.Clickable
	messageClicked *catshadow.Message
	messageClicks  map[*catshadow.Message]*Click
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
		msg := []byte(c.compose.Text())
		c.compose.SetText("")
		// truncate messages
		// TODO: this should split messages and return the set of message IDs sent
		if len(msg)+4 > catshadow.DoubleRatchetPayloadLength {
			msg = msg[:catshadow.DoubleRatchetPayloadLength-4]
		}
		msgId := catshadowClient.SendMessage(c.nickname, msg)
		return MessageSent{nickname: c.nickname, msgId: msgId}
	}
	if c.edit.Clicked() {
		return EditContact{nickname: c.nickname}
	}
	if c.back.Clicked() {
		return BackEvent{}
	}
	if c.msgcopy.Clicked() {
		clipboard.WriteOp{Text: string(c.messageClicked.Plaintext)}.Add(gtx.Ops)
		c.messageClicked = nil
		return nil
	}
	if c.msgdetails.Clicked() {
		c.messageClicked = nil // not implemented
	}

	for msg, click := range c.messageClicks {
		for _, e := range click.Events(gtx.Queue) {
			if e.Type == TypeClick {
				c.messageClicked = msg
			}
		}
	}

	for _, e := range c.cancel.Events(gtx.Queue) {
		if e.Type == TypeClick {
			c.messageClicked = nil
		}
	}

	return nil
}

func layoutMessage(gtx C, msg *catshadow.Message, isSelected bool) D {

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
			in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(0), Left: unit.Dp(8), Right: unit.Dp(8)}
			return in.Layout(gtx, func(gtx C) D {
				timeLabel := strings.Replace(durafmt.ParseShort(time.Now().Sub(msg.Timestamp).Truncate(time.Minute)).String(), "0 seconds", "now", 1)
				if isSelected {
					timeLabel = msg.Timestamp.Truncate(time.Minute).Format(time.RFC822)
					if msg.Outbound {
						timeLabel = "Sent: " + timeLabel
					} else {
						timeLabel = "Received: " + timeLabel
					}
				}
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.End, Spacing: layout.SpaceBetween}.Layout(gtx,
					layout.Rigid(material.Caption(th, timeLabel).Layout),
					layout.Rigid(material.Caption(th, status).Layout),
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

				dims := messageList.Layout(gtx, len(messages), func(gtx C, i int) layout.Dimensions {
					if _, ok := c.messageClicks[messages[i]]; !ok {
						c.messageClicks[messages[i]] = new(Click)
					}

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
					inbetween := layout.Inset{Top: unit.Dp(2)}
					if i > 0 {
						if messages[i-1].Outbound != messages[i].Outbound {
							inbetween = layout.Inset{Top: unit.Dp(8)}
						}
					}
					var dims D
					isSelected := messages[i] == c.messageClicked
					if messages[i].Outbound {
						dims = layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
							layout.Flexed(1, fill{th.Bg}.Layout),
							layout.Flexed(5, func(gtx C) D {
								return inbetween.Layout(gtx, func(gtx C) D {
									return bgSender.Layout(gtx, func(gtx C) D {
										return layoutMessage(gtx, messages[i], isSelected)
									})
								})
							}),
						)
					} else {
						dims = layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
							layout.Flexed(5, func(gtx C) D {
								return inbetween.Layout(gtx, func(gtx C) D {
									return bgReceiver.Layout(gtx, func(gtx C) D {
										return layoutMessage(gtx, messages[i], isSelected)
									})
								})
							}),
							layout.Flexed(1, fill{th.Bg}.Layout),
						)
					}
					a := pointer.Rect(image.Rectangle{Max: dims.Size})
					a.Add(gtx.Ops)
					c.messageClicks[messages[i]].Add(gtx.Ops)
					return dims

				})
				if c.messageClicked != nil {
					a := pointer.Rect(image.Rectangle{Max: dims.Size})
					a.Add(gtx.Ops)
					c.cancel.Add(gtx.Ops)
				}
				return dims
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
			// return the menu laid out for message actions
			if c.messageClicked != nil {
				return bg.Layout(gtx, func(gtx C) D {
					return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Baseline}.Layout(gtx,
						layout.Rigid(material.Button(th, c.msgcopy, "copy").Layout),
						layout.Flexed(1, fill{th.Bg}.Layout),
						layout.Rigid(material.Button(th, c.msgdetails, "details").Layout),
					)
				})
			}

			return bg.Layout(gtx, material.Editor(th, c.compose, ">").Layout)
		}),
	)
}

func newConversationPage(nickname string) *conversationPage {
	return &conversationPage{nickname: nickname,
		compose:       &widget.Editor{SingleLine: false, Submit: true},
		messageClicks: make(map[*catshadow.Message]*Click),
		back:          &widget.Clickable{},
		msgcopy:       &widget.Clickable{},
		msgdetails:    &widget.Clickable{},
		cancel:        new(Click),
		send:          &widget.Clickable{},
		edit:          &widget.Clickable{}}
}
