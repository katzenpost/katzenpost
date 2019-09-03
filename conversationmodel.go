package main

import (
	"github.com/therecipe/qt/core"
)

// Message holds the data for a message
type Message struct {
	core.QObject

	Nickname string
	Avatar   string
	Message  string
}

// ConversationModel holds a collection of messages
type ConversationModel struct {
	core.QAbstractListModel

	_ func() `constructor:"init"`

	_ map[int]*core.QByteArray `property:"roles"`
	_ []*Message               `property:"messages"`

	_ func(*Message) `slot:"addMessage"`
	_ func(*Message) `slot:"appendMessage"`
	_ func(int)      `slot:"removeMessage"`
	_ func()         `slot:"clear"`
}

func (m *ConversationModel) init() {
	m.SetRoles(map[int]*core.QByteArray{
		RoleNickname: core.NewQByteArray2("nickname", -1),
		RoleAvatar:   core.NewQByteArray2("avatar", -1),
		RoleMessage:  core.NewQByteArray2("message", -1),
	})

	m.ConnectData(m.data)
	m.ConnectRowCount(m.rowCount)
	m.ConnectColumnCount(m.columnCount)
	m.ConnectRoleNames(m.roleNames)

	m.ConnectAddMessage(m.addMessage)
	m.ConnectAppendMessage(m.appendMessage)
	m.ConnectRemoveMessage(m.removeMessage)
	m.ConnectClear(m.clear)
}

func (m *ConversationModel) data(index *core.QModelIndex, role int) *core.QVariant {
	if !index.IsValid() {
		return core.NewQVariant()
	}
	if index.Row() >= len(m.Messages()) {
		return core.NewQVariant()
	}

	var p = m.Messages()[len(m.Messages())-1-index.Row()]
	if p == nil {
		return core.NewQVariant()
	}

	switch role {
	case RoleNickname:
		{
			return core.NewQVariant15(p.Nickname)
		}
	case RoleAvatar:
		{
			return core.NewQVariant15(p.Avatar)
		}
	case RoleMessage:
		{
			return core.NewQVariant15(p.Message)
		}

	default:
		{
			return core.NewQVariant()
		}
	}
}

func (m *ConversationModel) rowCount(parent *core.QModelIndex) int {
	return len(m.Messages())
}

func (m *ConversationModel) columnCount(parent *core.QModelIndex) int {
	return 1
}

func (m *ConversationModel) roleNames() map[int]*core.QByteArray {
	return m.Roles()
}

func (m *ConversationModel) clear() {
	m.BeginResetModel()
	m.SetMessages([]*Message{})
	m.EndResetModel()
}

func (m *ConversationModel) addMessage(p *Message) {
	m.BeginInsertRows(core.NewQModelIndex(), 0, 0)
	m.SetMessages(append(m.Messages(), p))
	m.EndInsertRows()
}

func (m *ConversationModel) appendMessage(p *Message) {
	m.BeginInsertRows(core.NewQModelIndex(), len(m.Messages()), len(m.Messages()))
	m.SetMessages(append([]*Message{p}, m.Messages()...))
	m.EndInsertRows()
}

func (m *ConversationModel) removeMessage(row int) {
	trow := len(m.Messages()) - 1 - row
	m.BeginRemoveRows(core.NewQModelIndex(), row, row)
	m.SetMessages(append(m.Messages()[:trow], m.Messages()[trow+1:]...))
	m.EndRemoveRows()
}

func init() {
	ConversationModel_QRegisterMetaType()
	Message_QRegisterMetaType()
}
