package main

import (
	"github.com/therecipe/qt/core"
)

// Model Roles
const (
	RoleNickname = int(core.Qt__UserRole) + 1<<iota
	RoleAvatar
	RoleMessage
	RoleTimestamp
	RoleOutbound
)

// Contact holds the data for a contact
type Contact struct {
	core.QObject

	Nickname string
	Avatar   string
}

// ContactListModel holds a collection of contacts
type ContactListModel struct {
	core.QAbstractListModel

	_ func() `constructor:"init"`

	_ map[int]*core.QByteArray `property:"roles"`
	_ []*Contact               `property:"contacts"`

	_ func(*Contact) `slot:"addContact"`
	_ func(*Contact) `slot:"appendContact"`
	_ func(int)      `slot:"removeContact"`
	_ func()         `slot:"clear"`
}

func (m *ContactListModel) init() {
	m.SetRoles(map[int]*core.QByteArray{
		RoleNickname: core.NewQByteArray2("nickname", -1),
		RoleAvatar:   core.NewQByteArray2("avatar", -1),
	})

	m.ConnectData(m.data)
	m.ConnectRowCount(m.rowCount)
	m.ConnectColumnCount(m.columnCount)
	m.ConnectRoleNames(m.roleNames)

	m.ConnectAddContact(m.addContact)
	m.ConnectAppendContact(m.appendContact)
	m.ConnectRemoveContact(m.removeContact)
	m.ConnectClear(m.clear)
}

func (m *ContactListModel) data(index *core.QModelIndex, role int) *core.QVariant {
	if !index.IsValid() {
		return core.NewQVariant()
	}
	if index.Row() >= len(m.Contacts()) {
		return core.NewQVariant()
	}

	var p = m.Contacts()[len(m.Contacts())-1-index.Row()]
	if p == nil {
		return core.NewQVariant()
	}

	switch role {
	case RoleNickname:
		{
			return core.NewQVariant1(p.Nickname)
		}
	case RoleAvatar:
		{
			if p.Avatar == "" {
				return core.NewQVariant1("qrc:/qml/images/katzenpost_logo.png")
			} else {
				return core.NewQVariant1(p.Avatar)
			}
		}

	default:
		{
			return core.NewQVariant()
		}
	}
}

func (m *ContactListModel) rowCount(parent *core.QModelIndex) int {
	return len(m.Contacts())
}

func (m *ContactListModel) columnCount(parent *core.QModelIndex) int {
	return 1
}

func (m *ContactListModel) roleNames() map[int]*core.QByteArray {
	return m.Roles()
}

func (m *ContactListModel) clear() {
	m.BeginResetModel()
	m.SetContacts([]*Contact{})
	m.EndResetModel()
}

func (m *ContactListModel) addContact(p *Contact) {
	m.BeginInsertRows(core.NewQModelIndex(), 0, 0)
	m.SetContacts(append(m.Contacts(), p))
	m.EndInsertRows()
}

func (m *ContactListModel) appendContact(p *Contact) {
	m.BeginInsertRows(core.NewQModelIndex(), len(m.Contacts()), len(m.Contacts()))
	m.SetContacts(append([]*Contact{p}, m.Contacts()...))
	m.EndInsertRows()
}

func (m *ContactListModel) removeContact(row int) {
	trow := len(m.Contacts()) - 1 - row
	m.BeginRemoveRows(core.NewQModelIndex(), row, row)
	m.SetContacts(append(m.Contacts()[:trow], m.Contacts()[trow+1:]...))
	m.EndRemoveRows()
}

func init() {
	ContactListModel_QRegisterMetaType()
	Contact_QRegisterMetaType()
}
