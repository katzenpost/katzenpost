import QtQuick 2.5
import QtQuick.Controls 2.2
import QtQuick.Layouts 1.3

ListView {
    id: contactList

    Layout.fillHeight: true
    topMargin: 16
    leftMargin: 16
    bottomMargin: 16
    rightMargin: 16
    spacing: 16
    focus: true
    highlightFollowsCurrentItem: true
    model: accountBridge.contactListModel
    currentIndex: -1

    onCurrentItemChanged: {
        var nickname = model.data(model.index(currentIndex, 0), Qt.UserRole + 1)
        swipe.currentIndex = 1
        accountBridge.loadConversation(nickname)
    }

    delegate: ItemDelegate {
        highlighted: ListView.isCurrentItem
        width: contactList.width - contactList.leftMargin - contactList.rightMargin
        height: 48
        onClicked: {
            contactList.currentIndex = index
        }

        RowLayout {
            height: 48
            width: parent.width
            clip: true
            Image {
                id: avatar
                sourceSize.height: 48
                smooth: true
                source: model.avatar
            }
            Label {
                Layout.fillWidth: true
                height: 48
                text: model.nickname
            }
        }
    }
}
