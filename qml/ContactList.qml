import QtQuick 2.5
import QtQuick.Controls 2.2
import QtQuick.Layouts 1.3

ListView {
    id: contactList

    Layout.fillHeight: true
    width: 320
    topMargin: 16
    leftMargin: 16
    bottomMargin: 16
    rightMargin: 16
    spacing: 16

    model: accountBridge.contactListModel
    delegate: ItemDelegate {
        width: contactList.width - contactList.leftMargin - contactList.rightMargin
        height: 48
        onClicked: {
            swipe.currentIndex = 1
            accountBridge.loadConversation(model.nickname)
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
