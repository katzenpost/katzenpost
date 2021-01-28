import QtQuick 2.5
import QtQuick.Controls 2.2
import QtQuick.Layouts 1.3
import QtQuick.Dialogs 1.3

ListView {
    id: contactList

    Layout.fillHeight: true
    focus: true
    highlightFollowsCurrentItem: true
    model: accountBridge.contactListModel
    currentIndex: -1

    onCurrentItemChanged: {
        var nickname = model.data(model.index(currentIndex, 0), Qt.UserRole)
        swipe.currentIndex = 1
        conversationView.messageTextField.forceActiveFocus()
        accountBridge.loadConversation(nickname)
    }

    delegate: ItemDelegate {
        highlighted: ListView.isCurrentItem
        width: contactList.width - contactList.leftMargin - contactList.rightMargin
        height: 64
        onClicked: {
            contactList.currentIndex = index
        }

        MouseArea {
            anchors.fill: parent
            // we don't want to eat clicks on the Label
            acceptedButtons: Qt.RightButton
            propagateComposedEvents: true

            onReleased: {
                if (mouse.button == Qt.RightButton) {
                    contextMenu.x = mouse.x;
                    contextMenu.y = mouse.y;
                    contextMenu.open();
                    return;
                }

                mouse.accepted = false;
            }

            Menu {
                id: contextMenu
                MenuItem {
                    text: "Change Avatar"
                    onTriggered: {
                        contactList.currentIndex = index
                        imageFileDialog.open()
                    }
                }
            }
        }

        RowLayout {
            height: parent.height
            width: parent.width
            clip: true

            Image {
                id: avatar
                Layout.topMargin: 8
                Layout.bottomMargin: 8
                Layout.leftMargin: 8
                Layout.rightMargin: 4
                sourceSize.height: parent.height - 16
                smooth: true
                source: model.avatar
            }
            Label {
                Layout.topMargin: 8
                Layout.bottomMargin: 8
                Layout.leftMargin: 4
                Layout.rightMargin: 4
                Layout.fillWidth: true
                height: parent.height
                text: model.nickname
            }
            Label {
                Layout.topMargin: 8
                Layout.bottomMargin: 8
                Layout.leftMargin: 4
                Layout.rightMargin: 8
                height: parent.height
                text: "Awaiting key exchange"
                opacity: 0.66
                visible: !model.keyexchanged
            }
        }
    }

    FileDialog {
        id: imageFileDialog
        title: "Please choose an avatar"
        folder: shortcuts.home
        nameFilters: [ "Image files (*.jpg *.jpeg *.png *.gif)", "All files (*)" ]
        selectExisting: true
        selectMultiple: false

        onAccepted: {
            for (var i = 0; i < imageFileDialog.fileUrls.length; i++) {
                var nickname = model.data(model.index(0, 0), Qt.UserRole)

                accountBridge.loadAvatar(nickname, imageFileDialog.fileUrls[i])
            }
        }
    }
}
