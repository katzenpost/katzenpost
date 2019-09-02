import QtQuick 2.4
import QtQuick.Controls 2.2
import QtQuick.Controls.Material 2.1
import QtQuick.Layouts 1.3

ApplicationWindow {
    id: mainWindow
    visible: true

    Material.theme: settings.style == "Dark" ? Material.Dark : Material.Light
    Material.accent: Material.Purple
    // flags: Qt.FramelessWindowHint
    background: Rectangle {
        color: Material.color(Material.Grey, Material.Shade900)
    }

    minimumWidth: 600
    minimumHeight: 600
    width: settings.width > 0 ? settings.width : minimumWidth * 2
    height: settings.height > 0 ? settings.height : minimumWidth * 1.5
    Binding on x {
        when: settings.positionX > 0
        value: settings.positionX
    }
    Binding on y {
        when: settings.positionY > 0
        value: settings.positionY
    }

    Component.onCompleted: {
        if (settings.firstRun) {
            // connectDialog.open()
        }
    }
    onClosing: function() {
        console.log("Closing mainWindow")
        settings.positionX = mainWindow.x
        settings.positionY = mainWindow.y
        settings.width = mainWindow.width
        settings.height = mainWindow.height
    }

    Item {
/*
        AboutDialog {
            id: aboutDialog
            x: (mainWindow.width - width) / 2
            y: mainWindow.height / 6
            width: Math.min(mainWindow.width, mainWindow.height) / 3 * 2
        }
*/

        AddContactDialog {
            id: addContactDialog
            x: mainWindow.width / 2 - width / 2
            y: mainWindow.height / 2 - height / 2 - mainWindow.header.height
            width: 340
            height: 500
        }
    }

    header: ToolBar {
        ToolButton {
            id: drawerButton
            contentItem: Image {
                fillMode: Image.Pad
                horizontalAlignment: Image.AlignHCenter
                verticalAlignment: Image.AlignVCenter
                source: "images/drawer.png"
            }
            onClicked: {
                drawer.open()
            }
        }

        RowLayout {
            anchors.verticalCenter: parent.verticalCenter
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: 8

            ImageButton {
                opacity: 1.0
                roundness: 250
                horizontalAlignment: Image.AlignHCenter
                verticalAlignment: Image.AlignVCenter
                source: accountBridge.avatar
                sourceSize.height: 32
                onClicked: function() {
                    // Qt.openUrlExternally(accountBridge.profileURL)
                }
            }

            Label {
                id: titleLabel
                text: accountBridge.nickname
                font.pointSize: 13
                elide: Label.ElideRight
                horizontalAlignment: Image.AlignHCenter
                verticalAlignment: Qt.AlignVCenter
            }
        }

        ToolButton {
            id: postButton
            anchors.right: menuButton.left
            contentItem: Image {
                fillMode: Image.Pad
                horizontalAlignment: Image.AlignHCenter
                verticalAlignment: Image.AlignVCenter
                source: "images/post.png"
            }
            onClicked: {
            }
        }
        ToolButton {
            anchors.right: parent.right
            id: menuButton
            Layout.alignment: Qt.AlignRight
            contentItem: Image {
                fillMode: Image.Pad
                horizontalAlignment: Image.AlignHCenter
                verticalAlignment: Image.AlignVCenter
                source: "images/menu.png"
            }
            onClicked: optionsMenu.open()

            Menu {
                id: optionsMenu
                x: parent.width - width
                transformOrigin: Menu.TopRight

                MenuItem {
                    text: qsTr("Connect")
                    onTriggered: function() {
                        connectDialog.reset()
                        connectDialog.open()
                    }
                }
                /*
                MenuItem {
                    text: qsTr("Settings")
                    onTriggered: settingsDialog.open()
                }
                */
                MenuItem {
                    text: qsTr("About")
                    onTriggered: aboutDialog.open()
                }
            }
        }
    }

    Drawer {
        id: drawer
        width: Math.max(256, drawerLayout.implicitWidth + 16)
        height: mainWindow.height
        dragMargin: 0

        ColumnLayout {
            id: drawerLayout
            anchors.fill: parent

            Label {
                text: accountBridge.nickname
            }
            ToolSeparator {
                Layout.fillWidth: true
                orientation: Qt.Horizontal
            }

            ListView {
                id: listView
                currentIndex: -1
                Layout.fillWidth: true
                Layout.fillHeight: true
                delegate: ItemDelegate {
                    width: parent.width
                    text: model.title
                    highlighted: ListView.isCurrentItem
                    onClicked: {
                        listView.currentIndex = -1
                        drawer.close()
                        switch (model.sid) {
                        case 0:
                            addContactDialog.reset()
                            addContactDialog.open()
                            break
                        case 1:
                            Qt.quit()
                            break
                        }
                    }
                }
                model: ListModel {
                    ListElement {
                        title: qsTr("Add Contact")
                        property int sid: 0
                    }
                    ListElement {
                        title: qsTr("Exit")
                        property int sid: 1
                    }
                }
                ScrollIndicator.vertical: ScrollIndicator {
                }
            }
        }
    }

    RowLayout {
        anchors.fill: parent

        ListView {
            id: contactList
            Layout.fillHeight: true
            width: 320
            topMargin: 32
            leftMargin: 16
            bottomMargin: 32
            rightMargin: 16
            spacing: 16
            model: accountBridge.contactListModel
            delegate: ItemDelegate {
                width: contactList.width - contactList.leftMargin - contactList.rightMargin
                height: 64
                onClicked: accountBridge.loadConversation("other")

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
                        text: model.nickname
                        Layout.fillWidth: true
                        height: 48
                    }
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ListView {
                id: conversationView
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.margins: pane.leftPadding + messageField.leftPadding
                displayMarginBeginning: 40
                displayMarginEnd: 40
                verticalLayoutDirection: ListView.BottomToTop
                spacing: 12
                model: accountBridge.conversationModel
                delegate: Column {
                    anchors.right: sentByMe ? parent.right : undefined
                    spacing: 6

                    readonly property bool sentByMe: model.nickname == "me"

                    Row {
                        id: messageRow
                        spacing: 6
                        anchors.right: sentByMe ? parent.right : undefined

                        Image {
                            id: avatar
                            sourceSize.height: 48
                            smooth: true
                            source: model.avatar
                        }

                        Rectangle {
                            width: Math.min(messageText.implicitWidth + 24, conversationView.width - avatar.width - messageRow.spacing)
                            height: messageText.implicitHeight + 24
                            color: sentByMe ? "lightgrey" : "steelblue"

                            Label {
                                id: messageText
                                text: model.message
                                color: sentByMe ? "black" : "white"
                                anchors.fill: parent
                                anchors.margins: 12
                                wrapMode: Label.Wrap
                            }
                        }
                    }

                    Label {
                        id: timestampText
                        text: Qt.formatDateTime(model.timestamp, "d MMM hh:mm")
                        color: "lightgrey"
                        anchors.right: sentByMe ? parent.right : undefined
                    }
                }

                ScrollBar.vertical: ScrollBar {}
            }

            Pane {
                id: pane
                Layout.fillWidth: true

                RowLayout {
                    width: parent.width

                    TextArea {
                        id: messageField
                        Layout.fillWidth: true
                        placeholderText: qsTr("Compose message")
                        wrapMode: TextArea.Wrap
                    }

                    Button {
                        id: sendButton
                        text: qsTr("Send")
                        enabled: messageField.length > 0
                        onClicked: {
                            accountBridge.sendMessage("other", messageField.text);
                            messageField.text = "";
                        }
                    }
                }
            }
        }
    }
}
