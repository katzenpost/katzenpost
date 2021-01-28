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

        SettingsDialog {
            id: settingsDialog
            x: (mainWindow.width - width) / 2
            y: mainWindow.height / 6
            width: Math.min(mainWindow.width, mainWindow.height) / 3 * 2
        }

        Popup {
            id: errorDialog
            modal: true
            focus: true
            contentHeight: errorLayout.height
            visible: accountBridge.error.length > 0
            x: mainWindow.width / 2 - width / 2
            y: mainWindow.height / 2 - height / 2 - mainWindow.header.height
            width: Math.min(mainWindow.width * 0.66, errorLayout.implicitWidth + 32)
            closePolicy: Popup.CloseOnEscape

            ColumnLayout {
                id: errorLayout
                spacing: 20
                width: parent.width

                Label {
                    text: qsTr("Error")
                    font.bold: true
                }

                Label {
                    Layout.fillWidth: true
                    wrapMode: Label.Wrap
                    font.pointSize: 14
                    text: accountBridge.error
                }

                Button {
                    id: okButton
                    Layout.alignment: Qt.AlignCenter
                    highlighted: true

                    text: qsTr("Close")
                    onClicked: {
                        accountBridge.error = ""
                        errorDialog.close()
                    }
                }
            }
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

            Label {
                id: statusLabel
                text: accountBridge.status
                font.pointSize: 13
                elide: Label.ElideRight
                horizontalAlignment: Image.AlignHCenter
                verticalAlignment: Qt.AlignVCenter
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
                ScrollIndicator.vertical: ScrollIndicator {}
            }
        }
    }

    RowLayout {
        anchors.fill: parent

        ContactList {
            Layout.minimumWidth: mainWindow.width * 0.3
            Layout.preferredWidth: mainWindow.width * 0.3
            Layout.maximumWidth: mainWindow.width * 0.3
        }

        SwipeView {
            id: swipe
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            interactive: false

            currentIndex: 0

            Item {
                Label {
                    anchors.fill: parent
                    anchors.margins: 16

                    text: qsTr("Please select a contact to start messaging")
                    wrapMode: Text.Wrap
                    color: "white"
                    font.pointSize: 18
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }

            Item {
                ConversationView {}
            }
        }
    }
}
