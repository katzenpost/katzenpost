import QtQuick 2.4
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.1
import QtQuick.Layouts 1.3

Popup {
    id: addContactDialog
    property string contact

    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape

    property var reset: function() {
        connectSwipeView.currentIndex = 0
        contactArea.text = ""
        nicknameArea.text = ""
    }

    ColumnLayout {
        spacing: 16
        anchors.fill: parent
        clip: true

        Label {
            text: qsTr("Add a Contact")
            Layout.alignment: Qt.AlignHCenter
            font.bold: true
        }

        Image {
            id: logo
            Layout.alignment: Qt.AlignHCenter
            smooth: true
            source: "images/accounts/mastodon.svg"
            sourceSize.height: 96
        }

        SwipeView {
            id: connectSwipeView
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.alignment: Qt.AlignHCenter
            Component.onCompleted: contentItem.interactive = false

            currentIndex: 0
            Item {
                id: contactPage

                ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 16

                        TextField {
                            id: contactArea
                            focus: true
                            selectByMouse: true
                            placeholderText: qsTr("Contact")
                            Layout.fillWidth: true
                        }

                        Button {
                            id: connectButton
                            enabled: contactArea.text.length > 0
                            Layout.alignment: Qt.AlignBottom | Qt.AlignCenter
                            highlighted: true
                            text: qsTr("Next")

                            onClicked: {
                                connectSwipeView.currentIndex = 1
                            }
                        }
                }
            }

            Item {
                id: authPage

                ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 16

                        Label {
                            text: "Assign a nickname for this contact:"
                            Layout.alignment: Qt.AlignCenter
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                        }

                        TextField {
                            id: nicknameArea
                            focus: true
                            selectByMouse: true
                            placeholderText: qsTr("Nickname")
                            Layout.fillWidth: true
                        }

                        Button {
                            id: authButton
                            enabled: nicknameArea.text.length > 0
                            Layout.alignment: Qt.AlignBottom | Qt.AlignCenter
                            highlighted: true
                            text: qsTr("Add Contact")

                            onClicked: {
                                var contact = contactArea.text
                                var nickname = nicknameArea.text
                                var result = accountBridge.addContact(contact, nickname)
                                if (result) {
                                    addContactDialog.close()
                                }
                            }
                        }
                }
            }
        }

        PageIndicator {
            id: indicator
            Layout.alignment: Qt.AlignHCenter

            count: connectSwipeView.count
            currentIndex: connectSwipeView.currentIndex
        }
    }
}
