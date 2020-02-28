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
        passphraseArea.text = ""
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
            source: "images/katzenpost_logo.png"
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
                            id: nicknameArea
                            focus: true
                            selectByMouse: true
                            placeholderText: qsTr("Nickname")
                            Layout.fillWidth: true
                        }

                        TextField {
                            id: passphraseArea
                            focus: true
                            selectByMouse: true
                            echoMode: TextInput.Password
                            placeholderText: qsTr("Passphrase")
                            Layout.fillWidth: true
                        }

                        Button {
                            id: authButton
                            enabled: passphraseArea.text.length > 0 && nicknameArea.text.length > 0
                            Layout.alignment: Qt.AlignBottom | Qt.AlignCenter
                            highlighted: true
                            text: qsTr("Add Contact")

                            onClicked: {
                                var passphrase = passphraseArea.text
                                var nickname = nicknameArea.text
                                var result = accountBridge.addContact(passphrase, nickname)
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
