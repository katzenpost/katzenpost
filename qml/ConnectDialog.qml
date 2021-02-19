import QtQuick 2.4
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.1
import QtQuick.Layouts 1.3

Popup {
    id: connectDialog
    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape

    contentHeight: connectDialog.height

    property var reset: function() {
        passphraseArea.text = ""
    }

    ColumnLayout {
        spacing: 16
        anchors.fill: parent
        anchors.margins: 16

        Label {
            text: qsTr("Enter decryption passphrase")
            Layout.alignment: Qt.AlignHCenter
            font.bold: true
        }

        TextField {
            id: passphraseArea
            focus: true
            selectByMouse: true
            echoMode: TextInput.Password
            placeholderText: qsTr("Enter passphrase")
            Layout.fillWidth: true
            Keys.onReturnPressed: {
                if (!authButton.enabled) {
                    return
               }
               authButton.clicked()
               event.accepted = true
            }
        }

        Button {
            id: authButton
            // XXX: best practices plz, ok maybe even have 2 entry fields with a comparison but yolo for now
            enabled: passphraseArea.text.length > 0 && accountBridge.status != "Connected"
            Layout.alignment: Qt.AlignBottom | Qt.AlignCenter
            highlighted: true
            text: qsTr("Meow")

            onClicked: {
                var passphrase = passphraseArea.text
                accountBridge.loadCatshadow(passphrase)
                connectDialog.reset()
                connectDialog.close()
            }
        }
    }
}
