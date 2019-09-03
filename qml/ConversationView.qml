import QtQuick 2.5
import QtQuick.Controls 2.2
import QtQuick.Layouts 1.3

ColumnLayout {
    anchors.fill: parent

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

            readonly property bool sentByMe: model.nickname == accountBridge.nickname

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
                text: model.timestamp
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
