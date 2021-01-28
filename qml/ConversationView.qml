import QtQuick 2.5
import QtQuick.Controls 2.2
import QtQuick.Controls.Material 2.1
import QtQuick.Layouts 1.3

Page {
    anchors.fill: parent
    property alias messageTextField: messageField

    header: ToolBar {
        Material.primary: Material.accent

        ToolButton {
            text: qsTr("Back")
            anchors.left: parent.left
            anchors.leftMargin: 10
            anchors.verticalCenter: parent.verticalCenter
            onClicked: swipe.currentIndex = 0
        }

        Label {
            id: pageTitle
            text: accountBridge.keyExchanged ?
                qsTr("Chat with") + " " + accountBridge.recipient :
                qsTr("Awaiting key exchange with") + " " + accountBridge.recipient
            font.pixelSize: 20
            anchors.centerIn: parent
        }
    }

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
                anchors.right: model.outbound ? parent.right : undefined
                spacing: 6

                Row {
                    id: messageRow
                    spacing: 6
                    anchors.right: model.outbound ? parent.right : undefined

                    Image {
                        id: avatar
                        sourceSize.height: 48
                        smooth: true
                        source: model.avatar
                    }

                    Rectangle {
                        width: Math.min(messageText.implicitWidth + 24, conversationView.width - avatar.width - messageRow.spacing)
                        height: messageText.implicitHeight + 24
                        color: model.outbound ? "lightgrey" : "steelblue"

                        ChatText {
                            id: messageText
                            text: model.message
                            color: model.outbound ? "black" : "white"
                            anchors.fill: parent
                            anchors.margins: 12
                            wrapMode: Label.Wrap
                        }
                    }
                }

                Row {
                    spacing: 6
                    anchors.right: model.outbound ? parent.right : undefined

                    Label {
                        id: timestampText
                        text: model.timestamp
                        color: "lightgrey"
                    }
                    Label {
                        id: statusText
                        text: model.status == 1 ? "✓" : "✓✓"
                        color: "lightgrey"
                        visible: model.status > 0
                    }
                }
            }

            ScrollBar.vertical: ScrollBar {}
        }

        Pane {
            id: pane
            Layout.fillWidth: true

            RowLayout {
                width: parent.width

                ChatEdit {
                    id: messageField
                    Layout.fillWidth: true
                    placeholderText: qsTr("Compose message")
                    wrapMode: TextArea.Wrap

                    Keys.onReturnPressed: {
                        if (!sendButton.enabled) {
                            return
                        }

                        sendButton.clicked()
                        event.accepted = true
                    }
                }

                Button {
                    id: sendButton
                    text: qsTr("Send")
                    enabled: messageField.length > 0 && accountBridge.keyExchanged
                    onClicked: {
                        accountBridge.sendMessage(accountBridge.recipient, messageField.text);
                        messageField.text = "";
                    }
                }
            }
        }
    }
}
