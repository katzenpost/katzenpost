import QtQuick 2.5
import QtQuick.Controls 2.1

TextArea
{
    id: textInput
    selectByMouse: true
    persistentSelection: true

    MouseArea {
        anchors.fill: parent
        acceptedButtons: Qt.RightButton
        hoverEnabled: true
        onClicked: {
            contextMenu.x = mouse.x;
            contextMenu.y = mouse.y;
            contextMenu.open();
        }

        Menu {
            id: contextMenu
            MenuItem {
                text: "Cut"
                onTriggered: {
                    textInput.cut()
                }
            }
            MenuItem {
                text: "Copy"
                onTriggered: {
                    textInput.copy()
                }
            }
            MenuItem {
                text: "Paste"
                onTriggered: {
                    textInput.paste()
                }
            }
        }
    }
}
