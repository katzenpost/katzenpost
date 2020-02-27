import QtQuick 2.5
import QtQuick.Controls 2.2

TextEdit
{
    id: textInput
    selectByMouse: true
    readOnly: true
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
                text: "Copy"
                onTriggered: textInput.copy();
            }
        }
    }
}
