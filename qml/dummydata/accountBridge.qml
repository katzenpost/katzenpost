import QtQuick 2.4

QtObject {
    property string nickname: "username"
    property string avatar: "https://pbs.twimg.com/profile_images/908139250612363264/m-CkMJbl_400x400.jpg"
    property string error: ""

    property ListModel contactListModel: contacts
    property ListModel conversationModel: conversation
}
