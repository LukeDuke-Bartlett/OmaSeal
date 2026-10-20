import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui

// Store-new-secret form. Owns the three fields; reports intent upward via
// saveRequested/dismissRequested so no field id leaks outside this file.
Column {
  id: addForm

  property color fg
  property color accent

  // keyCatcher blocks shortcuts while any field holds focus.
  readonly property bool editing: serviceField.activeFocus || accountField.activeFocus || secretField.activeFocus

  signal saveRequested(string service, string account, string secret)
  signal dismissRequested()

  function submit() {
    addForm.saveRequested(serviceField.text.trim(), accountField.text.trim(), secretField.text)
  }

  function clear() {
    serviceField.text = ""
    accountField.text = ""
    secretField.text = ""
  }

  function dismiss() {
    clear()
    dismissRequested()
  }

  spacing: Style.space(8)

  PanelSectionHeader {
    text: "STORE NEW SECRET"
    foreground: addForm.fg
  }

  TextField {
    id: serviceField
    width: parent.width
    placeholderText: "Service (e.g. openrouter, github)"
    foreground: addForm.fg
    Keys.onEscapePressed: addForm.dismiss()
  }

  TextField {
    id: accountField
    width: parent.width
    placeholderText: "Account (e.g. default, personal)"
    foreground: addForm.fg
    Keys.onEscapePressed: addForm.dismiss()
  }

  TextField {
    id: secretField
    width: parent.width
    password: true
    placeholderText: "Secret payload"
    foreground: addForm.fg
    Keys.onReturnPressed: addForm.submit()
    Keys.onEscapePressed: addForm.dismiss()
  }

  RowLayout {
    width: parent.width
    Item { Layout.fillWidth: true }
    Button {
      text: "Save Secret"
      bordered: true
      accent: addForm.accent
      onClicked: addForm.submit()
    }
  }

  PanelSeparator {
    foreground: addForm.fg
    width: parent.width
  }
}
