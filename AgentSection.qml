import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui

// Agent trust strip: the Keychain-style status row, the inline passphrase
// field, and the fprintd notice. Owns the passphrase field — jobs drives the
// unlock proc and reaches the field only through clearPass/focusPass.
Column {
  id: agentSection

  property var status: null
  property color fg
  property color dim
  property color accent
  property color urgent
  property string fontFamily

  // keyCatcher blocks shortcuts while the passphrase field holds focus.
  readonly property bool editing: passphraseField.activeFocus

  signal unlockRequested(string passphrase)

  function clearPass() { passphraseField.text = "" }
  function focusPass() { passphraseField.forceActiveFocus() }

  spacing: Style.space(10)

  // Agent trust status — the Keychain-style lock indicator.
  RowLayout {
    width: parent.width
    spacing: Style.space(8)
    visible: agentSection.status !== null && agentSection.status.agentMode !== ""

    Text {
      Layout.fillWidth: true
      elide: Text.ElideRight
      text: "󰌆 AGENTS " + agentSection.status.agentMode.toUpperCase() +
            (agentSection.status.agentKeepAlive ? " · KA" : "") +
            (agentSection.status.agentMode === "ask" && agentSection.status.agentSessionActive
              ? " · UNLOCKED" + (agentSection.status.agentSessionExpires
                  ? " " + Qt.formatTime(new Date(agentSection.status.agentSessionExpires), "HH:mm")
                  : "")
              : "")
      color: (agentSection.status.agentMode === "open" || agentSection.status.agentSessionActive) ? agentSection.accent : agentSection.dim
      font.family: agentSection.fontFamily
      font.pixelSize: Style.font.caption
    }

    Button {
      visible: agentSection.status !== null && agentSection.status.agentMode === "ask" && !agentSection.status.agentSessionActive
      text: "Unlock"
      bordered: true
      onClicked: agentSection.unlockRequested(passphraseField.text)
    }
  }

  TextField {
    id: passphraseField
    width: parent.width
    visible: agentSection.status !== null && agentSection.status.agentMode === "ask" &&
             !agentSection.status.agentSessionActive && agentSection.status.agentBackend === "native"
    enabled: agentSection.status === null || !agentSection.status.unlockRunning
    password: true
    placeholderText: "OmaSeal passphrase"
    foreground: agentSection.fg
    Keys.onReturnPressed: agentSection.unlockRequested(passphraseField.text)
  }

  // fprintd availability notice — only relevant when ask mode gates on it.
  Text {
    visible: agentSection.status !== null && agentSection.status.agentMode === "ask" && !agentSection.status.fprintdAvailable
    width: parent.width
    text: "no fingerprint reader — unlock is ungated"
    color: agentSection.urgent
    font.family: agentSection.fontFamily
    font.pixelSize: Style.font.caption
  }
}
