import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "io.github.duketopceo.omaseal"
  manageIpc: false

  signal statusChanged()

  property var anchorItem: null
  property var hostWidget: null
  property var settings: null
  // Shadows the base's popoutSwitchClosing — keep it so the assignment in
  // closeForPopoutSwitch works even on a shell whose Panel predates the flag.
  property bool popoutSwitchClosing: false

  property string notice: ""
  property bool showLogs: false
  property bool isAdding: false

  // Model state lives in PanelModel; aliases keep the root's property
  // surface identical, so reads and writes here behave exactly as before.
  property alias searchFilter: secrets.searchFilter
  property alias allSecrets: secrets.allSecrets
  property alias selectedIndex: secrets.selectedIndex
  property alias expanded: secrets.expanded
  property alias serviceFilter: secrets.serviceFilter
  property alias sortMode: secrets.sortMode
  property alias serviceGroups: secrets.serviceGroups
  property alias hiddenCount: secrets.hiddenCount
  property alias totalAccesses: secrets.totalAccesses
  property alias topSecretLabel: secrets.topSecretLabel

  readonly property color fg: root.bar ? root.bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(root.fg, 1.5)
  readonly property color urgent: Color.urgent !== undefined ? Color.urgent : Color.accent
  readonly property color accent: Color.accent
  readonly property string fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
  readonly property var barIdentity: root.hostWidget || root

  PanelModel {
    id: secrets
    onNoticeSet: function(text) { root.notice = text }
  }

  PanelJobs {
    id: jobs
    model: secrets
    agentView: agentSection
    onNoticeSet: function(text) { root.notice = text }
    onDataChanged: root.statusChanged()
    onSaved: {
      addForm.clear()
      root.isAdding = false
    }
  }

  function open() {
    root.controller.show()
    jobs.refresh()
    jobs.refreshAgentStatus()
  }

  function close() {
    root.controller.hide()
    agentSection.clearPass()
    jobs.unlockPassphrase = ""
  }

  function toggle() {
    root.opened ? close() : open()
  }

  function closeForPopoutSwitch() {
    root.popoutSwitchClosing = true
    root.close()
    Qt.callLater(function() { root.popoutSwitchClosing = false })
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function") {
      return root.bar.switchPanelFrom(root.barIdentity, direction)
    }
    return false
  }

  Timer {
    id: logTimer
    interval: 3000
    repeat: true
    running: root.showLogs && root.opened
    onTriggered: jobs.refreshLog()
  }

  Component {
    id: logsComponent

    ColumnLayout {
      anchors.fill: parent
      anchors.margins: Style.space(14)
      spacing: Style.space(10)

      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(8)

        Text {
          Layout.fillWidth: true
          elide: Text.ElideRight
          text: "󰌋 OmaSeal"
          color: root.fg
          font.family: root.fontFamily
          font.pixelSize: Style.font.heading
          font.bold: true
        }

        Button {
          text: "Back"
          bordered: true
          onClicked: root.showLogs = false
        }
      }

      PanelSectionHeader {
        text: "LOGS"
        foreground: root.fg
      }

      ListView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        implicitHeight: Style.space(240)
        clip: true
        model: secrets.logModel

        delegate: Column {
          width: ListView.view.width
          spacing: Style.space(2)

          Row {
            spacing: Style.space(8)

            Text {
              text: model.time
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Text {
              text: model.source
              color: root.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          Text {
            width: parent.width
            text: model.message
            color: root.fg
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          Rectangle {
            width: parent.width
            height: Style.space(1)
            color: root.dim
            opacity: 0.2
          }
        }
      }

      RowLayout {
        Layout.fillWidth: true
        Item { Layout.fillWidth: true }
        Button {
          text: "Refresh"
          bordered: true
          onClicked: jobs.refreshLog()
        }
      }
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: root.expanded ? panel.fittedContentWidth(Style.space(920), 1180) : panel.fittedContentWidth(Style.space(380), 460)
    // +28: contentColumn is a ColumnLayout inset by anchors.margins, and
    // margins are not part of implicitHeight — add the 2×14 margin back so
    // the card keeps its visual padding when sizing to content.
    contentHeight: panel.fittedContentHeight(root.showLogs ? (logLoader.item ? logLoader.item.implicitHeight + Style.space(28) : Style.space(28)) : contentColumn.implicitHeight + Style.space(28), root.expanded ? 840 : 640)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: addForm.editing || agentSection.editing || searchField.activeFocus || vaultDropdown.popupOpen
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onMoveRequested: function(dx, dy) {
        if (secrets.secretsModel.count === 0) return
        var next = root.selectedIndex + dy
        if (next >= 0 && next < secrets.secretsModel.count) {
          root.selectedIndex = next
        }
      }
      onActivateRequested: {
        if (secrets.secretsModel.count > 0 && root.selectedIndex < secrets.secretsModel.count) {
          var item = secrets.secretsModel.get(root.selectedIndex)
          jobs.copySecret(item.service, item.account)
        }
      }
      onDeleteRequested: {
        if (secrets.secretsModel.count > 0 && root.selectedIndex < secrets.secretsModel.count) {
          var item = secrets.secretsModel.get(root.selectedIndex)
          jobs.deleteSecret(item.service, item.account)
        }
      }
      onTextKey: function(t) {
        if (t === "r" || t === "R") jobs.refresh()
        else if (t === "a" || t === "A") root.isAdding = !root.isAdding
        else if (t === "e" || t === "E") root.expanded = !root.expanded
        else if (t === "s" || t === "S") secrets.cycleSort()
        else if (t === "v" || t === "V") vaultDropdown.toggle()
        else if (t === "/" && searchField.visible) searchField.forceActiveFocus()
      }

      // ColumnLayout, not Column: anchors.fill pins the column to the card's
      // inner box and Layout.fillHeight on the list lets it absorb whatever
      // space remains. A positioner Column has no height bound — any child
      // taller than the card draws straight over the border.
      ColumnLayout {
        id: contentColumn
        anchors.fill: parent
        anchors.margins: Style.space(14)
        visible: !root.showLogs
        spacing: Style.space(10)

        // Header
        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(8)

          Text {
            // fillWidth + elide: the fixed-size buttons on the right can
            // never be pushed past the card edge by a narrow panel.
            Layout.fillWidth: true
            text: "󰌋 OmaSeal"
            color: root.fg
            font.family: root.fontFamily
            font.pixelSize: Style.font.heading
            font.bold: true
            elide: Text.ElideRight
          }

          Text {
            text: root.allSecrets.length
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            visible: root.allSecrets.length > 0
          }

          Button {
            text: root.isAdding ? "Cancel" : "+ Add"
            bordered: true
            onClicked: root.isAdding = !root.isAdding
          }

          Button {
            text: "Logs"
            bordered: true
            onClicked: root.showLogs = !root.showLogs
          }

          PanelActionButton {
            iconText: root.expanded ? "󰅃" : "󰅀"
            tooltipText: root.expanded ? "Collapse panel (e)" : "Expand panel — vaults + full list (e)"
            foreground: root.fg
            onClicked: root.expanded = !root.expanded
          }

          PanelActionButton {
            iconText: "󰑐"
            tooltipText: "Refresh secrets (r)"
            foreground: root.fg
            onClicked: jobs.refresh()
          }
        }

        PanelSeparator {
          foreground: root.fg
          Layout.fillWidth: true
        }

        // Expanded stats strip: totals at a glance.
        Text {
          visible: root.expanded
          Layout.fillWidth: true
          text: root.allSecrets.length + " SECRETS · " + root.totalAccesses + " ACCESSES · TOP: " + root.topSecretLabel
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }

        RowLayout {
          Layout.fillWidth: true
          Layout.fillHeight: true
          spacing: Style.space(12)

          // Vault sidebar — expanded mode only. One row per service.
          ColumnLayout {
            visible: root.expanded
            Layout.preferredWidth: Style.space(190)
            Layout.fillHeight: true
            Layout.alignment: Qt.AlignTop
            spacing: Style.space(4)

            PanelSectionHeader {
              text: "VAULTS"
              foreground: root.fg
            }

            Flickable {
              Layout.fillWidth: true
              Layout.fillHeight: true
              implicitHeight: Math.min(vaultCol.implicitHeight, Style.space(560))
              contentHeight: vaultCol.implicitHeight
              clip: true

              Column {
                id: vaultCol
                width: parent.width
                spacing: Style.space(2)

                Repeater {
                  model: root.serviceGroups
                  delegate: BorderSurface {
                    required property var modelData
                    width: vaultCol.width
                    implicitHeight: Style.space(30)
                    radius: Style.cornerRadius
                    color: root.serviceFilter === modelData.value ? Style.selectedFillFor(root.fg, root.accent) : Style.controlFill(false, vaultMouse.containsMouse, root.fg, root.accent)
                    borderSpec: Border.controlSpec(root.serviceFilter === modelData.value ? "selected" : (vaultMouse.containsMouse ? "hover-cursor" : "normal"), root.fg, root.accent)

                    MouseArea {
                      id: vaultMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      onClicked: root.serviceFilter = modelData.value
                    }

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(8)
                      anchors.rightMargin: Style.space(8)

                      Text {
                        Layout.fillWidth: true
                        text: modelData.label
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        elide: Text.ElideRight
                      }
                      Text {
                        text: modelData.count
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                      }
                    }
                  }
                }
              }
            }
          }

          // Main column
          ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: Style.space(10)

            AddEditForm {
              id: addForm
              Layout.fillWidth: true
              visible: root.isAdding
              fg: root.fg
              accent: root.accent
              onSaveRequested: function(service, account, secret) {
                jobs.saveSecret(service, account, secret)
              }
              onDismissRequested: root.isAdding = false
            }

            AgentSection {
              id: agentSection
              Layout.fillWidth: true
              status: jobs
              fg: root.fg
              dim: root.dim
              accent: root.accent
              urgent: root.urgent
              fontFamily: root.fontFamily
              onUnlockRequested: function(passphrase) { jobs.unlockAgent(passphrase) }
            }

            // Toolbar: vault picker + sort + search.
            RowLayout {
              Layout.fillWidth: true
              spacing: Style.space(6)
              visible: root.allSecrets.length > 0

              SearchableDropdown {
                id: vaultDropdown
                Layout.fillWidth: true
                showLabel: false
                placeholderText: "Vault…"
                triggerLabel: "All vaults"
                options: root.serviceGroups
                value: root.serviceFilter
                foreground: root.fg
                accent: root.accent
                fontFamily: root.fontFamily
                onChanged: function(v) { root.serviceFilter = v }
              }

              Button {
                text: secrets.sortLabel()
                bordered: true
                tooltipText: "Sort order (s)"
                onClicked: secrets.cycleSort()
              }
            }

            // Search field — Keychain Access style filtering.
            TextField {
              id: searchField
              Layout.fillWidth: true
              placeholderText: "Search secrets  (press /)"
              foreground: root.fg
              visible: root.allSecrets.length > 0
              onTextChanged: root.searchFilter = text
              Keys.onEscapePressed: searchField.focus = false
            }

            SecretsView {
              id: secretsView
              Layout.fillWidth: true
              Layout.fillHeight: true
              store: secrets
              isAdding: root.isAdding
              fg: root.fg
              dim: root.dim
              accent: root.accent
              urgent: root.urgent
              fontFamily: root.fontFamily
              onCopyRequested: function(service, account) { jobs.copySecret(service, account) }
              onDeleteRequested: function(service, account) { jobs.deleteSecret(service, account) }
              onRowEntered: function(service, account) { jobs.cancelArmedDelete(service, account) }
            }
          }
        }

        // Status Notice Banner
        Text {
          id: noticeText
          visible: root.notice !== ""
          Layout.fillWidth: true
          text: root.notice
          color: root.notice.toLowerCase().indexOf("fail") !== -1 ? root.urgent : root.accent
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

      }

      Loader {
        id: logLoader
        active: root.showLogs
        visible: root.showLogs
        anchors.fill: parent
        sourceComponent: logsComponent
        onLoaded: jobs.refreshLog()
      }
    }
  }
}
