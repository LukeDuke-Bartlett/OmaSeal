import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
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
  property bool popoutSwitchClosing: false

  property string searchFilter: ""
  onSearchFilterChanged: root.rebuildModel()
  property var allSecrets: []
  property string notice: ""
  property bool showLogs: false
  property int selectedIndex: 0
  property string pendingDeleteKey: ""
  property bool refreshPending: false
  property var pendingCopy: null
  property var pendingDel: null
  property bool agentStatusPending: false
  property bool saving: false
  property string getText: ""
  property bool isAdding: false
  property string agentMode: ""
  property bool agentSessionActive: false
  property string agentSessionExpires: ""
  property bool agentKeepAlive: false
  property bool fprintdAvailable: true
  property string agentBackend: ""
  // Staged only for the duration of the unlockProc stdin write; cleared
  // immediately after — never logged or shown.
  property string unlockPassphrase: ""

  // Organization state
  property bool expanded: false
  onExpandedChanged: root.rebuildModel()
  property string serviceFilter: ""      // "" = all vaults
  onServiceFilterChanged: root.rebuildModel()
  property string sortMode: "used"       // "used" | "recent" | "name"
  onSortModeChanged: root.rebuildModel()
  property int collapsedLimit: 14
  property var serviceGroups: []         // SearchableDropdown options
  property int hiddenCount: 0
  property int totalAccesses: 0
  property string topSecretLabel: ""

  Component {
    id: setProcComponent
    Process {
      stdinEnabled: true
      stderr: StdioCollector {
        waitForEnd: true
      }
    }
  }

  Component {
    id: copyProcComponent
    Process {
      stdinEnabled: true
      command: ["wl-copy", "--sensitive"]
    }
  }

  // This wl-clipboard build has no --clear-after flag, so the panel clears
  // the selection itself 30s after a successful copy. `omaseal clipclear`
  // clears only when the clipboard still holds that secret, so a stale
  // timer cannot wipe whatever the user copied in the meantime.
  property var lastCopied: null
  Timer {
    id: clipboardClearTimer
    interval: 30000
    onTriggered: {
      if (root.lastCopied === null) return
      clipboardClearProc.command = ["omaseal", "clipclear", root.lastCopied.service, root.lastCopied.account]
      clipboardClearProc.running = true
    }
  }
  Process {
    id: clipboardClearProc
  }

  readonly property color fg: root.bar ? root.bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(root.fg, 1.5)
  readonly property color urgent: Color.urgent !== undefined ? Color.urgent : "#f38ba8"
  readonly property color accent: Color.accent
  readonly property string fontFamily: root.bar ? root.bar.fontFamily : Style.font.family

  function open() {
    root.controller.show()
    root.refresh()
    root.refreshAgentStatus()
  }

  function close() {
    root.controller.hide()
    passphraseField.text = ""
    root.unlockPassphrase = ""
  }

  function toggle() {
    root.opened ? close() : open()
  }

  function closeForPopoutSwitch() {
    root.close()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function") {
      return root.bar.switchPanelFrom(root.hostWidget || root, direction)
    }
    return false
  }

  function secretKey(service, account) {
    return service + "\u0001" + account
  }

  function ago(iso) {
    if (!iso) return ""
    var d = new Date(iso)
    if (isNaN(d.getTime())) return ""
    var s = (Date.now() - d.getTime()) / 1000
    if (s < 0) s = 0
    if (s < 90) return "now"
    if (s < 3600) return Math.floor(s / 60) + "m"
    if (s < 86400) return Math.floor(s / 3600) + "h"
    if (s < 86400 * 30) return Math.floor(s / 86400) + "d"
    if (s < 86400 * 365) return Math.floor(s / (86400 * 30)) + "mo"
    return Math.floor(s / (86400 * 365)) + "y"
  }

  function sortLabel() {
    if (root.sortMode === "used") return "⇅ Used"
    if (root.sortMode === "recent") return "⇅ Recent"
    return "⇅ Name"
  }

  function cycleSort() {
    root.sortMode = root.sortMode === "used" ? "recent" : (root.sortMode === "recent" ? "name" : "used")
  }

  function refresh() {
    root.notice = ""
    root.pendingDeleteKey = ""
    listProc.command = ["omaseal", "list", "--json"]
    if (listProc.running) {
      root.refreshPending = true
    } else {
      listProc.running = true
    }
  }

  function refreshLog() {
    logProc.command = ["omaseal", "logs", "25", "--json"]
    if (!logProc.running) logProc.running = true
  }

  function applyList(raw) {
    try {
      var d = JSON.parse(raw)
      root.allSecrets = d
      root.rebuildModel()
    } catch (e) {
      root.notice = "Failed to parse secret list"
    }
  }

  // rebuildModel owns filtering, grouping, sorting, and the collapsed limit.
  // Ordering: service filter -> text filter -> sort -> limit. Selection is
  // preserved by identity across rebuilds.
  function rebuildModel() {
    var f = root.searchFilter.trim().toLowerCase()
    var selKey = ""
    if (root.selectedIndex >= 0 && root.selectedIndex < secretsModel.count) {
      var cur = secretsModel.get(root.selectedIndex)
      selKey = root.secretKey(cur.service, cur.account)
    }

    // Vault groups: one entry per distinct service, sorted by size.
    var counts = {}
    var names = []
    for (var g = 0; g < root.allSecrets.length; g++) {
      var gs = root.allSecrets[g].service || ""
      if (!(gs in counts)) { counts[gs] = 0; names.push(gs) }
      counts[gs]++
    }
    names.sort(function(a, b) {
      var d = counts[b] - counts[a]
      return d !== 0 ? d : (a.toLowerCase() < b.toLowerCase() ? -1 : 1)
    })
    var groups = [{ value: "", label: "All vaults", description: root.allSecrets.length + " secrets" }]
    for (var n = 0; n < names.length; n++) {
      groups.push({ value: names[n], label: names[n], description: counts[names[n]] + (counts[names[n]] === 1 ? " secret" : " secrets") })
    }
    root.serviceGroups = groups
    if (root.serviceFilter !== "" && !(root.serviceFilter in counts)) {
      root.serviceFilter = ""  // vault vanished — fall back to all
    }

    // Header stats strip (expanded view).
    var accesses = 0, topHits = 0, topName = ""
    for (var t = 0; t < root.allSecrets.length; t++) {
      var h = root.allSecrets[t].access_count || 0
      accesses += h
      if (h > topHits) {
        topHits = h
        topName = (root.allSecrets[t].service || "") + "/" + (root.allSecrets[t].account || "")
      }
    }
    root.totalAccesses = accesses
    root.topSecretLabel = topName !== "" ? topName + " ×" + topHits : "—"

    // Filter.
    var rows = []
    for (var i = 0; i < root.allSecrets.length; i++) {
      var it = root.allSecrets[i]
      if (root.serviceFilter !== "" && (it.service || "") !== root.serviceFilter) continue
      if (f !== "") {
        var hay = ((it.service || "") + "/" + (it.account || "") + " " + (it.label || "")).toLowerCase()
        if (hay.indexOf(f) === -1) continue
      }
      rows.push(it)
    }

    // Sort — decorate once so the comparator never reparses dates or
    // rebuilds key strings per comparison (O(n log n) calls otherwise).
    for (var d = 0; d < rows.length; d++) {
      rows[d]._key = ((rows[d].service || "") + "/" + (rows[d].account || "")).toLowerCase()
      var t = rows[d].last_accessed ? +new Date(rows[d].last_accessed) : 0
      rows[d]._ts = isNaN(t) ? 0 : t
    }
    rows.sort(function(a, b) {
      if (root.sortMode === "name") {
        return a._key < b._key ? -1 : (a._key > b._key ? 1 : 0)
      }
      if (root.sortMode === "recent") {
        if (a._ts !== b._ts) return b._ts - a._ts
      } else {
        var ha = a.access_count || 0, hb = b.access_count || 0
        if (ha !== hb) return hb - ha
        if (a._ts !== b._ts) return b._ts - a._ts
      }
      return a._key < b._key ? -1 : (a._key > b._key ? 1 : 0)
    })

    // Collapsed limit — bypassed while searching or filtering a vault.
    root.hiddenCount = 0
    var shown = rows
    if (!root.expanded && f === "" && root.serviceFilter === "" && rows.length > root.collapsedLimit) {
      shown = rows.slice(0, root.collapsedLimit)
      root.hiddenCount = rows.length - shown.length
    }

    var newIdx = -1
    secretsModel.clear()
    for (var r = 0; r < shown.length; r++) {
      var row = {
        service: shown[r].service || "",
        account: shown[r].account || "",
        label: shown[r].label || "",
        hits: shown[r].access_count || 0,
        lastTs: shown[r].last_accessed || "",
        owned: shown[r].owned !== false
      }
      secretsModel.append(row)
      if (selKey !== "" && root.secretKey(row.service, row.account) === selKey) {
        newIdx = secretsModel.count - 1
      }
    }
    if (newIdx >= 0) {
      root.selectedIndex = newIdx
    } else if (root.selectedIndex >= secretsModel.count) {
      root.selectedIndex = Math.max(0, secretsModel.count - 1)
    }
  }

  function refreshAgentStatus() {
    if (agentProc.running) {
      root.agentStatusPending = true
    } else {
      agentProc.running = true
    }
  }

  function applyAgentStatus(raw) {
    try {
      var d = JSON.parse(raw)
      root.agentMode = d.mode || ""
      root.agentSessionActive = d.session_active === true
      root.agentSessionExpires = d.session_expires || ""
      root.agentKeepAlive = d.keep_alive === true
      root.fprintdAvailable = d.fprintd_available !== false
      root.agentBackend = d.backend || ""
    } catch (e) {
      root.agentMode = ""
      root.agentSessionActive = false
      root.agentSessionExpires = ""
      root.agentKeepAlive = false
      root.fprintdAvailable = true
      root.agentBackend = ""
    }
  }

  function unlockAgent() {
    if (unlockProc.running) return
    var native = root.agentBackend === "native"
    if (native) {
      var pass = passphraseField.text
      if (!pass) {
        root.notice = "Enter the OmaSeal passphrase to unlock"
        passphraseField.forceActiveFocus()
        return
      }
      root.unlockPassphrase = pass
    } else {
      root.unlockPassphrase = ""
    }
    unlockProc.command = ["omaseal", "agent", "unlock"].concat(native ? ["--passphrase-stdin"] : [])
    unlockProc.stdinEnabled = true // a finished run latches it false
    unlockProc.running = true
  }

  function applyLogs(raw) {
    try {
      var d = JSON.parse(raw)
      logModel.clear()
      for (var i = 0; i < d.length; i++) {
        logModel.append({
          time: d[i].time || "",
          source: d[i].source || "",
          message: d[i].message || ""
        })
      }
    } catch (e) {
      logModel.clear()
    }
  }

  function saveSecret() {
    if (root.saving) return
    var service = serviceField.text.trim()
    var account = accountField.text.trim()
    var secret = secretField.text
    if (!service || !account || !secret) {
      root.notice = "Fill in service, account, and secret"
      return
    }
    root.saving = true
    root.notice = "Saving..."
    var proc = setProcComponent.createObject(root)
    proc.command = ["omaseal", "set", service, account]
    proc.exited.connect(function(exitCode) {
      if (exitCode === 0) {
        root.notice = "Saved"
        root.clearAddForm()
        root.refresh()
        root.statusChanged()
      } else {
        var detail = ""
        var lines = (proc.stderr.text || "").split("\n")
        for (var i = 0; i < lines.length; i++) {
          var l = lines[i].trim()
          if (l.indexOf("error:") === 0) { detail = l; break }
        }
        root.notice = detail !== "" ? "Save failed: " + detail : "Save failed"
      }
      root.saving = false
      proc.destroy()
    })
    proc.started.connect(function() {
      proc.write(secret)
      proc.stdinEnabled = false
    })
    proc.running = true
  }

  // Delete confirmation is armed by identity, not index: a list rebuild can
  // reshuffle rows, and the confirm must still target the armed secret.
  function deleteSecret(index, service, account) {
    var key = root.secretKey(service, account)
    if (root.pendingDeleteKey !== "" && root.pendingDeleteKey !== key) {
      root.pendingDeleteKey = ""
      deleteConfirmTimer.stop()
      root.notice = "Delete confirmation cancelled"
      return
    }
    if (root.pendingDeleteKey !== key) {
      root.pendingDeleteKey = key
      deleteConfirmTimer.restart()
      root.notice = "Press delete again to confirm deletion"
      return
    }
    deleteConfirmTimer.stop()
    root.pendingDeleteKey = ""
    if (delProc.running) {
      if (root.pendingDel !== null) {
        root.notice = "Delete already queued — wait for it to finish"
        return
      }
      root.pendingDel = {service: service, account: account}
      root.notice = "Delete queued"
      return
    }
    root.notice = "Deleting..."
    delProc.command = ["omaseal", "del", service, account]
    delProc.running = true
  }

  function copySecret(service, account) {
    if (getProc.running) {
      // Coalesce: run the newest request after the in-flight get exits.
      root.pendingCopy = {service: service, account: account}
      return
    }
    getProc.command = ["omaseal", "get", service, account]
    getProc.running = true
  }

  function runPendingCopy() {
    if (root.pendingCopy === null) return
    var c = root.pendingCopy
    root.pendingCopy = null
    getProc.command = ["omaseal", "get", c.service, c.account]
    getProc.running = true
  }

  function runPendingDel() {
    if (root.pendingDel === null) return
    var d = root.pendingDel
    root.pendingDel = null
    root.notice = "Deleting..."
    delProc.command = ["omaseal", "del", d.service, d.account]
    delProc.running = true
  }

  function clearAddForm() {
    serviceField.text = ""
    accountField.text = ""
    secretField.text = ""
    root.isAdding = false
  }

  Timer {
    id: deleteConfirmTimer
    interval: 5000
    onTriggered: {
      if (root.pendingDeleteKey !== "") {
        root.pendingDeleteKey = ""
        root.notice = "Delete confirmation expired"
      }
    }
  }

  Process {
    id: listProc
    command: ["omaseal", "list", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyList(text)
    }
    onExited: function(exitCode) {
      if (exitCode !== 0) {
        root.notice = "Failed to list secrets"
      }
      if (root.refreshPending) {
        root.refreshPending = false
        root.refresh()
      }
    }
  }

  Process {
    id: getProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.getText = text
    }
    onExited: function(exitCode) {
      // Capture-and-clear: the clipboard payload must not race a queued get.
      var secret = root.getText
      root.getText = ""
      // Only a successful get reaches the clipboard — a failed or empty
      // read must never clobber what the user already has.
      if (exitCode === 0 && secret !== "") {
        var proc = copyProcComponent.createObject(root)
        proc.exited.connect(function(ec) {
          if (ec === 0) {
            root.notice = "Copied to clipboard (clears in 30s)"
            root.lastCopied = {service: service, account: account}
            clipboardClearTimer.restart()
          } else {
            root.notice = "Copy failed"
          }
          proc.destroy()
        })
        proc.started.connect(function() {
          proc.write(secret)
          proc.stdinEnabled = false
        })
        proc.running = true
      } else {
        root.notice = "Copy failed"
      }
      root.runPendingCopy()
    }
  }

  Process {
    id: delProc
    onExited: function(exitCode) {
      if (exitCode === 0) {
        root.refresh() // clears notice
        root.notice = "Deleted"
        root.statusChanged()
      } else {
        root.notice = "Delete failed"
      }
      root.runPendingDel()
    }
  }

  Process {
    id: logProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyLogs(text)
    }
  }

  Process {
    id: agentProc
    command: ["omaseal", "agent", "status", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyAgentStatus(text)
    }
    onExited: function(exitCode) {
      if (root.agentStatusPending) {
        root.agentStatusPending = false
        root.refreshAgentStatus()
      }
    }
  }

  Process {
    id: unlockProc
    stdinEnabled: true
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      if (root.unlockPassphrase !== "") {
        unlockProc.write(root.unlockPassphrase + "\n")
      }
      root.unlockPassphrase = ""
      unlockProc.stdinEnabled = false
    }
    // A failed spawn skips onStarted/onExited — don't strand the staged pass.
    onRunningChanged: {
      if (!unlockProc.running) root.unlockPassphrase = ""
    }
    onExited: function(exitCode) {
      passphraseField.text = ""
      if (exitCode === 0) {
        root.refreshAgentStatus()
        root.refresh() // the store may have just unlocked — repopulate
      } else {
        var lines = (unlockProc.stderr.text || "").split("\n")
        var detail = ""
        for (var i = 0; i < lines.length; i++) {
          var l = lines[i].trim()
          if (l.indexOf("error:") === 0) { detail = l; break }
        }
        root.notice = detail !== "" ? "Unlock failed: " + detail : "Unlock failed"
        root.refreshAgentStatus()
      }
    }
  }

  Timer {
    id: logTimer
    interval: 3000
    repeat: true
    running: root.showLogs && root.opened
    onTriggered: root.refreshLog()
  }

  onShowLogsChanged: {
    if (root.showLogs) root.refreshLog()
  }

  ListModel {
    id: secretsModel
  }

  ListModel {
    id: logModel
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
        model: logModel

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
          onClicked: root.refreshLog()
        }
      }
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
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
      blocked: serviceField.activeFocus || accountField.activeFocus || secretField.activeFocus || searchField.activeFocus || passphraseField.activeFocus || vaultDropdown.popupOpen
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onMoveRequested: function(dx, dy) {
        if (secretsModel.count === 0) return
        var next = root.selectedIndex + dy
        if (next >= 0 && next < secretsModel.count) {
          root.selectedIndex = next
        }
      }
      onActivateRequested: {
        if (secretsModel.count > 0 && root.selectedIndex < secretsModel.count) {
          var item = secretsModel.get(root.selectedIndex)
          root.copySecret(item.service, item.account)
        }
      }
      onDeleteRequested: {
        if (secretsModel.count > 0 && root.selectedIndex < secretsModel.count) {
          var item = secretsModel.get(root.selectedIndex)
          root.deleteSecret(root.selectedIndex, item.service, item.account)
        }
      }
      onTextKey: function(t) {
        if (t === "r" || t === "R") root.refresh()
        else if (t === "a" || t === "A") root.isAdding = !root.isAdding
        else if (t === "e" || t === "E") root.expanded = !root.expanded
        else if (t === "s" || t === "S") root.cycleSort()
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
            text: root.allSecrets.length + ""
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
            onClicked: root.refresh()
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
                        text: modelData.description.replace(" secrets", "").replace(" secret", "")
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

            // Add Secret Form Collapsible
            Column {
              Layout.fillWidth: true
              spacing: Style.space(8)
              visible: root.isAdding

              PanelSectionHeader {
                text: "STORE NEW SECRET"
                foreground: root.fg
              }

              TextField {
                id: serviceField
                width: parent.width
                placeholderText: "Service (e.g. openrouter, github)"
                foreground: root.fg
                Keys.onEscapePressed: root.clearAddForm()
              }

              TextField {
                id: accountField
                width: parent.width
                placeholderText: "Account (e.g. default, personal)"
                foreground: root.fg
                Keys.onEscapePressed: root.clearAddForm()
              }

              TextField {
                id: secretField
                width: parent.width
                password: true
                placeholderText: "Secret payload"
                foreground: root.fg
                Keys.onReturnPressed: root.saveSecret()
                Keys.onEscapePressed: root.clearAddForm()
              }

              RowLayout {
                width: parent.width
                Item { Layout.fillWidth: true }
                Button {
                  text: "Save Secret"
                  bordered: true
                  accent: root.accent
                  onClicked: root.saveSecret()
                }
              }

              PanelSeparator {
                foreground: root.fg
                width: parent.width
              }
            }

            // Agent trust status — the Keychain-style lock indicator.
            RowLayout {
              Layout.fillWidth: true
              spacing: Style.space(8)
              visible: root.agentMode !== ""

              Text {
                Layout.fillWidth: true
                elide: Text.ElideRight
                text: "󰌆 AGENTS " + root.agentMode.toUpperCase() +
                      (root.agentKeepAlive ? " · KA" : "") +
                      (root.agentMode === "ask" && root.agentSessionActive
                        ? " · UNLOCKED" + (root.agentSessionExpires
                            ? " " + Qt.formatTime(new Date(root.agentSessionExpires), "HH:mm")
                            : "")
                        : "")
                color: (root.agentMode === "open" || root.agentSessionActive) ? root.accent : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              Button {
                visible: root.agentMode === "ask" && !root.agentSessionActive
                text: "Unlock"
                bordered: true
                onClicked: root.unlockAgent()
              }
            }

            TextField {
              id: passphraseField
              Layout.fillWidth: true
              visible: root.agentMode === "ask" && !root.agentSessionActive &&
                       root.agentBackend === "native"
              enabled: !unlockProc.running
              password: true
              placeholderText: "OmaSeal passphrase"
              foreground: root.fg
              Keys.onReturnPressed: root.unlockAgent()
            }

            // fprintd availability notice — only relevant when ask mode gates on it.
            Text {
              visible: root.agentMode === "ask" && !root.fprintdAvailable
              Layout.fillWidth: true
              text: "no fingerprint reader — unlock is ungated"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
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
                text: root.sortLabel()
                bordered: true
                tooltipText: "Sort order (s)"
                onClicked: root.cycleSort()
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

            // Section label + keybind hints on one row. The hints Text owns
            // the spare width and elides — a single long header string would
            // paint straight past the card's right border (PanelSectionHeader
            // is a bare Text: no width bound, no elide).
            RowLayout {
              Layout.fillWidth: true
              spacing: Style.space(8)

              PanelSectionHeader {
                text: "SECRETS (" + secretsModel.count + (root.hiddenCount > 0 ? "+" + root.hiddenCount : "") + ")"
                foreground: root.fg
              }

              Text {
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignRight
                text: "j/k nav · / search · v vault · s sort · ⏎ copy · x del · e " + (root.expanded ? "collapse" : "expand")
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideLeft
              }
            }

            // Scrollable secrets list — fillHeight absorbs whatever is left
            // of the card, so the list can never draw past the bottom border.
            Flickable {
              id: listFlickable
              Layout.fillWidth: true
              Layout.fillHeight: true
              Layout.minimumHeight: Style.space(60)
              implicitHeight: Math.min(secretsCol.implicitHeight,
                root.expanded ? Style.space(640)
                  : (root.isAdding ? Style.space(220) : Style.space(420)))
              contentHeight: secretsCol.implicitHeight
              clip: true

              Column {
                id: secretsCol
                width: parent.width
                spacing: Style.space(6)

                // Empty State
                Text {
                  visible: secretsModel.count === 0
                  width: parent.width
                  text: root.allSecrets.length > 0 ? "No matches." : "No secrets yet — press a or + Add to store one, or run: omaseal import 1password"
                  wrapMode: Text.WordWrap
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  horizontalAlignment: Text.AlignHCenter
                  topPadding: Style.space(12)
                  bottomPadding: Style.space(12)
                }

                // Secrets Repeater
                Repeater {
                  model: secretsModel
                  delegate: BorderSurface {
                    required property int index
                    required property string service
                    required property string account
                    required property string label
                    required property int hits
                    required property string lastTs
                    required property bool owned
                    width: secretsCol.width
                    implicitHeight: Style.space(42)
                    radius: Style.cornerRadius
                    color: index === root.selectedIndex ? Style.selectedFillFor(root.fg, root.accent) : Style.controlFill(false, rowMouse.containsMouse, root.fg, root.accent)
                    borderSpec: Border.controlSpec(index === root.selectedIndex ? "selected" : (rowMouse.containsMouse ? "hover-cursor" : "normal"), root.fg, root.accent)

                    MouseArea {
                      id: rowMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      onEntered: {
                        if (root.pendingDeleteKey !== "" && root.pendingDeleteKey !== root.secretKey(service, account)) {
                          root.pendingDeleteKey = ""
                          deleteConfirmTimer.stop()
                          root.notice = "Delete confirmation cancelled"
                        }
                        root.selectedIndex = index
                      }
                      onClicked: root.copySecret(service, account)
                    }

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(8)
                      spacing: Style.space(8)

                      Text {
                        text: "󰌋"
                        color: index === root.selectedIndex ? root.accent : root.dim
                        font.pixelSize: Style.font.bodySmall
                      }

                      Column {
                        Layout.fillWidth: true
                        spacing: Style.space(2)

                        Text {
                          width: parent.width
                          text: service + " / " + account
                          color: root.fg
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.bodySmall
                          font.bold: true
                          elide: Text.ElideRight
                        }

                        Text {
                          width: parent.width
                          text: {
                            var parts = []
                            if (!owned) parts.push("external")
                            if (label) parts.push(label)
                            if (lastTs) parts.push("used " + root.ago(lastTs))
                            return parts.join(" · ")
                          }
                          color: root.dim
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                          elide: Text.ElideRight
                          visible: text !== ""
                        }
                      }

                      // Usage tally — how often this secret has been read.
                      Text {
                        visible: hits > 0
                        text: "×" + hits
                        color: root.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Row {
                        spacing: Style.space(4)

                        PanelActionButton {
                          iconText: "󰆏"
                          tooltipText: "Copy to clipboard (sensitive)"
                          foreground: root.fg
                          onClicked: root.copySecret(service, account)
                        }

                        PanelActionButton {
                          iconText: "󰆴"
                          tooltipText: "Delete secret"
                          hoverColor: root.urgent
                          foreground: root.fg
                          onClicked: root.deleteSecret(index, service, account)
                        }
                      }
                    }
                  }
                }

                // Truncation footer — click or press e to expand.
                BorderSurface {
                  visible: root.hiddenCount > 0
                  width: secretsCol.width
                  implicitHeight: Style.space(30)
                  radius: Style.cornerRadius
                  color: Style.controlFill(false, moreMouse.containsMouse, root.fg, root.accent)
                  borderSpec: Border.controlSpec(moreMouse.containsMouse ? "hover-cursor" : "normal", root.fg, root.accent)

                  MouseArea {
                    id: moreMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    onClicked: root.expanded = true
                  }

                  Text {
                    anchors.centerIn: parent
                    text: "… " + root.hiddenCount + " more — expand for full list"
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }
              }
            }
          }
        }

        // Status Notice Banner
        Text {
          id: noticeText
          visible: root.notice !== ""
          Layout.fillWidth: true
          text: root.notice
          color: root.notice.indexOf("fail") !== -1 ? root.urgent : root.accent
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
        onLoaded: root.refreshLog()
      }
    }
  }
}
