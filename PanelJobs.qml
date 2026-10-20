import QtQuick
import Quickshell.Io

// Side effects for the secrets panel: every Process, every job-scoped Timer,
// and the functions that drive them. UI calls in through the functions;
// results come back out via noticeSet/dataChanged/saved.
Item {
  id: jobs

  signal noticeSet(string text)
  signal dataChanged()
  signal saved()

  // Injected collaborators — wired by Panel.qml at instantiation.
  property var model: null          // PanelModel
  property var agentView: null      // AgentSection (passphrase field lives there)

  // Agent status — what applyAgentStatus reports.
  property string agentMode: ""
  property bool agentSessionActive: false
  property string agentSessionExpires: ""
  property bool agentKeepAlive: false
  property bool fprintdAvailable: true
  property string agentBackend: ""

  // Job state.
  property bool saving: false
  property var pendingCopy: null    // coalesced next copy while copyProc is busy
  property var pendingDel: null     // coalesced next delete while delProc is busy
  property bool refreshPending: false
  property bool agentStatusPending: false
  property string pendingDeleteKey: ""
  property var lastCopied: null     // what clipboardClearTimer is allowed to clear
  // Staged only for the duration of the unlockProc stdin write; cleared
  // immediately after — never logged or shown.
  property string unlockPassphrase: ""
  property var copyTarget: null     // service/account of the in-flight copy
  // Spawn-failure sentinels: a Process whose exec fails skips onStarted AND
  // onExited, so `running` falling with no began-flag means the spawn died.
  property bool copyBegan: false
  property bool delBegan: false
  property bool listBegan: false
  readonly property bool unlockRunning: unlockProc.running

  Component {
    id: setProcComponent
    Process {
      stdinEnabled: true
      stderr: StdioCollector {
        waitForEnd: true
      }
    }
  }

  // This wl-clipboard build has no --clear-after flag, so the panel clears
  // the selection itself 30s after a successful copy. `omaseal clipclear`
  // clears only when the clipboard still holds that secret, so a stale
  // timer cannot wipe whatever the user copied in the meantime.
  Timer {
    id: clipboardClearTimer
    interval: 30000
    onTriggered: {
      if (jobs.lastCopied === null) return
      clipboardClearProc.command = ["omaseal", "clipclear", jobs.lastCopied.service, jobs.lastCopied.account]
      clipboardClearProc.running = true
    }
  }

  Process {
    id: clipboardClearProc
  }

  Timer {
    id: deleteConfirmTimer
    interval: 5000
    onTriggered: {
      if (jobs.pendingDeleteKey !== "") {
        jobs.pendingDeleteKey = ""
        jobs.noticeSet("Delete confirmation expired")
      }
    }
  }

  Process {
    id: listProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: jobs.model.applyList(text)
    }
    onStarted: jobs.listBegan = true
    onExited: function(exitCode) {
      jobs.listBegan = true
      if (exitCode !== 0) {
        jobs.noticeSet("Failed to list secrets")
      }
      if (jobs.refreshPending) {
        jobs.refreshPending = false
        jobs.refresh()
      }
    }
    onRunningChanged: {
      if (!listProc.running && !jobs.listBegan) {
        jobs.refreshPending = false  // a dead spawn can't satisfy it — don't loop
        jobs.noticeSet("Failed to list secrets")
      }
    }
  }

  // Copy: omaseal get pipes straight into wl-copy --sensitive — the secret
  // never lands in QML memory. Positional args keep service/account out of
  // the shell string. The && chain preserves the old contract: a failed or
  // empty get exits nonzero, so a bad read can't clobber the clipboard.
  Process {
    id: copyProc
    onStarted: jobs.copyBegan = true
    onExited: function(exitCode) {
      jobs.copyBegan = true
      if (exitCode === 0 && jobs.copyTarget !== null) {
        jobs.noticeSet("Copied to clipboard (clears in 30s)")
        jobs.lastCopied = jobs.copyTarget
        clipboardClearTimer.restart()
      } else {
        jobs.noticeSet("Copy failed")
      }
      jobs.runPendingCopy()
    }
    onRunningChanged: {
      if (!copyProc.running && !jobs.copyBegan && jobs.copyTarget !== null) {
        jobs.copyTarget = null
        jobs.noticeSet("Copy failed")
        jobs.runPendingCopy()
      }
    }
  }

  Process {
    id: delProc
    onStarted: jobs.delBegan = true
    onExited: function(exitCode) {
      jobs.delBegan = true
      if (exitCode === 0) {
        jobs.refresh() // clears notice
        jobs.noticeSet("Deleted")
        jobs.dataChanged()
      } else {
        jobs.noticeSet("Delete failed")
      }
      jobs.runPendingDel()
    }
    onRunningChanged: {
      if (!delProc.running && !jobs.delBegan) {
        jobs.noticeSet("Delete failed")
        jobs.runPendingDel()
      }
    }
  }

  Process {
    id: logProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: jobs.model.applyLogs(text)
    }
  }

  Process {
    id: agentProc
    command: ["omaseal", "agent", "status", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: jobs.applyAgentStatus(text)
    }
    onExited: function(exitCode) {
      if (jobs.agentStatusPending) {
        jobs.agentStatusPending = false
        jobs.refreshAgentStatus()
      }
    }
  }

  Process {
    id: unlockProc
    stdinEnabled: true
    stderr: StdioCollector { waitForEnd: true }
    onStarted: {
      if (jobs.unlockPassphrase !== "") {
        unlockProc.write(jobs.unlockPassphrase + "\n")
      }
      jobs.unlockPassphrase = ""
      unlockProc.stdinEnabled = false
    }
    // A failed spawn skips onStarted/onExited — don't strand the staged pass.
    onRunningChanged: {
      if (!unlockProc.running) jobs.unlockPassphrase = ""
    }
    onExited: function(exitCode) {
      if (jobs.agentView) jobs.agentView.clearPass()
      if (exitCode === 0) {
        jobs.refreshAgentStatus()
        jobs.refresh() // the store may have just unlocked — repopulate
      } else {
        var detail = jobs.firstErrorLine(unlockProc.stderr.text)
        jobs.noticeSet(detail !== "" ? "Unlock failed: " + detail : "Unlock failed")
        jobs.refreshAgentStatus()
      }
    }
  }

  function refresh() {
    jobs.noticeSet("")
    jobs.pendingDeleteKey = ""
    listProc.command = ["omaseal", "list", "--json"]
    if (listProc.running) {
      // A newer refresh coalesces — the oldest request is still satisfied
      // because the in-flight list is fresher than it.
      jobs.refreshPending = true
    } else {
      jobs.listBegan = false
      listProc.running = true
    }
  }

  function refreshLog() {
    logProc.command = ["omaseal", "logs", "25", "--json"]
    if (!logProc.running) logProc.running = true
  }

  function refreshAgentStatus() {
    if (agentProc.running) {
      jobs.agentStatusPending = true
    } else {
      agentProc.running = true
    }
  }

  function applyAgentStatus(raw) {
    try {
      var d = JSON.parse(raw)
      jobs.agentMode = d.mode || ""
      jobs.agentSessionActive = d.session_active === true
      jobs.agentSessionExpires = d.session_expires || ""
      jobs.agentKeepAlive = d.keep_alive === true
      jobs.fprintdAvailable = d.fprintd_available !== false
      jobs.agentBackend = d.backend || ""
    } catch (e) {
      jobs.agentMode = ""
      jobs.agentSessionActive = false
      jobs.agentSessionExpires = ""
      jobs.agentKeepAlive = false
      jobs.fprintdAvailable = true
      jobs.agentBackend = ""
    }
  }

  function unlockAgent(passphrase) {
    if (unlockProc.running) return
    var native = jobs.agentBackend === "native"
    if (native) {
      if (!passphrase) {
        jobs.noticeSet("Enter the OmaSeal passphrase to unlock")
        if (jobs.agentView) jobs.agentView.focusPass()
        return
      }
      jobs.unlockPassphrase = passphrase
    } else {
      jobs.unlockPassphrase = ""
    }
    unlockProc.command = ["omaseal", "agent", "unlock"].concat(native ? ["--passphrase-stdin"] : [])
    unlockProc.stdinEnabled = true // a finished run latches it false
    unlockProc.running = true
  }

  function saveSecret(service, account, secret) {
    if (jobs.saving) return
    if (!service || !account || !secret) {
      jobs.noticeSet("Fill in service, account, and secret")
      return
    }
    jobs.saving = true
    jobs.noticeSet("Saving...")
    var proc = setProcComponent.createObject(jobs)
    proc.command = ["omaseal", "set", service, account]
    proc.exited.connect(function(exitCode) {
      if (exitCode === 0) {
        jobs.noticeSet("Saved")
        jobs.saved()
        jobs.refresh()
        jobs.dataChanged()
      } else {
        var detail = jobs.firstErrorLine(proc.stderr.text)
        jobs.noticeSet(detail !== "" ? "Save failed: " + detail : "Save failed")
      }
      jobs.saving = false
      proc.destroy()
    })
    proc.started.connect(function() {
      proc.write(secret)
      proc.stdinEnabled = false
    })
    // A failed spawn skips onStarted/onExited — don't latch `saving` or leak
    // the created Process (same guard unlockProc has).
    var exitedSeen = false
    proc.exited.connect(function() { exitedSeen = true })
    proc.runningChanged.connect(function() {
      if (!proc.running && !exitedSeen) {
        jobs.saving = false
        jobs.noticeSet("Save failed")
        proc.destroy()
      }
    })
    proc.running = true
  }

  function firstErrorLine(stderrText) {
    var lines = (stderrText || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i].trim()
      if (l.indexOf("error:") === 0) return l
    }
    return ""
  }

  // Delete confirmation is armed by identity, not index: a list rebuild can
  // reshuffle rows, and the confirm must still target the armed secret.
  function deleteSecret(service, account) {
    var key = jobs.model.secretKey(service, account)
    if (jobs.pendingDeleteKey !== "" && jobs.pendingDeleteKey !== key) {
      jobs.pendingDeleteKey = ""
      deleteConfirmTimer.stop()
      jobs.noticeSet("Delete confirmation cancelled")
      return
    }
    if (jobs.pendingDeleteKey !== key) {
      jobs.pendingDeleteKey = key
      deleteConfirmTimer.restart()
      jobs.noticeSet("Press delete again to confirm deletion")
      return
    }
    deleteConfirmTimer.stop()
    jobs.pendingDeleteKey = ""
    if (delProc.running) {
      if (jobs.pendingDel !== null) {
        jobs.noticeSet("Delete already queued — wait for it to finish")
        return
      }
      jobs.pendingDel = {service: service, account: account}
      jobs.noticeSet("Delete queued")
      return
    }
    jobs.spawnDel(service, account)
  }

  function spawnDel(service, account) {
    jobs.noticeSet("Deleting...")
    delProc.command = ["omaseal", "del", service, account]
    jobs.delBegan = false
    delProc.running = true
  }

  function runPendingDel() {
    if (jobs.pendingDel === null) return
    var d = jobs.pendingDel
    jobs.pendingDel = null
    jobs.spawnDel(d.service, d.account)
  }

  // Armed-delete cancel — a hover on a different row drops the pending
  // confirmation so an accidental second click can't delete the wrong row.
  function cancelArmedDelete(service, account) {
    if (jobs.pendingDeleteKey !== "" && jobs.pendingDeleteKey !== jobs.model.secretKey(service, account)) {
      jobs.pendingDeleteKey = ""
      deleteConfirmTimer.stop()
      jobs.noticeSet("Delete confirmation cancelled")
    }
  }

  function spawnCopy(service, account) {
    jobs.copyTarget = {service: service, account: account}
    // The sentinel keeps $() from stripping trailing newlines; omaseal get
    // prints verbatim, and a stored secret may end in \n (readSecret trims
    // one). NUL still can't survive a shell variable — documented limit.
    copyProc.command = ["bash", "-c",
      'out=$(omaseal get "$1" "$2"; rc=$?; if [ $rc -eq 0 ]; then printf x; else exit $rc; fi) && out=${out%x} && [ -n "$out" ] && printf %s "$out" | wl-copy --sensitive',
      "omaseal-copy", service, account]
    jobs.copyBegan = false
    copyProc.running = true
  }

  function copySecret(service, account) {
    if (copyProc.running) {
      // Coalesce: run the newest request after the in-flight copy exits.
      jobs.pendingCopy = {service: service, account: account}
      return
    }
    jobs.spawnCopy(service, account)
  }

  function runPendingCopy() {
    if (jobs.pendingCopy === null) return
    var c = jobs.pendingCopy
    jobs.pendingCopy = null
    jobs.spawnCopy(c.service, c.account)
  }
}
