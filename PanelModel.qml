import QtQuick

// Model state for the secrets panel: the two ListModels, the derived list
// state (filters, sort, stats, selection), and the rebuild/apply functions.
// Root binds callers through property aliases, so no surface names change.
Item {
  id: model

  signal noticeSet(string text)

  property string searchFilter: ""
  onSearchFilterChanged: model.rebuildModel()
  property var allSecrets: []
  property int selectedIndex: 0

  // Organization state
  property bool expanded: false
  onExpandedChanged: model.rebuildModel()
  property string serviceFilter: ""      // "" = all vaults
  onServiceFilterChanged: model.rebuildModel()
  property string sortMode: "used"       // "used" | "recent" | "name"
  onSortModeChanged: model.rebuildModel()
  readonly property int collapsedLimit: 14
  property var serviceGroups: []         // SearchableDropdown options
  property int hiddenCount: 0
  property int totalAccesses: 0
  property string topSecretLabel: ""

  // `var` properties, not ids: ids are file-scoped, but callers reach this
  // object through a `store`/`model` reference — only real properties are
  // visible across that boundary.
  property var secretsModel: ListModel {}
  property var logModel: ListModel {}

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
    if (model.sortMode === "used") return "⇅ Used"
    if (model.sortMode === "recent") return "⇅ Recent"
    return "⇅ Name"
  }

  function cycleSort() {
    model.sortMode = model.sortMode === "used" ? "recent" : (model.sortMode === "recent" ? "name" : "used")
  }

  function applyList(raw) {
    try {
      var d = JSON.parse(raw)
      model.allSecrets = d
      model.rebuildModel()
    } catch (e) {
      model.noticeSet("Failed to parse secret list")
    }
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

  // rebuildModel owns filtering, grouping, sorting, and the collapsed limit.
  // Ordering: service filter -> text filter -> sort -> limit. Selection is
  // preserved by identity across rebuilds.
  function rebuildModel() {
    var f = model.searchFilter.trim().toLowerCase()
    var selKey = ""
    if (model.selectedIndex >= 0 && model.selectedIndex < secretsModel.count) {
      var cur = secretsModel.get(model.selectedIndex)
      selKey = model.secretKey(cur.service, cur.account)
    }

    // Vault groups: one entry per distinct service, sorted by size.
    var counts = {}
    var names = []
    for (var g = 0; g < model.allSecrets.length; g++) {
      var gs = model.allSecrets[g].service || ""
      if (!(gs in counts)) { counts[gs] = 0; names.push(gs) }
      counts[gs]++
    }
    names.sort(function(a, b) {
      var delta = counts[b] - counts[a]
      return delta !== 0 ? delta : (a.toLowerCase() < b.toLowerCase() ? -1 : 1)
    })
    var groups = [{ value: "", label: "All vaults", description: model.allSecrets.length + " secrets", count: model.allSecrets.length }]
    for (var n = 0; n < names.length; n++) {
      groups.push({ value: names[n], label: names[n], description: counts[names[n]] + (counts[names[n]] === 1 ? " secret" : " secrets"), count: counts[names[n]] })
    }
    model.serviceGroups = groups
    if (model.serviceFilter !== "" && !(model.serviceFilter in counts)) {
      model.serviceFilter = ""  // vault vanished — fall back to all; the change signal re-runs this rebuild
      return
    }

    // Header stats strip (expanded view).
    var accesses = 0, topHits = 0, topName = ""
    for (var t = 0; t < model.allSecrets.length; t++) {
      var h = model.allSecrets[t].access_count || 0
      accesses += h
      if (h > topHits) {
        topHits = h
        topName = (model.allSecrets[t].service || "") + "/" + (model.allSecrets[t].account || "")
      }
    }
    model.totalAccesses = accesses
    model.topSecretLabel = topName !== "" ? topName + " ×" + topHits : "—"

    // Filter.
    var rows = []
    for (var i = 0; i < model.allSecrets.length; i++) {
      var it = model.allSecrets[i]
      if (model.serviceFilter !== "" && (it.service || "") !== model.serviceFilter) continue
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
      var ts = rows[d].last_accessed ? +new Date(rows[d].last_accessed) : 0
      rows[d]._ts = isNaN(ts) ? 0 : ts
    }
    rows.sort(function(a, b) {
      if (model.sortMode === "name") {
        return a._key < b._key ? -1 : (a._key > b._key ? 1 : 0)
      }
      if (model.sortMode === "recent") {
        if (a._ts !== b._ts) return b._ts - a._ts
      } else {
        var ha = a.access_count || 0, hb = b.access_count || 0
        if (ha !== hb) return hb - ha
        if (a._ts !== b._ts) return b._ts - a._ts
      }
      return a._key < b._key ? -1 : (a._key > b._key ? 1 : 0)
    })

    // Collapsed limit — bypassed while searching or filtering a vault.
    model.hiddenCount = 0
    var shown = rows
    if (!model.expanded && f === "" && model.serviceFilter === "" && rows.length > model.collapsedLimit) {
      shown = rows.slice(0, model.collapsedLimit)
      model.hiddenCount = rows.length - shown.length
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
      if (selKey !== "" && model.secretKey(row.service, row.account) === selKey) {
        newIdx = secretsModel.count - 1
      }
    }
    if (newIdx >= 0) {
      model.selectedIndex = newIdx
    } else if (model.selectedIndex >= secretsModel.count) {
      model.selectedIndex = Math.max(0, secretsModel.count - 1)
    }
  }
}
