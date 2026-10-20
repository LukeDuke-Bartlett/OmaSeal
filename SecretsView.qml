import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui

// The secrets list surface: section header + scrollable rows + empty state.
// Reads model state through `store` (PanelModel) and reports every action
// upward through signals — delegates keep their `model.*` context props.
ColumnLayout {
  id: view

  property var store: null          // PanelModel
  property bool isAdding: false
  property color fg
  property color dim
  property color accent
  property color urgent
  property string fontFamily

  signal copyRequested(string service, string account)
  signal deleteRequested(string service, string account)
  signal rowEntered(string service, string account)

  spacing: Style.space(10)

  // Section label + keybind hints on one row. The hints Text owns
  // the spare width and elides — a single long header string would
  // paint straight past the card's right border (PanelSectionHeader
  // is a bare Text: no width bound, no elide).
  RowLayout {
    Layout.fillWidth: true
    spacing: Style.space(8)

    PanelSectionHeader {
      text: "SECRETS (" + view.store.secretsModel.count + (view.store.hiddenCount > 0 ? "+" + view.store.hiddenCount : "") + ")"
      foreground: view.fg
    }

    Text {
      Layout.fillWidth: true
      horizontalAlignment: Text.AlignRight
      text: "j/k nav · / search · v vault · s sort · ⏎ copy · x del · e " + (view.store.expanded ? "collapse" : "expand")
      color: view.dim
      font.family: view.fontFamily
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
      view.store.expanded ? Style.space(640)
        : (view.isAdding ? Style.space(220) : Style.space(420)))
    contentHeight: secretsCol.implicitHeight
    clip: true

    Column {
      id: secretsCol
      width: parent.width
      spacing: Style.space(6)

      // Empty State
      Text {
        visible: view.store.secretsModel.count === 0
        width: parent.width
        text: view.store.allSecrets.length > 0 ? "No matches." : "No secrets yet — press a or + Add to store one, or run: omaseal import 1password"
        wrapMode: Text.WordWrap
        color: view.dim
        font.family: view.fontFamily
        font.pixelSize: Style.font.bodySmall
        horizontalAlignment: Text.AlignHCenter
        topPadding: Style.space(12)
        bottomPadding: Style.space(12)
      }

      // Secrets Repeater
      Repeater {
        model: view.store.secretsModel
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
          color: index === view.store.selectedIndex ? Style.selectedFillFor(view.fg, view.accent) : Style.controlFill(false, rowMouse.containsMouse, view.fg, view.accent)
          borderSpec: Border.controlSpec(index === view.store.selectedIndex ? "selected" : (rowMouse.containsMouse ? "hover-cursor" : "normal"), view.fg, view.accent)

          MouseArea {
            id: rowMouse
            anchors.fill: parent
            hoverEnabled: true
            onEntered: {
              view.rowEntered(service, account)
              view.store.selectedIndex = index
            }
            onClicked: view.copyRequested(service, account)
          }

          RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Style.space(10)
            anchors.rightMargin: Style.space(8)
            spacing: Style.space(8)

            Text {
              text: "󰌋"
              color: index === view.store.selectedIndex ? view.accent : view.dim
              font.pixelSize: Style.font.bodySmall
            }

            Column {
              Layout.fillWidth: true
              spacing: Style.space(2)

              Text {
                width: parent.width
                text: service + " / " + account
                color: view.fg
                font.family: view.fontFamily
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
                  if (lastTs) parts.push("used " + view.store.ago(lastTs))
                  return parts.join(" · ")
                }
                color: view.dim
                font.family: view.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
                visible: text !== ""
              }
            }

            // Usage tally — how often this secret has been read.
            Text {
              visible: hits > 0
              text: "×" + hits
              color: view.accent
              font.family: view.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            Row {
              spacing: Style.space(4)

              PanelActionButton {
                iconText: "󰆏"
                tooltipText: "Copy to clipboard (sensitive)"
                foreground: view.fg
                onClicked: view.copyRequested(service, account)
              }

              PanelActionButton {
                iconText: "󰆴"
                tooltipText: "Delete secret"
                hoverColor: view.urgent
                foreground: view.fg
                onClicked: view.deleteRequested(service, account)
              }
            }
          }
        }
      }

      // Truncation footer — click or press e to expand.
      BorderSurface {
        visible: view.store.hiddenCount > 0
        width: secretsCol.width
        implicitHeight: Style.space(30)
        radius: Style.cornerRadius
        color: Style.controlFill(false, moreMouse.containsMouse, view.fg, view.accent)
        borderSpec: Border.controlSpec(moreMouse.containsMouse ? "hover-cursor" : "normal", view.fg, view.accent)

        MouseArea {
          id: moreMouse
          anchors.fill: parent
          hoverEnabled: true
          onClicked: view.store.expanded = true
        }

        Text {
          anchors.centerIn: parent
          text: "… " + view.store.hiddenCount + " more — expand for full list"
          color: view.dim
          font.family: view.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
