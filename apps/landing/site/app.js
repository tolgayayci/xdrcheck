// Fills the page's figures and links from data/summary.json (written by apps/dashboard/scripts/build_data.py, so no
// number on the page is typed by hand), and builds the hero's square grid, one square per corpus row.
(function () {
  "use strict";
  var NF = new Intl.NumberFormat("en-US");

  function get(obj, path) {
    return path.split(".").reduce(function (o, k) { return o === null || o === undefined ? undefined : o[k]; }, obj);
  }

  function fill(s) {
    document.querySelectorAll("[data-k]").forEach(function (el) {
      var v = get(s, el.getAttribute("data-k"));
      if (typeof v === "number") el.textContent = NF.format(v);
      else if (typeof v === "string") el.textContent = v;
    });
    document.querySelectorAll("[data-list]").forEach(function (el) {
      var v = get(s, el.getAttribute("data-list"));
      if (Array.isArray(v)) el.textContent = v.join(", ");
    });
    // A claim is shown only when the data backs it: the replay line needs every pair to fail before its fix and pass
    // after it and at the current commit; the others need their data.
    var ok = {
      scan: !!s.scan,
      replay: !!(s.replay && s.replay.pairs && s.replay.pairs_reproduced === s.replay.pairs && s.replay.pairs_current_passes === s.replay.pairs),
      siblings: !!(s.siblings && s.siblings.top && s.siblings.top.reproduces.length > 1),
    };
    document.querySelectorAll("[data-need]").forEach(function (el) { el.hidden = !ok[el.getAttribute("data-need")]; });
    document.querySelectorAll("[data-link]").forEach(function (el) {
      var url = s.links && s.links[el.getAttribute("data-link")];
      if (!url) { el.hidden = true; return; }
      el.href = url + (el.getAttribute("data-hash") || "");
      el.hidden = false;
    });
    var shapes = document.getElementById("shapes");
    if (shapes && s.corpus && s.corpus.risk_shapes) {
      shapes.textContent = "";
      s.corpus.risk_shapes.forEach(function (x) {
        var li = document.createElement("li");
        li.textContent = x.label + " ";
        var n = document.createElement("span");
        n.className = "n";
        n.textContent = NF.format(x.entries) + (x.entries === 1 ? " entry" : " entries");
        li.appendChild(n);
        shapes.appendChild(li);
      });
    }
    board(s.row_labels || []);
  }

  // Squares that flash orange are chosen for rhythm, not results: the board is an illustration.
  function board(rows) {
    var root = document.getElementById("cells");
    if (!root) return;
    var cols = 12;
    var frag = document.createDocumentFragment();
    rows.forEach(function (g, i) {
      var cell = document.createElement("div");
      cell.className = i % 13 === 7 ? "cell miss" : "cell";
      cell.style.animationDelay = ((i % cols) * 0.14 + Math.floor(i / cols) * 0.22).toFixed(2) + "s";
      var text = document.createElement("span");
      text.textContent = /^cap-/.test(g) ? "CAP " + g.slice(4) : g.replace(/^protocol-/, "P");
      cell.appendChild(text);
      cell.appendChild(document.createElement("i"));
      frag.appendChild(cell);
    });
    root.textContent = "";
    root.appendChild(frag);
  }

  function start() {
    fetch("data/summary.json").then(function (r) {
      if (!r.ok) throw new Error(r.status);
      return r.json();
    }).then(fill).catch(function () {
      document.querySelectorAll("[data-k]").forEach(function (el) { el.textContent = "?"; });
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
