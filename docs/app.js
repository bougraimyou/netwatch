/**
 * NetWatch dashboard.
 *
 * Renders one report document. The same file is used three ways: inlined into a
 * self-contained report, loaded from report.json on the static demo, and fetched
 * through the API of `netwatch serve`.
 *
 * All report content is inserted with textContent. A capture is untrusted input
 * and a DNS name is a string an attacker controls, so nothing here builds markup
 * from data.
 */

(function () {
  "use strict";

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var value = attrs[key];
        if (value === null || value === undefined) return;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = String(value);
        else if (key === "html") node.innerHTML = value; // only for static markup
        else node.setAttribute(key, String(value));
      });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) return;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }

  function human(n) {
    if (n === null || n === undefined) return "0";
    var value = Number(n);
    if (!isFinite(value)) return String(n);
    if (value < 1000) return String(value);
    var units = ["", "k", "M", "G", "T"];
    var i = 0;
    while (value >= 1000 && i < units.length - 1) {
      value /= 1000;
      i += 1;
    }
    return value.toFixed(value >= 100 ? 0 : 1) + units[i];
  }

  function duration(seconds) {
    var total = Math.round(Number(seconds) || 0);
    if (total < 60) return total + "s";
    var minutes = Math.floor(total / 60);
    var rest = total % 60;
    if (minutes < 60) return minutes + "m " + (rest < 10 ? "0" : "") + rest + "s";
    var hours = Math.floor(minutes / 60);
    return hours + "h " + (minutes % 60 < 10 ? "0" : "") + (minutes % 60) + "m";
  }

  function card(label, value, sub, extraClass) {
    var classes = "card" + (extraClass ? " " + extraClass : "");
    return el("div", { class: classes }, [
      el("div", { class: "k", text: label }),
      el("div", { class: "v", text: value }),
      sub ? el("div", { class: "s", text: sub }) : null
    ]);
  }

  function renderEvidence(alert) {
    var evidence = alert.evidence || {};
    var rows = [];
    Object.keys(evidence).forEach(function (key) {
      var value = evidence[key];
      var display;
      if (Array.isArray(value)) {
        display = value.length ? value.join(", ") : "(none)";
      } else if (value && typeof value === "object") {
        display = JSON.stringify(value);
      } else {
        display = String(value);
      }
      if (display.length > 600) display = display.slice(0, 600) + "...";
      rows.push(el("div", { class: "k", text: key }));
      rows.push(el("div", { class: "v", text: display }));
    });

    var block = el("div", { class: "evidence" }, [
      el("div", { class: "kv" }, rows)
    ]);

    (alert.packets || []).forEach(function (packet) {
      var caption = "packet #" + packet.packet;
      if (packet.hex) {
        block.appendChild(
          el("div", { class: "hex" }, [
            el("span", { class: "label", text: caption + " - first " + packet.bytes + " bytes" }),
            document.createTextNode(packet.hex.match(/.{1,32}/g).join("\n"))
          ])
        );
      } else if (packet.note) {
        block.appendChild(el("div", { class: "hex" }, [
          el("span", { class: "label", text: caption }),
          document.createTextNode(packet.note)
        ]));
      }
    });
    return block;
  }

  function renderAlert(alert) {
    var evidenceCount = Object.keys(alert.evidence || {}).length;
    var detail = el("details", null, [
      el("summary", { text: "evidence" }),
      renderEvidence(alert)
    ]);
    return el("article", { class: "alert " + alert.severity }, [
      el("div", { class: "head" }, [
        el("span", { class: "chip " + alert.severity, text: alert.severity }),
        el("span", { class: "title", text: alert.title }),
        el("span", { class: "spacer" }),
        el("span", { class: "host", text: alert.host || "" })
      ]),
      el("div", { class: "sum", text: alert.summary || "" }),
      el("div", { class: "desc", text: alert.description || "" }),
      detail
    ]);
  }

  function renderBars(items, valueKey, labelKey) {
    if (!items.length) return el("div", { class: "empty", text: "No data in this capture." });
    var max = Math.max.apply(
      null,
      items.map(function (item) {
        return item[valueKey];
      })
    );
    return el(
      "div",
      { class: "bars" },
      items.map(function (item) {
        var width = max > 0 ? Math.max(2, (item[valueKey] / max) * 100) : 0;
        return el("div", { class: "bar-row" }, [
          el("span", { text: item[labelKey] }),
          el("div", { class: "bar-track" }, [el("div", { class: "bar-fill", style: "width:" + width + "%" })]),
          el("span", { class: "n", text: human(item[valueKey]) })
        ]);
      })
    );
  }

  function renderTable(headers, rows, numericColumns) {
    if (!rows.length) return el("div", { class: "empty", text: "No data in this capture." });
    var head = el(
      "tr",
      null,
      headers.map(function (header) {
        return el("th", { text: header });
      })
    );
    var body = rows.map(function (row) {
      return el(
        "tr",
        null,
        row.map(function (cell, index) {
          var isNum = (numericColumns || []).indexOf(index) !== -1;
          return el("td", { class: isNum ? "num" : null, text: cell });
        })
      );
    });
    return el("table", null, [el("thead", null, [head]), el("tbody", null, body)]);
  }

  function renderRuleStatus(rules) {
    var rows = rules.map(function (rule) {
      return [
        rule.name,
        rule.ran ? "ran" : "skipped",
        rule.ran ? String(rule.alerts) : rule.skipped_reason || ""
      ];
    });
    var table = renderTable(["rule", "status", "alerts"], rows, [2]);
    table.querySelectorAll("tbody tr").forEach(function (row, index) {
      var cell = row.children[1];
      cell.className = rules[index].ran ? "status-ok" : "status-skip";
    });
    return table;
  }

  function render(report) {
    var root = document.getElementById("app");
    root.textContent = "";

    var capture = report.capture || {};
    var counts = report.severity_counts || {};
    var alertTotal = report.alert_count || 0;

    var top = el("header", { class: "top" }, [
      el("div", { class: "brand" }, [
        document.createTextNode("netwatch"),
        el("span", { class: "dot", text: "." })
      ]),
      el("span", { class: "meta", text: capture.name || "" }),
      el("span", { class: "spacer" }),
      el("span", { class: "pill", text: "v" + ((report.tool || {}).version || "?") }),
      el("span", { class: "pill", text: (report.tool || {}).generated_at || "" })
    ]);
    root.appendChild(top);

    root.appendChild(el("h2", { text: "Capture" }));
    root.appendChild(
      el("div", { class: "cards" }, [
        card("packets", human(capture.packets), null),
        card("traffic", capture.wire_bytes_human || "0 B", (capture.payload_bytes_human || "") + " payload"),
        card("flows", human(capture.flows), null),
        card("hosts", human(capture.hosts), null),
        card("duration", duration(capture.duration_s), capture.start || ""),
        card(
          "alerts",
          String(alertTotal),
          alertTotal ? Object.keys(counts).map(function (k) { return k + " " + counts[k]; }).join("  ") : "nothing fired",
          alertTotal ? "alert-card" : "alert-card clean"
        )
      ])
    );

    root.appendChild(el("h2", { text: "Alerts" }));
    var alerts = report.alerts || [];
    if (!alerts.length) {
      root.appendChild(
        el("div", { class: "note" }, [
          el("div", { text: "No rule fired on this capture." }),
          el("ul", null, [
            el("li", { text: "That is a result, not an absence of checks. The rule status table below shows which rules actually ran." })
          ])
        ])
      );
    } else {
      root.appendChild(el("div", { class: "alerts" }, alerts.map(renderAlert)));
    }

    root.appendChild(el("h2", { text: "Rules" }));
    root.appendChild(renderRuleStatus(report.rules || []));

    root.appendChild(el("h2", { text: "Protocols" }));
    root.appendChild(renderBars(report.protocols || [], "packets", "name"));

    root.appendChild(el("h2", { text: "Top talkers" }));
    root.appendChild(
      renderTable(
        ["host", "scope", "out", "in", "peers", "ports", "dns"],
        (report.top_hosts || []).map(function (host) {
          return [host.address, host.scope, human(host.bytes_out), human(host.bytes_in), String(host.peers), String(host.ports), String(host.dns_queries)];
        }),
        [4, 5, 6]
      )
    );

    root.appendChild(el("h2", { text: "Largest flows" }));
    root.appendChild(
      renderTable(
        ["source", "destination", "proto", "packets", "payload"],
        (report.top_flows || []).map(function (flow) {
          return [
            flow.src + ":" + flow.sport,
            flow.dst + ":" + flow.dport,
            flow.proto,
            String(flow.packets),
            flow.bytes_human
          ];
        }),
        [3, 4]
      )
    );

    root.appendChild(el("h2", { text: "DNS" }));
    root.appendChild(
      renderTable(
        ["domain", "queries"],
        (report.top_domains || []).map(function (item) {
          return [item.domain, String(item.queries)];
        }),
        [1]
      )
    );

    var integrity = report.integrity || {};
    var limitations = report.limitations || [];
    root.appendChild(el("h2", { text: "What this report does not claim" }));
    root.appendChild(
      el("div", { class: "note" }, [
        el("div", { text: "Scope and known limits of this run." }),
        el("ul", null, limitations.map(function (text) { return el("li", { text: text }); })),
        el("ul", null, [
          el("li", { text: "baseline: " + ((report.baseline || {}).description || "not supplied") }),
          el("li", { text: "retained packet samples: " + (integrity.raw_samples_retained || 0) }),
          el("li", {
            text: "vlans: " + ((integrity.vlans || []).length ? integrity.vlans.join(", ") : "none tagged")
          })
        ])
      ])
    );

    root.appendChild(
      el("footer", null, [
        el("div", {
          text: "NetWatch reads a capture and answers one question: what in this traffic does not look like the rest of it."
        })
      ])
    );
  }

  function fail(message) {
    var root = document.getElementById("app");
    root.textContent = "";
    var hint =
      window.location.protocol === "file:"
        ? "Browsers block fetch() on file:// URLs. Open report.html for the self-contained version, or serve this folder over HTTP (python -m http.server -d docs)."
        : "Run `netwatch serve` or serve the folder over HTTP; the dashboard needs report.json next to index.html.";
    root.appendChild(
      el("div", { class: "note" }, [
        el("div", { text: "Could not load a report." }),
        el("ul", null, [el("li", { text: message }), el("li", { text: hint })])
      ])
    );
  }

  function boot() {
    if (window.__NETWATCH_REPORT__) {
      render(window.__NETWATCH_REPORT__);
      return;
    }
    fetch("report.json", { cache: "no-store" })
      .then(function (response) {
        if (!response.ok) throw new Error("report.json returned " + response.status);
        return response.json();
      })
      .then(render)
      .catch(function (error) {
        fail(String(error.message || error));
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
