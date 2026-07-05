let refreshMs = 5000;
let lastPayload = "";

const container = document.getElementById("topology-chart");
const chart = echarts.init(container);
chart.on("click", (params) => {
  if (params.dataType === "node" && params.data.peerId) {
    window.location.href = `/peers/${params.data.peerId}`;
  }
});
window.addEventListener("resize", () => chart.resize());

const COL_X = { server: 120, peer: 480, subnet: 840 };
const PEER_GAP = 78;
const SUBNET_GAP = 34;
const BAND_GAP = 70;

function fmtBytes(num) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (Math.abs(num) >= 1024 && i < units.length - 1) {
    num /= 1024;
    i++;
  }
  return num.toFixed(1) + " " + units[i];
}

function splitCidrs(value) {
  return (value || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function peerCategory(p) {
  if (!p.enabled) return "Disabled";
  return p.online ? "Online" : "Offline";
}

function buildOption(data) {
  const nodes = [];
  const links = [];
  let y = 0;

  for (const iface of data.interfaces) {
    const bandTop = y;
    let peerY = bandTop;

    for (const p of iface.peers) {
      const subnets = splitCidrs(p.extra_allowed_ips);
      const rowHeight = Math.max(PEER_GAP, subnets.length * SUBNET_GAP + 26);
      const rowCenter = peerY + rowHeight / 2;
      const active = p.enabled && p.online;

      const lines = [
        `Peer: ${p.name}${p.has_private_key ? "" : " (imported)"}`,
        `Address: ${p.address}`,
        `Status: ${peerCategory(p).toLowerCase()}`,
      ];
      if (p.endpoint) lines.push(`Endpoint: ${p.endpoint}`);
      lines.push(`RX ${fmtBytes(p.rx_bytes)} / TX ${fmtBytes(p.tx_bytes)}`);
      if (p.client_allowed_ips) lines.push(`Client routes: ${p.client_allowed_ips}`);

      nodes.push({
        id: `peer-${p.id}`,
        peerId: p.id,
        name: p.name,
        category: peerCategory(p),
        x: COL_X.peer,
        y: rowCenter,
        symbolSize: 26,
        tooltipLines: lines,
      });
      links.push({
        source: `iface-${iface.id}`,
        target: `peer-${p.id}`,
        lineStyle: {
          width: active ? 2.5 : 1.5,
          type: active ? "solid" : "dashed",
          color: active ? "#10b981" : "#94a3b8",
          curveness: 0.12,
        },
      });

      subnets.forEach((subnet, i) => {
        const id = `subnet-${p.id}-${subnet}`;
        nodes.push({
          id,
          name: subnet,
          category: "Site subnet",
          x: COL_X.subnet,
          y: rowCenter - ((subnets.length - 1) * SUBNET_GAP) / 2 + i * SUBNET_GAP,
          symbol: "roundRect",
          symbolSize: [Math.max(96, subnet.length * 7.5), 22],
          label: {
            position: "inside",
            fontSize: 10,
            fontFamily: "monospace",
            color: "#92400e",
          },
          tooltipLines: [`Site subnet: ${subnet}`, `Via peer: ${p.name}`],
        });
        links.push({
          source: `peer-${p.id}`,
          target: id,
          lineStyle: {
            width: 1.5,
            type: p.enabled ? "solid" : "dashed",
            color: "#f59e0b",
            curveness: 0.12,
          },
        });
      });

      peerY += rowHeight;
    }

    const bandHeight = Math.max(peerY - bandTop, PEER_GAP);
    nodes.push({
      id: `iface-${iface.id}`,
      name: iface.name,
      category: "Server",
      x: COL_X.server,
      y: bandTop + bandHeight / 2,
      symbolSize: 52,
      label: { fontWeight: "bold" },
      tooltipLines: [
        `Interface: ${iface.name} (${iface.up ? "up" : "down"})${iface.imported ? " [imported]" : ""}`,
        `Address: ${iface.address}`,
        `Subnet: ${iface.subnet}`,
        `Endpoint: ${iface.host}:${iface.listen_port}`,
        `Peer isolation: ${iface.peer_isolation ? "on" : "off"}`,
        `RX ${fmtBytes(iface.total_rx)} / TX ${fmtBytes(iface.total_tx)}`,
      ],
      itemStyle: iface.up ? {} : { color: "#94a3b8" },
    });

    y = bandTop + bandHeight + BAND_GAP;
  }

  const totalHeight = Math.max(y - BAND_GAP, 200);
  container.style.height = Math.max(480, totalHeight + 120) + "px";
  chart.resize();

  return {
    tooltip: {
      formatter: (params) =>
        params.dataType === "node" && params.data.tooltipLines
          ? params.data.tooltipLines.join("<br>")
          : "",
    },
    legend: {
      bottom: 0,
      data: ["Server", "Online", "Offline", "Disabled", "Site subnet"],
    },
    series: [
      {
        type: "graph",
        layout: "none",
        roam: true,
        edgeSymbol: ["none", "arrow"],
        edgeSymbolSize: 6,
        label: { show: true, position: "right", fontSize: 11, color: "#334155" },
        categories: [
          { name: "Server", itemStyle: { color: "#1e293b" } },
          { name: "Online", itemStyle: { color: "#10b981" } },
          { name: "Offline", itemStyle: { color: "#cbd5e1" } },
          { name: "Disabled", itemStyle: { color: "#f87171" } },
          { name: "Site subnet", itemStyle: { color: "#fef3c7", borderColor: "#f59e0b", borderWidth: 1 } },
        ],
        emphasis: { focus: "adjacency" },
        data: nodes,
        links,
      },
    ],
  };
}

async function refresh() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();
    if (data.meta && data.meta.refresh_seconds) {
      refreshMs = data.meta.refresh_seconds * 1000;
    }
    const payload = JSON.stringify(data.interfaces);
    if (payload === lastPayload) return;
    lastPayload = payload;
    chart.setOption(buildOption(data), true);
    const badge = document.getElementById("isolation-badge");
    if (badge) {
      const isolated = data.interfaces
        .filter((i) => i.peer_isolation)
        .map((i) => i.name);
      badge.innerHTML = isolated.length
        ? `<span class="rounded-full bg-amber-100 px-3 py-1 text-xs font-medium text-amber-700">Peer isolation on: ${isolated.join(", ")}</span>`
        : "";
    }
  } catch {
    /* keep last rendering */
  }
}

async function loop() {
  await refresh();
  setTimeout(loop, refreshMs);
}
loop();
