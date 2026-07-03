const REFRESH_MS = 5000;

function fmtBytes(num) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (Math.abs(num) >= 1024 && i < units.length - 1) {
    num /= 1024;
    i++;
  }
  return num.toFixed(1) + " " + units[i];
}

function fmtHandshake(iso) {
  if (!iso) return "never";
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  return Math.floor(seconds / 3600) + "h ago";
}

async function refresh() {
  let data;
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    data = await res.json();
  } catch {
    return;
  }

  const online = data.peers.filter((p) => p.online).length;
  const set = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  set("peer-count", data.peers.length);
  set("online-count", online);
  set("total-rx", fmtBytes(data.interface.total_rx));
  set("total-tx", fmtBytes(data.interface.total_tx));

  const tbody = document.querySelector("#peer-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  for (const p of data.peers) {
    const tr = document.createElement("tr");
    const badge = p.online
      ? '<span class="badge ok">online</span>'
      : p.enabled
        ? '<span class="badge muted">offline</span>'
        : '<span class="badge err">disabled</span>';
    tr.innerHTML =
      `<td><a href="/peers/${p.id}"></a></td>` +
      `<td>${p.address}</td>` +
      `<td>${badge}</td>` +
      `<td>${fmtHandshake(p.latest_handshake)}</td>` +
      `<td>${fmtBytes(p.rx_bytes)}</td>` +
      `<td>${fmtBytes(p.tx_bytes)}</td>`;
    tr.querySelector("a").textContent = p.name;
    tbody.appendChild(tr);
  }
}

refresh();
setInterval(refresh, REFRESH_MS);
