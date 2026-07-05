let refreshMs = 5000;

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

  if (data.meta && data.meta.refresh_seconds) {
    refreshMs = data.meta.refresh_seconds * 1000;
  }

  const tbody = document.querySelector("#peer-table tbody");
  if (!tbody) return;
  const badgeBase = "rounded-full px-2 py-0.5 text-xs font-medium";
  const esc = (s) =>
    String(s).replace(/[&<>"]/g, (ch) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch]
    );
  let html = "";
  for (const iface of data.interfaces) {
    for (const p of iface.peers) {
      const badge = p.online
        ? `<span class="${badgeBase} bg-emerald-100 text-emerald-700">online</span>`
        : p.enabled
          ? `<span class="${badgeBase} bg-slate-100 text-slate-500">offline</span>`
          : `<span class="${badgeBase} bg-red-100 text-red-700">disabled</span>`;
      html +=
        `<tr class="hover:bg-slate-50">` +
        `<td class="truncate px-4 py-3"><a href="/peers/${p.id}" class="font-medium text-blue-600 hover:underline">${esc(p.name)}</a></td>` +
        `<td class="truncate px-4 py-3 text-slate-500">${esc(iface.name)}</td>` +
        `<td class="truncate px-4 py-3 font-mono text-xs">${esc(p.address)}</td>` +
        `<td class="px-4 py-3">${badge}</td>` +
        `<td class="whitespace-nowrap px-4 py-3 text-slate-500 tabular-nums">${fmtHandshake(p.latest_handshake)}</td>` +
        `<td class="whitespace-nowrap px-4 py-3 text-slate-500 tabular-nums">${fmtBytes(p.rx_bytes)}</td>` +
        `<td class="whitespace-nowrap px-4 py-3 text-slate-500 tabular-nums">${fmtBytes(p.tx_bytes)}</td>` +
        `</tr>`;
    }
  }
  if (tbody.dataset.html !== html) {
    tbody.dataset.html = html;
    tbody.innerHTML = html;
  }
}

async function loop() {
  await refresh();
  setTimeout(loop, refreshMs);
}
loop();
