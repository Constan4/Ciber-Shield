// Ciber-Shield dashboard.js
// Utilidades globales del dashboard

// Actualizar el badge de scans activos cada 30s
let pollActive = null;
function startActivePoll() {
  pollActive = setInterval(async () => {
    try {
      const r = await fetch('/api/scans?status=running&per_page=5');
      const d = await r.json();
      if (d.status === 'ok') {
        const badge = document.querySelector('.badge.bg-warning');
        if (badge && d.data.total > 0) {
          badge.textContent = d.data.total + ' activo(s)';
        }
      }
    } catch(e) {}
  }, 30000);
}
document.addEventListener('DOMContentLoaded', startActivePoll);

// Copy to clipboard helper
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    const el = event.target;
    const orig = el.textContent;
    el.textContent = '✓';
    setTimeout(() => { el.textContent = orig; }, 1200);
  });
}

// Tooltip init
document.addEventListener('DOMContentLoaded', () => {
  const tts = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  tts.forEach(t => new bootstrap.Tooltip(t));
});
