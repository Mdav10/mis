// ============================================================
// MIS — PWA install helper
//  · Auto-hides when app is installed
//  · Works offline via service worker
//  · Never shows install on desktop
// ============================================================
(function () {
  let deferredPrompt = null;
  let installed = false;

  // Detect installed mode
  function checkInstalled() {
    if (window.matchMedia('(display-mode: standalone)').matches) return true;
    if (window.matchMedia('(display-mode: fullscreen)').matches) return true;
    if (window.matchMedia('(display-mode: minimal-ui)').matches) return true;
    if (window.navigator.standalone === true) return true;
    if (document.referrer.startsWith('android-app://')) return true;
    return false;
  }

  installed = checkInstalled();

  // Register SW
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/service-worker.js', { scope: '/' })
      .then(() => console.log('✅ SW registered'))
      .catch((e) => console.warn('SW failed:', e));
  }

  // Capture Chrome's install prompt
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    console.log('✅ beforeinstallprompt captured');
    renderButtons();
  });

  // Installed event
  window.addEventListener('appinstalled', () => {
    installed = true;
    hideAllInstallUI();
  });

  // Re-check when the display mode changes (installed → standalone)
  try {
    window.matchMedia('(display-mode: standalone)').addEventListener('change', (e) => {
      installed = e.matches;
      if (installed) hideAllInstallUI();
    });
  } catch (_) { /* older browsers */ }

  function isMobile() {
    const ua = navigator.userAgent || '';
    return /Android|iPhone|iPad|iPod|Mobile/i.test(ua);
  }

  function hideAllInstallUI() {
    document.querySelectorAll('.mis-install-btn').forEach(b => b.style.display = 'none');
    const pill = document.getElementById('mis-install-pill');
    if (pill) pill.style.display = 'none';
    const banner = document.getElementById('mis-install-banner');
    if (banner) banner.remove();
  }

  function renderButtons() {
    if (installed) return;
    if (!isMobile()) return;      // no install UI on desktop
    document.querySelectorAll('.mis-install-btn').forEach(b => {
      b.style.display = 'inline-block';
    });
    const pill = document.getElementById('mis-install-pill');
    if (pill) pill.style.display = 'inline-block';
  }

  // Public API
  window.misInstall = async function () {
    if (installed) return;
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      if (outcome === 'accepted') {
        installed = true;
        hideAllInstallUI();
      }
      deferredPrompt = null;
      return;
    }
    showManualInstallDialog();
  };

  // Manual instructions — appears if Chrome won't play
  function showManualInstallDialog() {
    if (document.getElementById('mis-manual-install')) return;
    const ua = (navigator.userAgent || '').toLowerCase();
    let steps = [];
    if (ua.includes('android')) {
      steps = [
        'Tap the <b>⋮ three dots</b> in Chrome (top-right)',
        'Tap <b>Add to Home screen</b> or <b>Install app</b>',
        'Tap <b>Install</b> to confirm',
      ];
    } else if (ua.includes('iphone') || ua.includes('ipad')) {
      steps = [
        'Tap the <b>Share</b> button at the bottom',
        'Scroll down, tap <b>Add to Home Screen</b>',
        'Tap <b>Add</b> to confirm',
      ];
    } else {
      steps = [
        'Look for the install icon in the browser address bar',
        'Or open the browser menu and choose <b>Install</b>',
      ];
    }
    const modal = document.createElement('div');
    modal.id = 'mis-manual-install';
    modal.innerHTML = `
      <div style="position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;">
        <div style="background:#161b22;border:1px solid #ffb000;border-radius:12px;max-width:380px;width:100%;padding:24px;font-family:monospace;color:#e6edf3;">
          <div style="font-size:24px;text-align:center;margin-bottom:8px;">📲</div>
          <h2 style="color:#ffb000;text-align:center;font-size:15px;letter-spacing:2px;margin:0 0 16px 0;text-transform:uppercase;">Install MIS</h2>
          <ol style="padding-left:20px;font-size:13px;line-height:1.8;">
            ${steps.map(s => `<li style="margin-bottom:8px;">${s}</li>`).join('')}
          </ol>
          <button onclick="document.getElementById('mis-manual-install').remove()"
                  style="width:100%;margin-top:20px;padding:14px;background:#ffb000;color:#0a0a08;border:none;border-radius:6px;font-weight:700;font-size:13px;letter-spacing:2px;cursor:pointer;text-transform:uppercase;">
            OK
          </button>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }

  // On load — if installed, hide everything. Otherwise ready the buttons.
  window.addEventListener('load', () => {
    if (installed) { hideAllInstallUI(); return; }
    if (deferredPrompt) renderButtons();
  });

  // Watch for standalone detection after load (some browsers only detect it late)
  setTimeout(() => {
    if (checkInstalled()) { installed = true; hideAllInstallUI(); }
  }, 1500);

  window.misIsInstalled = () => installed;
})();
