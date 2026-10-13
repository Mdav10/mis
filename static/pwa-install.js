// ============================================================
// MIS — PWA install (works even when Chrome hides the button)
// ============================================================
(function () {
  let deferredPrompt = null;
  let installed = false;

  if (window.matchMedia('(display-mode: standalone)').matches) installed = true;
  if (window.navigator.standalone === true) installed = true;

  // Register SW (needed for PWA)
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/service-worker.js', { scope: '/' })
      .then(() => console.log('✅ SW registered'))
      .catch((e) => console.warn('SW failed:', e));
  }

  // Capture Chrome's install prompt when it DOES fire
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    console.log('✅ beforeinstallprompt captured');
    renderButtons();
  });

  window.addEventListener('appinstalled', () => {
    installed = true;
    hideBanner();
    hideButtons();
  });

  // Public — called by buttons
  window.misInstall = async function () {
    // Case 1: Chrome fired the event, use it directly
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      if (outcome === 'accepted') installed = true;
      deferredPrompt = null;
      return;
    }

    // Case 2: Chrome didn't fire, show fallback instructions
    // But make them extremely clear — with visuals
    showManualInstallDialog();
  };

  window.misDismissBanner = function () {
    sessionStorage.setItem('mis_banner_dismissed', '1');
    hideBanner();
  };

  // ---------- Manual dialog when Chrome won't cooperate ----------
  function showManualInstallDialog() {
    if (document.getElementById('mis-manual-install')) return;

    const ua = navigator.userAgent.toLowerCase();
    let steps = [];

    if (ua.includes('android')) {
      steps = [
        'Tap the <b>⋮ three dots</b> at the top-right of Chrome',
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
        'Look for the install icon in the address bar',
        'Or open your browser menu and choose <b>Install</b>',
      ];
    }

    const modal = document.createElement('div');
    modal.id = 'mis-manual-install';
    modal.innerHTML = `
      <div style="
        position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:99999;
        display:flex;align-items:center;justify-content:center;padding:20px;
        backdrop-filter:blur(6px);
      ">
        <div style="
          background:#161b22;border:1px solid #ffb000;border-radius:12px;
          max-width:380px;width:100%;padding:24px;
          font-family:monospace;color:#e6edf3;
          box-shadow:0 20px 60px rgba(0,0,0,0.8);
        ">
          <div style="font-size:24px;text-align:center;margin-bottom:8px;">📲</div>
          <h2 style="color:#ffb000;text-align:center;font-size:15px;letter-spacing:2px;margin:0 0 16px 0;text-transform:uppercase;">Install MIS</h2>
          <p style="font-size:12px;color:#8a8577;margin:0 0 20px 0;text-align:center;">Add MIS to your home screen for full-screen access.</p>
          <ol style="padding-left:20px;font-size:13px;line-height:1.8;color:#e6edf3;">
            ${steps.map(s => `<li style="margin-bottom:8px;">${s}</li>`).join('')}
          </ol>
          <button onclick="document.getElementById('mis-manual-install').remove()"
            style="
              width:100%;margin-top:20px;padding:14px;
              background:#ffb000;color:#0a0a08;border:none;border-radius:6px;
              font-weight:700;font-size:13px;letter-spacing:2px;cursor:pointer;
              text-transform:uppercase;
            ">
            OK — Got It
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  function renderButtons() {
    document.querySelectorAll('.mis-install-btn').forEach(b => b.style.display = 'inline-block');
    showBanner();
  }
  function hideButtons() {
    document.querySelectorAll('.mis-install-btn').forEach(b => b.style.display = 'none');
  }

  // ---------- Always-visible banner ----------
  function showBanner() {
    if (installed) return;
    if (document.getElementById('mis-install-banner')) return;
    if (sessionStorage.getItem('mis_banner_dismissed') === '1') return;

    const div = document.createElement('div');
    div.id = 'mis-install-banner';
    div.innerHTML = `
      <span style="font-size:22px;">📲</span>
      <div style="flex:1;">
        <div style="font-weight:700;color:#ffb000;letter-spacing:1px;font-size:12px;">INSTALL MIS</div>
        <div style="font-size:11px;color:#8a8577;">Full-screen app, no browser bar</div>
      </div>
      <button onclick="window.misInstall()"
        style="background:#ffb000;color:#0a0a08;border:none;padding:8px 14px;border-radius:4px;font-weight:700;font-size:11px;letter-spacing:1.5px;cursor:pointer;">INSTALL</button>
      <button onclick="window.misDismissBanner()"
        style="background:transparent;color:#8a8577;border:none;padding:8px;font-size:16px;cursor:pointer;">✕</button>
    `;
    div.style.cssText = 'position:fixed;top:44px;left:8px;right:8px;z-index:9998;display:flex;align-items:center;gap:10px;background:#161b22;border:1px solid #ffb000;border-radius:6px;padding:10px 12px;box-shadow:0 4px 20px rgba(0,0,0,0.6);font-family:monospace;';
    document.body.appendChild(div);
  }

  function hideBanner() {
    const b = document.getElementById('mis-install-banner');
    if (b) b.remove();
  }

  // Show the banner immediately on load — not waiting for Chrome
  window.addEventListener('load', () => {
    if (installed) return;
    // If Chrome fired the event, show buttons + banner
    if (deferredPrompt) {
      renderButtons();
    } else {
      // Even without event, show the banner so user has a tap target
      setTimeout(() => showBanner(), 500);
    }
  });

  window.misIsInstalled = () => installed;
})();
