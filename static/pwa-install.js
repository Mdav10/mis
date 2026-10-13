// ============================================================
// MIS — PWA Install Helper
// Catches the browser's beforeinstallprompt event and turns
// it into a real "Install" button that fires the native flow.
// ============================================================
(function () {
  let deferredPrompt = null;
  let installed = false;

  // Already installed as PWA?
  if (window.matchMedia('(display-mode: standalone)').matches) {
    installed = true;
  }
  if (navigator.standalone === true) {
    installed = true;
  }

  // ---------- Capture the install event ----------
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    showInstallBanner();
    showInstallButton();
  });

  // ---------- Handle user clicking install ----------
  window.doInstall = async function () {
    if (!deferredPrompt) {
      // Fallback: show instructions based on platform
      showInstallInstructions();
      return;
    }
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === 'accepted') {
      console.log('User accepted install');
      hideInstallBanner();
      installed = true;
    } else {
      console.log('User dismissed install');
    }
    deferredPrompt = null;
  };

  // ---------- Track installation ----------
  window.addEventListener('appinstalled', () => {
    console.log('MIS installed as PWA');
    installed = true;
    hideInstallBanner();
    hideInstallButton();
  });

  // ---------- Banner UI ----------
  function showInstallBanner() {
    if (installed) return;
    if (document.getElementById('mis-install-banner')) return;
    if (localStorage.getItem('mis_banner_dismissed') === '1') return;

    const div = document.createElement('div');
    div.id = 'mis-install-banner';
    div.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;flex:1;">
        <span style="font-size:22px;">⬇</span>
        <div style="flex:1;">
          <div style="font-weight:700;color:#ffb000;letter-spacing:1px;font-size:12px;">INSTALL MIS</div>
          <div style="font-size:11px;color:#8a8577;">Add to home screen, run full-screen</div>
        </div>
      </div>
      <button onclick="doInstall()" style="background:#ffb000;color:#0a0a08;border:none;padding:8px 14px;border-radius:4px;font-weight:700;font-size:11px;letter-spacing:1.5px;cursor:pointer;">INSTALL</button>
      <button onclick="dismissBanner()" style="background:transparent;color:#8a8577;border:none;padding:8px;font-size:16px;cursor:pointer;">✕</button>
    `;
    div.style.cssText = 'position:fixed;top:44px;left:8px;right:8px;z-index:9999;display:flex;align-items:center;gap:10px;background:#161b22;border:1px solid #ffb000;border-radius:6px;padding:10px 12px;box-shadow:0 4px 20px rgba(0,0,0,0.6);font-family:monospace;';
    document.body.appendChild(div);
  }

  window.dismissBanner = function () {
    localStorage.setItem('mis_banner_dismissed', '1');
    hideInstallBanner();
  };

  function hideInstallBanner() {
    const b = document.getElementById('mis-install-banner');
    if (b) b.remove();
  }

  // ---------- Install button on page ----------
  function showInstallButton() {
    if (installed) return;
    document.querySelectorAll('.mis-install-btn').forEach(btn => {
      btn.style.display = 'inline-block';
    });
  }

  function hideInstallButton() {
    document.querySelectorAll('.mis-install-btn').forEach(btn => {
      btn.style.display = 'none';
    });
  }

  // ---------- Fallback instructions ----------
  function showInstallInstructions() {
    const ua = navigator.userAgent.toLowerCase();
    let msg = '';
    if (ua.includes('android')) {
      msg = 'Tap the ⋮ menu in Chrome, then choose "Install app" or "Add to Home screen".';
    } else if (ua.includes('iphone') || ua.includes('ipad')) {
      msg = 'Tap the Share button, then choose "Add to Home Screen".';
    } else {
      msg = 'Look for the install icon in your browser\'s address bar.';
    }
    alert('To install MIS as an app:\n\n' + msg);
  }

  // ---------- Auto-check on load ----------
  window.addEventListener('load', () => {
    if (installed) return;
    // If we already have the prompt deferred, show button immediately
    if (deferredPrompt) {
      showInstallButton();
      showInstallBanner();
    }
  });

  // Expose helper for templates
  window.misIsInstalled = () => installed;
})();
