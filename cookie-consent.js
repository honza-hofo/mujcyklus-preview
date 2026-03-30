// MujCyklus - GDPR Cookie Consent Banner
(function() {
  if (localStorage.getItem('mujcyklus_cookie_consent')) return;

  var banner = document.createElement('div');
  banner.id = 'cookieConsentBanner';
  banner.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:#fff;box-shadow:0 -4px 20px rgba(0,0,0,0.15);padding:20px;z-index:100000;font-family:inherit;border-top:3px solid #E8577D';

  banner.innerHTML = '<div style="max-width:600px;margin:0 auto">' +
    '<p style="font-size:14px;color:#333;margin-bottom:12px;line-height:1.5">' +
    'Tato aplikace používá nezbytné cookies pro správné fungování (přihlášení, relace). ' +
    'Bez těchto cookies aplikace nemůže fungovat. Analytické cookies nepoužíváme.' +
    '</p>' +
    '<p style="font-size:12px;color:#888;margin-bottom:16px">' +
    'Více informací v <a href="/privacy" style="color:#E8577D">zásadách ochrany osobních údajů</a>.' +
    '</p>' +
    '<div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">' +
    '<button id="cookieAccept" style="padding:12px 32px;background:#E8577D;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;min-width:140px">Přijmout</button>' +
    '<button id="cookieReject" style="padding:12px 32px;background:#fff;color:#E8577D;border:2px solid #E8577D;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;min-width:140px">Pouze nezbytné</button>' +
    '</div>' +
    '</div>';

  document.body.appendChild(banner);

  document.getElementById('cookieAccept').addEventListener('click', function() {
    localStorage.setItem('mujcyklus_cookie_consent', JSON.stringify({ accepted: true, date: new Date().toISOString() }));
    banner.remove();
  });

  document.getElementById('cookieReject').addEventListener('click', function() {
    localStorage.setItem('mujcyklus_cookie_consent', JSON.stringify({ accepted: false, essential_only: true, date: new Date().toISOString() }));
    banner.remove();
  });
})();
