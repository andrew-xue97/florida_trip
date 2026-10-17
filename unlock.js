// Decrypts window.FLORIDA_ENC (see build.mjs) with the passcode the user types.
(function () {
  var fromB64 = function (s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };

  async function decrypt(pass, blob, subtle) {
    subtle = subtle || crypto.subtle;
    var material = await subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    var key = await subtle.deriveKey(
      { name: 'PBKDF2', salt: fromB64(blob.salt), iterations: blob.iter, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    var pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.ct));
    return new TextDecoder().decode(pt);
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { decrypt: decrypt };
    return;
  }

  var form = document.getElementById('unlock-form');
  var input = document.getElementById('passcode');
  var msg = document.getElementById('unlock-msg');
  var page = document.getElementById('trip-page');
  var body = document.getElementById('trip-body');
  var lockBtn = document.getElementById('lock-btn');
  if (!form) return;

  // Decrypted content lives only in memory and in the DOM; a reload or Lock clears it.
  function show(html) {
    body.innerHTML = html;
    page.hidden = false;
    document.body.classList.add('unlocked');
    window.scrollTo(0, 0);
  }

  function lock() {
    body.innerHTML = '';
    page.hidden = true;
    document.body.classList.remove('unlocked');
    window.scrollTo(0, 0);
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    msg.textContent = '';
    if (!window.FLORIDA_ENC) {
      msg.textContent = 'Nothing to unlock yet.';
      return;
    }
    form.classList.add('busy');
    try {
      var html = await decrypt(input.value, window.FLORIDA_ENC);
      input.value = '';
      show(html);
      history.pushState({ unlocked: true }, '', '#trip');
    } catch (err) {
      msg.textContent = 'Wrong passcode.';
    } finally {
      form.classList.remove('busy');
    }
  });

  lockBtn.addEventListener('click', function () {
    if (history.state && history.state.unlocked) history.back();
    else lock();
  });

  // Back button (or Lock) returns to the landing page and clears the content.
  window.addEventListener('popstate', lock);

  // A direct visit to /#trip has nothing decrypted yet, so start on the landing page.
  if (location.hash === '#trip') history.replaceState(null, '', location.pathname);
})();
