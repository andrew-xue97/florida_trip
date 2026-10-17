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
  var panel = document.getElementById('private-panel');
  var body = document.getElementById('private-body');
  var close = document.getElementById('private-close');
  if (!form) return;

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
      body.innerHTML = html;
      panel.hidden = false;
      document.body.classList.add('panel-open');
      input.value = '';
    } catch (err) {
      msg.textContent = 'Wrong passcode.';
    } finally {
      form.classList.remove('busy');
    }
  });

  close.addEventListener('click', function () {
    panel.hidden = true;
    body.innerHTML = '';
    document.body.classList.remove('panel-open');
  });
})();
