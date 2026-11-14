// The passkey buttons of owt-accounts' second-factor pages. A button
// `data-owt-passkey="create"` or `"get"` carries the server's options as JSON in
// `data-options`; a click runs the browser's ceremony, puts the answer as JSON in the
// form's `passkey_credential` field and submits the form. Without WebAuthn the button
// stays hidden and the other factors remain.
(function () {
  "use strict";
  function toBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var b = atob(s), a = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a.buffer;
  }
  function toB64(buf) {
    var a = new Uint8Array(buf), s = "";
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function ids(list) {
    (list || []).forEach(function (c) { c.id = toBuf(c.id); });
  }
  function extensions(c) {
    return c.getClientExtensionResults ? c.getClientExtensionResults() : {};
  }
  function create(opts) {
    var p = opts.publicKey;
    p.challenge = toBuf(p.challenge);
    p.user.id = toBuf(p.user.id);
    ids(p.excludeCredentials);
    return navigator.credentials.create(opts).then(function (c) {
      var r = {
        id: c.id, rawId: toB64(c.rawId), type: c.type, extensions: extensions(c),
        response: {
          attestationObject: toB64(c.response.attestationObject),
          clientDataJSON: toB64(c.response.clientDataJSON)
        }
      };
      if (c.response.getTransports) r.response.transports = c.response.getTransports();
      return r;
    });
  }
  function get(opts) {
    var p = opts.publicKey;
    p.challenge = toBuf(p.challenge);
    ids(p.allowCredentials);
    return navigator.credentials.get(opts).then(function (c) {
      return {
        id: c.id, rawId: toB64(c.rawId), type: c.type, extensions: extensions(c),
        response: {
          authenticatorData: toB64(c.response.authenticatorData),
          clientDataJSON: toB64(c.response.clientDataJSON),
          signature: toB64(c.response.signature),
          userHandle: c.response.userHandle ? toB64(c.response.userHandle) : null
        }
      };
    });
  }
  document.querySelectorAll("[data-owt-passkey]").forEach(function (button) {
    var form = button.form;
    if (!form || !window.PublicKeyCredential || !navigator.credentials) return;
    button.hidden = false;
    button.addEventListener("click", function (event) {
      event.preventDefault();
      if (!form.reportValidity()) return;
      var opts = JSON.parse(button.getAttribute("data-options"));
      var run = button.getAttribute("data-owt-passkey") === "create" ? create : get;
      var error = document.querySelector("[data-owt-passkey-error]");
      button.disabled = true;
      run(opts).then(function (answer) {
        form.querySelector("input[name=passkey_credential]").value = JSON.stringify(answer);
        form.submit();
      }, function (e) {
        button.disabled = false;
        if (error) {
          error.hidden = false;
          error.textContent = "The passkey did not answer (" + ((e && e.name) || "cancelled") +
            "). Try again, or use another way to confirm it is you.";
        }
      });
    });
  });
})();
