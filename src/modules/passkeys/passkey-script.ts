// ponytail: hand-written against navigator.credentials rather than a browser
// library. The only work is base64url <-> bytes at the edges; the JSON shapes
// are what @simplewebauthn/server expects.
const b64u = `
const b64u = {
  dec: (s) => Uint8Array.from(
    atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)),
    (ch) => ch.charCodeAt(0)),
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, ''),
};
const ids = (list) => (list || []).map((c) => ({ ...c, id: b64u.dec(c.id) }));
const csrf = (form) => form.querySelector('[name=csrf_token]').value;
`

// The login page: the button, plus the browser's passkey autofill on the
// email field (conditional mediation) where supported. One options fetch per
// page view serves both; the challenge is only spent when a response is
// verified.
export const passkeySignInScript = `<script>
(() => {
${b64u}
  const form = document.getElementById('passkey-form');
  const button = document.getElementById('passkey-button');
  const error = document.getElementById('passkey-error');
  // The form ships hidden so a no-JS page never shows a button that does
  // nothing; only unhide it once this script has actually run and the API
  // exists.
  if (!window.PublicKeyCredential) return;
  form.hidden = false;
  let options;
  let optionsAt = 0;
  let ctrl;
  // The challenge inside 'options' expires after 5 minutes server-side; a
  // page left open longer than that would otherwise keep submitting a dead
  // one. Re-fetch once the cached options are older than 4 minutes.
  const load = () => {
    if (options && Date.now() - optionsAt > 4 * 60 * 1000) options = undefined;
    if (!options) {
      optionsAt = Date.now();
      options = fetch('/oauth/authorize/passkey/options', {
        method: 'POST', body: new URLSearchParams({ csrf_token: csrf(form) }),
      }).then((r) => { if (!r.ok) throw new Error('options'); return r.json(); });
    }
    return options;
  };
  const get = async (mediation) => {
    ctrl?.abort();
    // Captured in a local before the await: a concurrent call (the
    // conditional-mediation call racing a button click) would otherwise read
    // the new 'ctrl' this call itself just assigned, aborting itself instead
    // of the one it meant to replace.
    const c = ctrl = new AbortController();
    const o = await load();
    const cred = await navigator.credentials.get({
      mediation, signal: c.signal,
      publicKey: { ...o, challenge: b64u.dec(o.challenge), allowCredentials: ids(o.allowCredentials) },
    });
    if (!cred) return;
    const r = cred.response;
    form.credential.value = JSON.stringify({
      id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: {
        clientDataJSON: b64u.enc(r.clientDataJSON),
        authenticatorData: b64u.enc(r.authenticatorData),
        signature: b64u.enc(r.signature),
        userHandle: r.userHandle ? b64u.enc(r.userHandle) : undefined,
      },
    });
    form.submit();
  };
  button.addEventListener('click', () => get('optional').catch((e) => {
    if (e.name !== 'AbortError') { options = undefined; error.hidden = false; }
  }));
  PublicKeyCredential.isConditionalMediationAvailable?.()
    .then((ok) => ok && get('conditional')).catch(() => {});
})();
</script>`

// The enrolment offer page (Task 6). Continuing is always possible: on
// success, on "already registered on this device", and via Not now.
export function passkeyRegisterScript(continueHref: string): string {
  return `<script>
(() => {
${b64u}
  const form = document.getElementById('passkey-register');
  const note = document.getElementById('passkey-error');
  // Escaped so a redirect target ending in a script-closing tag (or
  // containing one) cannot close this element early and inject markup.
  // (Spelling it out literally here would do exactly that to this comment.)
  const next = ${JSON.stringify(continueHref).replace(/</g, '\\u003c')};
  // No WebAuthn support: there is nothing this page can offer, so go straight
  // on rather than show a Create button that can only ever fail.
  if (!window.PublicKeyCredential) { location.href = next; return; }
  const post = (path, fields) => fetch(path, {
    method: 'POST', body: new URLSearchParams({ csrf_token: csrf(form), ...fields }),
  }).then((r) => { if (!r.ok) throw new Error(path); return r; });
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const o = await (await post('/oauth/passkeys/register/options', {})).json();
      const cred = await navigator.credentials.create({ publicKey: {
        ...o, challenge: b64u.dec(o.challenge),
        user: { ...o.user, id: b64u.dec(o.user.id) },
        excludeCredentials: ids(o.excludeCredentials),
      } });
      const r = cred.response;
      await post('/oauth/passkeys/register', { credential: JSON.stringify({
        id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults(),
        authenticatorAttachment: cred.authenticatorAttachment || undefined,
        response: {
          clientDataJSON: b64u.enc(r.clientDataJSON),
          attestationObject: b64u.enc(r.attestationObject),
          transports: r.getTransports ? r.getTransports() : [],
        },
      }) });
      location.href = next;
    } catch (e) {
      // InvalidStateError: this device already holds a passkey for the account.
      if (e.name === 'InvalidStateError') { location.href = next; return; }
      note.hidden = false;
    }
  });
})();
</script>`
}
