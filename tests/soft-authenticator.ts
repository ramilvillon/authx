import { isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers'

// A passkey in a test: a real P-256 key and the byte layouts WebAuthn uses,
// so @simplewebauthn/server verifies its responses exactly as it would a
// browser's. `countsUses` false models a synced passkey (counter stays 0).
export async function createSoftAuthenticator(opts: {
  rpId?: string
  origin?: string
  userVerified?: boolean
  countsUses?: boolean
} = {}) {
  const rpId = opts.rpId ?? 'test.local'
  const origin = opts.origin ?? 'http://test.local'
  const uv = opts.userVerified ?? true
  const keys = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )
  const credId = crypto.getRandomValues(new Uint8Array(16))
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey)
  const cose = new Map<number, number | Uint8Array>([
    [1, 2], // kty EC2
    [3, -7], // alg ES256
    [-1, 1], // crv P-256
    [-2, isoBase64URL.toBuffer(jwk.x!)],
    [-3, isoBase64URL.toBuffer(jwk.y!)],
  ])
  const b64u = (b: Uint8Array<ArrayBuffer>) => isoBase64URL.fromBuffer(b)
  const sha256 = async (b: Uint8Array<ArrayBuffer>) =>
    new Uint8Array(await crypto.subtle.digest('SHA-256', b))
  const enc = (s: string) => new TextEncoder().encode(s)
  let userHandle = ''
  const state = { counter: 0 }

  // rpIdHash(32) | flags(1) | counter(4) [| attested credential data]
  async function authData(attested?: Uint8Array) {
    const head = new Uint8Array(37)
    head.set(await sha256(enc(rpId)), 0)
    head[32] = 0x01 | (uv ? 0x04 : 0) | (attested ? 0x40 : 0) // UP | UV | AT
    new DataView(head.buffer).setUint32(33, state.counter)
    return attested ? new Uint8Array([...head, ...attested]) : head
  }
  const clientData = (type: string, challenge: string) =>
    enc(JSON.stringify({ type, challenge, origin, crossOrigin: false }))

  return {
    state,
    credentialId: b64u(credId),
    async register(o: { challenge: string; user: { id: string } }) {
      userHandle = o.user.id
      const attested = new Uint8Array([
        ...new Uint8Array(16), // aaguid: not disclosed
        0,
        credId.length,
        ...credId,
        ...isoCBOR.encode(cose),
      ])
      const attestationObject = isoCBOR.encode(
        new Map<string, unknown>([
          ['fmt', 'none'],
          ['attStmt', new Map()],
          ['authData', await authData(attested)],
        ]) as never,
      )
      return {
        id: b64u(credId),
        rawId: b64u(credId),
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: b64u(clientData('webauthn.create', o.challenge)),
          attestationObject: b64u(attestationObject),
          transports: ['internal'],
        },
      }
    },
    async authenticate(o: { challenge: string }) {
      if (opts.countsUses) state.counter++
      const ad = await authData()
      const cd = clientData('webauthn.get', o.challenge)
      const raw = new Uint8Array(
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          keys.privateKey,
          new Uint8Array([...ad, ...await sha256(cd)]),
        ),
      )
      return {
        id: b64u(credId),
        rawId: b64u(credId),
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: b64u(cd),
          authenticatorData: b64u(ad),
          signature: b64u(derSignature(raw)),
          userHandle,
        },
      }
    },
  }
}

// WebCrypto signs ECDSA as raw r||s; WebAuthn carries it DER-encoded.
function derSignature(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const int = (b: Uint8Array) => {
    let i = 0
    while (i < b.length - 1 && b[i] === 0) i++
    let v = b.slice(i)
    if (v[0] & 0x80) v = new Uint8Array([0, ...v])
    return [0x02, v.length, ...v]
  }
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))]
  return new Uint8Array([0x30, body.length, ...body])
}
