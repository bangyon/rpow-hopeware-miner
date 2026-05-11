import crypto from 'node:crypto';
import * as secp from '@noble/secp256k1';

const PRIVATE_KEY = process.argv[2];

function sha256hex(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

async function createNostrAuth(method, url, bodyStr = '') {
  const privBytes = Uint8Array.from(Buffer.from(PRIVATE_KEY, 'hex'));
  const pubkey = Buffer.from(secp.schnorr.getPublicKey(privBytes)).toString('hex');
  const created_at = Math.floor(Date.now() / 1000);
  const kind = 27235;

  const tags = [['u', url], ['method', method]];
  if (bodyStr && bodyStr !== '{}') {
    tags.push(['payload', sha256hex(bodyStr)]);
  }

  const serialized = JSON.stringify([0, pubkey, created_at, kind, tags, '']);
  const id = sha256hex(serialized);
  const idBytes = Uint8Array.from(Buffer.from(id, 'hex'));
  const sigBytes = await secp.schnorr.signAsync(idBytes, privBytes);
  const sig = Buffer.from(sigBytes).toString('hex');

  const event = { id, pubkey, created_at, kind, tags, content: '', sig };
  const b64 = Buffer.from(JSON.stringify(event)).toString('base64');

  console.log('=== Generated Event ===');
  console.log(JSON.stringify(event, null, 2));
  console.log('\n=== Base64 ===');
  console.log('Nostr ' + b64);

  // Verify signature
  const valid = await secp.schnorr.verify(sig, id, pubkey);
  console.log('\n=== Signature valid?', valid, '===');
}

await createNostrAuth('POST', 'https://rpow.hopeware.ltd/alpha/challenge', '{}');
