/**
 * hopeware-miner.mjs v3
 * Bot mining untuk rpow.hopeware.ltd — Token A (RPOWA) dan Token B (RPOWB)
 *
 * Setup:
 *   npm install @noble/secp256k1 @noble/hashes
 *
 * Cara pakai:
 *   node hopeware-miner.mjs --key <private_key_hex> [--token a|b|both] [--threads 4]
 */

import crypto from 'node:crypto';
import { parseArgs } from 'node:util';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import * as secp from '@noble/secp256k1';

// versi baru @noble/secp256k1 tidak butuh hmacSha256Sync setup
// ─── Telegram ─────────────────────────────────────────────────────────────────
const TG_TOKEN = process.env.TG_TOKEN || '';
const TG_CHAT  = process.env.TG_CHAT  || '';
const TG_EVERY = parseInt(process.env.TG_EVERY || '10');

async function tgNotify(msg) {
  if (!TG_TOKEN || !TG_CHAT) return;
  try {
    await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TG_CHAT, text: msg, parse_mode: 'HTML' }),
    });
  } catch (_) {}
}


const __filename = fileURLToPath(import.meta.url);

// ─── CLI Args ────────────────────────────────────────────────────────────────

const { values: args } = parseArgs({
  options: {
    key:     { type: 'string',  short: 'k' },
    token:   { type: 'string',  short: 't', default: 'both' },
    threads: { type: 'string',  short: 'n', default: '4' },
    delay:   { type: 'string',  short: 'd', default: '500' },
    verbose: { type: 'boolean', short: 'v', default: false },
    help:    { type: 'boolean', short: 'h', default: false },
  },
  allowPositionals: true,
});

// ─── Worker Thread (harus dicek SEBELUM CLI args) ────────────────────────────

if (!isMainThread) {
  const { prefix, targetBits, startNonce, step } = workerData;

  // Decode hex prefix ke bytes
  const prefixBytes = Buffer.from(prefix, 'hex');
  const buf = Buffer.alloc(prefixBytes.length + 8);
  prefixBytes.copy(buf, 0);

  function countLeadingZeroBits(buf) {
    let count = 0;
    for (let i = buf.length - 1; i >= 0; i--) {
      const b = buf[i];
      if (b === 0) { count += 8; continue; }
      let bits = 0;
      for (; !(b & (1 << bits)); bits++) {}
      return count + bits;
    }
    return count;
  }

  let nonce = BigInt(startNonce);
  const stepBig = BigInt(step);

  while (true) {
    // Tulis nonce sebagai 8 bytes little-endian
    let a = nonce;
    for (let r = 0; r < 8; r++) {
      buf[prefixBytes.length + r] = Number(a & 0xffn);
      a >>= 8n;
    }

    const hash = crypto.createHash('sha256').update(buf).digest();
    if (countLeadingZeroBits(hash) >= targetBits) {
      parentPort.postMessage({ nonce: nonce.toString(), hash: hash.toString('hex') });
      break;
    }
    nonce += stepBig;
  }
  process.exit(0);
}

// ─── Config ───────────────────────────────────────────────────────────────────

if (args.help || !args.key) {
  console.log(`
hopeware-miner v3 — Bot mining untuk rpow.hopeware.ltd

Usage:
  node hopeware-miner.mjs --key <private_key_hex> [options]

Options:
  -k, --key      <hex>    Private key Nostr (hex 64 chars) [WAJIB]
  -t, --token    <type>   a | b | both (default: both)
  -n, --threads  <n>      CPU threads (default: 4)
  -d, --delay    <ms>     Delay antar mint (default: 500)
  -v, --verbose           Detail output
`);
  process.exit(0);
}

const CONFIG = {
  privateKeyHex: args.key,
  token:         args.token.toLowerCase(),
  threads:       parseInt(args.threads, 10),
  delay:         parseInt(args.delay, 10),
  verbose:       args.verbose,
  baseUrl:       'https://rpow.hopeware.ltd',
};

// ─── Nostr NIP-98 ─────────────────────────────────────────────────────────────

function sha256hex(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

async function createNostrAuth(method, url, bodyStr = '') {
  const privBytes = Uint8Array.from(Buffer.from(CONFIG.privateKeyHex, 'hex'));
  const pubkey = Buffer.from(secp.schnorr.getPublicKey(privBytes)).toString('hex');
  const created_at = Math.floor(Date.now() / 1000);
  const kind = 27235;

  // Server expect URL tanpa /alpha/ atau /beta/ prefix di tag
  const tagUrl = url.replace('/alpha/', '/').replace('/beta/', '/');

  const tags = [
    ['u', tagUrl],
    ['method', method],
  ];
  if (bodyStr && bodyStr !== '{}') {
    tags.push(['payload', sha256hex(bodyStr)]);
  }

  const serialized = JSON.stringify([0, pubkey, created_at, kind, tags, '']);
  const id = sha256hex(serialized);
  const idBytes = Uint8Array.from(Buffer.from(id, 'hex'));
  const sigBytes = await secp.schnorr.signAsync(idBytes, privBytes);
  const sig = Buffer.from(sigBytes).toString('hex');

  const event = { id, pubkey, created_at, kind, tags, content: '', sig };
  return 'Nostr ' + Buffer.from(JSON.stringify(event)).toString('base64');
}

// ─── API Client ───────────────────────────────────────────────────────────────

async function apiRequest(method, path, body = null) {
  const url = CONFIG.baseUrl + path;
  const bodyStr = body !== null ? JSON.stringify(body) : null;
  const auth = await createNostrAuth(method, url, bodyStr || '');

  const res = await fetch(url, {
    method,
    headers: {
      'Authorization': auth,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Origin': CONFIG.baseUrl,
      'Referer': CONFIG.baseUrl + '/',
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    },
    body: bodyStr,
  });

  const text = await res.text();
  try { return { ok: res.ok, status: res.status, data: JSON.parse(text) }; }
  catch { return { ok: res.ok, status: res.status, data: text }; }
}

// ─── Mining ───────────────────────────────────────────────────────────────────

function mineWithThreads(prefix, targetBits, numThreads) {
  return new Promise((resolve, reject) => {
    let done = false;
    const workers = [];
    for (let i = 0; i < numThreads; i++) {
      const w = new Worker(__filename, {
        workerData: { prefix, targetBits, startNonce: i, step: numThreads },
      });
      w.on('message', result => {
        if (done) return;
        done = true;
        workers.forEach(ww => ww.terminate());
        resolve(result);
      });
      w.on('error', reject);
      workers.push(w);
    }
  });
}

// ─── Stats ────────────────────────────────────────────────────────────────────

const stats = { a: { minted: 0, errors: 0, totalMs: 0 }, b: { minted: 0, errors: 0, totalMs: 0 } };
let startTime = Date.now();

function printStats() {
  const up = Math.floor((Date.now() - startTime) / 1000);
  const hh = String(Math.floor(up/3600)).padStart(2,'0');
  const mm = String(Math.floor((up%3600)/60)).padStart(2,'0');
  const ss = String(up%60).padStart(2,'0');
  console.log(`\n── Stats [${hh}:${mm}:${ss}] ──────────────────────────────`);
  console.log(`RPOWA: ${stats.a.minted} minted  ${stats.a.errors} errors  avg: ${stats.a.minted ? Math.round(stats.a.totalMs/stats.a.minted)+'ms' : '-'}`);
  console.log(`RPOWB: ${stats.b.minted} minted  ${stats.b.errors} errors  avg: ${stats.b.minted ? Math.round(stats.b.totalMs/stats.b.minted)+'ms' : '-'}`);
  console.log('─'.repeat(50));
}

// ─── Mine Loop ────────────────────────────────────────────────────────────────

async function mineLoop(tokenType) {
  const label = tokenType === 'a' ? 'RPOWA' : 'RPOWB';
  const path  = tokenType === 'a' ? '/alpha' : '/beta';
  const s     = tokenType === 'a' ? stats.a  : stats.b;

  console.log(`[${label}] Starting with ${CONFIG.threads} threads`);

  while (true) {
    try {
      const cr = await apiRequest('POST', `${path}/challenge`, {});
      if (!cr.ok || !cr.data.challenge_id) {
        s.errors++;
        // Baca retry_after dari response server
        const retryAfter = cr.data?.retry_after || 5;
        console.log(`[${label}] ✗ Challenge (${cr.status}) — retry in ${retryAfter}s`);
        await sleep(retryAfter * 1000);
        continue;
      }

      const { challenge_id, nonce_prefix, difficulty_bits } = cr.data;
      if (CONFIG.verbose) console.log(`[${label}] Challenge: ${challenge_id} | ${difficulty_bits} bits`);

      const t0 = Date.now();
      const { nonce } = await mineWithThreads(nonce_prefix, difficulty_bits, CONFIG.threads);
      const elapsed = Date.now() - t0;

      const mr = await apiRequest('POST', `${path}/mint`, { challenge_id, solution_nonce: nonce });

      if (mr.ok) {
        s.minted++;
        s.totalMs += elapsed;
        console.log(`[${label}] ✓ Minted #${s.minted}  nonce=${nonce}  ${elapsed}ms`);
        if (s.minted % TG_EVERY === 0) {
          const upSec = Math.floor((Date.now() - startTime) / 1000);
          const tph = (s.minted / upSec * 3600).toFixed(1);
          tgNotify(`⛏ <b>Hopeware Miner</b>\n🪙 ${label}: <b>${s.minted} minted</b>\n⚡ Rate: ${tph} token/hr\n❌ Errors: ${s.errors}`);
        }
      } else {
        s.errors++;
        const retryAfter = mr.data?.retry_after || 5;
        console.log(`[${label}] ✗ Mint failed (${mr.status}) — retry in ${retryAfter}s`);
        await sleep(retryAfter * 1000);
        continue; // skip delay bawah, langsung retry
      }

    } catch (e) {
      s.errors++;
      console.log(`[${label}] Error: ${e.message}`);
      await sleep(5000);
    }

    await sleep(CONFIG.delay);
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const pubkey = Buffer.from(secp.schnorr.getPublicKey(Uint8Array.from(Buffer.from(CONFIG.privateKeyHex, 'hex')))).toString('hex');

  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║     hopeware-miner v3  —  rpow.hopeware.ltd      ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log(`Pubkey : ${pubkey}`);
  console.log(`Token  : ${CONFIG.token.toUpperCase()}`);
  console.log(`Threads: ${CONFIG.threads}`);
  console.log(`Delay  : ${CONFIG.delay}ms\n`);

  try {
    const me = await apiRequest('GET', '/me');
    if (me.ok) console.log(`Balance — RPOWA: ${me.data.balance_a ?? me.data.balance ?? '?'}  RPOWB: ${me.data.balance_b ?? '?'}\n`);
    else console.log(`Balance: ${JSON.stringify(me.data)}\n`);
  } catch (e) { console.log(`Balance check error: ${e.message}\n`); }

  setInterval(printStats, 30000);
  startTime = Date.now();
  tgNotify(`🚀 <b>Hopeware Miner Started</b>\n👤 Pubkey: <code>${pubkey.slice(0,16)}...</code>\n🧵 Threads: ${CONFIG.threads}\n🎯 Token: ${CONFIG.token.toUpperCase()}`);

  const loops = [];
  if (CONFIG.token === 'a' || CONFIG.token === 'both') loops.push(mineLoop('a'));
  if (CONFIG.token === 'b' || CONFIG.token === 'both') loops.push(mineLoop('b'));

  await Promise.all(loops);
}

main().catch(err => { console.error('Fatal:', err.message); process.exit(1); });
