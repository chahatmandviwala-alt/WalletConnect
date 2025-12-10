// server.js — AirGap-style UR:CRYPTO-HDKEY with the same encoding as make-ur-airgap-exact.js
// Top-level CBOR map (in this order): 3(pubkey), 4(chainCode), 6(tag304 origin), 8(parentFP uint32), 9("AirGap - meta")
// Origin (tag 304) payload: { 1: [index, boolean, ...], 2: masterFP (uint32) }

const express = require('express');
const crypto = require('crypto');
const QRCode = require('qrcode');

const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const bip32 = BIP32Factory(ecc);
const bip39 = require('bip39');
const cbor = require('cbor');
const { UR, UREncoder } = require('@ngraveio/bc-ur');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

function hash160(buf) {
  const sha = crypto.createHash('sha256').update(buf).digest();
  return crypto.createHash('ripemd160').update(sha).digest();
}
function fingerprintOf(node) {
  const h160 = hash160(Buffer.from(node.publicKey));
  return h160.readUInt32BE(0) >>> 0; // uint32
}
function parsePath(pathStr) {
  const s = String(pathStr || '').trim();
  if (!/^m(\/\d+'?)*$/.test(s)) throw new Error('Invalid derivation path.');
  return s.split('/').slice(1).map(seg => {
    const hardened = seg.endsWith("'");
    const idx = parseInt(hardened ? seg.slice(0, -1) : seg, 10);
    if (!Number.isFinite(idx)) throw new Error('Invalid index in path.');
    return { index: idx, hardened };
  });
}
function parentPathOf(pathStr) {
  const parts = pathStr.split('/');
  return parts.length <= 2 ? 'm' : parts.slice(0, -1).join('/');
}
function u32FromHexBE(hex8) {
  if (!hex8) return null;
  const b = Buffer.from(hex8, 'hex');
  if (b.length !== 4) throw new Error('Override fingerprint must be 8 hex chars');
  return b.readUInt32BE(0) >>> 0;
}

// Build origin/tag(304) payload with compact array + masterFP (uint32)
function buildOriginTag304(pathStr, masterFpU32) {
  const parts = parsePath(pathStr);
  const arr = [];
  for (const p of parts) {
    arr.push(p.index, !!p.hardened); // compact: index, boolean
  }
  const inner = new Map();
  inner.set(1, arr);                  // components compact array
  inner.set(2, masterFpU32 >>> 0);    // sourceFP as uint32
  return new cbor.Tagged(304, inner); // tag 304
}

app.post('/api/gen', async (req, res) => {
  try {
    const {
      mnemonic,
      passphrase = '',
      path = `m/44'/60'/0'`,
      qrScale = 8,
      // Optional: force the *exact* fingerprints (to match your earlier sample byte-for-byte)
      forceMasterFpHex = '',  // e.g. '281d1d2b'
      forceParentFpHex = '',  // e.g. '63323166'
      parentFrom = 'auto'     // 'auto' (immediate parent) or 'm44h60h' to force parent=m/44'/60'
    } = req.body || {};

    const words = String(mnemonic || '').trim().toLowerCase().replace(/\s+/g, ' ');
    if (!bip39.validateMnemonic(words)) return res.status(400).json({ error: 'Invalid BIP39 mnemonic.' });

    const seed   = await bip39.mnemonicToSeed(words, passphrase);
    const master = bip32.fromSeed(seed);

    // derive the requested node
    parsePath(path); // validates
    const node = master.derivePath(path);

    // decide the parent (AirGap-style sample earlier used m/44'/60' for account path; here we default to immediate parent)
    let parentPath = parentPathOf(path);
    if (parentFrom === 'm44h60h') parentPath = `m/44'/60'`;
    const parent = parentPath === 'm' ? master : master.derivePath(parentPath);

    // compute fingerprints, then override if provided
    let masterFpU32 = fingerprintOf(master);
    let parentFpU32 = fingerprintOf(parent);
    const mOverride = u32FromHexBE(forceMasterFpHex);
    const pOverride = u32FromHexBE(forceParentFpHex);
    if (mOverride !== null) masterFpU32 = mOverride;
    if (pOverride !== null) parentFpU32 = pOverride;

    // build origin (tag 304) and top-level map (3,4,6,8,9)
    const originTagged = buildOriginTag304(path, masterFpU32);
    const top = new Map();
    top.set(3, Buffer.from(node.publicKey));      // pubkey (33B)
    top.set(4, Buffer.from(node.chainCode));      // chainCode (32B)
    top.set(6, originTagged);                     // origin (tag 304)
    top.set(8, parentFpU32 >>> 0);                // parent fp (uint32)
    top.set(9, 'AirGap - meta');                  // meta string (as in your working sample)

    const cborBytes = cbor.encode(top);
    const ur = new UR(cborBytes, 'crypto-hdkey');
    const urText = new UREncoder(ur, 400).nextPart().toUpperCase();

    const scale = Math.max(3, Math.min(12, Number(qrScale) || 8));
    const qrDataUrl = await QRCode.toDataURL(urText, { errorCorrectionLevel: 'L', margin: 1, scale });

    res.json({
      ur: urText,
      path,
      parentPath,
      masterFpHex: (masterFpU32 >>> 0).toString(16).padStart(8, '0'),
      parentFpHex: (parentFpU32 >>> 0).toString(16).padStart(8, '0'),
      qrDataUrl,
    });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

const PORT = 3001;
app.listen(PORT, () => console.log(`👉 Open http://localhost:${PORT}`));
