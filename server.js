#!/usr/bin/env node
// ASCENDIA realm server — zero dependencies (Node 16+).
//   node server.js            (PORT=8080 by default)
// Serves index.html, stores accounts + cloud saves (scrypt-hashed passwords) and relays multiplayer messages.
// For internet play put it behind HTTPS (e.g. Caddy/nginx) so the game connects over wss:// and passwords are encrypted in transit.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 8080;
const DATA = process.env.DATA_FILE || path.join(__dirname, 'ascendia-data.json');
let DB = { users: {} };
try { DB = JSON.parse(fs.readFileSync(DATA, 'utf8')); if (!DB.users) DB.users = {}; } catch (e) {}
let dirty = false;
function flush() {
  if (!dirty) return; dirty = false;
  fs.writeFile(DATA + '.tmp', JSON.stringify(DB), err => { if (!err) fs.rename(DATA + '.tmp', DATA, () => {}); });
}
setInterval(flush, 5000);
process.on('SIGINT', () => { dirty = true; try { fs.writeFileSync(DATA, JSON.stringify(DB)); } catch (e) {} process.exit(0); });

const clients = new Set();
const RELAY = new Set(['st', 'chat', 'inv', 'acc', 'pleave', 'run', 'dmg', 'hello', 'leave']);

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    fs.readFile(path.join(__dirname, 'index.html'), (err, buf) => {
      if (err) { res.writeHead(404); res.end('index.html not found next to server.js'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(buf);
    });
  } else if (req.url === '/health') { res.writeHead(200); res.end('ok ' + clients.size); }
  else { res.writeHead(404); res.end('Not found'); }
});

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key || String(req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  const c = { socket, id: crypto.randomBytes(5).toString('hex'), ok: false, user: null, name: '', st: null, buf: Buffer.alloc(0), frag: null, rate: 0, rt: 0, fails: 0, dead: false };
  clients.add(c);
  socket.on('data', d => {
    c.buf = Buffer.concat([c.buf, d]);
    if (c.buf.length > 3e6) { socket.destroy(); return; }
    try { parse(c); } catch (e) { socket.destroy(); }
  });
  socket.on('close', () => drop(c));
  socket.on('error', () => {});
});

function parse(c) {
  for (;;) {
    const b = c.buf; if (b.length < 2) return;
    const op = b[0] & 15, fin = !!(b[0] & 128), masked = !!(b[1] & 128);
    let len = b[1] & 127, off = 2;
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
    if (len > 2e6 || !masked) { c.socket.destroy(); return; }
    if (b.length < off + 4 + len) return;
    const mask = b.slice(off, off + 4), payload = Buffer.from(b.slice(off + 4, off + 4 + len));
    for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
    c.buf = b.slice(off + 4 + len);
    if (op === 8) { c.socket.end(); return; }
    if (op === 9) { frame(c, payload, 10); continue; }
    if (op === 10) continue;
    if (op === 1 || op === 0) {
      c.frag = op === 1 ? [payload] : (c.frag || []).concat([payload]);
      if (fin) { const s = Buffer.concat(c.frag).toString('utf8'); c.frag = null; onMsg(c, s); }
    }
  }
}
function frame(c, data, op) {
  if (c.dead) return;
  const p = Buffer.isBuffer(data) ? data : Buffer.from(data); let h;
  if (p.length < 126) h = Buffer.from([128 | op, p.length]);
  else if (p.length < 65536) { h = Buffer.alloc(4); h[0] = 128 | op; h[1] = 126; h.writeUInt16BE(p.length, 2); }
  else { h = Buffer.alloc(10); h[0] = 128 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(p.length), 2); }
  try { c.socket.write(Buffer.concat([h, p])); } catch (e) {}
}
const send = (c, o) => frame(c, JSON.stringify(o), 1);

const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 32, (e, k) => e ? rej(e) : res(k.toString('hex'))));
const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
function authOk(c, name, key, save) {
  for (const o of clients) if (o !== c && o.ok && key && o.user === key) { send(o, { t: 'kick' }); o.socket.end(); }
  c.ok = true; c.name = name; c.user = key;
  send(c, { t: 'auth', ok: true, name, save: save || null });
  console.log('[+] ' + name + (key ? '' : ' (guest)') + '  online=' + [...clients].filter(x => x.ok).length);
}
async function onMsg(c, s) {
  const now = Date.now(); if (now - c.rt > 1000) { c.rt = now; c.rate = 0; }
  if (++c.rate > 90) return;
  if (s.length > 1.5e6) return;
  let m; try { m = JSON.parse(s); } catch (e) { return; }
  if (!m || typeof m.t !== 'string') return;
  if (!c.ok) {
    if (m.t === 'guest') { authOk(c, 'Guest' + crypto.randomInt(1000, 9999), null, null); return; }
    if (m.t !== 'reg' && m.t !== 'login') return;
    if (c.fails >= 6) { send(c, { t: 'auth', ok: false, err: 'Too many attempts.' }); c.socket.end(); return; }
    const u = String(m.u || ''), p = String(m.p || ''), k = u.toLowerCase();
    if (!NAME_RE.test(u) || k.indexOf('guest') === 0 || p.length < 6 || p.length > 100) { send(c, { t: 'auth', ok: false, err: 'Invalid username or password format.' }); return; }
    try {
      if (m.t === 'reg') {
        if (DB.users[k]) { send(c, { t: 'auth', ok: false, err: 'That username is taken.' }); return; }
        const salt = crypto.randomBytes(16).toString('hex'), hash = await scrypt(p, salt);
        if (DB.users[k]) { send(c, { t: 'auth', ok: false, err: 'That username is taken.' }); return; }
        DB.users[k] = { name: u, salt, hash, save: null, created: Date.now() }; dirty = true;
        authOk(c, u, k, null);
      } else {
        const r = DB.users[k];
        const good = r && crypto.timingSafeEqual(Buffer.from(await scrypt(p, r.salt), 'hex'), Buffer.from(r.hash, 'hex'));
        if (!good) { c.fails++; send(c, { t: 'auth', ok: false, err: 'Wrong username or password.' }); return; }
        authOk(c, r.name, k, r.save);
      }
    } catch (e) { send(c, { t: 'auth', ok: false, err: 'Server error.' }); }
    return;
  }
  if (m.t === 'save') {
    if (c.user && m.save && typeof m.save === 'object' && m.save.p && DB.users[c.user]) { DB.users[c.user].save = m.save; dirty = true; }
    return;
  }
  if (!RELAY.has(m.t) || s.length > 6000) return;
  if (m.t === 'hello') {
    const peers = [];
    for (const o of clients) if (o !== c && o.ok && o.st) peers.push(Object.assign({ t: 'st', id: o.id }, o.st));
    send(c, { t: 'welcome', peers });
  }
  if (m.t === 'st') {
    const n = v => Number.isFinite(+v) ? +v : 0;
    c.st = { name: String(m.name || c.name).replace(/[\x00-\x1f<>]/g, '').slice(0, 16), color: /^#[0-9a-f]{6}$/i.test(m.color) ? m.color : '#ffd24a', lvl: n(m.lvl) | 0, fl: n(m.fl) | 0, mode: String(m.mode).slice(0, 4), f: n(m.f) | 0, rs: n(m.rs) >>> 0, x: n(m.x), y: n(m.y), face: n(m.face), mv: !!m.mv };
    m = Object.assign({ t: 'st' }, c.st);
  }
  if (m.t === 'chat') m = { t: 'chat', ch: m.ch === 'Whisper' ? 'Whisper' : 'World', to: m.to, name: String(m.name || c.name).slice(0, 16), color: m.color, msg: String(m.msg || '').slice(0, 120) };
  m.id = c.id;
  if (m.to) { for (const o of clients) if (o.ok && o.id === m.to) send(o, m); }
  else for (const o of clients) if (o !== c && o.ok) send(o, m);
}
function drop(c) {
  if (c.dead) return; c.dead = true; clients.delete(c);
  if (c.ok) { for (const o of clients) if (o.ok) send(o, { t: 'leave', id: c.id }); console.log('[-] ' + c.name + '  online=' + [...clients].filter(x => x.ok).length); }
}
server.listen(PORT, () => {
  console.log('ASCENDIA realm server running.\n  Open  http://localhost:' + PORT + '  (the game auto-connects to the realm it was served from)\n  Or set the Multiplayer server field in the game to  ws://<this-host>:' + PORT);
});
