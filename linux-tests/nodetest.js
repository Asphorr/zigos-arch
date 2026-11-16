// nodetest.js — what Node programs lean on, under ZigOS: V8's JIT, libuv's
// event loop and thread pool, child processes, OpenSSL and zlib, worker
// threads, sockets. Prints "nodetest.js: OK" or the checks that failed.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const cp = require('child_process');
const crypto = require('crypto');
const zlib = require('zlib');
const { Worker } = require('worker_threads');

let failed = 0;
function check(name, got, want) {
  if (got === want) return;
  console.log(`nodetest.js: FAIL ${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  failed++;
}

function fib(n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

async function main() {
  check('jit', fib(27), 196418);

  // Files, directly and through the thread pool.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nodetest-'));
  const f = path.join(dir, 'a.txt');
  fs.writeFileSync(f, 'hello');
  check('fs-sync', fs.readFileSync(f, 'utf8'), 'hello');
  await fs.promises.appendFile(f, ' world');
  check('fs-async', await fs.promises.readFile(f, 'utf8'), 'hello world');
  check('stat', (await fs.promises.stat(f)).size, 11);
  check('readdir', fs.readdirSync(dir).join(','), 'a.txt');

  const order = [];
  await new Promise((done) => {
    setTimeout(() => { order.push(2); done(); }, 20);
    setTimeout(() => order.push(1), 5);
  });
  check('timers', order.join(','), '1,2');

  check('execFile', cp.execFileSync('/bin/echo', ['from', 'child']).toString().trim(), 'from child');
  check('spawn-status', cp.spawnSync('/bin/sh', ['-c', 'exit 3']).status, 3);

  check('sha256', crypto.createHash('sha256').update('abc').digest('hex'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  const gz = await new Promise((ok, bad) => zlib.gzip('x'.repeat(10000), (e, b) => (e ? bad(e) : ok(b))));
  check('zlib', zlib.gunzipSync(gz).length, 10000);
  const key = await new Promise((ok, bad) =>
    crypto.pbkdf2('pw', 'salt', 1000, 16, 'sha256', (e, k) => (e ? bad(e) : ok(k.toString('hex')))));
  check('pbkdf2', key.length, 32);

  // A worker: its own V8 isolate on its own thread.
  const w = new Worker(
    'const { parentPort } = require("worker_threads");' +
    'parentPort.on("message", (m) => parentPort.postMessage(m * 2));',
    { eval: true });
  const doubled = await new Promise((ok, bad) => {
    w.on('message', ok);
    w.on('error', bad);
    w.postMessage(21);
  });
  check('worker', doubled, 42);
  await w.terminate();

  const srv = net.createServer((s) => s.end('pong')).listen(0, '127.0.0.1');
  await new Promise((ok) => srv.on('listening', ok));
  const reply = await new Promise((ok, bad) => {
    const c = net.connect(srv.address().port, '127.0.0.1');
    let d = '';
    c.on('data', (x) => { d += x; });
    c.on('end', () => ok(d));
    c.on('error', bad);
  });
  check('tcp', reply, 'pong');
  srv.close();

  fs.rmSync(dir, { recursive: true });
  console.log(failed ? `nodetest.js: ${failed} failed` : 'nodetest.js: OK');
}

main().catch((e) => {
  console.log('nodetest.js: FAIL ' + ((e && e.stack) || e));
  process.exitCode = 1;
});
