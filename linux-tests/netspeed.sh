# netspeed.sh — how fast one TCP download runs under ZigOS: from the host
# next door (QEMU's 10.0.2.2: HTTP on 8099 and HTTPS on 8443, servers the
# run script starts there), where only the guest's own stack and the
# virtual NIC count, and from the npm registry, the download `npm install`
# of Claude Code waits for. Read by node, as npm reads, and by busybox
# wget. A measurement: it prints "netspeed: ..." lines and always exits 0.
#
# In the image as /etc/netspeed.sh (tools/add_rootfs_to_image.sh); a mode-19
# case, picked alone with -Dlinuxtest-only=netspeed.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
# Applets by name: alone, before alptest's apk run, the image has no links
# for them.
HOME=/tmp/netspeed.home
export PATH HOME
mkdir -p "$HOME"
near=http://10.0.2.2:8099/big
near_tls=https://10.0.2.2:8443/big
far=https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64-musl/-/claude-code-linux-x64-musl-2.1.325.tgz

# node: label url bytes
bynode() {
    busybox timeout -s KILL 300 node -e "
const t0 = Date.now();
let n = 0;
const report = (how) => {
  const s = (Date.now() - t0) / 1000;
  console.log('netspeed: $1 ' + n + ' bytes in ' + s.toFixed(2) + ' s = ' + Math.round(n / s / 1024) + ' KiB/s' + how);
  process.exit(0);
};
setTimeout(() => report(', stopped at the time limit'), 240000);
fetch('$2').then(async (r) => {
  for await (const c of r.body) { n += c.length; if (n >= $3) break; }
  report('');
}).catch((e) => console.log('netspeed: $1 failed: ' + e));" 2>&1
}

# wget, timed by node: label url
bywget() {
    busybox timeout -s KILL 320 node -e "
const t0 = Date.now();
const r = require('child_process').spawnSync('sh', ['-c', 'busybox timeout -s KILL 300 busybox wget -q -O - $2 | wc -c'], { encoding: 'utf8' });
const n = parseInt(r.stdout, 10) || 0;
const s = (Date.now() - t0) / 1000;
console.log('netspeed: $1 ' + n + ' bytes in ' + s.toFixed(2) + ' s = ' + Math.round(n / s / 1024) + ' KiB/s');" 2>&1
}

bynode "near, node" "$near" 67108864
bywget "near, wget" "$near"
# The same through TLS: what decrypting costs here (a self-signed host).
export NODE_TLS_REJECT_UNAUTHORIZED=0
bynode "near, TLS, node" "$near_tls" 67108864 | grep netspeed
unset NODE_TLS_REJECT_UNAUTHORIZED
bynode "npm registry, node" "$far" 33554432
# Two at once: one connection's limit, or the machine's?
bynode "npm registry, first of two" "$far" 16777216 &
bynode "npm registry, second of two" "$far" 16777216
wait
rm -rf "$HOME"
echo "netspeed: done"
exit 0
