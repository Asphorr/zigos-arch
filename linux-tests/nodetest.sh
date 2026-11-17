# nodetest.sh — Alpine's Node.js and npm under ZigOS: node runs, then
# nodetest.js, then fetch and npm out on the network. Prints "nodetest: OK"
# and exits 0, or names what differed.
#
# In the image as /etc/nodetest.sh with /etc/nodetest.js
# (tools/add_rootfs_to_image.sh); boot mode 19 runs
# `busybox sh /etc/nodetest.sh`.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/tmp/nodetest.home
export PATH HOME
fail=0

check() {
    if [ "$2" != "$3" ]; then
        echo "nodetest: FAIL $1: got '$2', want '$3'"
        fail=1
    fi
}

# A hang fails its own check instead of the whole run.
node() { busybox timeout -s KILL 180 /usr/bin/node "$@"; }
npm() { busybox timeout -s KILL 300 /usr/bin/npm "$@"; }

rm -rf "$HOME"
mkdir -p "$HOME"
check version "$(node --version 2>&1 | cut -c1-4)" v22.
check eval "$(node -e 'console.log(6 * 7)' 2>&1)" 42
check js "$(node /etc/nodetest.js 2>&1 | tail -n 20)" "nodetest.js: OK"

check fetch "$(node -e "fetch('https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/APKINDEX.tar.gz').then(async (r) => console.log(r.status, (await r.arrayBuffer()).byteLength > 100000))" 2>&1)" "200 true"

check npm "$(npm --version 2>&1)" 10.9.1
mkdir -p "$HOME/app"
cd "$HOME/app" || exit 1
npm init -y > /dev/null 2>&1
npm install --no-audit --no-fund is-number 2>&1 | tail -n 3
check npminstall "$(node -e "console.log(require('is-number')(5))" 2>&1)" true
cd /
rm -rf "$HOME"

if [ "$fail" = 0 ]; then
    echo "nodetest: OK"
fi
exit "$fail"
