# nodestress.sh — the node workload the kernel once crashed under, again
# and again: fetch over TLS from several node processes at once, each with
# its own threads, sockets and DNS lookups. Prints "nodestress: OK" when
# every round came back.
#
# In the image as /etc/nodestress.sh (tools/add_rootfs_to_image.sh); run by
# hand (`sh /etc/nodestress.sh [ROUNDS]`), or as a mode-19 case for a hunt.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/tmp/nodestress.home
export PATH HOME
rounds=${1:-10}
url=https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/APKINDEX.tar.gz
fail=0
mkdir -p "$HOME"

one() {
    timeout -s KILL 180 node -e "
fetch('$url').then(async (r) => {
  const n = (await r.arrayBuffer()).byteLength;
  console.log(r.status === 200 && n > 100000 ? 'ok' : 'bad ' + r.status + ' ' + n);
}).catch((e) => console.log('err ' + e));" 2>&1
}

i=0
while [ "$i" -lt "$rounds" ]; do
    i=$((i + 1))
    one > /tmp/ns.a & a=$!
    one > /tmp/ns.b & b=$!
    one > /tmp/ns.c
    wait "$a"; wait "$b"
    got="$(cat /tmp/ns.a /tmp/ns.b /tmp/ns.c | tr '\n' ' ')"
    echo "nodestress: round $i: $got"
    [ "$got" = "ok ok ok " ] || fail=1
done
rm -rf "$HOME" /tmp/ns.a /tmp/ns.b /tmp/ns.c

if [ "$fail" = 0 ]; then
    echo "nodestress: OK"
fi
exit "$fail"
