# alptest.sh — Alpine's own programs under ZigOS, as Alpine ships them:
# linked at run time against musl and their libraries, from the root
# tools/add_rootfs_to_image.sh wrote. python3 runs /etc/alptest.py; git keeps
# a repository: commits, a branch and its merge, a clone, a repack; apk
# installs and removes packages; openssl and ssh-keygen make keys, sign and
# shake hands. Ends with "alptest: OK" and status 0, or names what differed.

PATH=/usr/bin:/bin:/usr/sbin:/sbin
HOME=/root
GIT_PAGER=cat
export PATH HOME GIT_PAGER
fail=0

check() {
    if [ "$2" != "$3" ]; then
        echo "alptest: FAIL $1: got '$2', want '$3'"
        fail=1
    fi
}

check python "$(python3 -c 'print(6 * 7)')" 42
python3 /etc/alptest.py || fail=1

d=/tmp/alptest.$$
rm -rf "$d"
mkdir -p "$d"
cd "$d" || exit 1
g() { git -c user.name=zigos -c user.email=zigos@example.invalid "$@"; }
check gitver "$(git --version | cut -d' ' -f1-2)" "git version"
g init -q -b main repo
cd repo || exit 1
printf 'one\n' > a.txt
g add a.txt
g commit -q -m first
check log "$(g log --format=%s)" first
printf 'two\n' >> a.txt
check diff "$(g diff --numstat)" "$(printf '1\t0\ta.txt')"
g commit -q -a -m second
g checkout -q -b side
printf 'b\n' > b.txt
g add b.txt
g commit -q -m third
g checkout -q main
check branch "$(ls | tr '\n' ' ')" "a.txt "
g merge -q side
check merge "$(ls | tr '\n' ' ')$(g rev-list --count HEAD)" "a.txt b.txt 3"
check status "$(g status --porcelain)" ""
check show "$(g show HEAD~1:a.txt | tr '\n' ' ')" "one two "
got=$(g grep -c two 2>&1)
check grep "$got" "a.txt:1"
# What changes it, when it fails: one thread, no index.
[ "$got" = "a.txt:1" ] || echo "alptest: grep with one thread: '$(g grep --threads=1 -c two 2>&1)'; without the index: '$(g grep --no-index -c two a.txt 2>&1)'"
cd ..
# A local clone: git-upload-pack at the other end of a pipe, the objects
# hard links.
g clone -q repo clone
check clone "$(cd clone && g log --format=%s -1)" third
cd repo || exit 1
g gc -q
check gc "$(g count-objects -v | grep '^packs:')" "packs: 1"
check fsck "$(g fsck --no-progress 2>&1)" ""
cd /
rm -rf "$d"

# apk itself, when the root has packages in /root/pkgs (`apk fetch tree less
# libncursesw ncurses-terminfo-base`): their signatures checked against
# Alpine's keys, less installed with the two it needs, the database asked,
# all removed again.
if [ -d /root/pkgs ]; then
    apk verify /root/pkgs/tree-*.apk > /tmp/apk.out 2>&1
    r=$?
    check apkverify "$r" 0
    [ "$r" = 0 ] || sed 's/^/alptest: apk verify: /' /tmp/apk.out
    apk add --no-network --no-progress --quiet /root/pkgs/*.apk > /tmp/apk.out 2>&1
    r=$?
    check apkadd "$r" 0
    [ "$r" = 0 ] || sed 's/^/alptest: apk add: /' /tmp/apk.out
    check tree "$(tree --version | cut -d' ' -f1-2)" "tree v2.2.1"
    check less "$(less --version | head -1 | cut -d' ' -f1-2)" "less 668"
    check apkinfo "$(apk info -e tree less libncursesw | sort | tr '\n' ' ')" "less libncursesw tree "
    check apkfiles "$(apk info -L tree | grep -c '^usr/bin/tree$')" 1
    apk del --no-network --no-progress --quiet tree less libncursesw ncurses-terminfo-base > /tmp/apk.out 2>&1
    r=$?
    check apkdel "$r" 0
    [ "$r" = 0 ] || sed 's/^/alptest: apk del: /' /tmp/apk.out
    check apkgone "$(apk info -e tree less)" ""
    # Busybox's trigger, run by apk, makes both names its applets again.
    check bbapplets "$(readlink /usr/bin/tree) $(readlink /usr/bin/less)" "/bin/busybox /bin/busybox"
    rm -f /tmp/apk.out
fi

# openssl and ssh-keygen with no network: a digest, an ed25519 key, a
# certificate, a signature and its check, a TLS 1.3 handshake over
# loopback; ssh key pairs, a signed file and its check.
if command -v openssl > /dev/null && command -v ssh-keygen > /dev/null; then
    s=/tmp/alpssl.$$
    rm -rf "$s"
    mkdir -p "$s"
    check sha256 "$(printf zigos | openssl dgst -sha256 -r | cut -d' ' -f1)" 384270d489b1402cf5cc06383829e96bd5e57d7f960bc98847a359c587e93af6
    openssl genpkey -algorithm ed25519 -out "$s/k.pem" 2> /dev/null
    openssl pkey -in "$s/k.pem" -pubout -out "$s/pub.pem"
    openssl req -x509 -new -key "$s/k.pem" -subj /CN=zigos -days 1 -out "$s/c.pem" 2> /dev/null
    check cert "$(openssl x509 -in "$s/c.pem" -noout -subject)" "subject=CN=zigos"
    printf 'signed by zigos\n' > "$s/msg"
    openssl pkeyutl -sign -inkey "$s/k.pem" -rawin -in "$s/msg" -out "$s/sig"
    check pkeyverify "$(openssl pkeyutl -verify -pubin -inkey "$s/pub.pem" -rawin -in "$s/msg" -sigfile "$s/sig")" "Signature Verified Successfully"
    # -rev: the server sends each line back reversed, and ends at CLOSE.
    # (A background job's stdin is /dev/null, which a plain s_server takes
    # for the end of what it has to send, and hangs up.)
    timeout 30 openssl s_server -accept 127.0.0.1:4433 -key "$s/k.pem" -cert "$s/c.pem" -naccept 1 -rev > "$s/srv.out" 2>&1 &
    sleep 1
    printf 'hello-tls\nCLOSE\n' | timeout 30 openssl s_client -connect 127.0.0.1:4433 -CAfile "$s/c.pem" -brief -ign_eof > "$s/cli.out" 2>&1
    wait
    check tlsproto "$(grep -c 'Protocol version: TLSv1.3' "$s/cli.out")" 1
    check tlsverify "$(grep -c 'Verification: OK' "$s/cli.out")" 1
    check tlsdata "$(grep -c slt-olleh "$s/cli.out")" 1
    if ! grep -q slt-olleh "$s/cli.out" || ! grep -q 'Verification: OK' "$s/cli.out"; then
        sed 's/^/alptest: s_server: /' "$s/srv.out"
        sed 's/^/alptest: s_client: /' "$s/cli.out"
    fi

    ssh-keygen -q -t ed25519 -N '' -C zigos -f "$s/id"
    check sshfp "$(ssh-keygen -l -f "$s/id.pub" | cut -d' ' -f1,3-)" "256 zigos (ED25519)"
    ssh-keygen -q -t rsa -b 2048 -N '' -C zigos -f "$s/rsa"
    check sshrsa "$(ssh-keygen -l -f "$s/rsa.pub" | cut -d' ' -f1,4)" "2048 (RSA)"
    echo "zigos $(cut -d' ' -f1,2 "$s/id.pub")" > "$s/allowed"
    ssh-keygen -Y sign -f "$s/id" -n file "$s/msg" > "$s/sign.out" 2>&1
    ssh-keygen -Y verify -f "$s/allowed" -I zigos -n file -s "$s/msg.sig" < "$s/msg" > "$s/verify.out" 2>&1
    r=$?
    check sshverify "$r" 0
    if [ "$r" != 0 ]; then
        sed 's/^/alptest: ssh-keygen sign: /' "$s/sign.out"
        sed 's/^/alptest: ssh-keygen verify: /' "$s/verify.out"
        ls -l "$s" | sed 's/^/alptest: /'
    fi
    echo tampered >> "$s/msg"
    ssh-keygen -Y verify -f "$s/allowed" -I zigos -n file -s "$s/msg.sig" < "$s/msg" > /dev/null 2>&1
    check sshtamper "$([ $? -ne 0 ] && echo refused)" refused
    rm -rf "$s"
fi

if [ "$fail" = 0 ]; then
    echo "alptest: OK"
fi
exit "$fail"
