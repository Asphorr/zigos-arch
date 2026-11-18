# nettest.sh — Linux programs reach the outside world from ZigOS: names
# through /etc/resolv.conf (the kernel writes it from the DHCP lease), plain
# HTTP, TLS with the certificate checked, apk from the real mirror, git over
# https. Needs the machine online. Prints "nettest: OK" and exits 0, or
# names what differed.
#
# In the image as /etc/nettest.sh (tools/add_rootfs_to_image.sh); boot mode
# 19 runs `busybox sh /etc/nettest.sh`.

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
fail=0

check() {
    if [ "$2" != "$3" ]; then
        echo "nettest: FAIL $1: got '$2', want '$3'"
        fail=1
    fi
}

host=dl-cdn.alpinelinux.org
mirror=https://$host/alpine/v3.21/main
index=x86_64/APKINDEX.tar.gz

# Names: busybox's resolver and musl's both read /etc/resolv.conf.
check resolv "$(grep -c '^nameserver ' /etc/resolv.conf)" 1
check nslookup "$(nslookup "$host" 2>&1 | grep -c '^Address' | awk '{ print ($1 > 0) }')" 1
check getaddrinfo "$(python3 -c "import socket; print(len(socket.getaddrinfo('$host', 443, socket.AF_INET)) > 0)" 2>&1)" True

# Plain HTTP, a file of some hundreds of KiB.
check http "$(wget -q -O - "http://$host/alpine/v3.21/main/$index" | wc -c | awk '{ print ($1 > 100000) }')" 1

# TLS: the chain verified against the CA bundle, then a download through it.
check verify "$(openssl s_client -connect "$host:443" -servername "$host" -verify_return_error < /dev/null 2>&1 | grep -q 'Verify return code: 0 (ok)' && echo ok)" ok
check https "$(python3 -c "
import urllib.request as u
r = u.urlopen('$mirror/$index', timeout=60)
print(r.status, len(r.read()) > 100000)" 2>&1)" "200 True"

# wget over https as Alpine has it: the dynamic busybox hands TLS to
# ssl_client, which checks the certificate (the static busybox in /bin
# refuses https, having no way to check one).
if [ -x /bin/busybox-dyn ] && [ -x /usr/bin/ssl_client ]; then
    check wgethttps "$(/bin/busybox-dyn wget -q -O - "$mirror/$index" 2>&1 | wc -c | awk '{ print ($1 > 100000) }')" 1
fi

# apk from the mirror, then the program it brought.
apk add --no-cache -X "$mirror" jq > /tmp/nettest.apk 2>&1 || cat /tmp/nettest.apk
check apk "$(jq -n '6 * 7' 2>&1)" 42

# pip from the mirror, then a download from PyPI through it.
apk add --no-cache -X "$mirror" -X "${mirror%/main}/community" py3-pip > /tmp/nettest.apk 2>&1 || cat /tmp/nettest.apk
rm -rf /tmp/nettest.pip
python3 -m pip download -q --no-deps -d /tmp/nettest.pip six 2>&1 | tail -n 3
check pip "$(ls /tmp/nettest.pip 2>&1 | grep -c '^six-.*\.whl$')" 1
rm -rf /tmp/nettest.pip

# git over https (git-remote-https, libcurl).
rm -rf /tmp/nettest.git
git clone -q --depth 1 https://github.com/octocat/Hello-World /tmp/nettest.git 2>&1 | tail -n 3
check gitclone "$(cat /tmp/nettest.git/README 2>&1)" "Hello World!"
rm -rf /tmp/nettest.git /tmp/nettest.apk

if [ "$fail" = 0 ]; then
    echo "nettest: OK"
fi
exit "$fail"
