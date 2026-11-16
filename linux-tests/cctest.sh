# cctest.sh — Claude Code installed from npm and started under ZigOS: the
# package from the registry, then `claude --version` and `--help`, which load
# the whole CLI without an account. Prints "cctest: OK" and exits 0, or names
# what differed. Needs the machine online.
#
# In the image as /etc/cctest.sh (tools/add_rootfs_to_image.sh); boot mode 19
# runs `busybox sh /etc/cctest.sh`.

PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/tmp/cctest.home
SHELL=/bin/sh
export PATH HOME SHELL
fail=0

check() {
    if [ "$2" != "$3" ]; then
        echo "cctest: FAIL $1: got '$2', want '$3'"
        fail=1
    fi
}

rm -rf "$HOME"
mkdir -p "$HOME"
timeout -s KILL 600 npm install -g --no-audit --no-fund @anthropic-ai/claude-code 2>&1 | tail -n 5
check installed "$([ -x /usr/local/bin/claude ] && echo yes)" yes
check version "$(timeout -s KILL 180 claude --version 2>&1 | grep -c 'Claude Code')" 1
check help "$(timeout -s KILL 180 claude --help 2>&1 | grep -c -i 'usage')" 1
rm -rf "$HOME"

if [ "$fail" = 0 ]; then
    echo "cctest: OK"
fi
exit "$fail"
