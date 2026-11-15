# bbtest.sh — a static busybox under ZigOS: its shell runs this, and applets
# through the links in /bin. Each line checked prints nothing when right;
# the script ends with "bbtest: OK" and status 0, or names what differed.
#
# In the image as /etc/bbtest.sh (tools/add_busybox_to_image.sh); boot mode
# 19 runs `busybox sh /etc/bbtest.sh`.

PATH=/bin
export PATH
fail=0

check() {
    if [ "$2" != "$3" ]; then
        echo "bbtest: FAIL $1: got '$2', want '$3'"
        fail=1
    fi
}

# The shell itself: expansion, arithmetic, control flow, functions.
check echo "$(echo hello)" hello
check arith "$((6 * 7 + 1))" 43
x=abcdef
check substr "${x#abc}${x%def}" defabc
n=0
for i in 1 2 3 4; do n=$((n + i)); done
check for "$n" 10
case zigos in z*) c=yes ;; *) c=no ;; esac
check case "$c" yes
twice() { echo "$1$1"; }
check func "$(twice ab)" abab
check status "$(false; echo $?)$(true; echo $?)" 10
check subshell "$( (exit 7); echo $?)" 7

# Applets through the links, pipes between processes.
check tr "$(echo abc | tr a-c A-C)" ABC
check pipe3 "$(echo 'b
a
c' | sort | head -n 2 | tr '\n' ' ')" "a b "
check wc "$(printf 'one\ntwo\nthree\n' | wc -l | tr -d ' ')" 3
check sed "$(echo 'hello world' | sed 's/world/zigos/')" "hello zigos"
check grep "$(printf 'red\ngreen\nblue\n' | grep -c e)" 3
check awk "$(echo '3 4' | awk '{ print $1 * $2 }')" 12
check cut "$(echo 'a:b:c' | cut -d: -f2)" b
check seq "$(seq 1 5 | tr '\n' ' ')" "1 2 3 4 5 "
check expr "$(expr 100 / 7)" 14
check basename "$(basename /a/b/c.txt .txt)$(dirname /a/b/c.txt)" c/a/b
check xargs "$(echo 'x y z' | xargs -n 1 echo | wc -l | tr -d ' ')" 3
check uname "$(uname -s)" Linux

# Files: redirection, append, here-documents, the tree.
d=/tmp/bbtest.$$
rm -rf "$d"
mkdir -p "$d/sub/deep"
check mkdir "$([ -d "$d/sub/deep" ] && echo yes)" yes
echo first > "$d/f"
echo second >> "$d/f"
check append "$(cat "$d/f" | tr '\n' ' ')" "first second "
cat > "$d/here" <<EOF
alpha
beta $((2 + 3))
EOF
check heredoc "$(tail -n 1 "$d/here")" "beta 5"
cp "$d/f" "$d/sub/copy"
check cp "$(cat "$d/sub/copy" | wc -c | tr -d ' ')" 13
mv "$d/sub/copy" "$d/sub/deep/moved"
check mv "$([ -f "$d/sub/deep/moved" ] && [ ! -e "$d/sub/copy" ] && echo yes)" yes
ln -s f "$d/link"
check symlink "$(readlink "$d/link")$(cat "$d/link" | head -n 1)" ffirst
ln "$d/f" "$d/hard"
check hardlink "$(ls -l "$d/hard" | awk '{ print $2 }')" 2
check ls "$(ls "$d" | tr '\n' ' ')" "f hard here link sub "
check find "$(find "$d" -type f | wc -l | tr -d ' ')" 4
check du "$([ -n "$(du -s "$d")" ] && echo yes)" yes
check pwd "$(cd "$d/sub/deep" && pwd)" "$d/sub/deep"
check cd "$(cd "$d/sub" && cd .. && pwd)" "$d"
: > "$d/empty"
check test "$([ -s "$d/f" ] && [ ! -s "$d/empty" ] && [ -L "$d/link" ] && echo yes)" yes
touch "$d/new"
check touch "$([ -e "$d/new" ] && echo yes)" yes

# Processes: background jobs, wait, exit statuses, signals.
(exit 3) &
wait $!
check wait "$?" 3
sleep 5 &
job=$!
kill "$job"
wait "$job"
check kill "$?" 143
got=$(sh -c 'trap "echo trapped" USR1; kill -USR1 $$; echo after')
check trap "$(echo $got)" "trapped after"
check exec "$(sh -c 'exec echo replaced')" replaced
check env "$(FOO=bar env | grep -c '^FOO=bar$')" 1
check kill0 "$(kill -0 $$ && echo alive)" alive
yes | head -n 3 > "$d/yes"
check sigpipe "$(wc -l < "$d/yes" | tr -d ' ')" 3
check dd "$(dd if=/dev/zero bs=1024 count=4 2>/dev/null | wc -c | tr -d ' ')" 4096
check date "$([ "$(date +%Y)" -ge 2024 ] && echo yes)" yes

rm -rf "$d"
check rm "$([ -e "$d" ] || echo gone)" gone

if [ "$fail" = 0 ]; then
    echo "bbtest: OK"
fi
exit "$fail"
