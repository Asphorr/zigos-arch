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

# /proc: the applets that read it.
sleep 30 &
napper=$!
# The child is a copy of this shell until it has exec'd: give it the time.
tries=0
while read -r comm < "/proc/$napper/comm" && [ "$comm" != sleep ] && [ "$tries" -lt 50 ]; do
    tries=$((tries + 1))
    sleep 0.02
done
check ps "$(ps -o pid,comm | awk -v p="$napper" '$1 == p { print $2 }')" sleep
check pidof "$(busybox pidof sleep | tr ' ' '\n' | grep -c "^$napper\$")" 1
check psargs "$(ps -o pid,args | awk -v p="$napper" '$1 == p { print $2, $3 }')" "sleep 30"
kill "$napper"
wait "$napper"
check free "$(busybox free | awk '/^Mem:/ { print ($2 > 0) }')" 1
check uptime "$(busybox uptime | grep -c 'load average')" 1
check procfd "$(readlink /proc/self/fd/1 | grep -c -e '^pipe:' -e '^/dev/')" 1
check mounts "$(grep -c ' / ext2 ' /proc/mounts)" 1

# The network, on this machine alone: a web server and its client over
# loopback, then a listener and a talker. The server is a shell script nc
# runs per connection, the socket as its stdin and stdout.
mkdir -p "$d/www"
echo "served by busybox" > "$d/www/index.html"
cat > "$d/serve.sh" <<'EOF'
cr=$(printf '\r')
read -r method path proto
while read -r line; do
    [ "$line" = "$cr" ] || [ -z "$line" ] && break
done
if [ -f "$1$path" ]; then
    printf 'HTTP/1.0 200 OK\r\n\r\n'
    cat "$1$path"
else
    printf 'HTTP/1.0 404 Not Found\r\n\r\n'
fi
EOF
nc -lk -p 8081 -e sh "$d/serve.sh" "$d/www" &
web=$!
got=
for try in 1 2 3 4 5 6 7 8 9 10; do
    got=$(wget -q -O - http://127.0.0.1:8081/index.html 2>/dev/null) && break
    sleep 1
done
check http "$got" "served by busybox"
check http404 "$(wget -q -O - http://127.0.0.1:8081/absent 2>&1 | grep -c 'error: HTTP/1.0 404')" 1
kill "$web"
wait "$web"
check refused "$(wget -q -O - http://127.0.0.1:8081/ 2>&1 | grep -c 'Connection refused')" 1
nc -l -p 8082 > "$d/heard" &
listener=$!
for try in 1 2 3 4 5 6 7 8 9 10; do
    echo "over tcp" | nc 127.0.0.1 8082 2>/dev/null && break
    sleep 1
done
wait "$listener"
check nc "$(cat "$d/heard")" "over tcp"

# A dynamically linked busybox, when the image has one
# (tools/add_musl_to_image.sh): the kernel maps it and musl's dynamic
# linker, which links it and starts it.
if [ -f /bin/busybox-dyn ]; then
    bd=/bin/busybox-dyn
    check dynamic "$($bd echo linked at run time)" "linked at run time"
    check dynpipe "$(echo 'b a' | $bd tr ' ' '\n' | $bd sort | $bd tr -d '\n')" ab
    check dynsh "$($bd sh -c 'x=4; echo $((x * x))')" 16
    # The dynamic linker run as a program: it maps busybox itself.
    check ldso "$(/lib/ld-musl-x86_64.so.1 $bd echo by the linker)" "by the linker"
fi

# A script the kernel starts by its #! line: env runs it with execve, and
# musl's execvp doesn't fall back to sh.
printf '#!/bin/sh -e\necho "$0: $1"\n' > "$d/hello.sh"
check shebang "$(env "$d/hello.sh" world)" "$d/hello.sh: world"
printf '#!%s\n' "$d/hello.sh" > "$d/nested.sh"
check shebang2 "$(env "$d/nested.sh" x)" "$d/hello.sh: $d/nested.sh"

rm -rf "$d"
check rm "$([ -e "$d" ] || echo gone)" gone

if [ "$fail" = 0 ]; then
    echo "bbtest: OK"
fi
exit "$fail"
