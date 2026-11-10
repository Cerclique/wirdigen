#!/bin/sh
# Temporary: records tshark gotchas for the #51 PR. Not a test; never fails.
lua=$PWD/crates/wirdigen/tests/cases/uints/uints.lua
dir=$(mktemp -d)
chmod 755 "$dir"
cd "$dir" || exit 0
export LC_ALL=C TZ=UTC WIRESHARK_CONFIG_DIR="$dir/config"
mkdir -p config
printf '0000  01 02 03 04 05 06 07\n' > one.txt
text2pcap -q -u 40000,9999 one.txt one.pcapng
printf 'local x = = 1\n' > bad.lua
chmod -R a+rwX "$dir"

as() {
  if [ "$(id -u)" = 0 ] && id tester >/dev/null 2>&1; then
    runuser -u tester -- env HOME=/home/tester LC_ALL=C TZ=UTC WIRESHARK_CONFIG_DIR="$dir/config" "$@"
  else
    "$@"
  fi
}

echo "== uid $(id -u): Lua load error"
as tshark -r one.pcapng -X lua_script:bad.lua; echo "exit status: $?"
echo "== uid $(id -u): Lua load error with -d"
as tshark -r one.pcapng -X lua_script:bad.lua -d udp.port==9999,uints; echo "exit status: $?"

echo "== uid $(id -u) (as is): uints.lua"
tshark -r one.pcapng -X lua_script:"$lua" -d udp.port==9999,uints -O uints; echo "exit status: $?"

echo "== empty UDP payload (full UDP header, -4 -i 17)"
printf '0000  9c 40 27 0f 00 08 00 00\n' > empty.txt
text2pcap -q -4 10.0.0.1,10.0.0.2 -i 17 empty.txt empty.pcapng; echo "text2pcap exit: $?"
as tshark -r empty.pcapng -X lua_script:"$lua" -d udp.port==9999,uints -O udp,uints; echo "exit status: $?"
as tshark -r empty.pcapng -X lua_script:"$lua" -d udp.port==9999,uints -T json -J "uints _ws.lua" --no-duplicate-keys
echo "== offset-0 line without bytes"
printf '0000\n' > none.txt
text2pcap -u 40000,9999 none.txt none.pcapng; echo "text2pcap exit: $?"
as tshark -r none.pcapng 2>&1; echo "exit status: $?"
echo "== -J uints JSON of one packet"
as tshark -r one.pcapng -X lua_script:"$lua" -d udp.port==9999,uints -T json -J uints --no-duplicate-keys
exit 0
