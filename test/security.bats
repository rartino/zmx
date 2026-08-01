#!/usr/bin/env bats

load test_helper

mode_of() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

@test "fresh directories logs and sockets use exact modes under multiple umasks" {
  local secure_dir="$BATS_TEST_TMPDIR/fresh-secure"
  run env ZMX_DIR="$secure_dir" sh -c 'umask 000; exec "$1" list --short' sh "$ZMX"
  [ "$status" -eq 0 ]
  [ "$(mode_of "$secure_dir")" = 700 ]
  [ "$(mode_of "$secure_dir/logs")" = 700 ]
  [ "$(mode_of "$secure_dir/logs/zmx.log")" = 600 ]

  env ZMX_DIR="$secure_dir" "$ZMX" run socket-mode -d true
  wait_for_session_in_dir() {
    local i=0
    while (( i < 50 )); do
      env ZMX_DIR="$secure_dir" "$ZMX" list --short 2>/dev/null | grep -qx socket-mode && return 0
      sleep 0.1
      (( i++ )) || true
    done
    return 1
  }
  wait_for_session_in_dir
  [ "$(mode_of "$secure_dir/socket-mode")" = 600 ]
  env ZMX_DIR="$secure_dir" "$ZMX" kill --force socket-mode

  local restrictive_dir="$BATS_TEST_TMPDIR/fresh-restrictive"
  run env ZMX_DIR="$restrictive_dir" sh -c 'umask 077; exec "$1" list --short' sh "$ZMX"
  [ "$status" -eq 0 ]
  [ "$(mode_of "$restrictive_dir")" = 700 ]
  [ "$(mode_of "$restrictive_dir/logs")" = 700 ]
  [ "$(mode_of "$restrictive_dir/logs/zmx.log")" = 600 ]
}

@test "rotated logs retain mode 0600" {
  "$ZMX" list --short
  truncate -s 2097152 "$ZMX_DIR/logs/zmx.log"
  chmod 600 "$ZMX_DIR/logs/zmx.log"

  "$ZMX" list --short
  [ "$(mode_of "$ZMX_DIR/logs/zmx.log")" = 600 ]
  [ "$(wc -c < "$ZMX_DIR/logs/zmx.log")" -lt 2097152 ]
}

@test "insecure existing directory fails without repair" {
  local insecure="$BATS_TEST_TMPDIR/insecure"
  mkdir -p "$insecure"
  chmod 755 "$insecure"

  run env ZMX_DIR="$insecure" "$ZMX" list --short
  [ "$status" -ne 0 ]
  [[ "$output" == *"chmod 700"* ]]
  [[ "$output" == *"intended service owner/group"* ]]
  [ "$(mode_of "$insecure")" = 755 ]

  run env ZMX_DIR="$insecure/" "$ZMX" list --short
  [ "$status" -ne 0 ]
  [ "$(mode_of "$insecure")" = 755 ]
}

@test "symlink and wrong-type runtime paths fail closed" {
  local real="$BATS_TEST_TMPDIR/real" link="$BATS_TEST_TMPDIR/link" wrong="$BATS_TEST_TMPDIR/wrong"
  mkdir -p "$real"
  chmod 700 "$real"
  ln -s "$real" "$link"
  printf x > "$wrong"

  run env ZMX_DIR="$link" "$ZMX" list --short
  [ "$status" -ne 0 ]
  [ -L "$link" ]

  run env ZMX_DIR="$wrong" "$ZMX" list --short
  [ "$status" -ne 0 ]
  [ -f "$wrong" ]
}

@test "custom modes apply under umask and existing configured modes are accepted" {
  local shared="$BATS_TEST_TMPDIR/shared"
  run env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 \
    sh -c 'umask 077; exec "$1" list --short' sh "$ZMX"
  [ "$status" -eq 0 ]
  [ "$(mode_of "$shared")" = 770 ]
  [ "$(mode_of "$shared/logs")" = 770 ]
  [ "$(mode_of "$shared/logs/zmx.log")" = 660 ]

  run env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 "$ZMX" list --short
  [ "$status" -eq 0 ]

  env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 \
    "$ZMX" run shared-mode -d true
  wait_for_shared_session() {
    local i=0
    while (( i < 50 )); do
      env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 \
        "$ZMX" list --short 2>/dev/null | grep -qx shared-mode && return 0
      sleep 0.1
      (( i++ )) || true
    done
    return 1
  }
  wait_for_shared_session
  [ "$(mode_of "$shared/shared-mode")" = 660 ]
  [ "$(mode_of "$shared/logs/shared-mode.log")" = 660 ]

  env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 \
    "$ZMX" kill --force shared-mode
}

@test "custom modes do not widen missing non-zmx ancestors" {
  local root="$BATS_TEST_TMPDIR/nested-parents"
  mkdir -p "$root"
  chmod 700 "$root"

  run env -u ZMX_DIR \
    XDG_RUNTIME_DIR="$root/runtime" XDG_STATE_HOME="$root/state" \
    ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 "$ZMX" list --short
  [ "$status" -eq 0 ]

  [ "$(mode_of "$root/runtime")" = 700 ]
  [ "$(mode_of "$root/runtime/zmx")" = 770 ]
  [ "$(mode_of "$root/state")" = 700 ]
  [ "$(mode_of "$root/state/zmx")" = 700 ]
  [ "$(mode_of "$root/state/zmx/logs")" = 770 ]
  [ "$(mode_of "$root/state/zmx/logs/zmx.log")" = 660 ]
}

@test "different-uid members of the configured service group can use owner-created sessions" {
  [ "$(id -u)" -eq 0 ] || skip "requires root to exercise distinct effective UIDs"
  command -v setpriv >/dev/null 2>&1 || skip "requires setpriv"

  local shared="$BATS_TEST_TMPDIR/cross-uid"
  local service_uid=42001 client_uid=42002 shared_gid=42000
  chmod 755 "$BATS_TEST_TMPDIR"
  mkdir -p "$shared/logs"
  chown "$service_uid:$shared_gid" "$shared" "$shared/logs"
  chmod 770 "$shared" "$shared/logs"

  service_zmx() {
    setpriv --reuid="$service_uid" --regid="$shared_gid" --clear-groups \
      env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 "$ZMX" "$@"
  }
  client_zmx() {
    setpriv --reuid="$client_uid" --regid="$shared_gid" --clear-groups \
      env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 "$ZMX" "$@"
  }

  service_zmx run service-session -d true
  local i=0
  while (( i < 50 )); do
    client_zmx list --short 2>/dev/null | grep -qx service-session && break
    sleep 0.1
    (( i++ )) || true
  done
  run client_zmx list --short
  [ "$status" -eq 0 ]
  [[ "$output" == *"service-session"* ]]

  run client_zmx kill --force service-session
  [ "$status" -eq 0 ]

  setpriv --reuid="$client_uid" --regid="$shared_gid" --clear-groups \
    sh -c 'mv "$1/logs" "$1/logs.owner" && mkdir "$1/logs" && chmod 770 "$1/logs"' sh "$shared"
  run client_zmx list --short
  [ "$status" -ne 0 ]
  [[ "$output" == *"WrongOwner"* ]]
}

@test "custom mode mismatches fail without mutation and print dynamic remediation" {
  local wrong_dir="$BATS_TEST_TMPDIR/wrong-dir"
  mkdir -p "$wrong_dir"
  chmod 700 "$wrong_dir"
  run env ZMX_DIR="$wrong_dir" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 "$ZMX" list --short
  [ "$status" -ne 0 ]
  [[ "$output" == *"chmod 770"* ]]
  [ "$(mode_of "$wrong_dir")" = 700 ]

  local wrong_log="$BATS_TEST_TMPDIR/wrong-log"
  mkdir -p "$wrong_log/logs"
  chmod 770 "$wrong_log" "$wrong_log/logs"
  printf old > "$wrong_log/logs/zmx.log"
  chmod 600 "$wrong_log/logs/zmx.log"
  run env ZMX_DIR="$wrong_log" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 "$ZMX" list --short
  [ "$status" -ne 0 ]
  [[ "$output" == *"chmod 660"* ]]
  [ "$(mode_of "$wrong_log/logs/zmx.log")" = 600 ]

  local wrong_socket="$BATS_TEST_TMPDIR/wrong-socket"
  env ZMX_DIR="$wrong_socket" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 \
    "$ZMX" run socket-mismatch -d true
  local i=0
  while (( i < 50 )); do
    [ -S "$wrong_socket/socket-mismatch" ] && break
    sleep 0.1
    (( i++ )) || true
  done
  [ -S "$wrong_socket/socket-mismatch" ]
  chmod 600 "$wrong_socket/socket-mismatch"
  run env ZMX_DIR="$wrong_socket" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 \
    "$ZMX" run socket-mismatch -d true
  [ "$status" -ne 0 ]
  [[ "$output" == *"chmod 660"* ]]
  [ "$(mode_of "$wrong_socket/socket-mismatch")" = 600 ]
  chmod 660 "$wrong_socket/socket-mismatch"
  env ZMX_DIR="$wrong_socket" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 \
    "$ZMX" kill --force socket-mismatch
}

@test "custom log mode survives rotation" {
  local shared="$BATS_TEST_TMPDIR/rotate-shared"
  env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 "$ZMX" list --short
  truncate -s 2097152 "$shared/logs/zmx.log"
  chmod 660 "$shared/logs/zmx.log"

  env ZMX_DIR="$shared" ZMX_DIR_MODE=770 ZMX_LOG_MODE=660 "$ZMX" list --short
  [ "$(mode_of "$shared/logs/zmx.log")" = 660 ]
  [ "$(wc -c < "$shared/logs/zmx.log")" -lt 2097152 ]
}

@test "malformed and out-of-range mode values fail clearly" {
  run env ZMX_DIR_MODE=888 "$ZMX" list --short
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid ZMX_DIR_MODE"* ]]
  [[ "$output" == *"octal permission mode"* ]]

  run env ZMX_LOG_MODE=1000 "$ZMX" list --short
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid ZMX_LOG_MODE"* ]]
}

@test "insecure existing logs fail without mutation" {
  local secure="$BATS_TEST_TMPDIR/log-path" target="$BATS_TEST_TMPDIR/log-target"
  mkdir -p "$secure/logs"
  chmod 700 "$secure" "$secure/logs"
  printf old > "$target"
  chmod 600 "$target"
  ln -s "$target" "$secure/logs/zmx.log"

  run env ZMX_DIR="$secure" "$ZMX" list --short
  [ "$status" -ne 0 ]
  [[ "$output" == *"chmod 600"* ]]
  [ -L "$secure/logs/zmx.log" ]

  rm "$secure/logs/zmx.log"
  printf old > "$secure/logs/zmx.log"
  chmod 644 "$secure/logs/zmx.log"
  run env ZMX_DIR="$secure" "$ZMX" list --short
  [ "$status" -ne 0 ]
  [ "$(mode_of "$secure/logs/zmx.log")" = 644 ]
}

@test "insecure per-session log fails visibly before daemonization" {
  "$ZMX" list --short
  printf old > "$ZMX_DIR/logs/preflight.log"
  chmod 644 "$ZMX_DIR/logs/preflight.log"

  run "$ZMX" run preflight -d true
  [ "$status" -ne 0 ]
  [[ "$output" == *"chmod 600"* ]]
  [[ "$output" == *"chown"* ]]
  [ "$(mode_of "$ZMX_DIR/logs/preflight.log")" = 644 ]
  [ ! -e "$ZMX_DIR/preflight" ]
}

@test "wrong-type and symlink session sockets fail without mutation" {
  local regular="$ZMX_DIR/not-a-socket" target="$BATS_TEST_TMPDIR/socket-target"
  printf x > "$regular"
  chmod 600 "$regular"
  run "$ZMX" run not-a-socket -d true
  [ "$status" -ne 0 ]
  [[ "$output" == *"chmod 600"* ]]
  [ -f "$regular" ]

  printf x > "$target"
  chmod 600 "$target"
  ln -s "$target" "$ZMX_DIR/socket-link"
  run "$ZMX" run socket-link -d true
  [ "$status" -ne 0 ]
  [ -L "$ZMX_DIR/socket-link" ]
}

@test "internal runtime names are reserved" {
  run "$ZMX" run logs -d true
  [ "$status" -ne 0 ]
  [ -d "$ZMX_DIR/logs" ]
}

@test "no-HOME fallback keeps log and socket namespaces separate" {
  local fallback_root="$BATS_TEST_TMPDIR/fallback-root"
  local runtime_dir="$fallback_root/zmx-$(id -u)"
  mkdir -p "$fallback_root"

  run env -u ZMX_DIR -u XDG_RUNTIME_DIR -u XDG_STATE_HOME -u HOME \
    TMPDIR="$fallback_root" "$ZMX" run fallback-session -d true
  [ "$status" -eq 0 ]
  [ -S "$runtime_dir/fallback-session" ]
  [ -f "$runtime_dir/logs/fallback-session.log" ]
  [ "$(mode_of "$runtime_dir")" = 700 ]
  [ "$(mode_of "$runtime_dir/logs")" = 700 ]

  env -u ZMX_DIR -u XDG_RUNTIME_DIR -u XDG_STATE_HOME -u HOME \
    TMPDIR="$fallback_root" "$ZMX" kill --force fallback-session
}

@test "default input policy rejects opt-in mismatch before PTY queue" {
  "$ZMX" run policy-default -d echo ready
  wait_for_session policy-default

  run "$ZMX" send --log-input policy-default never-queued-secret
  [ "$status" -ne 0 ]

  run "$ZMX" history policy-default
  [[ "$output" != *"never-queued-secret"* ]]
}

@test "logging-enabled session requires explicit acknowledgment" {
  run "$ZMX" run --log-input policy-logged -d echo ready
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  wait_for_session policy-logged

  run "$ZMX" send policy-logged never-queued-default
  [ "$status" -ne 0 ]

  run "$ZMX" send --log-input policy-logged acknowledged-input
  [ "$status" -eq 0 ]
}

@test "malformed IPC frames do not terminate the session daemon" {
  command -v python3 >/dev/null || skip "python3 is unavailable"
  "$ZMX" run malformed-frames -d echo ready
  wait_for_session malformed-frames

  python3 - "$ZMX_DIR/malformed-frames" <<'PY'
import socket
import struct
import sys

path = sys.argv[1]

def frame(tag, payload=b""):
    return struct.pack("<BI3x", tag, len(payload)) + payload

def connect():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    return sock

sock = connect()
sock.sendall(frame(8, b"\xff"))
sock.close()

sock = connect()
sock.sendall(frame(19, b"\x00"))
header = b""
while len(header) < 8:
    header += sock.recv(8 - len(header))
assert header[0] == 10
sock.sendall(frame(12, struct.pack("<I", 0xffffffff)))
sock.close()

sock = connect()
sock.sendall(frame(11, b"\x00valid-target"))
sock.close()

# Oversized declared input is rejected as soon as its header arrives.
sock = connect()
sock.sendall(struct.pack("<BI3x", 0, 1024 * 1024 + 1))
sock.close()
PY

  sleep 0.2
  run "$ZMX" list --short
  [ "$status" -eq 0 ]
  [[ "$output" == *"malformed-frames"* ]]
}

@test "write is atomic within its advertised limit and rejects larger input" {
  local input="$BATS_TEST_TMPDIR/write-input"
  local dest="$BATS_TEST_TMPDIR/write-output"
  local oversized="$BATS_TEST_TMPDIR/write-oversized"
  head -c 122880 /dev/zero | tr '\0' x > "$input"
  head -c 131073 /dev/zero > "$oversized"

  "$ZMX" run atomic-write -d bash -c 'stty -echo; echo ready'
  wait_for_output atomic-write ready
  run bash -c '"$1" write atomic-write "$2" < "$3"' bash "$ZMX" "$dest" "$input"
  [ "$status" -eq 0 ]

  local i=0
  while (( i < 100 )); do
    [ -f "$dest" ] && cmp -s "$input" "$dest" && break
    sleep 0.1
    (( i++ )) || true
  done
  cmp -s "$input" "$dest"

  run bash -c '"$1" write atomic-write "$2" < "$3"' bash "$ZMX" "$dest.too-large" "$oversized"
  [ "$status" -ne 0 ]
  [ ! -e "$dest.too-large" ]

  local newline_dest="$BATS_TEST_TMPDIR/path-with-trailing-newline"$'\n'
  local stripped_dest="${newline_dest%$'\n'}"
  run bash -c 'printf newline-safe | "$1" write atomic-write "$2"' bash "$ZMX" "$newline_dest"
  [ "$status" -eq 0 ]
  [ -f "$newline_dest" ]
  [ ! -e "$stripped_dest" ]
  [ "$(cat "$newline_dest")" = newline-safe ]
}

@test "write does not report success while the foreground process is not reading" {
  local dest="$BATS_TEST_TMPDIR/busy-write-output"
  "$ZMX" run busy-write -d bash -c 'sleep 6; echo awake'
  wait_for_session busy-write

  run bash -c 'printf should-not-ack | "$1" write busy-write "$2"' bash "$ZMX" "$dest"
  [ "$status" -ne 0 ]
  [ ! -e "$dest" ]
}

@test "default session logs contain neither plaintext nor hex PTY input" {
  local secret="zmx-noecho-7c04d913"
  local hex
  hex=$(printf %s "$secret" | od -An -tx1 | tr -d ' \n')

  "$ZMX" run no-input-log -d bash -c 'stty -echo; IFS= read -r value; stty echo; printf done'
  wait_for_session no-input-log
  "$ZMX" send no-input-log "${secret}"$'\r'
  wait_for_output no-input-log done

  ! grep -R -F "$secret" "$ZMX_DIR/logs"
  ! grep -R -F "$hex" "$ZMX_DIR/logs"
}

@test "opt-in session logs PTY input exactly once" {
  local secret="zmx-optin-f6e15a27"
  local hex
  hex=$(printf %s "$secret" | od -An -tx1 | tr -d ' \n')

  "$ZMX" run --log-input opt-input-log -d echo ready
  wait_for_session opt-input-log
  "$ZMX" send --log-input opt-input-log "$secret"

  local count=0 i=0
  while (( i < 50 )); do
    count=$(grep -R -F -o "$hex" "$ZMX_DIR/logs" | wc -l | tr -d ' ')
    [ "$count" -eq 1 ] && break
    sleep 0.1
    (( i++ )) || true
  done
  [ "$count" -eq 1 ]
}

@test "nested switch applies prefix once creates target and carries no old input" {
  command -v script >/dev/null || skip "script utility is unavailable"
  script --version 2>&1 | grep -q util-linux || skip "test requires util-linux script"

  local secret="old-session-typeahead-3d8a"
  local inner_cmd="sleep 0.6; '$ZMX' attach inner"
  {
    sleep 0.2
    printf %s "$secret"
    sleep 1.5
    printf '\034'
  } | timeout 8 script -qfec \
    "env ZMX_DIR='$ZMX_DIR' ZMX_SESSION_PREFIX='sw.' '$ZMX' attach outer bash -lc \"$inner_cmd\"" \
    /dev/null

  run "$ZMX" list --short
  [ "$status" -eq 0 ]
  [[ "$output" == *"sw.inner"* ]]
  [[ "$output" != *"sw.sw.inner"* ]]

  run "$ZMX" history sw.inner
  [ "$status" -eq 0 ]
  [[ "$output" != *"$secret"* ]]
}
