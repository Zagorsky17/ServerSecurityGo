#!/usr/bin/env bash
set -euo pipefail
ssg=${1:?binary path required}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/image/etc/cron.d" "$tmp/image/root/.ssh" "$tmp/archive"
chmod 700 "$tmp/archive"
printf 'root:x:0:0::/root:/bin/bash\n' > "$tmp/image/etc/passwd"
printf 'TOKEN="ssg-collect-canary"\n' > "$tmp/image/etc/cron.d/example"
printf 'ssg-collect-canary\n' > "$tmp/image/root/.ssh/id_ed25519"
export SSG_HOST_ROOT="$tmp/image" SSG_DATA_DIR="$tmp/state" SSG_PROC_ROOT=/proc
export SSG_ALLOWLIST_FILE="$tmp/missing" SSG_AUTH_LOG_ENABLED=true
set +e
"$ssg" triage --format json --output "$tmp/triage.json" --fail-on none
code=$?
set -e
test "$code" = 3
set +e
"$ssg" collect --output "$tmp/archive/evidence.tar.gz" > "$tmp/result.json"
code=$?
set -e
test "$code" = 3
python3 - "$tmp" <<'PY'
import hashlib, json, pathlib, sys, tarfile
p = pathlib.Path(sys.argv[1])
r = json.loads((p / 'triage.json').read_text())
assert r['incomplete'] and not r['snapshot']['processes'], r
archive = p / 'archive/evidence.tar.gz'
assert archive.stat().st_mode & 0o777 == 0o600
result = json.loads((p / 'result.json').read_text())
assert hashlib.sha256(archive.read_bytes()).hexdigest() == result['sha256']
with tarfile.open(archive) as t:
    members = {m.name: t.extractfile(m).read() for m in t.getmembers()}
    manifest = members['MANIFEST.sha256'].decode()
    for name, data in members.items():
        assert b'ssg-collect-canary' not in data, name
        assert 'id_ed25519' not in name, name
        if name != 'MANIFEST.sha256':
            assert f'{hashlib.sha256(data).hexdigest()}  {name}\n' in manifest, name
print('Offline triage and evidence archive verified')
PY
