#!/usr/bin/env bash
# Только одноразовый runner: контейнер создаётся, но никогда не запускается.
set -euo pipefail
fixture=$(mktemp -d /tmp/ssg-docker-security.XXXXXX)
image="ssg-security-fixture:${GITHUB_RUN_ID:-local}"
container_id=""
cleanup() {
    if [ -n "$container_id" ]; then docker rm "$container_id" >/dev/null; fi
    docker image rm "$image" >/dev/null 2>&1 || true
    rm -rf -- "$fixture"
}
trap cleanup EXIT
printf 'fixture\n' > "$fixture/marker"
tar -C "$fixture" -cf - marker | docker import - "$image" >/dev/null
container_id=$(docker create --network none --privileged --cap-add SYS_ADMIN \
    --security-opt seccomp=unconfined --env SECRET=SSG_SENTINEL_SECRET_VALUE \
    --mount type=bind,source=/etc,target=/host-etc,readonly \
    --mount type=bind,source=/var/run/docker.sock,target=/docker.sock,readonly \
    "$image" /never-executed)
go test -race -c -o "$fixture/exposure.test" ./internal/exposure
sudo env SSG_TEST_CONTAINER_ID="$container_id" "$fixture/exposure.test" -test.v -test.run '^TestRealDockerSecurity$'
