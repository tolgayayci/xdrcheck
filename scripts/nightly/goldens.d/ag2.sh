# shellcheck shell=bash
# Nightly golden part `ag2`: sourced by scripts/nightly/goldens.sh after nightly_init, which provides
# the lib.sh helpers, tag, goldens_root and tree. Not run on its own.
t0=$(date +%s)
image="$(pin stellar_core.test_image)"
if skipped ag2; then
  result ag2 SKIPPED 0 "XDRCHECK_NIGHTLY_SKIP names ag2"
elif [ ! -f "$tree/FETCHED.json" ]; then
  result ag2 BLOCKED 0 "no golden tree at $tree; run make fetch"
elif ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  result ag2 BLOCKED 0 "docker is not available; AG-2 runs the stellar-core test image in a container"
elif ! docker image inspect "$image" >/dev/null 2>&1; then
  result ag2 BLOCKED 0 "the stellar-core test image is not present (${image%%@*}); make fetch-nightly pulls it by digest"
else
  name="${XDRCHECK_DOCKER_PREFIX:-xdrcheck-nightly}-ag2-$$"
  trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
  set +e
  # The tree is mounted read-only; the tests write their scratch state into a working directory on disk (a tmpfs
  # would count against the container's memory limit, and the [tx] tests' buckets outgrow it). AG2_MEMORY sets the
  # limit; the container is kept until its state is read, so an out-of-memory kill is reported as one.
  work="$OUT/ag2-work"; rm -rf "$work"; mkdir -p "$work"
  docker run --name "$name" --network none --memory "${AG2_MEMORY:-12g}" --user "$(id -u):$(id -g)" \
    --volume "$tree:/goldens:ro" --volume "$work:/work" --workdir /work \
    --entrypoint /usr/bin/stellar-core "$image" \
    test '[tx]' --ll fatal -r simple --disable-dots --rng-seed 12345 --check-lcm /goldens \
    >"$OUT/ag2.log" 2>&1
  rc=$?
  oom=$(docker inspect -f '{{.State.OOMKilled}}' "$name" 2>/dev/null || echo unknown)
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
  set -e
  trap - EXIT
  [ "$oom" = true ] && echo "  ag2: killed for exceeding the ${AG2_MEMORY:-12g} memory limit (AG2_MEMORY raises it)"
  tail -n 5 "$OUT/ag2.log" | sed 's/^/  ag2: /'
  if [ $rc = 0 ]; then
    result ag2 PASS $(($(date +%s) - t0)) "stellar-core's --check-lcm accepts the golden tree at $tag"
  else
    result ag2 FAIL $(($(date +%s) - t0)) "stellar-core test --check-lcm exited $rc; see $OUT/ag2.log"
  fi
fi
