#!/usr/bin/env bash

# Copyright 2020 The Kubermatic Kubernetes Platform contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

### Contains commonly used functions for the other scripts.

# Required for signal propagation to work so
# the cleanup trap gets executed when a script
# receives a SIGINT
set -o monitor

# Get the operating system
# Possible values are:
#		* linux for linux
#		* darwin for macOS
#
# usage:
# if [ "${OS}" == "darwin" ]; then
#   # do macos stuff
# fi
OS="$(echo $(uname) | tr '[:upper:]' '[:lower:]')"

worker_name() {
  echo "${KUBERMATIC_WORKERNAME:-$(uname -n)}" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]'
}

retry() {
  # Works only with bash but doesn't fail on other shells
  start_time=$(date +%s)
  set +e
  actual_retry $@
  rc=$?
  set -e
  elapsed_time=$(($(date +%s) - $start_time))
  write_junit "$rc" "$elapsed_time"
  return $rc
}

# We use an extra wrapping to write junit and have a timer
actual_retry() {
  retries=$1
  shift

  count=0
  delay=1
  until "$@"; do
    rc=$?
    count=$((count + 1))
    if [ $count -lt "$retries" ]; then
      echo "Retry $count/$retries exited $rc, retrying in $delay seconds..." > /dev/stderr
      sleep $delay
    else
      echo "Retry $count/$retries exited $rc, no more retries left." > /dev/stderr
      return $rc
    fi
    delay=$((delay * 2))
  done
  return 0
}

echodate() {
  # do not use -Is to keep this compatible with macOS
  echo "[$(date +%Y-%m-%dT%H:%M:%S%:z)]" "$@"
}

write_junit() {
  # Doesn't make any sense if we don't know a testname
  if [ -z "${TEST_NAME:-}" ]; then return; fi
  # Only run in CI
  if [ -z "${ARTIFACTS:-}" ]; then return; fi

  rc=$1
  duration=${2:-0}
  errors=0
  failure=""
  if [ "$rc" -ne 0 ]; then
    errors=1
    failure='<failure type="Failure">Step failed</failure>'
  fi
  TEST_CLASS="${TEST_CLASS:-Kubermatic}"
  cat << EOF > ${ARTIFACTS}/junit.$(echo $TEST_NAME | sed 's/ /_/g' | tr '[:upper:]' '[:lower:]').xml
<?xml version="1.0" ?>
<testsuites>
  <testsuite errors="$errors" failures="$errors" name="$TEST_CLASS" tests="1">
    <testcase classname="$TEST_CLASS" name="$TEST_NAME" time="$duration">
      $failure
    </testcase>
  </testsuite>
</testsuites>
EOF
}

is_containerized() {
  # we're inside a Kubernetes pod/container or inside a container launched by containerize()
  [ -n "${KUBERNETES_SERVICE_HOST:-}" ] || [ -n "${CONTAINERIZED:-}" ]
}

containerize() {
  local cmd="$1"
  local image="${CONTAINERIZE_IMAGE:-quay.io/kubermatic/util:2.6.0}"
  local gocache="${CONTAINERIZE_GOCACHE:-/tmp/.gocache}"
  local gomodcache="${CONTAINERIZE_GOMODCACHE:-/tmp/.gomodcache}"
  local skip="${NO_CONTAINERIZE:-}"

  # short-circuit containerize when in some cases it needs to be avoided
  [ -n "$skip" ] && return

  if ! is_containerized; then
    echodate "Running $cmd in a Docker container using $image..."
    mkdir -p "$gocache"
    mkdir -p "$gomodcache"

    exec docker run \
      -v "$PWD":/go/src/k8c.io/dashboard \
      -v "$gocache":"$gocache" \
      -v "$gomodcache":"$gomodcache" \
      -w /go/src/k8c.io/dashboard \
      -e "GOCACHE=$gocache" \
      -e "GOMODCACHE=$gomodcache" \
      -e "CONTAINERIZED=true" \
      -u "$(id -u):$(id -g)" \
      --entrypoint="$cmd" \
      --rm \
      -it \
      $image $@

    exit $?
  fi
}

# appendTrap appends to existing traps, if any. It is needed because Bash replaces existing handlers
# rather than appending: https://stackoverflow.com/questions/3338030/multiple-bash-traps-for-the-same-signal
# Needing this func is a strong indicator that Bash is not the right language anymore. Also, this
# basically needs unit tests.
appendTrap() {
  command="$1"
  signal="$2"

  # Have existing traps, must append
  if [[ "$(trap -p | grep $signal)" ]]; then
    existingHandlerName="$(trap -p | grep $signal | awk '{print $3}' | tr -d "'")"

    newHandlerName="${command}_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13)"
    # Need eval to get a random func name
    eval "$newHandlerName() { $command; $existingHandlerName; }"
    echodate "Appending $command as trap for $signal, existing command $existingHandlerName"
    trap $newHandlerName $signal
  # First trap
  else
    echodate "Using $command as trap for $signal"
    trap $command $signal
  fi
}

# returns the current time as a number of milliseconds
nowms() {
  echo $(($(date +%s%N) / 1000000))
}

# returns the number of milliseconds elapsed since the given time
elapsed() {
  echo $(($(nowms) - $1))
}

# pushes a Prometheus metric to a pushgateway
pushMetric() {
  local metric="$1"
  local value="$2"
  local labels="${3:-}"
  local kind="${4:-gauge}"
  local help="${5:-}"
  local pushgateway="${PUSHGATEWAY_URL:-}"
  local job="ci"
  local instance="${PROW_JOB_ID:-}"
  local prowjob="${JOB_NAME:-}"

  if [ -z "$pushgateway" ]; then
    return
  fi

  local payload="# TYPE $metric $kind"

  if [ -n "$help" ]; then
    payload="$payload\n# HELP $metric $help"
  fi

  if [ -n "$labels" ]; then
    labels=",$labels"
  fi

  payload="$payload\n$metric{prowjob=\"$prowjob\"$labels} $value\n"

  echo -e "$payload" | curl --data-binary @- -s "$pushgateway/metrics/job/$job/instance/$instance"
}

pushElapsed() {
  pushMetric "$1" $(elapsed $2) "${3:-}" "${4:-}" "${5:-}"
}

# err print an error log to stderr
err() {
  echo "$(date) E: $*" >> /dev/stderr
}

# fatal can be used to print logs to stderr
fatal() {
  echo "$(date) F: $*" >> /dev/stderr
  exit 1
}

check_all_deployments_ready() {
  local namespace="$1"

  # check that Deployments have been created
  local deployments
  deployments=$(kubectl -n $namespace get deployments -o json)

  if [ $(echo "$deployments" | jq '.items | length') -eq 0 ]; then
    echodate "No Deployments created yet."
    return 1
  fi

  # check that all Deployments are ready
  local unready
  unready=$(echo "$deployments" | jq -r '[.items[] | select(.spec.replicas > 0) | select (.status.availableReplicas < .spec.replicas) | .metadata.name] | @tsv')
  if [ -n "$unready" ]; then
    echodate "Not all Deployments have finished rolling out, namely: $unready"
    return 1
  fi

  return 0
}

check_pod_count() {
  [[ $(kubectl --namespace "$1" get pods --selector "$2" --output json | jq -r '.items | length') -eq $3 ]]
}

check_seed_ready() {
  status="$(kubectl --namespace "$1" get seed "$2" --output json | jq -r '.status.conditions.ResourcesReconciled.status')"
  if [ "$status" != "True" ]; then
    echodate "Seed does not yet have ResourcesReconciled=True condition."
    return 1
  fi

  return 0
}

cleanup_kubermatic_clusters_in_kind() {
  # Tolerate errors and just continue
  set +e

  # Clean up clusters
  echodate "Cleaning up clusters..."
  kubectl delete cluster --all --ignore-not-found=true
  echodate "Done cleaning up clusters"
  # Kill all descendant processes
  pkill -P $$
  set -e
}

docker_logs() {
  if [[ $? -ne 0 ]]; then
    echodate "Printing Docker logs"
    cat /tmp/docker.log
    echodate "Done printing Docker logs"
  fi
}

start_docker_daemon_ci() {
  # DOCKER_REGISTRY_MIRROR_ADDR is injected via Prow preset;
  # start-docker.sh is part of the build image.
  DOCKER_REGISTRY_MIRROR="${DOCKER_REGISTRY_MIRROR_ADDR:-}" DOCKER_MTU=1400 start-docker.sh
}

start_docker_daemon() {
  if docker stats --no-stream > /dev/null 2>&1; then
    echodate "Not starting Docker again, it's already running."
    return
  fi

  # Start Docker daemon
  echodate "Starting Docker"
  dockerd > /tmp/docker.log 2>&1 &

  echodate "Started Docker successfully"
  appendTrap docker_logs EXIT

  # Wait for Docker to start
  echodate "Waiting for Docker"
  retry 5 docker stats --no-stream
  echodate "Docker became ready"
}

repeat() {
  local end=$1
  local str="${2:-=}"

  for i in $(seq 1 $end); do
    echo -n "${str}"
  done
}

heading() {
  local title="$@"
  echo "$title"
  repeat ${#title} "="
  echo
}

# copy_crds_to_chart is used during GitHub releases and for e2e tests,
# it ensures that the auto-generated CRDs in pkg/ are copied into the
# operator chart.
copy_crds_to_chart() {
  chartCRDs=charts/kubermatic-operator/crd/k8c.io
  sourceCRDs=pkg/crd/k8c.io

  mkdir -p $chartCRDs
  cp $sourceCRDs/* $chartCRDs
}

# go_test wraps running `go test` commands. The first argument needs to be file name
# for a junit result file that will be generated if go-junit-report is present and
# $ARTIFACTS is set. The remaining arguments are passed to `go test`.
go_test() {
  local junit_name="${1:-}"
  shift

  # only run go-junit-report if binary is present and we're in CI / the ARTIFACTS environment is set
  if [ -x "$(command -v go-junit-report)" ] && [ ! -z "${ARTIFACTS:-}" ]; then
    go test "$@" 2>&1 | go-junit-report -set-exit-code -iocopy -out ${ARTIFACTS}/junit.${junit_name}.xml
  else
    go test "$@"
  fi
}

# safebase64 ensures the given value is base64-encoded.
# If the given value is already encoded, it will be echoed
# unchanged.
safebase64() {
  local value="$1"

  set +e
  decoded="$(echo "$value" | base64 -d 2> /dev/null)"
  if [ $? -eq 0 ]; then
    echo "$value"
    return 0
  fi

  echo "$value" | base64 -w0
  echo
}

run_swagger() {
  # For some reason, since go-swagger 0.30.0, GOFLAGS with `-trimpath` causes
  # Swagger to ignore/forget/don't see half of the necessary types and completely
  # mangles the generated spec.
  # After multiple days of debugging we simply gave up and ensure that GOFLAGS
  # is not set for generating/verifying the Swagger spec.
  export GOFLAGS=

  go run github.com/go-swagger/go-swagger/cmd/swagger $@
}

kubermatic_git_hash() {
  cd modules/api/

  # in most cases this gives us something like "v2.21.1-0.20221111113237-e6c193aeffb0",
  # but this can also be a tagged release
  selector="$(go list -json -m k8c.io/kubermatic/v2 | jq -r '.Replace.Version // .Version')"

  # parse Go's pseudo version and extract git hash if possible
  if ! [[ "$selector" =~ ^v.+-.+-([a-f0-9]+)$ ]]; then
    # seems like we have a fixed tag like "v2.20.7"
    echo "$selector"
    return
  fi

  # selector is in fact a pseudo version, abuse github to resolve it to the full hash
  selector="${BASH_REMATCH[1]}"
  patchURL="https://github.com/kubermatic/kubermatic/commit/$selector.patch"

  # first line in the patch file contains the hash and date, like
  # "From 09081f7b55200900773e079260d15a403382f756 Mon Sep 17 00:00:00 2001";
  # this uses https://unix.stackexchange.com/a/13472 to extract the hash
  curl --silent "$patchURL" | grep -oP '^From \K\w+'
}

ensure_github_host_pubkey() {
  # check whether we already have a known_hosts entry for Github
  if ssh-keygen -F github.com > /dev/null 2>&1; then
    echo " [*] Github's SSH host key already present" > /dev/stderr
  else
    local github_rsa_key
    # https://help.github.com/en/github/authenticating-to-github/githubs-ssh-key-fingerprints
    github_rsa_key="github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk="

    echo " [*] Adding Github's SSH host key to known hosts" > /dev/stderr
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    echo "$github_rsa_key" >> "$HOME/.ssh/known_hosts"
    chmod 600 "$HOME/.ssh/known_hosts"
  fi
}
