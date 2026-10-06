#!/usr/bin/env bash
# Start a disposable GitLab CE instance for the live acceptance tests, then
# print the environment the tests need (GITLAB_URL, GITLAB_TOKEN,
# GITLAB_PROJECT_ID) as KEY=value lines on stdout.
#
#   scripts/gitlab-ce.sh up   [> env-file]   # start + bootstrap (~5 min)
#   scripts/gitlab-ce.sh down                # remove the container
#
# Requires docker (or podman aliased as docker), curl and jq.
set -euo pipefail

CONTAINER="${GITLAB_CONTAINER:-vault-plugin-gitlab-ce}"
IMAGE="${GITLAB_IMAGE:-gitlab/gitlab-ce:19.4.1-ce.0@sha256:9b33b45b9f42d176bada85ee5ecb81ddab7e506c435f44cd582206e284b2809c}"
PORT="${GITLAB_PORT:-8929}"
URL="http://127.0.0.1:${PORT}"
# Fixed, throwaway credential: the instance only lives for the test run.
TOKEN="${GITLAB_BOOTSTRAP_TOKEN:-glpat-vault-plugin-acceptance}"
TIMEOUT="${GITLAB_BOOT_TIMEOUT:-900}"

log() { echo "[gitlab-ce] $*" >&2; }

up() {
  if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    log "starting $IMAGE on $URL"
    docker run -d --name "$CONTAINER" \
      --shm-size 256m \
      -p "127.0.0.1:${PORT}:${PORT}" \
      -e GITLAB_OMNIBUS_CONFIG="
        external_url '${URL}';
        puma['worker_processes'] = 0;
        sidekiq['concurrency'] = 5;
        prometheus_monitoring['enable'] = false;
        gitlab_rails['usage_ping_enabled'] = false;
        gitlab_rails['initial_root_password'] = 'not-used-$(date +%s)-Aa1!';
      " \
      "$IMAGE" >/dev/null
  fi

  log "waiting for GitLab to be ready (up to ${TIMEOUT}s)"
  local deadline=$((SECONDS + TIMEOUT))
  until curl -fsS -o /dev/null "${URL}/users/sign_in"; do
    if ((SECONDS > deadline)); then
      log "timed out; last container logs:"
      docker logs --tail 100 "$CONTAINER" >&2 || true
      exit 1
    fi
    sleep 10
  done

  log "creating root API token"
  docker exec "$CONTAINER" gitlab-rails runner "
    user = User.find_by_username('root')
    user.personal_access_tokens.where(name: 'vault-acceptance').delete_all
    token = user.personal_access_tokens.build(name: 'vault-acceptance', scopes: ['api'], expires_at: 2.days.from_now)
    token.set_token('${TOKEN}')
    token.save!
  " >&2

  log "creating test project"
  local project_id
  project_id=$(curl -fsS -H "PRIVATE-TOKEN: ${TOKEN}" "${URL}/api/v4/projects?search=vault-acceptance&owned=true" | jq -r '.[0].id // empty')
  if [ -z "$project_id" ]; then
    project_id=$(curl -fsS -X POST -H "PRIVATE-TOKEN: ${TOKEN}" \
      --data-urlencode "name=vault-acceptance" "${URL}/api/v4/projects" | jq -r '.id')
  fi

  log "ready: project ${project_id}"
  echo "GITLAB_URL=${URL}"
  echo "GITLAB_TOKEN=${TOKEN}"
  echo "GITLAB_PROJECT_ID=${project_id}"
}

down() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  log "removed $CONTAINER"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
