#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 davidlahoz
# ca-backup.sh: nightly, read-only export of Entra Conditional Access config to git.
# Auth: OAuth2 client credentials with a certificate (no client secrets).
# See README.md for setup, permissions and troubleshooting.
set -Eeuo pipefail
shopt -s inherit_errexit
export LC_ALL=C

readonly GRAPH=https://graph.microsoft.com/v1.0
readonly KEY_FILE=${KEY_FILE:-/run/secrets/app_key}
readonly CRT_FILE=${CRT_FILE:-/run/secrets/app_crt}
readonly AUDIT_HOURS=26

# Export targets: <folder name> -> <Graph v1.0 path>. Extend here (Intune, app registrations, ...).
declare -A TARGETS=(
  [ca-policies]=identity/conditionalAccess/policies
  [named-locations]=identity/conditionalAccess/namedLocations
  [auth-strengths]=policies/authenticationStrengthPolicies
)

WORK='' REPO='' TOKEN='' FAIL_LINE='' FAIL_MSG=''

log() { printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "${TENANT_LABEL:-?}" "$*" >&2; }
die() { FAIL_MSG=$*; FAIL_LINE=${BASH_LINENO[0]}; log "ERROR: $*"; exit 1; }

notify() { # <priority> <title> <message>; optional, never fails the run
  [[ -n ${NTFY_URL:-} ]] || return 0
  local auth=()
  [[ -n ${NTFY_TOKEN:-} ]] && auth=(-H "Authorization: Bearer $NTFY_TOKEN")
  curl -sS --max-time 15 "${auth[@]}" -H "Priority: $1" -H "Title: $2" \
    --data-binary "$3" "$NTFY_URL" >/dev/null || log "WARN: ntfy notification failed"
}

on_exit() {
  local rc=$?
  if [[ -n $WORK && -d $WORK ]]; then rm -rf -- "$WORK"; fi
  if ((rc != 0)); then
    log "FAILED (exit $rc, line ${FAIL_LINE:-?})"
    notify urgent "CA backup FAILED [${TENANT_LABEL:-?}]" \
      "exit $rc at line ${FAIL_LINE:-?}${FAIL_MSG:+: $FAIL_MSG}"
  fi
}

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

uuid() { # random 128-bit id in UUID format (used as JWT jti)
  local h; h=$(openssl rand -hex 16)
  printf '%s-%s-4%s-%s-%s' "${h:0:8}" "${h:8:4}" "${h:13:3}" "${h:16:4}" "${h:20:12}"
}

check_env() {
  local v missing=()
  for v in TENANT_ID CLIENT_ID TENANT_LABEL GIT_REPO; do
    [[ -n ${!v:-} ]] || missing+=("$v")
  done
  ((${#missing[@]} == 0)) || die "missing required env: ${missing[*]}"
  [[ $TENANT_LABEL =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || die "TENANT_LABEL must match [A-Za-z0-9_-]"
  [[ -r $KEY_FILE ]] || die "private key not readable: $KEY_FILE"
  [[ -r $CRT_FILE ]] || die "certificate not readable: $CRT_FILE"
}

# Client assertion JWT (RS256), see "Microsoft identity platform certificate credentials".
make_assertion() {
  local now x5t header claims sig
  now=$(date +%s)
  x5t=$(openssl x509 -in "$CRT_FILE" -outform DER | openssl dgst -sha1 -binary | b64url)
  header=$(jq -cjn --arg x5t "$x5t" '{alg: "RS256", typ: "JWT", x5t: $x5t}' | b64url)
  claims=$(jq -cjn --arg aud "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
    --arg sub "$CLIENT_ID" --arg jti "$(uuid)" --argjson now "$now" \
    '{aud: $aud, iss: $sub, sub: $sub, jti: $jti, nbf: $now, iat: $now, exp: ($now + 600)}' | b64url)
  sig=$(printf '%s.%s' "$header" "$claims" | openssl dgst -sha256 -sign "$KEY_FILE" -binary | b64url)
  printf '%s.%s.%s' "$header" "$claims" "$sig"
}

get_token() {
  local assertion resp
  assertion=$(make_assertion)
  resp=$(curl -sS --fail-with-body --max-time 30 \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "scope=https://graph.microsoft.com/.default" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=$assertion" \
    "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token") ||
    die "token request failed: $(jq -r '.error_description // .error // .' <<<"$resp" 2>/dev/null | head -c 600 || true)"
  TOKEN=$(jq -r '.access_token // empty' <<<"$resp")
  [[ -n $TOKEN ]] || die "token response contained no access_token"
}

graph_get_all() { # <path> <outfile>: GET all pages (@odata.nextLink), write merged .value array
  local url="$GRAPH/$1" out=$2 page n=0 dir
  dir=$(mktemp -d "$WORK/pages.XXXXXX")
  while [[ -n $url ]]; do
    n=$((n + 1))
    page=$(curl -sS --fail-with-body --max-time 60 --retry 3 \
      -H "Authorization: Bearer $TOKEN" -H "Accept: application/json" "$url") ||
      die "Graph GET failed (${url%%\?*}): $(jq -c '.error // .' <<<"$page" 2>/dev/null | head -c 600 || true)"
    printf '%s' "$page" >"$dir/$n.json"
    url=$(jq -r '."@odata.nextLink" // empty' <<<"$page")
  done
  jq -s '[.[].value[]]' "$dir"/*.json >"$out"
}

safe_name() { # file-system safe, stable, max 80 chars
  local s=${1//[^A-Za-z0-9._-]/_}
  s=${s#.}
  printf '%s' "${s:0:80}"
}

export_target() { # <target>
  local t=$1 dir="$REPO/$TENANT_LABEL/$1" json="$WORK/$1.json" count prev obj id name
  graph_get_all "${TARGETS[$t]}" "$json"
  count=$(jq length "$json")
  if [[ $t == ca-policies ]]; then
    prev=0
    if [[ -d $dir ]]; then prev=$(find "$dir" -name '*.json' | wc -l); fi
    if ((count == 0 && prev > 0)); then
      die "empty-export guard: 0 CA policies exported but repo has $prev; refusing to commit"
    fi
  fi
  rm -rf -- "$dir" && mkdir -p "$dir"   # rebuild so deletions show up in git
  while IFS= read -r obj; do
    id=$(jq -r '.id' <<<"$obj")
    name=$(jq -r '.displayName // "unnamed"' <<<"$obj")
    jq -S . <<<"$obj" >"$dir/$(safe_name "$name")__$(safe_name "$id").json"
  done < <(jq -c '.[]' "$json")
  log "$t: $count exported"
}

audit_lines() { # best effort: never fails the backup
  local since filter
  since=$(date -u -d "-$AUDIT_HOURS hours" +%FT%TZ)
  filter=$(jq -rn --arg f "activityDateTime ge $since and loggedByService eq 'Conditional Access'" '$f | @uri')
  if ! (graph_get_all "auditLogs/directoryAudits?\$filter=$filter" "$WORK/audit.json"); then
    log "WARN: audit enrichment failed; continuing without it"
    echo "- (audit log unavailable)"
    return 0
  fi
  jq -r 'sort_by(.activityDateTime) | .[] |
    "- \(.activityDateTime) \(.activityDisplayName): "
    + ([.targetResources[]? | .displayName // empty] | join(", ") | if . == "" then "?" else . end)
    + " — by " + (.initiatedBy.user.userPrincipalName // .initiatedBy.app.displayName // "unknown")' \
    "$WORK/audit.json" 2>/dev/null || echo "- (audit log unparsable)"
}

push_with_retry() { # several tenants share one repo: on rejection, rebase once and retry
  local branch; branch=$(git -C "$REPO" rev-parse --abbrev-ref HEAD)
  git -C "$REPO" push -q origin "HEAD:$branch" && return 0
  log "push rejected; pull --rebase and retry once"
  git -C "$REPO" pull -q --rebase origin "$branch"
  git -C "$REPO" push -q origin "HEAD:$branch"
}

main() {
  trap 'FAIL_LINE=${FAIL_LINE:-$LINENO}' ERR
  trap on_exit EXIT
  check_env
  WORK=$(mktemp -d) REPO="$WORK/repo"
  get_token
  git clone -q --depth 1 "$GIT_REPO" "$REPO"
  git -C "$REPO" config user.name "${GIT_COMMITTER_NAME:-ca-backup}"
  git -C "$REPO" config user.email "${GIT_COMMITTER_EMAIL:-ca-backup@localhost}"

  local t stat audit msg
  for t in "${!TARGETS[@]}"; do export_target "$t"; done

  git -C "$REPO" add -A -- "$TENANT_LABEL"
  if git -C "$REPO" diff --cached --quiet; then
    log "no change"
    return 0
  fi
  stat=$(git -C "$REPO" diff --cached --shortstat | sed 's/^ *//')
  audit=$(audit_lines)
  [[ -n $audit ]] || audit="- (no Conditional Access audit events in the last ${AUDIT_HOURS}h)"
  msg=$(printf 'CA drift [%s] %s\n\n%s\n\nAudit (last %sh):\n%s\n' \
    "$TENANT_LABEL" "$(date -u +%F)" "$stat" "$AUDIT_HOURS" "$audit")
  git -C "$REPO" commit -q -F - <<<"$msg"
  push_with_retry
  log "committed and pushed: $stat"
  notify high "CA drift [$TENANT_LABEL]" "$stat"$'\n'"$audit"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
