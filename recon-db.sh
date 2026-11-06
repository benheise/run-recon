#!/usr/bin/env bash
# =============================================================================
# recon-db.sh  --  optional PostgreSQL cache + storage layer for run-recon.
#
# Reuses the local PostgreSQL service that Kali already runs for Metasploit
# (msfdb). Stores expensive lookups (passive-crawl URL sets, OSINT API
# responses) with a TTL so repeat runs don't re-crawl the same targets or hammer
# API providers, and persists each run's host inventory for later reference.
#
# Two ways to use it:
#   * sourced by run-recon (functions only) when you pass --db
#   * run directly for one-time setup / queries:
#       sudo ./recon-db.sh init         # create the 'recon' DB + schema (see below)
#       ./recon-db.sh schema            # (re)create tables in an existing DB
#       ./recon-db.sh stats             # row counts
#       ./recon-db.sh hosts [PATTERN]   # dump stored hosts (optional host filter)
#       ./recon-db.sh latest [PATTERN]  # current state: newest run wins per URL
#       ./recon-db.sh import <csv|dir>  # import historic run CSVs (oldest first)
#       ./recon-db.sh vulns <csv> --nvd-feed DIR [--kev-file F] [--epss-file F] [-o OUT]
#                                       # offline NVD/KEV/EPSS join on the CSV's cpe column (no DB needed)
#       ./recon-db.sh clean <path>... [--dry-run] [--rows]
#                                       # prune empty intermediate files; keep report data (no DB needed)
#       ./recon-db.sh fix-collation     # REINDEX + refresh collation after a glibc upgrade
#       ./recon-db.sh purge [DAYS]      # delete cache rows older than DAYS (default 30)
#
# `init` (db_setup) sets up the database by this method order:
#   1. PRIMARY -- provision a dedicated, password-authenticated login role and
#      database on the LOCAL PostgreSQL, mirroring how msfdb provisions its own:
#      create the role WITH PASSWORD, grant it CREATEDB, then create a UTF-8
#      database from template0 owned by it, connecting as the role over 127.0.0.1
#      (RECON_DB_USER/RECON_DB_NAME/RECON_DB_HOST/RECON_DB_PORT, default
#      recon/recon/127.0.0.1/5432). Needs the postgres superuser (sudo -u postgres)
#      once to create the role/db; thereafter it's plain password auth over TCP,
#      independent of Metasploit.
#   2. BACKUP -- reuse Metasploit's msfdb credentials from database.yml (MSF_DB_YML,
#      default /usr/share/metasploit-framework/config/database.yml, then
#      ~/.msf4/database.yml; runs 'msfdb init' if needed). Tries a separate 'recon'
#      database and, if that can't be reached (e.g. msfdb's pg_hba.conf only
#      authorizes 'msf' for the 'msf' database), stores the namespaced
#      recon_cache / recon_hosts tables IN the 'msf' database itself (no collision
#      with Metasploit's tables).
#   3. otherwise, report and return non-zero -- run-recon continues without a DB.
#   The resolved connection (incl. password) is written to ~/.config/recon/db.env
#   (chmod 600), which run-recon and this script auto-load.
#
# Connection (libpq): the above is overridden by any standard PG env vars
#   (PGHOST/PGPORT/PGUSER/PGPASSWORD) or a single RECON_DB_DSN you set yourself.
#   Database name defaults to 'recon' (RECON_DB_NAME).
#
# Every function is fail-soft: if psql or the DB is unavailable, it returns
# non-zero / empty and the caller continues without caching.
# =============================================================================

: "${RECON_DB_NAME:=recon}"
# Dedicated role/endpoint for the PRIMARY setup method (a standalone password-
# authenticated login role, provisioned the way msfdb provisions 'msf').
: "${RECON_DB_USER:=recon}"
: "${RECON_DB_HOST:=127.0.0.1}"
: "${RECON_DB_PORT:=5432}"
: "${RECON_DB_ENV:=${HOME:-/root}/.config/recon/db.env}"
# Metasploit's msfdb-generated database.yml. We reuse its password-authenticated
# 'msf' role so our connection doesn't depend on pg_hba peer/ident. Primary path
# first (as installed on Kali), then per-user / env-configured fallbacks.
: "${MSF_DB_YML:=/usr/share/metasploit-framework/config/database.yml}"

# auto-load persisted connection settings (written by `init`), if present
if [ -f "$RECON_DB_ENV" ]; then
  # shellcheck disable=SC1090
  . "$RECON_DB_ENV" 2>/dev/null || true
fi

_db_have() { command -v "$1" >/dev/null 2>&1; }
_sql_esc() { local s="${1-}"; printf '%s' "${s//\'/\'\'}"; }   # escape ' for SQL literals (pure bash, no fork)

# _psql [args...] : run psql against the recon DB, quiet/tuples-only/unaligned.
# Connection precedence: RECON_DB_DSN, else PG* env with -d $RECON_DB_NAME.
_psql() {
  _db_have psql || return 3
  if [ -n "${RECON_DB_DSN:-}" ]; then
    psql "$RECON_DB_DSN" -qtAX -v ON_ERROR_STOP=0 "$@"
  else
    psql -d "${PGDATABASE:-$RECON_DB_NAME}" -qtAX -v ON_ERROR_STOP=0 "$@"
  fi
}

# db_available : true only if psql exists AND the recon DB answers a trivial query
db_available() {
  _db_have psql || return 1
  _psql -c 'SELECT 1' >/dev/null 2>&1
}

# db_schema : create tables/indexes if missing (idempotent). Assumes DB reachable.
db_schema() {
  _psql >/dev/null 2>&1 <<'SQL' || return 1
CREATE TABLE IF NOT EXISTS recon_cache (
  source     text        NOT NULL,
  key        text        NOT NULL,
  value      text,
  fetched_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source, key)
);
CREATE INDEX IF NOT EXISTS recon_cache_fetched_idx ON recon_cache (fetched_at);
CREATE TABLE IF NOT EXISTS recon_hosts (
  run_ts       text NOT NULL,
  seed_domain  text,
  url          text NOT NULL,
  host         text,
  ip           text,
  asn          text,
  asn_org      text,
  status_code  text,
  webserver    text,
  title        text,
  technologies text,
  PRIMARY KEY (run_ts, url)
);
CREATE INDEX IF NOT EXISTS recon_hosts_host_idx ON recon_hosts (host);
CREATE INDEX IF NOT EXISTS recon_hosts_seed_idx ON recon_hosts (seed_domain);
SQL
}

# db_cache_get <source> <key> <ttl_seconds> : echo value iff younger than ttl.
db_cache_get() {
  local src key ttl val
  src="$(_sql_esc "$1")"; key="$(_sql_esc "$2")"; ttl="${3:-0}"
  case "$ttl" in ''|*[!0-9]*) ttl=0;; esac
  [ "$ttl" -gt 0 ] || return 1
  val="$(_psql -c \
    "SELECT value FROM recon_cache WHERE source='$src' AND key='$key' AND fetched_at > now() - interval '$ttl seconds'" \
    2>/dev/null)" || return 1
  [ -n "$val" ] && { printf '%s' "$val"; return 0; }
  return 1
}

# db_cache_put <source> <key> <value> : upsert (concurrency-safe).
db_cache_put() {
  local src key val
  src="$(_sql_esc "$1")"; key="$(_sql_esc "$2")"; val="$(_sql_esc "$3")"
  _psql >/dev/null 2>&1 <<SQL || return 1
INSERT INTO recon_cache (source, key, value, fetched_at)
VALUES ('$src', '$key', '$val', now())
ON CONFLICT (source, key) DO UPDATE SET value = EXCLUDED.value, fetched_at = now();
SQL
}

# db_bulk_cache <source> <file> : upsert many "key<TAB>value" rows in ONE
# statement (far fewer psql spawns than per-key). Escaping is pure-bash.
db_bulk_cache() {
  local source="$1" f="$2" src k v rows=""
  [ -f "$f" ] || return 1
  src="$(_sql_esc "$source")"
  while IFS=$'\t' read -r k v || [ -n "$k" ]; do
    [ -n "$k" ] || continue
    rows="${rows:+$rows,}('$src','${k//\'/\'\'}','${v//\'/\'\'}',now())"
  done < "$f"
  [ -n "$rows" ] || return 0
  _psql >/dev/null 2>&1 <<SQL || return 1
INSERT INTO recon_cache (source, key, value, fetched_at) VALUES $rows
ON CONFLICT (source, key) DO UPDATE SET value = EXCLUDED.value, fetched_at = now();
SQL
}

# db_cache_mget <source> <ttl_seconds> <keyfile> : batched read. For the newline-
# separated keys in <keyfile>, print "key<TAB>value" for every entry of <source>
# still fresher than ttl. One psql round-trip regardless of key count.
db_cache_mget() {
  local source="$1" ttl="$2" keyfile="$3" src
  [ -f "$keyfile" ] && [ -s "$keyfile" ] || return 1
  case "$ttl" in ''|*[!0-9]*) ttl=0;; esac
  [ "$ttl" -gt 0 ] || return 1
  case "$keyfile" in *"'"*) return 1;; esac   # \copy path has no escape mechanism
  src="$(_sql_esc "$source")"
  _psql <<SQL 2>/dev/null
CREATE TEMP TABLE _mget (k text);
\copy _mget FROM '$keyfile'
SELECT c.key || E'\t' || c.value FROM recon_cache c
  JOIN (SELECT DISTINCT k FROM _mget WHERE k <> '') m ON c.key = m.k
 WHERE c.source = '$src' AND c.fetched_at > now() - interval '$ttl seconds';
DROP TABLE _mget;
SQL
}

# db_load_csv <csv> <run_ts> : client-side \copy the run CSV into recon_hosts.
db_load_csv() {
  local csv="$1" ts norm rc; ts="$(_sql_esc "$2")"
  [ -f "$csv" ] || return 1
  # Normalize to the canonical 12-column schema first (matching columns by header
  # NAME). The live run CSV now carries extra TLS/enrichment columns (tls_*, ipv6,
  # cloud, rdap_org, geo), and \copy into the fixed 12-column _stage would otherwise
  # fail with "extra data after last expected column"; older/narrower exports also
  # load this way. Fall back to the raw CSV if the normalizer is unavailable (e.g.
  # no python3) and the file already matches.
  norm="$(_import_normalize "$csv" 2>/dev/null)" && [ -n "$norm" ] || norm="$csv"
  # psql \copy takes a client-side path in single quotes with no escape mechanism,
  # so a quote in the path would break the command -- skip rather than emit bad SQL.
  case "$norm" in *"'"*)
    echo "[!] recon_hosts load skipped: CSV path contains a single quote." >&2
    [ "$norm" != "$csv" ] && rm -f "$norm"
    return 1;;
  esac
  _psql >/dev/null 2>&1 <<SQL
CREATE TEMP TABLE _stage (
  seed_domain text, url text, host text, sources text, status_code text,
  content_length text, webserver text, title text, technologies text,
  ip text, asn text, asn_org text
);
\copy _stage FROM '$norm' WITH (FORMAT csv, HEADER true)
INSERT INTO recon_hosts (run_ts, seed_domain, url, host, ip, asn, asn_org, status_code, webserver, title, technologies)
SELECT '$ts', seed_domain, url, host, ip, asn, asn_org, status_code, webserver, title, technologies
FROM _stage
ON CONFLICT (run_ts, url) DO NOTHING;
SQL
  rc=$?
  [ "$norm" != "$csv" ] && rm -f "$norm"
  return "$rc"
}

# _import_normalize <csv> : write a temp CSV normalized to the canonical 12-column
# schema (header + rows), matching source columns by header NAME so older exports
# with fewer/renamed columns still load (missing -> empty). Prints the temp path;
# returns non-zero if the file is unreadable or has no 'url' column.
_import_normalize() {
  local src="$1" out rc
  out="$(mktemp "${TMPDIR:-/tmp}/recon_import.XXXXXX" 2>/dev/null)" || return 1
  python3 - "$src" "$out" <<'PY'
import sys, csv
src, out = sys.argv[1], sys.argv[2]
CANON = ["seed_domain","url","host","sources","status_code","content_length",
         "webserver","title","technologies","ip","asn","asn_org"]
ALIAS = {"seed":"seed_domain","domain":"seed_domain","status":"status_code",
         "length":"content_length","content-length":"content_length","tech":"technologies",
         "technology":"technologies","server":"webserver","web_server":"webserver",
         "web-server":"webserver","asn_name":"asn_org","asnorg":"asn_org","as_org":"asn_org",
         "ip_address":"ip","ipaddr":"ip","source":"sources"}
try:
    fin = open(src, newline="", encoding="utf-8", errors="replace")
except Exception:
    sys.exit(1)
with fin:
    r = csv.reader(fin)
    try:
        header = next(r)
    except StopIteration:
        sys.exit(1)
    idx = {}
    for i, h in enumerate(header):
        key = (h or "").strip().lower()
        key = ALIAS.get(key, key)
        if key in CANON and key not in idx:
            idx[key] = i
    if "url" not in idx:
        sys.exit(2)
    with open(out, "w", newline="", encoding="utf-8") as fout:
        w = csv.writer(fout)
        w.writerow(CANON)
        for row in r:
            if not row:
                continue
            vals = [row[idx[c]] if c in idx and idx[c] < len(row) else "" for c in CANON]
            # undo run-recon's CSV formula guard: store the value the site actually sent
            vals = [(v[1:] if v[:1] == "'" and v[1:2] in ("=", "+", "-", "@", "\t", "\r") else v) for v in vals]
            if not (vals[1] or "").strip():
                continue
            w.writerow(vals)
sys.exit(0)
PY
  rc=$?
  if [ "$rc" -eq 0 ]; then printf '%s' "$out"; return 0; fi
  rm -f "$out"; return "$rc"
}

# db_import_csvs <path>... : import historic run CSVs into recon_hosts. Each file is
# loaded as its own run (run_ts from a 'recon-<TS>.csv' filename, else the file's
# mtime), OLDEST FIRST, so the newest run is authoritative for current-state queries
# ('recon-db.sh latest'). Columns are matched by header name (older/narrower CSVs
# still load). Existing (run_ts,url) rows are kept -- re-importing is a no-op.
db_import_csvs() {
  db_available || { echo "[!] recon DB not reachable (run 'recon-db.sh init')." >&2; return 1; }
  db_schema >/dev/null 2>&1 || true
  [ "$#" -gt 0 ] || { echo "usage: recon-db.sh import <csv-or-directory>..." >&2; return 2; }
  local p f files=()
  for p in "$@"; do
    if [ -d "$p" ]; then
      while IFS= read -r f; do [ -n "$f" ] && files+=("$f"); done \
        < <(find "$p" -type f -name '*.csv' 2>/dev/null)
    elif [ -f "$p" ]; then files+=("$p")
    else echo "[!] skip (not found): $p" >&2; fi
  done
  [ "${#files[@]}" -gt 0 ] || { echo "[!] no CSV files found to import." >&2; return 1; }
  # derive a sortable run_ts per file (recon-<TS>.csv -> TS, else mtime), sort asc
  local listing ts base
  listing="$(for f in "${files[@]}"; do
    base="$(basename "$f")"
    ts="$(printf '%s' "$base" | sed -n 's/^recon-\(.*\)\.csv$/\1/p')"
    [ -n "$ts" ] || ts="$(date -r "$f" +%Y%m%d-%H%M%S 2>/dev/null || echo 00000000-000000)"
    printf '%s\t%s\n' "$ts" "$f"
  done | LC_ALL=C sort)"
  local -A seen=() ; local n_files=0 total=0 path uts rows
  while IFS=$'\t' read -r ts path || [ -n "$ts" ]; do
    [ -n "$path" ] || continue
    # keep each file a distinct run even if two share a timestamp
    if [ -n "${seen[$ts]:-}" ]; then seen[$ts]=$(( seen[$ts] + 1 )); uts="${ts}#${seen[$ts]}"
    else seen[$ts]=1; uts="$ts"; fi
    local norm; norm="$(_import_normalize "$path")" \
      || { echo "[!] skip (unreadable or no 'url' column): $path" >&2; continue; }
    if [ ! -s "$norm" ]; then echo "[!] skip (no data rows): $path" >&2; rm -f "$norm"; continue; fi
    if db_load_csv "$norm" "$uts"; then
      rows="$(( $(wc -l < "$norm") - 1 ))"; [ "$rows" -lt 0 ] && rows=0
      echo "[+] $path -> run_ts=$uts ($rows row(s))"
      n_files=$((n_files + 1)); total=$((total + rows))
    else
      echo "[!] load failed: $path" >&2
    fi
    rm -f "$norm"
  done <<< "$listing"
  echo "[+] imported $n_files file(s), $total row(s). Newest run_ts wins -- see 'recon-db.sh latest'."
}

# --- Metasploit msfdb credential reuse -------------------------------------
# shell-quote a value for safe inclusion in db.env; quote an SQL identifier.
_shq()   { printf "'%s'" "$(printf '%s' "${1-}" | sed "s/'/'\\\\''/g")"; }
_ident() { printf '"%s"' "$(printf '%s' "${1-}" | sed 's/"/""/g')"; }

# _msf_yml_path : first existing msfdb database.yml among the known locations
_msf_yml_path() {
  local c
  for c in "$MSF_DB_YML" "${MSF_DATABASE_CONFIG:-}" \
           "${HOME:-/root}/.msf4/database.yml" \
           ${SUDO_USER:+"/home/$SUDO_USER/.msf4/database.yml"}; do
    [ -n "$c" ] && [ -f "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

# _yml_first <key> <file> : first value for a simple "key: value" yaml scalar,
# stripping surrounding quotes and trailing whitespace.
_yml_first() {
  sed -n "s/^[[:space:]]*$1:[[:space:]]*//p" "$2" 2>/dev/null | head -1 \
    | sed -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# _msf_read_creds [file] : populate MSF_USER/MSF_PASS/MSF_HOST/MSF_PORT/MSF_DBNAME
# from the msfdb database.yml. Returns 0 only if username AND password were found.
# shellcheck disable=SC2120  # the file arg is optional (used by tests); default resolves it
_msf_read_creds() {
  local f="${1:-}"; [ -n "$f" ] || f="$(_msf_yml_path)" || return 1
  MSF_USER="$(_yml_first username "$f")"
  MSF_PASS="$(_yml_first password "$f")"
  MSF_HOST="$(_yml_first host "$f")"; [ -n "$MSF_HOST" ] || MSF_HOST="127.0.0.1"
  MSF_PORT="$(_yml_first port "$f")"; [ -n "$MSF_PORT" ] || MSF_PORT="5432"
  MSF_DBNAME="$(_yml_first database "$f")"; [ -n "$MSF_DBNAME" ] || MSF_DBNAME="msf"
  [ -n "$MSF_USER" ] && [ -n "$MSF_PASS" ]
}

# _msf_creds_work : true(0) if the current MSF_* creds actually authenticate
_msf_creds_work() {
  [ -n "${MSF_USER:-}" ] && [ -n "${MSF_PASS:-}" ] || return 1
  PGHOST="$MSF_HOST" PGPORT="$MSF_PORT" PGUSER="$MSF_USER" PGPASSWORD="$MSF_PASS" \
    PGDATABASE="$MSF_DBNAME" psql -qtAX -w -c 'SELECT 1' >/dev/null 2>&1
}

# _run_msfdb_init : run 'msfdb init' as the invoking (non-root) user when possible
_run_msfdb_init() {
  _db_have msfdb || return 1
  echo "[*] running 'msfdb init' to initialise Metasploit's PostgreSQL + credentials..." >&2
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && _db_have sudo; then
    sudo -u "$SUDO_USER" -H msfdb init >/dev/null 2>&1 || msfdb init >/dev/null 2>&1 || return 1
  else
    msfdb init >/dev/null 2>&1 || return 1
  fi
  return 0
}

# _write_db_env : persist the resolved PG* connection (incl. password) to db.env (0600)
_write_db_env() {
  mkdir -p "$(dirname "$RECON_DB_ENV")" 2>/dev/null || true
  {
    echo "# written by recon-db.sh init on $(date -u +%FT%TZ 2>/dev/null || date)"
    [ -n "${PGHOST:-}" ] && echo "export PGHOST=$(_shq "$PGHOST")"
    [ -n "${PGPORT:-}" ] && echo "export PGPORT=$(_shq "$PGPORT")"
    echo "export PGUSER=$(_shq "${PGUSER:-}")"
    [ -n "${PGPASSWORD:-}" ] && echo "export PGPASSWORD=$(_shq "$PGPASSWORD")"
    echo "export PGDATABASE=$(_shq "${PGDATABASE:-$RECON_DB_NAME}")"
  } > "$RECON_DB_ENV" 2>/dev/null || true
  chmod 600 "$RECON_DB_ENV" 2>/dev/null || true
}

# _psql_super [args...] : run psql as the postgres superuser, with any exported
# PG* stripped so it authenticates via peer as 'postgres' (not the reused msf role).
_psql_super() {
  sudo -u postgres env -u PGHOST -u PGPORT -u PGUSER -u PGPASSWORD -u PGDATABASE psql "$@"
}

# db_collation_mismatch : true when the connected DB's recorded collation version no
# longer matches the OS collation library -- the usual aftermath of a glibc upgrade
# on a rolling distro (Kali). Data is unaffected; text-index sort order can go stale.
db_collation_mismatch() {
  _db_have psql || return 1
  local out
  # Primary: catalog comparison (PG 15+). If the column/function isn't present the
  # query errors (-> empty) and we fall back to the WARNING Postgres emits on connect.
  out="$(_psql -c "SELECT datcollversion <> pg_database_collation_actual_version(oid) FROM pg_database WHERE datname = current_database() AND datcollversion IS NOT NULL" 2>/dev/null)"
  case "$out" in
    t) return 0;;
    f) return 1;;
  esac
  _psql -c 'SELECT 1' 2>&1 >/dev/null | grep -qi 'collation version mismatch'
}

# db_fix_collation : REINDEX the connected database, then refresh its recorded
# collation version (clearing the mismatch warning). Runs as the DB owner when it
# can (no sudo in the common dedicated-'recon' case), falling back to the postgres
# superuser (e.g. when the recon tables live inside the msf database).
db_fix_collation() {
  db_available || { echo "[!] recon DB not reachable (see connection env / run 'recon-db.sh init')." >&2; return 1; }
  local db="${PGDATABASE:-$RECON_DB_NAME}"
  echo "[*] refreshing collation on '$db' (REINDEX, then REFRESH COLLATION VERSION)..." >&2
  # REINDEX first (rebuild every index under the current collation), THEN refresh the
  # stored version -- refreshing alone would silence the warning but leave stale indexes.
  if _psql -c "REINDEX DATABASE \"$db\"" >/dev/null 2>&1 \
     && _psql -c "ALTER DATABASE \"$db\" REFRESH COLLATION VERSION" >/dev/null 2>&1; then
    echo "[+] done as the database owner (no sudo needed)." >&2
  elif _db_have sudo \
       && _psql_super -d "$db" -c "REINDEX DATABASE \"$db\"" >/dev/null 2>&1 \
       && _psql_super -d "$db" -c "ALTER DATABASE \"$db\" REFRESH COLLATION VERSION" >/dev/null 2>&1; then
    echo "[+] done via the postgres superuser." >&2
  else
    echo "[!] could not refresh collation automatically. Run as the postgres superuser:" >&2
    echo "      sudo -u postgres psql -d \"$db\" -c 'REINDEX DATABASE \"$db\";'" >&2
    echo "      sudo -u postgres psql -d \"$db\" -c 'ALTER DATABASE \"$db\" REFRESH COLLATION VERSION;'" >&2
    return 1
  fi
  if db_collation_mismatch; then
    echo "[!] '$db' is refreshed, but the warning may persist from a shared catalog." >&2
    echo "    template1/postgres (and msf) were created under the old glibc too; refresh each:" >&2
    echo "      sudo -u postgres psql -tAc 'SELECT datname FROM pg_database WHERE datallowconn' | \\" >&2
    echo "        while read d; do sudo -u postgres psql -d \"\$d\" \\" >&2
    echo "          -c \"REINDEX DATABASE \\\"\$d\\\"; ALTER DATABASE \\\"\$d\\\" REFRESH COLLATION VERSION;\"; done" >&2
    return 1
  fi
  echo "[+] collation version is current for '$db'; the mismatch warning is cleared." >&2
}

# _gen_pass : print a strong random alphanumeric password (like msfdb generates
# one for its role). Prefers /dev/urandom; falls back to openssl, then a hash.
_gen_pass() {
  local p=""
  if [ -r /dev/urandom ]; then
    p="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 32 || true)"
  fi
  [ -n "$p" ] || p="$(openssl rand -hex 24 2>/dev/null || true)"
  [ -n "$p" ] || p="$( { date +%s%N; echo "$$ $RANDOM"; } | sha256sum 2>/dev/null | head -c 40 || true)"
  printf '%s' "$p"   # always exit 0; caller checks for emptiness
}

# _new_recon_db : PRIMARY setup method. Provision a dedicated, password-
# authenticated 'recon' login role + database on the LOCAL PostgreSQL, mirroring
# how msfdb provisions its own role/db (create user WITH PASSWORD; grant CREATEDB;
# create a UTF-8 database from template0 owned by the role, connecting as the role
# over 127.0.0.1). Independent of Metasploit. Needs the postgres superuser (sudo).
# On success, leaves PG* + db.env pointing at the new DB and returns 0.
_new_recon_db() {
  _db_have sudo || { echo "[*] (primary) no sudo available; skipping dedicated-role setup." >&2; return 1; }
  local pass; pass="$(_gen_pass)"; [ -n "$pass" ] || { echo "[!] (primary) could not generate a password." >&2; return 1; }
  echo "[*] (primary) provisioning a dedicated '$RECON_DB_USER' role + '$RECON_DB_NAME' database on the local PostgreSQL (msfdb-style)..." >&2

  # 1) create-or-repair the login role with a password + CREATEDB (idempotent) --
  # equivalent to msfdb's: create user; alter role createdb; alter role password.
  _psql_super -v ON_ERROR_STOP=0 >/dev/null 2>&1 <<SQL || { echo "[!] (primary) could not reach the postgres superuser (sudo -u postgres)." >&2; return 1; }
DO \$\$ BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = '$(_sql_esc "$RECON_DB_USER")') THEN
    ALTER ROLE $(_ident "$RECON_DB_USER") WITH LOGIN CREATEDB PASSWORD '$(_sql_esc "$pass")';
  ELSE
    CREATE ROLE $(_ident "$RECON_DB_USER") WITH LOGIN CREATEDB PASSWORD '$(_sql_esc "$pass")';
  END IF;
END \$\$;
SQL

  export PGHOST="$RECON_DB_HOST" PGPORT="$RECON_DB_PORT" PGUSER="$RECON_DB_USER" PGPASSWORD="$pass"

  # 2) create the UTF-8 database owned by the role, connecting AS the role over TCP
  # (msfdb's `createdb -O msf -h 127.0.0.1 -U msf -E UTF-8 -T template0 msf`).
  # Fall back to a superuser create if the role can't create it directly.
  if ! PGDATABASE="$RECON_DB_NAME" psql -qtAX -w -c 'SELECT 1' >/dev/null 2>&1; then
    if _db_have createdb && PGPASSWORD="$pass" createdb -h "$RECON_DB_HOST" -p "$RECON_DB_PORT" \
         -U "$RECON_DB_USER" -O "$RECON_DB_USER" -E UTF-8 -T template0 "$RECON_DB_NAME" >/dev/null 2>&1; then
      echo "[*] (primary) created database '$RECON_DB_NAME' as '$RECON_DB_USER'." >&2
    else
      echo "[*] (primary) creating '$RECON_DB_NAME' via the postgres superuser..." >&2
      # Inherit the server's default encoding/locale here (no template0 override)
      # so this fallback works regardless of the server locale; the createdb path
      # above already matches msfdb's UTF-8/template0 when createdb is present.
      _psql_super -v ON_ERROR_STOP=0 >/dev/null 2>&1 <<SQL
SELECT 'CREATE DATABASE $(_ident "$RECON_DB_NAME") OWNER $(_ident "$RECON_DB_USER")'
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$(_sql_esc "$RECON_DB_NAME")')\gexec
ALTER DATABASE $(_ident "$RECON_DB_NAME") OWNER TO $(_ident "$RECON_DB_USER");
SQL
    fi
  fi

  # 3) ensure the role can create objects in public (PostgreSQL 15+ locks this down).
  _psql_super -d "$RECON_DB_NAME" -v ON_ERROR_STOP=0 >/dev/null 2>&1 <<SQL || true
ALTER SCHEMA public OWNER TO $(_ident "$RECON_DB_USER");
GRANT ALL ON SCHEMA public TO $(_ident "$RECON_DB_USER");
SQL

  # 4) verify (connect as the recon role over TCP), then persist ONLY on success
  # so a failed attempt doesn't leave a stale db.env pointing at an unusable DB.
  if db_available && db_schema; then
    _write_db_env
    return 0
  fi
  return 1
}

# --- privileged one-time setup ---------------------------------------------
# db_setup : create the recon database + schema, reusing the local postgres
# service. Method order: (1) PRIMARY -- provision a dedicated password-authed
# 'recon' role + database on the local PostgreSQL (msfdb-style); (2) BACKUP --
# reuse Metasploit's msfdb credentials (a separate 'recon' DB, or the 'msf'
# database with namespaced tables); (3) give up and let the caller run without a DB.
db_setup() {
  mkdir -p "$(dirname "$RECON_DB_ENV")" 2>/dev/null || true

  if db_available; then
    echo "[*] recon DB already reachable; ensuring schema." >&2
    db_schema && echo "[+] schema ready." >&2 || { echo "[!] schema creation failed." >&2; return 1; }
    if db_collation_mismatch; then
      echo "[!] NOTE: '${PGDATABASE:-$RECON_DB_NAME}' has a collation version mismatch -- Postgres's OS" >&2
      echo "    collation library (glibc) was upgraded since this DB was created. Your data is fine." >&2
      echo "    Rebuild indexes and clear the warning in one step:  ./recon-db.sh fix-collation" >&2
    fi
    return 0
  fi

  if ! _db_have psql; then
    echo "[!] psql not found. Install the client: sudo apt install postgresql-client" >&2
    return 1
  fi
  # start the service if it's installed but down (Kali uses the 'postgresql' unit)
  if _db_have systemctl && ! systemctl is-active --quiet postgresql 2>/dev/null; then
    echo "[*] starting postgresql service..." >&2
    sudo systemctl start postgresql 2>/dev/null || service postgresql start 2>/dev/null || true
  fi

  # --- PRIMARY: dedicated 'recon' role + database on the local PostgreSQL ------
  if _new_recon_db; then
    echo "[+] recon DB ready (dedicated '$RECON_DB_NAME' database, user=$RECON_DB_USER). Settings saved to $RECON_DB_ENV." >&2
    return 0
  fi
  echo "[*] (primary) dedicated setup did not complete; trying the Metasploit-credential backup." >&2
  unset PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE   # clear the primary's attempt

  # --- BACKUP: reuse Metasploit's msfdb credentials (password auth) -----------
  # Read them from database.yml; if the file is missing or the creds don't work,
  # run 'msfdb init' (which sets up postgres + the msf role/db) and re-read.
  _msf_read_creds || true
  if ! _msf_creds_work; then
    if _run_msfdb_init; then _msf_read_creds || true; fi
  fi
  if _msf_creds_work; then
    echo "[*] (backup) reusing msfdb credentials (user='$MSF_USER' @ $MSF_HOST:$MSF_PORT, from $(_msf_yml_path)) to host database '$RECON_DB_NAME'." >&2
    export PGHOST="$MSF_HOST" PGPORT="$MSF_PORT" PGUSER="$MSF_USER" PGPASSWORD="$MSF_PASS"
    if ! PGDATABASE="$RECON_DB_NAME" psql -qtAX -w -c 'SELECT 1' >/dev/null 2>&1; then
      # create the recon DB: try as the msf role (needs CREATEDB), else via the
      # postgres superuser, owned by the msf role so it can connect.
      if PGDATABASE="$MSF_DBNAME" psql -qtAX -w -v ON_ERROR_STOP=1 \
           -c "CREATE DATABASE $(_ident "$RECON_DB_NAME")" >/dev/null 2>&1; then
        echo "[*] created database '$RECON_DB_NAME' as '$MSF_USER'." >&2
      elif _db_have sudo; then
        echo "[*] '$MSF_USER' lacks CREATEDB; creating '$RECON_DB_NAME' via the postgres superuser..." >&2
        # Cluster-level: create the DB and make the msf role its owner (idempotent
        # ALTER covers a pre-existing DB owned by someone else).
        _psql_super -v ON_ERROR_STOP=0 >/dev/null 2>&1 <<SQL
SELECT 'CREATE DATABASE $(_ident "$RECON_DB_NAME") OWNER '||quote_ident('$(_sql_esc "$MSF_USER")')
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$(_sql_esc "$RECON_DB_NAME")')\gexec
ALTER DATABASE $(_ident "$RECON_DB_NAME") OWNER TO $(_ident "$MSF_USER");
GRANT ALL PRIVILEGES ON DATABASE $(_ident "$RECON_DB_NAME") TO $(_ident "$MSF_USER");
SQL
        # In-database: let the msf role create objects in the public schema.
        # PostgreSQL 15+ no longer grants CREATE on public to non-owners, so
        # without this a connected msf could still fail at CREATE TABLE.
        _psql_super -d "$RECON_DB_NAME" -v ON_ERROR_STOP=0 >/dev/null 2>&1 <<SQL
ALTER SCHEMA public OWNER TO $(_ident "$MSF_USER");
GRANT ALL ON SCHEMA public TO $(_ident "$MSF_USER");
SQL
      else
        echo "[!] Cannot create '$RECON_DB_NAME' ('$MSF_USER' lacks CREATEDB and sudo is unavailable)." >&2
      fi
    fi
    _write_db_env
    if db_available && db_schema; then
      echo "[+] recon DB ready (separate '$RECON_DB_NAME' database, user=$MSF_USER). Settings saved to $RECON_DB_ENV." >&2
      return 0
    fi
    # The separate database isn't reachable with the msf credentials -- it may not
    # have been created, or (common) msfdb's pg_hba.conf only authorizes the 'msf'
    # role for the 'msf' database. Fall back to the msf database itself, which we've
    # already proven reachable, using our namespaced recon_* tables (these do not
    # collide with Metasploit's own tables).
    echo "[*] separate '$RECON_DB_NAME' DB not reachable; using the '$MSF_DBNAME' database with recon_* tables instead." >&2
    export PGDATABASE="$MSF_DBNAME"
    _write_db_env
    if db_available && db_schema; then
      echo "[+] recon DB ready (recon_* tables in the '$MSF_DBNAME' database, user=$MSF_USER). Settings saved to $RECON_DB_ENV." >&2
      return 0
    fi
    unset PGDATABASE
    echo "[!] (backup) reused msfdb creds but neither '$RECON_DB_NAME' nor '$MSF_DBNAME' was usable." >&2
  else
    echo "[*] (backup) no usable msfdb credentials, and 'msfdb init' was unavailable or failed." >&2
  fi

  # --- final fallback: no database -------------------------------------------
  # Both methods failed. The database is optional -- run-recon degrades to a
  # normal, uncached run -- so this is not fatal, just reported.
  echo "[!] Could not set up a recon database by any method; continuing without the DB cache." >&2
  echo "    Retry after ensuring PostgreSQL is running and you have sudo:  sudo ./recon-db.sh init" >&2
  echo "    Or set PGUSER/PGPASSWORD/PGDATABASE (or RECON_DB_DSN) in $RECON_DB_ENV, then:  ./recon-db.sh schema" >&2
  return 1
}

# ===========================================================================
# vulns : offline NVD/KEV/EPSS vulnerability join (FPV-07)
# ===========================================================================
# Joins the run CSV's `cpe` column with NVD CVE JSON 2.0 feeds + CISA KEV + FIRST
# EPSS that YOU download -- nothing is fetched here and nothing is sent to any
# target. Version-aware CPE matching (vendor+product, numeric compare incl. the
# update field 9.3p1, versionStart*/End* ranges, prerelease ordering, 2.4==2.4.0),
# newest-record-wins across the yearly + modified feeds, and a match-confidence
# column (version/range/all-versions/"(platform not verified)"/product-only, the
# last listed only for KEV CVEs). Ported from WebInventory's -StoreQuery Vulnerabilities.
# Writes <out> (default <csv>.vulns.csv), sorted KEV-first then EPSS then CVSS, plus
# a <out>.provenance.json sidecar (feed file names, SHA-256, record counts, KEV
# catalogVersion, EPSS model/date). No database required.
db_vulns() {
  local csv="" nvd="" kev="" epss="" out="" rc=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --nvd-feed|--nvd)   nvd="${2:-}";  shift 2 || shift;;
      --kev-file|--kev)   kev="${2:-}";  shift 2 || shift;;
      --epss-file|--epss) epss="${2:-}"; shift 2 || shift;;
      -o|--output)        out="${2:-}";  shift 2 || shift;;
      -h|--help)
        echo "usage: recon-db.sh vulns <run.csv> --nvd-feed DIR [--kev-file F] [--epss-file F] [-o OUT]" >&2
        return 0;;
      -*) echo "[!] vulns: unknown option: $1" >&2; return 2;;
      *)  if [ -z "$csv" ]; then csv="$1"; else echo "[!] vulns: extra argument ignored: $1" >&2; fi; shift;;
    esac
  done
  command -v python3 >/dev/null 2>&1 || { echo "[!] vulns: python3 is required." >&2; return 1; }
  if [ -z "$csv" ] || [ ! -f "$csv" ]; then
    echo "[!] vulns: run CSV not found." >&2
    echo "    usage: recon-db.sh vulns <run.csv> --nvd-feed DIR [--kev-file F] [--epss-file F] [-o OUT]" >&2
    return 2
  fi
  if [ -z "$nvd" ]; then
    echo "[!] vulns: --nvd-feed DIR is required (the NVD CVE JSON 2.0 feeds you downloaded:" >&2
    echo "    nvdcve-2.0-YYYY.json.gz for each year + nvdcve-2.0-modified.json.gz)." >&2
    return 2
  fi
  [ -e "$nvd" ] || { echo "[!] vulns: --nvd-feed path not found: $nvd" >&2; return 2; }
  [ -n "$kev" ]  && [ ! -f "$kev" ]  && { echo "[!] vulns: --kev-file not found: $kev" >&2; return 2; }
  [ -n "$epss" ] && [ ! -f "$epss" ] && { echo "[!] vulns: --epss-file not found: $epss" >&2; return 2; }
  [ -n "$out" ] || out="${csv%.csv}.vulns.csv"
  # -I: isolated mode -- the feeds are files you downloaded; don't let cwd/env inject code.
  python3 -I - "$csv" "$nvd" "$kev" "$epss" "$out" <<'PYVULN'
import sys, os, csv, json, gzip, re, hashlib, datetime
from urllib.parse import urlparse

# argv: <run.csv> <nvd_feed_dir> <kev_file|""> <epss_file|""> <out.csv>
csv_path = sys.argv[1]
nvd_dir  = sys.argv[2]
kev_path = sys.argv[3] if len(sys.argv) > 3 else ""
epss_path= sys.argv[4] if len(sys.argv) > 4 else ""
out_path = sys.argv[5] if len(sys.argv) > 5 else (csv_path.rsplit(".", 1)[0] + ".vulns.csv")

# --- helpers ----------------------------------------------------------------
def _open_any(path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.endswith(".gz") \
           else open(path, "r", encoding="utf-8", errors="replace")

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
def _clean(s, limit=400):
    s = _CTRL.sub(" ", str(s or "")).strip()
    return s[:limit]

def _csv_safe(s):
    # FPV-01: neutralize spreadsheet formula injection in exported text fields
    s = str(s or "")
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

def _cpe_split(s):
    # split a CPE 2.3 formatted string on unescaped ':'
    parts, cur = [], []
    for i, ch in enumerate(s):
        if ch == ":" and (i == 0 or s[i-1] != "\\"):
            parts.append("".join(cur)); cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts

def _unescape(s):
    return re.sub(r"\\(.)", r"\1", s or "")

def parse_cpe(s):
    # -> (part, vendor, product, version, update) all unescaped/lowercased; or None
    if not s or not s.startswith("cpe:2.3:"):
        return None
    p = _cpe_split(s)
    if len(p) < 6:
        return None
    return (p[2].lower(), _unescape(p[3]).lower(), _unescape(p[4]).lower(),
            _unescape(p[5]).lower(), _unescape(p[6]).lower() if len(p) > 6 else "*")

# --- version comparison (WebInventory semantics) ----------------------------
# pre-release words sort BEFORE the release; other letters (patch/vendor) AFTER;
# 2.4 == 2.4.0 (numeric pad); update field concatenates (9.3 + p1 -> 9.3p1).
_PRE = {"rc", "beta", "alpha", "pre", "dev", "snapshot", "eap", "a", "b", "m", "preview"}
def _vtokens(v):
    v = (v or "").strip().lower()
    if v[:1] == "v":
        v = v[1:]
    toks = []
    for run in re.findall(r"[0-9]+|[a-z]+", v):
        if run.isdigit():
            toks.append((1, int(run)))
        elif run in _PRE:
            toks.append((0, run))
        else:
            toks.append((2, run))
    return toks

def vcmp(a, b):
    ta, tb = _vtokens(a), _vtokens(b)
    n = max(len(ta), len(tb))
    pad = (1, 0)
    ta = ta + [pad] * (n - len(ta))
    tb = tb + [pad] * (n - len(tb))
    return -1 if ta < tb else (1 if ta > tb else 0)

def in_range(v, si, se, ei, ee):
    if si and vcmp(v, si) < 0:  return False
    if se and vcmp(v, se) <= 0: return False
    if ei and vcmp(v, ei) > 0:  return False
    if ee and vcmp(v, ee) >= 0: return False
    return True

_WILD = ("*", "-", "", "na")

# --- load inventory CPEs from the run CSV -----------------------------------
rows = []            # list of dicts (row context)
rows_by_prod = {}    # (vendor, product) -> list of (row_idx, version, cpe_string)
with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
    r = csv.DictReader(f)
    for rec in r:
        cpes = [c.strip() for c in (rec.get("cpe") or "").split(";") if c.strip()]
        if not cpes:
            continue
        u = rec.get("url") or ""
        try:
            pr = urlparse(u if "://" in u else "http://" + u)
            port = pr.port or (443 if (pr.scheme or "").lower() == "https" else 80)
        except Exception:
            port = ""
        idx = len(rows)
        rows.append({
            "seed_domain": rec.get("seed_domain", ""),
            "host": rec.get("host", ""),
            "ip": rec.get("ip", ""),
            "port": str(port),
            "url": u,
            "status_code": rec.get("status_code", ""),
            "products": rec.get("technologies", ""),
            "cpes": cpes,
        })
        for c in cpes:
            pc = parse_cpe(c)
            if not pc:
                continue
            _, vendor, product, version, update = pc
            # fold the service's version+update into one comparable token (rare for us)
            sv = version if version not in _WILD else ""
            if update not in _WILD:
                sv = (sv + update)
            rows_by_prod.setdefault((vendor, product), []).append((idx, sv, c))

inv_products = set(rows_by_prod.keys())

# --- KEV --------------------------------------------------------------------
kev = {}            # cve -> (dateAdded, dueDate, ransomware)
kev_meta = {"file": "", "sha256": "", "catalogVersion": "", "count": 0}
if kev_path and os.path.exists(kev_path):
    try:
        with _open_any(kev_path) as f:
            kj = json.load(f)
        kev_meta["file"] = os.path.basename(kev_path)
        kev_meta["sha256"] = _sha256(kev_path)
        kev_meta["catalogVersion"] = kj.get("catalogVersion", "")
        for v in kj.get("vulnerabilities", []):
            cid = (v.get("cveID") or "").upper()
            if cid:
                kev[cid] = (v.get("dateAdded", ""), v.get("dueDate", ""),
                            v.get("knownRansomwareCampaignUse", ""))
        kev_meta["count"] = len(kev)
    except Exception as e:
        sys.stderr.write("[!] KEV load failed: %s\n" % e)

# --- EPSS -------------------------------------------------------------------
epss = {}           # cve -> (epss, percentile)
epss_meta = {"file": "", "sha256": "", "model_version": "", "score_date": "", "rows": 0}
if epss_path and os.path.exists(epss_path):
    try:
        with _open_any(epss_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    m1 = re.search(r"model_version:([^,\s]+)", line)
                    m2 = re.search(r"score_date:([^,\s]+)", line)
                    if m1: epss_meta["model_version"] = m1.group(1)
                    if m2: epss_meta["score_date"] = m2.group(1)
                    continue
                if line.lower().startswith("cve,"):
                    continue
                parts = line.split(",")
                if len(parts) >= 3:
                    epss[parts[0].upper()] = (parts[1], parts[2])
        epss_meta["file"] = os.path.basename(epss_path)
        epss_meta["sha256"] = _sha256(epss_path)
        epss_meta["rows"] = len(epss)
    except Exception as e:
        sys.stderr.write("[!] EPSS load failed: %s\n" % e)

# --- NVD join ---------------------------------------------------------------
def cvss_of(cve):
    metrics = cve.get("metrics") or {}
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                     ("cvssMetricV2", "2.0")):
        arr = metrics.get(key) or []
        if arr:
            d = arr[0].get("cvssData") or {}
            score = d.get("baseScore", "")
            sev = d.get("baseSeverity", "") or arr[0].get("baseSeverity", "")
            return (str(score), str(sev), ver)
    return ("", "", "")

def en_desc(cve):
    for d in (cve.get("descriptions") or []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""

def node_hits_product(node):
    # does this node's cpeMatch name one of our inventory products (vulnerable)?
    for cm in (node.get("cpeMatch") or []):
        if not cm.get("vulnerable", False):
            continue
        pc = parse_cpe(cm.get("criteria", ""))
        if pc and (pc[1], pc[2]) in inv_products:
            return True
    return False

def node_satisfied_by(node, cpe_set):
    # for AND platform checks: does the service's own CPE set satisfy this node?
    for cm in (node.get("cpeMatch") or []):
        pc = parse_cpe(cm.get("criteria", ""))
        if not pc:
            continue
        for sc in cpe_set:
            spc = parse_cpe(sc)
            if spc and spc[0] == pc[0] and spc[1] == pc[1] and spc[2] == pc[2]:
                return True
    return False

def classify(cm, service_ver):
    # returns match-type string or None (no match). service_ver "" => product-only.
    pc = parse_cpe(cm.get("criteria", ""))
    if not pc:
        return None
    cversion, cupdate = pc[3], pc[4]
    si = cm.get("versionStartIncluding"); se = cm.get("versionStartExcluding")
    ei = cm.get("versionEndIncluding");   ee = cm.get("versionEndExcluding")
    has_range = any([si, se, ei, ee])
    if cversion not in _WILD:
        nvdver = cversion + (cupdate if cupdate not in _WILD else "")
        if not service_ver:
            return "product-only"
        return "version" if vcmp(service_ver, nvdver) == 0 else None
    if has_range:
        if not service_ver:
            return "product-only"
        return "range" if in_range(service_ver, si, se, ei, ee) else None
    # no version, no range -> all versions affected
    return "all-versions" if service_ver else "product-only"

# best match per (row_idx, cve): keep the strongest confidence
_RANK = {"version": 5, "range": 4, "all-versions": 3,
         "version (platform not verified)": 2, "range (platform not verified)": 2,
         "all-versions (platform not verified)": 2, "product-only": 1}
def _rank(m):
    return _RANK.get(m, 0)

best = {}   # (row_idx, cve) -> dict(match, cpe, cvss.., published, desc)

nvd_meta = []
feed_files = []
if os.path.isdir(nvd_dir):
    for fn in sorted(os.listdir(nvd_dir)):
        if re.match(r"nvdcve-2\.0-.*\.json(\.gz)?$", fn):
            feed_files.append(os.path.join(nvd_dir, fn))
elif os.path.isfile(nvd_dir):
    feed_files.append(nvd_dir)

# Pass 1: stream every feed, keep ONLY CVEs that name an inventory product, and for
# each CVE keep the record with the newest lastModified (yearly vs modified feed) --
# newest-record-wins decides the whole record (description, CVSS, config), not just
# the match rank. Rejected status is evaluated on the winning record in pass 2.
cve_rec = {}        # cid -> (lastModified, cve-dict)
def _touches_inventory(cve):
    for conf in (cve.get("configurations") or []):
        for node in (conf.get("nodes") or []):
            if node_hits_product(node):
                return True
    return False

for path in feed_files:
    recs = 0
    try:
        with _open_any(path) as f:
            data = json.load(f)
    except Exception as e:
        sys.stderr.write("[!] NVD feed load failed (%s): %s\n" % (os.path.basename(path), e))
        nvd_meta.append({"file": os.path.basename(path), "sha256": _sha256(path), "records": 0})
        continue
    for item in data.get("vulnerabilities", []):
        recs += 1
        cve = item.get("cve") or {}
        cid = (cve.get("id") or "").upper()
        if not cid or not _touches_inventory(cve):
            continue
        lastmod = cve.get("lastModified", "")
        prev = cve_rec.get(cid)
        if prev is None or lastmod > prev[0]:
            cve_rec[cid] = (lastmod, cve)
    nvd_meta.append({"file": os.path.basename(path), "sha256": _sha256(path), "records": recs})

# Pass 2: join the winning record of each CVE against the inventory.
for cid, (lastmod, cve) in cve_rec.items():
    if (cve.get("vulnStatus") or "") == "Rejected":
        continue
    configs = cve.get("configurations") or []
    score, sev, cvver = cvss_of(cve)
    pub = cve.get("published", "")
    desc = en_desc(cve)
    is_kev = cid in kev
    if configs:
        for conf in configs:
            op = conf.get("operator", "")
            nodes = conf.get("nodes") or []
            prod_nodes = [n for n in nodes if node_hits_product(n)]
            if not prod_nodes:
                continue
            other_nodes = [n for n in nodes if n not in prod_nodes]
            for pnode in prod_nodes:
                for cm in (pnode.get("cpeMatch") or []):
                    if not cm.get("vulnerable", False):
                        continue
                    pc = parse_cpe(cm.get("criteria", ""))
                    if not pc or (pc[1], pc[2]) not in inv_products:
                        continue
                    key_prod = (pc[1], pc[2])
                    for (ridx, sv, scpe) in rows_by_prod[key_prod]:
                        m = classify(cm, sv)
                        if not m:
                            continue
                        if m == "product-only" and not is_kev:
                            continue   # product-only is KEV-only (noise control)
                        if op == "AND" and other_nodes:
                            cpe_set = rows[ridx]["cpes"]
                            if not all(node_satisfied_by(n, cpe_set) for n in other_nodes):
                                m = m + " (platform not verified)"
                        k = (ridx, cid)
                        prev = best.get(k)
                        if prev is None or _rank(m) > _rank(prev["match"]):
                            best[k] = {"match": m, "cpe": scpe, "cvss": score,
                                       "sev": sev, "cvver": cvver, "pub": pub, "desc": desc}

# --- emit -------------------------------------------------------------------
HEADER = ["seed_domain", "host", "ip", "port", "url", "status_code", "products", "cpe",
          "cve", "kev", "kev_date_added", "kev_due_date", "kev_ransomware",
          "epss", "epss_percentile", "cvss_score", "cvss_severity", "cvss_version",
          "published", "match", "description"]

def _epss_num(cid):
    try:
        return float(epss.get(cid, ("0",))[0])
    except Exception:
        return 0.0

def _cvss_num(s):
    try:
        return float(s)
    except Exception:
        return 0.0

out_rows = []
for (ridx, cid), info in best.items():
    row = rows[ridx]
    ka = kev.get(cid, ("", "", ""))
    ep = epss.get(cid, ("", ""))
    out_rows.append([
        row["seed_domain"], row["host"], row["ip"], row["port"], row["url"],
        row["status_code"], _csv_safe(row["products"]), _csv_safe(info["cpe"]),
        cid, "Yes" if cid in kev else "", ka[0], ka[1], ka[2],
        ep[0], ep[1], info["cvss"], info["sev"], info["cvver"],
        info["pub"], info["match"], _csv_safe(_clean(info["desc"])),
    ])

# sort: KEV first, then EPSS desc, then CVSS desc, then CVE
out_rows.sort(key=lambda r: (0 if r[9] == "Yes" else 1,
                             -_epss_num(r[8]), -_cvss_num(r[15]), r[8]))

with open(out_path, "w", newline="", encoding="utf-8") as fo:
    w = csv.writer(fo)
    w.writerow(HEADER)
    w.writerows(out_rows)

prov = {
    "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "input_csv": os.path.basename(csv_path),
    "nvd_feeds": nvd_meta,
    "kev": kev_meta,
    "epss": epss_meta,
    "services_with_cpes": len(rows),
    "vuln_rows": len(out_rows),
}
with open(out_path + ".provenance.json", "w", encoding="utf-8") as pf:
    json.dump(prov, pf, indent=2)

kevn = sum(1 for r in out_rows if r[9] == "Yes")
sys.stderr.write("[+] vuln join: %d row(s) across %d service(s); %d KEV; NVD feeds: %d\n"
                 % (len(out_rows), len(rows), kevn, len(nvd_meta)))
PYVULN
  rc=$?
  [ "$rc" -eq 0 ] && echo "[+] vulns: wrote $out  (+ ${out}.provenance.json)"
  return "$rc"
}

# ===========================================================================
# clean : data-retention sweep -- prune empty intermediate files, keep report data
# ===========================================================================
# run-recon already drops empty side-artifacts on a normal run, but a --keep-work
# run leaves the _work-* tree behind: per-domain raw/<host>/ dirs (~40 intermediate
# files each, many empty), empty done/<host> markers, and empty parts/ files -- which
# across many domains is thousands of blank files. `clean` prunes zero-byte and
# whitespace-only files recursively, removes directories left empty, and PRESERVES
# everything the HTML report consumes: it never deletes .csv/.html/.json files or
# screenshot images, whatever their size. --dry-run previews; --rows additionally
# writes a <csv>.cleaned.csv with blank (no-host, no-url) data rows dropped, without
# touching the original.
db_clean() {
  local dryrun=0 dorows=0 paths=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dry-run|-n) dryrun=1; shift;;
      --rows)       dorows=1; shift;;
      -h|--help) echo "usage: recon-db.sh clean <path>... [--dry-run] [--rows]" >&2; return 0;;
      -*) echo "[!] clean: unknown option: $1" >&2; return 2;;
      *) paths+=("$1"); shift;;
    esac
  done
  [ "${#paths[@]}" -gt 0 ] || { echo "usage: recon-db.sh clean <path>... [--dry-run] [--rows]" >&2; return 2; }
  command -v python3 >/dev/null 2>&1 || { echo "[!] clean: python3 is required." >&2; return 1; }
  RECON_CLEAN_DRYRUN="$dryrun" RECON_CLEAN_ROWS="$dorows" python3 -I - "${paths[@]}" <<'PYCLEAN'
import sys, os

paths = sys.argv[1:]
DRY  = os.environ.get("RECON_CLEAN_DRYRUN", "0") == "1"
ROWS = os.environ.get("RECON_CLEAN_ROWS", "0") == "1"

# never delete these, whatever their size -- the report (and the operator) need them
KEEP_EXT = {".csv", ".html", ".htm", ".json", ".png", ".jpg", ".jpeg", ".gif",
            ".webp", ".svg", ".pdf"}
# refuse to sweep obviously dangerous roots
_DANGER = {os.path.abspath(p) for p in ("/", os.path.expanduser("~"))}

def is_blank(path):
    try:
        if os.path.getsize(path) == 0:
            return True
        if os.path.getsize(path) <= 65536:
            with open(path, "rb") as f:
                return f.read().strip() == b""
    except OSError:
        return False   # unreadable -> never delete
    return False        # large file -> real data

removed_files = removed_bytes = removed_dirs = 0
tops = []
for p in paths:
    ap = os.path.abspath(p)
    if ap in _DANGER:
        sys.stderr.write("[!] clean: refusing to sweep %s\n" % ap)
        continue
    if not os.path.exists(ap):
        sys.stderr.write("[!] clean: not found: %s\n" % p)
        continue
    tops.append(ap)

csv_targets = []
for top in tops:
    if os.path.isfile(top):
        ext = os.path.splitext(top)[1].lower()
        if ext == ".csv" and ROWS:
            csv_targets.append(top)
        if is_blank(top) and ext not in KEEP_EXT:
            sz = os.path.getsize(top)
            sys.stdout.write(("[dry-run] would remove " if DRY else "removed ") + top + "\n")
            if not DRY:
                try: os.remove(top)
                except OSError: continue
            removed_files += 1; removed_bytes += sz
        continue
    # directory: prune blank files, then empty dirs (bottom-up)
    for root, dirs, files in os.walk(top, topdown=False):
        for name in files:
            fp = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            if ext == ".csv" and ROWS:
                csv_targets.append(fp)
            if ext in KEEP_EXT:
                continue
            if is_blank(fp):
                try: sz = os.path.getsize(fp)
                except OSError: sz = 0
                sys.stdout.write(("[dry-run] would remove " if DRY else "removed ") + fp + "\n")
                if not DRY:
                    try: os.remove(fp)
                    except OSError: continue
                removed_files += 1; removed_bytes += sz
        if os.path.abspath(root) in tops:
            continue   # never remove a path the user named
        try:
            if not os.listdir(root):
                sys.stdout.write(("[dry-run] would rmdir " if DRY else "rmdir ") + root + "\n")
                if not DRY:
                    try: os.rmdir(root)
                    except OSError: continue
                removed_dirs += 1
        except OSError:
            pass

# --rows: write a <csv>.cleaned.csv dropping data rows with no host AND no url
pruned_rows = 0
if ROWS and csv_targets:
    import csv as _csv
    for cpath in sorted(set(csv_targets)):
        if cpath.endswith(".cleaned.csv"):
            continue
        try:
            with open(cpath, newline="", encoding="utf-8", errors="replace") as fh:
                rd = _csv.reader(fh); rowsall = list(rd)
        except OSError:
            continue
        if not rowsall:
            continue
        header = rowsall[0]
        idx = {h.strip().lower(): i for i, h in enumerate(header)}
        hi, ui = idx.get("host"), idx.get("url")
        if hi is None and ui is None:
            continue   # not a recon inventory CSV
        kept = [header]; dropped = 0
        for row in rowsall[1:]:
            host = row[hi].strip() if (hi is not None and hi < len(row)) else ""
            url  = row[ui].strip() if (ui is not None and ui < len(row)) else ""
            if not host and not url:
                dropped += 1
            else:
                kept.append(row)
        if dropped:
            outp = cpath[:-4] + ".cleaned.csv"
            sys.stdout.write(("[dry-run] would write " if DRY else "wrote ") +
                             "%s (dropped %d blank row(s))\n" % (outp, dropped))
            if not DRY:
                with open(outp, "w", newline="", encoding="utf-8") as fo:
                    _csv.writer(fo).writerows(kept)
            pruned_rows += dropped

def _h(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%.0f %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0

sys.stderr.write("[+] clean%s: %d blank file(s) (%s), %d empty dir(s)%s\n" % (
    " (dry-run)" if DRY else "", removed_files, _h(removed_bytes), removed_dirs,
    (", %d blank CSV row(s)" % pruned_rows) if ROWS else ""))
PYCLEAN
}

# --- CLI (only when executed directly, not when sourced) -------------------
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  cmd="${1:-help}"
  case "$cmd" in
    init)   db_setup;;
    schema) db_available || { echo "[!] recon DB not reachable (see connection env)." >&2; exit 1; }
            db_schema && echo "[+] schema ready." || { echo "[!] failed." >&2; exit 1; };;
    stats)  db_available || { echo "[!] recon DB not reachable." >&2; exit 1; }
            _psql <<'SQL'
SELECT 'cache rows: '||count(*) FROM recon_cache
UNION ALL SELECT 'cache sources: '||count(DISTINCT source) FROM recon_cache
UNION ALL SELECT 'host rows: '||count(*) FROM recon_hosts
UNION ALL SELECT 'runs stored: '||count(DISTINCT run_ts) FROM recon_hosts;
SQL
            ;;
    hosts)  db_available || { echo "[!] recon DB not reachable." >&2; exit 1; }
            pat="$(_sql_esc "${2:-}")"
            _psql -c "SELECT run_ts,host,ip,asn_org,status_code FROM recon_hosts WHERE host LIKE '%${pat}%' ORDER BY host LIMIT 500";;
    import) shift; db_import_csvs "$@";;
    latest) db_available || { echo "[!] recon DB not reachable." >&2; exit 1; }
            # current-state view: the newest run_ts wins per URL (older data is kept
            # in recon_hosts but superseded here). Optional host-substring filter.
            pat="$(_sql_esc "${2:-}")"
            _psql -c "SELECT DISTINCT ON (url) run_ts,host,url,ip,asn_org,status_code,title FROM recon_hosts WHERE host LIKE '%${pat}%' ORDER BY url, run_ts DESC LIMIT 1000";;
    purge)  db_available || { echo "[!] recon DB not reachable." >&2; exit 1; }
            days="${2:-30}"; case "$days" in ''|*[!0-9]*) days=30;; esac
            _psql -c "DELETE FROM recon_cache WHERE fetched_at < now() - interval '$days days'" && echo "[+] purged cache older than $days days.";;
    fix-collation|fixcollation) db_fix_collation;;
    vulns)  shift; db_vulns "$@";;
    clean)  shift; db_clean "$@";;
    help|-h|--help) sed -n '2,49p' "$0" | sed 's/^# \{0,1\}//';;
    *) echo "unknown command: $cmd (try: init|schema|stats|hosts|latest|import|vulns|clean|fix-collation|purge)" >&2; exit 2;;
  esac
fi
