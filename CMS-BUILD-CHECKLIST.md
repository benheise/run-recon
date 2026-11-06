# Active CMS/App Scanning — Build Checklist (run-recon.sh v1.6.0)

Implements the "Active CMS Scanning Technique Catalog and Build Plan" as a new opt-in stage
gated behind `--active` and folded into `--all`. Two-tier architecture per the plan: shell out
to best-of-breed CLIs when present, with a native bash+curl/ffuf primitive tier for graceful
degradation. Passive-by-default fingerprinting; aggressive enumeration behind the flag.

## A. Core `--active` stage (run-recon.sh)
- [x] 1. Config defaults: `ACTIVE`, `CMS_WORDLIST` (SecLists CMS list), `CMS_MAX` (host cap), honor `WPSCAN_API_TOKEN` env.
- [x] 2. `cms_scan` helper — CMS **fingerprint** per live host: whatweb → nuclei tech-detect → native curl (`meta generator`, `/wp-content`, `/sites/default`, `/administrator`); classify WordPress/Drupal/Joomla/other.
- [x] 3. **WordPress** module: shell out `wpscan` (`--enumerate vp,vt,u`, `--api-token` if token) when present; native tier otherwise — version (`/readme.html`, meta generator, `/feed/` generator), users (`/wp-json/wp/v2/users`, `/?author=N` redirect), plugins/themes passive (grep `/wp-content/plugins|themes/<slug>/` from HTML) + aggressive brute via **ffuf** (`/wp-content/plugins/FUZZ/readme.txt`, `/wp-content/themes/FUZZ/style.css`).
- [x] 4. **Drupal** module: `droopescan scan drupal` when present; native — `/CHANGELOG.txt` + `/core/CHANGELOG.txt` version, meta generator.
- [x] 5. **Joomla** module: `joomscan --url` when present; native — `/administrator/manifests/files/joomla.xml` version, `/language/en-GB/en-GB.xml`.
- [x] 6. **Generic/unknown** module: `cmseek -u --batch` (auto-detects many CMSs) on hosts no fingerprint classified.
- [x] 7. **Vuln mapping**: `nuclei -tags tech,cms` on all detected-CMS hosts (durable MIT-licensed OSS layer); WPScan vuln DB via token when present.
- [x] 8. Findings → `$WORKDIR/parts/cms.<safe>.txt`; call `cms_scan` from `process_one`.
- [x] 9. Aggregate → `<out>.cms.txt` (add `cms` to the kinds loop).
- [x] 10. Arg parser: `--active`, `--cms-wordlist FILE`; add `ACTIVE=1` to `--all`.
- [x] 11. Preflight: passive-only gating; graceful-degradation warnings (which specialist tools present; WPScan token note; wordlist note); stage still runs on the native tier.
- [x] 12. Exports: `ACTIVE CMS_WORDLIST CMS_MAX WPSCAN_API_TOKEN`; `export -f cms_scan`.
- [x] 13. Help text: document `--active` + `--cms-wordlist`.
- [x] 14. Startup banner: show `active`/CMS state.
- [x] 15. VERSION → 1.6.0; `bash -n` clean.

## B. Installer (setup-recon-env.sh)
- [x] 16. Add `droopescan` (pipx), `cmseek` (git-venv), `wpscan` (gem), `whatweb` (pkg), `joomscan` (git clone) + `ruby` to base pkgs; verification list; version bump.

## C. PowerShell provisioner
- [x] 17. Mirror the new tools.

## D. Test suite (test-run-recon.sh)
- [x] 18. Mocks: `whatweb`, `wpscan`, `droopescan`, `joomscan`, `cmseek` (nuclei already mocked).
- [x] 19. Scenarios: `--active` full dispatch (whatweb → wpscan/droopescan/joomscan + nuclei tech,cms + artifact); native ffuf plugin brute fallback (wpscan hidden); generic `cmseek` path (fingerprint unknown); `--all` includes active; `--passive-only` disables it.

## E. Docs
- [x] 20. README: capability-matrix row, usage examples, caveats (traffic/attribution, WPScan 25 req/day non-commercial cap vs nuclei-templates, version-based vuln over-reporting).

## F. Finalize
- [x] 21. `bash -n` all; full suite green; sync to work; present; check off.

---

## ✅ Completed — run-recon.sh v1.6.0

All 21 items implemented and verified.

- **run-recon.sh → 1.6.0** (1449 lines): `cms_scan` helper (fingerprint → per-CMS deep enum → nuclei vuln map), `--active` + `--cms-wordlist` flags, folded into `--all`, passive-only gating, graceful-degradation preflight, exports, `<out>.cms.txt` aggregation, help + banner. `bash -n` clean.
- **setup-recon-env.sh → 1.5.0**: droopescan (pipx), cmseek (git-venv), wpscan (gem), joomscan (git clone), whatweb + ruby (base pkgs); verification list updated.
- **Setup-ReconEnv.ps1**: parity for all five CMS tools.
- **test-run-recon.sh → 154 assertions / 40 scenarios, all passing**: mocks for whatweb/wpscan/droopescan/joomscan/cmseek; scenarios for full dispatch, native ffuf fallback (wpscan absent), generic cmseek path (unknown fingerprint), `--all` inclusion, and `--passive-only` gating.
- **README.md**: install-table row, usage examples, capability-matrix row, pipeline step, and four caveats (traffic/attribution noise, WPScan 25 req/day cap vs nuclei-templates MIT, native-tier fallback, version→CVE over-reporting).

### Architecture as built (matches the plan's two-tier model)
- **Tier 1 — shell out to best-of-breed CLIs** when present: whatweb (fingerprint), wpscan/droopescan/joomscan (per-CMS deep enum), cmseek (generic), nuclei `-tags tech,cms` (durable OSS vuln layer).
- **Tier 2 — native curl/ffuf primitives** for graceful degradation: WP version (`/readme.html`, meta generator), users (`/wp-json/wp/v2/users`, `/?author=N`), passive plugin/theme refs, aggressive slug brute (ffuf `wp-content/{plugins,themes}/FUZZ`), Drupal `/CHANGELOG.txt`, Joomla `/administrator/manifests/files/joomla.xml`.
- **Passive-by-default fingerprint, aggressive behind the flag**; WPScan token optional (nuclei-templates is the always-available vuln source).

### Real-install smoke-test notes (accepted project caveats)
Native curl/ffuf probes and specialist-CLI exactness can't be exercised in the mock harness (no target web server). Confirm on a real Kali install: `cmseek -u` non-interactive behavior, `joomscan` binary name, wpscan `--format cli-no-color`/`--enumerate` flags, and droopescan output parsing. Mocks validate the wiring, dispatch, and graceful degradation.
