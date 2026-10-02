# Sandbox reader and production-retention QA — 2026-10-02

Four-role board QA verdict: **APPROVE the bounded Decision 0010 implementation**
on the measured local evidence below. This is not a target solve, independent
validation authority, saved-state migration or general descendant supervision.
All checks ran sequentially on the 4 GB host. No target or external provider
request occurred. Production-path fixtures substituted fixed local payloads
for Pi and used an explicitly synthetic Groq environment value; no operator
credential was read. Reader fixtures generated their own synthetic keypair.

## Commands executed by the delegated QA reviewer

- `bash -n sandbox/setup.sh sandbox/run-sandboxed.sh sandbox/egress.sh`: passed.
- A Python subprocess matrix invoked `bash sandbox/setup.sh <absent scratch
  runtime>` with each noncanonical `PLUTO_UID`, `PLUTO_RUN_DIR`,
  `PLUTO_CONTROL_DIR`, `PLUTO_ENGAGEMENTS_DIR`, and `PLUTO_KEYDIR`: five refusals,
  each exit 1 with its canonical-path error before provisioning. The destination
  remained absent and canonical directory inode/mtime/mode snapshots unchanged.
- `python3 -m py_compile extensions/test/sandbox-boundary-qa.py` and
  `node --check extensions/test/sandbox-retention.integration.mjs`: passed.
- `python3 extensions/test/sandbox-boundary-qa.py reader
  --before-schema-guard`: executed in approved root host context against the
  earlier `/opt` deployment. Reproduced the view-substitution gap below.
- `python3 extensions/test/sandbox-boundary-qa.py reader`: executed in approved
  root host context after the guarded redeployment; all nine reader scenarios
  passed, plus verified owned cleanup.
- `python3 extensions/test/sandbox-boundary-qa.py production`: executed in
  approved root host context; both production-path scenarios passed, including
  matching-owner recovery and unchanged continuity checks.
- From `extensions`, `node --test --test-concurrency=1 --test-reporter=tap
  dist/state/promotion-sign-isolated.test.js`: **5/5 passed, zero skipped** in
  approved host context. The first restricted-context attempt failed its test
  worker with `ERR_TEST_FAILURE`; it produced no individual assertion result.
  The host rerun is the passing evidence.

The boundary fixture's first attempt omitted the host `sbin` directories from
its policy utility PATH. Policy apply refused before workload startup; its
owned lock/scratch cleanup passed. The fixture PATH was corrected before the
successful executions. This was a QA-fixture failure, not a production success.

## Measured reader behavior

The persistent deployed reader ran with real/effective/saved/filesystem UID
**994**, `NoNewPrivs: 1`, and no private-key or provider/token environment
variable, even though synthetic provider/token variables were present in the
root daemon environment. A Node preload replaced root's `DatabaseSync`
constructor with a throwing class. Actual readiness and signing still worked.
This directly exercises the strict daemon path without a root SQLite open.

An actual confined runtime process tried direct paths and twelve alternate
`/proc/<same-uid-pid>/root/...` paths to a disposable readable repository file
under `/root`, a readable private host `/tmp` file, and a synthetic root-only
private key. **No read succeeded**. This establishes the tested root/private-tmp
masking paths, including the same-UID bubblewrap-monitor concern; it does not
establish general host read isolation.

| Scenario | Observed result |
| --- | --- |
| Reader SIGKILL | Signing returned `ERR Confined signing reader exited`; later signing continued to refuse; no reader workload remained |
| Reader SIGSTOP | Connection deadline returned no signature within the fixture's four-second bound; later signing refused permanently and the reader terminated |
| Root daemon SIGKILL | Its confined reader terminated; no Pluto UID workload remained |
| Ledger inode replacement | Signing and health refused `signer ledger or ancestor was replaced` |
| State-directory replacement | Signing and health refused `signer ledger or ancestor was replaced` |
| Journal symlink to root-only synthetic sentinel | Signing and health refused `unsafe signer ledger sidecar`; sentinel bytes/mode/owner unchanged |
| Dropped validations table | Signing and health refused the ordinary-table requirement in the guarded deployment |
| Findings table replaced by same-shape view | Earlier deployment signed; guarded deployment refused signing and health with `Reader requires ordinary findings/validations tables` |

Each ordinary fixture initially signed its fixed synthetic candidate/passed
validation, preventing a universally broken signer from satisfying the reject
checks. No captured signature or synthetic key is retained in this report.
Owned egress and launch locks were removed only after fixture workloads ended.

The focused five-case suite additionally exercised ordinary/table-view/virtual
schema rules, refusal of legacy root SQLite in requested sandbox mode, reader
environment filtering, typed bounded claim validation, and actual pipe
transport handling of malformed JSON, wrong correlation, oversized replies,
worker exit and timeout. It is regression evidence alongside the real confined
process cases, not a substitute for them.

## Measured production transaction behavior

The real production `runSandbox` transaction was invoked twice. The successful
payload was deployed `ledger-probe.js`; the failure payload was an absent local
script. Neither invoked Pi, a provider or a target.

Both transactions reported retained protection and left:

- an actual `inet pluto_egress` table with the launch's matching owner comment;
- a root-owned launch lock and matching owner record;
- a root-owned mode-0600 recovery marker naming the same run;
- no remaining signer endpoint or Pluto UID workload after owned handles stopped.

A later sandbox-check launch refused the recovery hold without changing the
marker or owner record. A different egress ownership token could not tear down
the policy. Explicit root fixture recovery removed only the matching policy,
marker and lock after checking workload state. The database and synthetic
descriptor/hold artifacts retained identical SHA-256 hashes across recovery.
These synthetic continuity records are not proof of valid session metadata;
the separate source-profile fixture below checks genuine bindings and holds.

The missing-script case proves conservative retention after failed local payload
execution. It does not inject a low-level OS `spawn` error or prove arbitrary
detached descendants terminated. The implementation's monotonic flag and
unconditional retention supply the conservative boundary for production.

## Coordinating-agent checks, not rerun by this reviewer

The coordinating agent reports the fresh guarded source build and full serial
extension suite **234/234 passed, zero skipped**. It executed
`/tmp/pluto-resume-qa.sh` after redeployment, which ran production sandbox-check
readiness, `/tmp/pluto-profile-local-qa.py`, and
`/tmp/pluto-startup-final-qa.py`, all exit 0. The profile and startup orchestrators
are also preserved as `extensions/test/sandbox-profile-qa.py` and
`extensions/test/sandbox-startup-qa.py`.

Reported measured coverage includes actual UID/no_new_privs and filesystem
write/denial checks; real signed synthetic promotion/direct-flip and failed
validation refusal; cold WAL and later writes; thirteen actual source-profile
extensions; same-association resume/trust; persisted provider holds and pause
recovery; explicit retry; root-selected STOP and delegate guards; disabled
bubblewrap refusal; unchanged historical relocation refusal; concurrent lock
and stale-endpoint refusal; SIGTERM at signer startup; and owned teardown.
The source-profile provider is a local faux provider with no fetch. These are
coordinating-agent execution results, distinguished from this reviewer's runs.

## Verification limits

Forged passed-validation rows remain an open residual: a signature still
establishes provenance of ledger claims, not independent evidence truth.
Production automatically retains protection; a general root recovery tool and
strong descendant supervision remain separately scoped. Controlled-fixture
quiescence observations do not authorize cleanup of arbitrary production runs.
No bound-v1 migration, target restoration, autonomous target completion, live
provider access or general host read-isolation claim follows from this QA.

At guarded QA execution, deployed compiled file SHA-256 values were:

- `promotion-reader.js`: `310a4807de9c7d8abe46929ac474fa9ac44fdaffbbe0569d5e27659706284971`
- `promotion-sign-isolated.js`: `d41241e7783dd98f781d4a11aadacc21da074c7b87a7d395dafb7b7071977226`

Portable boundary orchestrator SHA-256:
`3ddd0266e70f1448af9426be3c4e4a71e01d2581bd108df7154f1980fc3cb8f9`.
Local production-payload fixture SHA-256:
`e44325561ea374b4d5fd9d3a8b55ca02befc857f6b68e4d21caa810120d4794c`.
