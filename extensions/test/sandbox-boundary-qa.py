#!/usr/bin/env python3
"""Serial host-only QA of real confined reader and owned production resources.

Run explicitly in an approved root host context. Each invocation refuses any
existing Pluto workload, control hold, launch lock or egress policy. No provider
or target call is made. Cleanup touches only this fixture's recorded ownership.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parents[2]
RUNTIME = Path('/opt/cyber-pluto')
RUN = Path('/run/cyber-pluto')
CONTROL = Path('/var/lib/cyber-pluto/control')
ENGAGEMENTS = Path('/var/lib/cyber-pluto/engagements')
NODE = '/usr/local/bin/node'
HOST_PATH = '/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin'
UID = int(subprocess.check_output(['id', '-u', 'pluto']))
GID = int(subprocess.check_output(['id', '-g', 'pluto']))
TAG = 'qa-' + uuid.uuid4().hex[:12]
EVENTS: list[dict[str, object]] = []


def command(args: list[str], **options: object) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, timeout=30, **options)
    assert result.returncode == 0, f'{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}'
    return result


def emit(name: str, **fields: object) -> None:
    record = {'check': name, **fields}
    EVENTS.append(record)
    print(json.dumps(record), flush=True)


def uid_pids() -> list[int]:
    found: list[int] = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            for line in (path / 'status').read_text().splitlines():
                if line.startswith('Uid:') and UID in map(int, line.split()[1:]):
                    found.append(int(path.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return found


def wait_quiet(seconds: float = 5) -> None:
    deadline = time.monotonic() + seconds
    while uid_pids():
        assert time.monotonic() < deadline, f'fixture workloads remain: {uid_pids()}'
        time.sleep(.025)


def table() -> dict[str, object] | None:
    inventory = json.loads(command(['nft', '-j', 'list', 'tables']).stdout)
    return next((entry['table'] for entry in inventory['nftables'] if entry.get('table', {}).get('family') == 'inet' and entry['table'].get('name') == 'pluto_egress'), None)


def prerequisites() -> None:
    assert os.geteuid() == 0, 'approved root host execution required'
    assert not uid_pids(), 'existing Pluto UID workloads; refusing fixture'
    assert not table(), 'existing egress policy; refusing fixture'
    assert not (RUN / 'launch.lock').exists(), 'existing launch lock; refusing fixture'
    for name in ['KILL_SWITCH', 'PAUSED', 'RECOVERY_REQUIRED.json']:
        assert not (CONTROL / name).exists(), f'existing control hold: {name}'


class ReaderFixture:
    def __init__(self, base: Path, case: str):
        self.base = base / case
        self.base.mkdir(mode=0o755)
        self.eng = self.base / 'engagement'
        self.eng.mkdir(mode=0o750)
        os.chown(self.eng, UID, GID)
        for name in ['state', 'logs', 'evidence', 'sessions', 'pi-agent']:
            directory = self.eng / name
            directory.mkdir(mode=0o750)
            os.chown(directory, UID, GID)
        self.run = self.base / 'run'
        self.control = self.base / 'control'
        self.signers = self.run / 'signers'
        self.signer = self.signers / 'fixture'
        for directory in [self.run, self.control, self.signers, self.signer]:
            directory.mkdir(mode=0o755)
        self.ledger = self.eng / 'state/pluto.db'
        db = sqlite3.connect(self.ledger)
        db.executescript("""
            CREATE TABLE findings(id INTEGER PRIMARY KEY,target_id INTEGER,status TEXT);
            CREATE TABLE validations(id INTEGER PRIMARY KEY,finding_id INTEGER,passed INTEGER,validator TEXT,baseline_ref TEXT,attack_ref TEXT);
            INSERT INTO findings VALUES(1,1,'candidate');
            INSERT INTO validations VALUES(1,1,1,'qa-fixture','synthetic-baseline','synthetic-attack');
        """)
        db.close()
        os.chown(self.ledger, UID, GID)
        self.ledger.chmod(0o600)
        self.socket = self.signer / 'promotion.sock'
        self.env = {
            'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/nonexistent',
            'PLUTO_CWD': str(RUNTIME), 'PLUTO_STATE_DIR': str(self.eng / 'state'),
            'PLUTO_RUN_DIR': str(self.run), 'PLUTO_CONTROL_DIR': str(self.control),
            'PLUTO_SIGNER_DIR': str(self.signer), 'PLUTO_KILL_FILE': str(self.control / 'KILL_SWITCH'),
            'PLUTO_SIGNER_RUN_ID': TAG, 'PLUTO_SANDBOX_MODE': 'requested',
            'PLUTO_READINESS_UID': str(UID), 'PLUTO_UID': 'pluto',
            'PI_CODING_AGENT_DIR': str(self.eng / 'pi-agent'),
            'PLUTO_PROMOTION_SIGNER_CMD': f'{NODE} {RUNTIME}/extensions/dist/state/promotion-sign-client.js {self.socket}',
            'PLUTO_PROMOTION_PUBKEY': str(base / 'public.pub'),
        }
        self.log = (self.base / 'daemon.log').open('w+')
        self.daemon = subprocess.Popen([
            NODE, '--require', str(base / 'deny-root-sqlite.cjs'),
            str(RUNTIME / 'extensions/dist/state/promotion-sign-daemon.js'), str(self.socket),
        ], env={**self.env, 'PLUTO_SIGNER_STRICT': '1', 'PLUTO_PROMOTION_PRIVKEY': str(base / 'private.key'), 'OPENAI_API_KEY': 'synthetic-must-not-reach-reader', 'PLUTO_CODEX_ACCESS_TOKEN': 'synthetic-must-not-reach-reader'},
            start_new_session=True, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 8
        while not self.socket.exists():
            assert self.daemon.poll() is None, self.diagnostics()
            assert time.monotonic() < deadline, 'reader daemon startup timed out'
            time.sleep(.025)
        assert self.request({'op': 'health', 'challenge': 'a' * 64}).startswith('{')
        self.reader_pid = self.find_reader()

    def diagnostics(self) -> str:
        self.log.flush()
        return (self.base / 'daemon.log').read_text()

    def find_reader(self) -> int:
        matches = []
        for pid in uid_pids():
            try:
                args = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
                if args and args[0] == NODE.encode() and str(RUNTIME / 'extensions/dist/state/promotion-reader.js').encode() in args:
                    matches.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                pass
        assert len(matches) == 1, matches
        return matches[0]

    def request(self, body: dict[str, object]) -> str:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(4)
            connection.connect(str(self.socket))
            connection.sendall(json.dumps(body).encode())
            connection.shutdown(socket.SHUT_WR)
            result = b''
            while True:
                part = connection.recv(16_384)
                if not part:
                    break
                result += part
                assert len(result) <= 16_384
            return result.decode()

    def refuse(self) -> str:
        try:
            result = self.request({'findingId': 1, 'validationId': 1})
        except (socket.timeout, ConnectionResetError):
            result = 'transport refusal'
        assert not result.startswith('OK '), f'unexpected signature: {result}'
        return result

    def close(self) -> None:
        try:
            os.killpg(self.daemon.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.daemon.wait(timeout=4)
        except subprocess.TimeoutExpired:
            os.killpg(self.daemon.pid, signal.SIGKILL)
            self.daemon.wait(timeout=4)
        wait_quiet()
        self.log.close()


def reader_checks(expect_view_rejection: bool) -> None:
    prerequisites()
    base = Path(tempfile.mkdtemp(prefix='pluto-reader-boundary-'))
    base.chmod(0o755)
    policy_env = {'PATH': HOST_PATH, 'PLUTO_UID': 'pluto', 'PLUTO_EGRESS_RUN_ID': TAG, 'LC_ALL': 'C'}
    lock = RUN / 'launch.lock'
    acquired = policy = False
    fixture: ReaderFixture | None = None
    root_source = REPO / f'.qa-source-{TAG}'
    host_tmp = base / 'synthetic-host-tmp'
    try:
        lock.mkdir(mode=0o700)
        acquired = True
        (lock / 'owner.json').write_text(json.dumps({'runId': TAG, 'pid': os.getpid(), 'qa': True}))
        command(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', str(base / 'private.key')])
        (base / 'private.key').chmod(0o400)
        command(['openssl', 'pkey', '-in', str(base / 'private.key'), '-pubout', '-out', str(base / 'public.pub')])
        (base / 'public.pub').chmod(0o444)
        (base / 'deny-root-sqlite.cjs').write_text("const sqlite=require('node:sqlite');sqlite.DatabaseSync=class{constructor(){throw new Error('QA forbids root SQLite opens')}};require('node:module').syncBuiltinESMExports();console.log('root SQLite disabled');")
        (base / 'deny-root-sqlite.cjs').chmod(0o444)
        command([str(RUNTIME / 'sandbox/egress.sh'), 'apply', '127.0.0.1'], env=policy_env)
        policy = True
        for case in ['identity', 'loss', 'stall', 'daemon-kill', 'main', 'ancestor', 'sidecar', 'schema-drop', 'schema-view']:
            fixture = ReaderFixture(base, case)
            assert fixture.request({'findingId': 1, 'validationId': 1}).startswith('OK ')
            if case == 'identity':
                status = (Path('/proc') / str(fixture.reader_pid) / 'status').read_text()
                assert f'Uid:\t{UID}\t{UID}\t{UID}\t{UID}' in status and 'NoNewPrivs:\t1' in status
                env_names = [(field.split(b'=', 1)[0]).decode() for field in (Path('/proc') / str(fixture.reader_pid) / 'environ').read_bytes().split(b'\0') if field]
                assert not any(name == 'PLUTO_PROMOTION_PRIVKEY' or name.endswith(('API_KEY', 'AUTH_TOKEN', 'ACCESS_TOKEN', 'REFRESH_TOKEN')) for name in env_names), env_names
                root_source.write_text('synthetic-root-source-fixture')
                root_source.chmod(0o444)
                host_tmp.write_text('synthetic-private-host-tmp-fixture')
                host_tmp.chmod(0o444)
                probe = fixture.eng / 'proc-mask.mjs'
                probe.write_text("""import {readFileSync,readdirSync} from 'node:fs';
const uid=process.getuid();const [rootPath,tmpPath,keyPath]=process.argv.slice(2);const reads=[];let checked=0;
for(const path of [rootPath,tmpPath,keyPath]){try{readFileSync(path);reads.push(path)}catch{}}
for(const pid of readdirSync('/proc').filter(x=>/^\\d+$/.test(x))){try{const status=readFileSync('/proc/'+pid+'/status','utf8');if(!new RegExp('^Uid:\\\\s+'+uid+'\\\\s','m').test(status))continue;for(const path of [rootPath,tmpPath,keyPath]){checked++;try{readFileSync('/proc/'+pid+'/root'+path);reads.push('/proc/'+pid+'/root'+path)}catch{}}}catch{}}
console.log(JSON.stringify({reads,checked}));if(reads.length||checked===0)process.exit(1);
""")
                probe.chmod(0o444)
                result = command([str(RUNTIME / 'sandbox/run-sandboxed.sh'), str(fixture.eng), '--', NODE, str(probe), str(root_source), str(host_tmp), str(base / 'private.key')], env=fixture.env)
                masks = json.loads(result.stdout)
                emit(case, uid=UID, noNewPrivileges=True, credentialEnvironmentAbsent=True, procAlternateMask=masks, rootSqliteConstructorDisabled=True)
            elif case in ['loss', 'stall']:
                os.kill(fixture.reader_pid, signal.SIGKILL if case == 'loss' else signal.SIGSTOP)
                start = time.monotonic()
                refusal = fixture.refuse()
                assert time.monotonic() - start < 4.2
                wait_quiet()
                assert fixture.refuse() != 'OK '
                emit(case, refusal=refusal, permanentRefusal=True, readerCleanup=True)
            elif case == 'daemon-kill':
                os.kill(fixture.daemon.pid, signal.SIGKILL)
                fixture.daemon.wait(timeout=3)
                wait_quiet()
                emit(case, readerTerminated=True)
            else:
                sentinel = base / 'root-only-sentinel'
                sentinel.write_bytes(b'root-only-QA-sentinel')
                sentinel.chmod(0o400)
                before = sentinel.read_bytes(), sentinel.stat().st_mode, sentinel.stat().st_uid
                if case == 'main':
                    fixture.ledger.rename(fixture.ledger.with_name('old-pluto.db'))
                    shutil.copyfile(fixture.ledger.with_name('old-pluto.db'), fixture.ledger)
                    os.chown(fixture.ledger, UID, GID)
                elif case == 'ancestor':
                    state = fixture.eng / 'state'
                    state.rename(fixture.eng / 'old-state')
                    state.mkdir(mode=0o750)
                    os.chown(state, UID, GID)
                    shutil.copyfile(fixture.eng / 'old-state/pluto.db', fixture.ledger)
                    os.chown(fixture.ledger, UID, GID)
                elif case == 'sidecar':
                    Path(str(fixture.ledger) + '-journal').symlink_to(sentinel)
                else:
                    db = sqlite3.connect(fixture.ledger)
                    if case == 'schema-drop':
                        db.execute('DROP TABLE validations')
                    else:
                        db.executescript('ALTER TABLE findings RENAME TO shadow_findings; CREATE VIEW findings AS SELECT * FROM shadow_findings;')
                    db.commit()
                    db.close()
                response = fixture.request({'findingId': 1, 'validationId': 1})
                if case == 'schema-view' and not expect_view_rejection:
                    assert response.startswith('OK '), response
                    emit(case, beforeGuard='signature accepted for substituted view', acceptance=False)
                else:
                    assert not response.startswith('OK '), response
                    health = fixture.request({'op': 'health', 'challenge': 'b' * 64})
                    assert not health.startswith('{'), health
                    emit(case, promotionRefused=response, healthRefused=health, sentinelUnchanged=True)
                assert before == (sentinel.read_bytes(), sentinel.stat().st_mode, sentinel.stat().st_uid)
            fixture.close()
            fixture = None
        emit('reader-suite', result='passed', expectedViewRejection=expect_view_rejection)
    finally:
        if fixture:
            fixture.close()
        if acquired:
            wait_quiet()
            if policy:
                command([str(RUNTIME / 'sandbox/egress.sh'), 'teardown'], env=policy_env)
            assert json.loads((lock / 'owner.json').read_text())['runId'] == TAG
            (lock / 'owner.json').unlink()
            lock.rmdir()
        root_source.unlink(missing_ok=True)
        shutil.rmtree(base)
        emit('reader-fixture-cleanup', result='verified', ownedPolicyRemoved=True)


def production_checks() -> None:
    for mode in ['normal', 'missing']:
        prerequisites()
        label = 'qa-retention-' + uuid.uuid4().hex[:12]
        engagement = ENGAGEMENTS / label
        signer = RUN / 'signers' / label
        lock = RUN / 'launch.lock'
        recovery = CONTROL / 'RECOVERY_REQUIRED.json'
        owner: dict[str, object] | None = None
        try:
            result = command([NODE, str(REPO / 'extensions/test/sandbox-retention.integration.mjs'), label, mode], cwd=str(REPO))
            assert 'qaProductionRetention' in result.stdout, result.stdout
            owner = json.loads((lock / 'owner.json').read_text())
            marker = json.loads(recovery.read_text())
            assert owner['runId'] == marker['runId']
            assert 'Production workload dispatched' in marker['reason']
            rules = table()
            assert rules and rules['comment'] == 'pluto-run:' + str(owner['runId'])
            assert lock.stat().st_uid == 0 and recovery.stat().st_uid == 0 and recovery.stat().st_mode & 0o077 == 0
            wait_quiet()
            assert not (signer / 'promotion.sock').exists(), 'signer endpoint retained'
            # Synthetic continuity records stand in for artifacts that recovery
            # must preserve; source-profile QA separately checks genuine holds.
            descriptor = engagement / 'sessions/qa.binding.json'
            hold = engagement / 'sessions/qa.outcome.json'
            descriptor.write_text(json.dumps({'qa': True, 'association': label, 'trust': 'unchanged'}))
            hold.write_text(json.dumps({'qa': True, 'providerHold': 'fixture-persisted'}))
            preserved = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in [engagement / 'state/pluto.db', descriptor, hold]}
            before_marker, before_owner = recovery.read_bytes(), (lock / 'owner.json').read_bytes()
            refused = subprocess.run([str(RUNTIME / 'cyberpluto'), '127.0.0.1', '--label', label, '--sandbox-check'], capture_output=True, text=True, timeout=20)
            assert refused.returncode != 0 and 'RECOVERY_REQUIRED.json' in refused.stderr, refused.stderr
            assert recovery.read_bytes() == before_marker and (lock / 'owner.json').read_bytes() == before_owner
            foreign = subprocess.run([str(RUNTIME / 'sandbox/egress.sh'), 'teardown'], env={'PATH': HOST_PATH, 'PLUTO_EGRESS_RUN_ID': 'foreign-qa-owner'}, capture_output=True, text=True, timeout=10)
            assert foreign.returncode != 0 and table() == rules
            # Explicit root recovery is confined to the verified fixture token.
            command([str(RUNTIME / 'sandbox/egress.sh'), 'teardown'], env={'PATH': HOST_PATH, 'PLUTO_EGRESS_RUN_ID': str(owner['runId']), 'LC_ALL': 'C'})
            assert not table()
            assert json.loads(recovery.read_text())['runId'] == owner['runId']
            recovery.unlink()
            (lock / 'owner.json').unlink()
            lock.rmdir()
            assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in preserved.items())
            emit('production-' + mode, protectionRetained=True, rootOwnedLockAndRecovery=True, anotherLaunchRefused=True, foreignTeardownRefused=True, explicitRootRecovery='owned fixture resources only', continuityPreserved=True, payload='fixed local probe' if mode == 'normal' else 'missing local script', modelOrTarget='none')
        finally:
            # On unexpected failure, only known fixture ownership permits release.
            if owner and recovery.exists() and json.loads(recovery.read_text()).get('runId') == owner['runId']:
                wait_quiet()
                command([str(RUNTIME / 'sandbox/egress.sh'), 'teardown'], env={'PATH': HOST_PATH, 'PLUTO_EGRESS_RUN_ID': str(owner['runId']), 'LC_ALL': 'C'})
                recovery.unlink()
                if lock.exists() and json.loads((lock / 'owner.json').read_text()).get('runId') == owner['runId']:
                    (lock / 'owner.json').unlink()
                    lock.rmdir()
            if not table() and not lock.exists() and not uid_pids():
                shutil.rmtree(engagement, ignore_errors=True)
                if signer.exists() and not list(signer.iterdir()):
                    signer.rmdir()
            prerequisites()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['reader', 'production'])
    parser.add_argument('--before-schema-guard', action='store_true')
    args = parser.parse_args()
    if args.mode == 'reader':
        reader_checks(not args.before_schema_guard)
    else:
        production_checks()
