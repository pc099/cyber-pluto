#!/usr/bin/env python3
"""Explicit serial root-host QA; no live provider or target calls."""
import os,pathlib,subprocess,json,uuid,time,shutil,signal
runtime='/opt/cyber-pluto'
tag='qa-'+uuid.uuid4().hex[:12]
base=pathlib.Path('/tmp')/('pluto-profile-'+tag)
eng=base/'engagement'; run=base/'run'; control=base/'control'; signer=run/'signers'/'fixture'; lock=pathlib.Path('/run/cyber-pluto/launch.lock')
uid=int(subprocess.check_output(['id','-u','pluto'])); gid=int(subprocess.check_output(['id','-g','pluto']))
daemon=None; child=None; acquired=False; policy=False; success=False
policyenv={**os.environ,'PLUTO_EGRESS_RUN_ID':tag,'LC_ALL':'C'}
def command(args,**kw):return subprocess.run(args,check=True,text=True,timeout=40,**kw)
def quiet():
 for p in pathlib.Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   for line in (p/'status').read_text().splitlines():
    if line.startswith('Uid:') and uid in map(int,line.split()[1:]):return False
  except FileNotFoundError:pass
 return True
try:
 assert quiet(),'existing confined workload'
 lock.mkdir(mode=0o700);acquired=True;(lock/'owner.json').write_text(json.dumps({'runId':tag,'pid':os.getpid(),'qa':True}))
 command(['nft','-j','list','tables'],stdout=subprocess.PIPE)
 base.mkdir(mode=0o755)
 monitor=base/'deny-root-sqlite.cjs';monitor.write_text("const sqlite=require('node:sqlite');sqlite.DatabaseSync=class{constructor(){throw new Error('QA forbids root SQLite opens')}};require('node:module').syncBuiltinESMExports();console.log('root SQLite constructor disabled');")
 monitor.chmod(0o444)
 for d in [run,control,run/'signers',signer]:d.mkdir(mode=0o755)
 eng.mkdir(mode=0o750);os.chown(eng,uid,gid)
 for name in ['state','sessions','logs','evidence','pi-agent']:
  p=eng/name;p.mkdir(mode=0o750);os.chown(p,uid,gid)
 fixture=eng/'profile-fixture.mjs';shutil.copyfile(str(pathlib.Path(__file__).resolve().parent/'sandbox-profile.integration.mjs'),fixture);fixture.chmod(0o444)
 env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/nonexistent','PLUTO_TARGET_HOST':'127.0.0.1','PLUTO_TARGET_LABEL':'profile-fixture','PLUTO_SCOPE_HOSTS':'127.0.0.1','PLUTO_CWD':runtime,'PLUTO_STATE_DIR':str(eng/'state'),'PLUTO_LOG_DIR':str(eng/'logs'),'PLUTO_EVIDENCE_DIR':str(eng/'evidence'),'PLUTO_CONTROL_DIR':str(control),'PLUTO_KILL_FILE':str(control/'KILL_SWITCH'),'PLUTO_RUN_DIR':str(run),'PLUTO_SIGNER_DIR':str(signer),'PLUTO_SIGNER_RUN_ID':tag,'PLUTO_PROMOTION_SIGNER_SOCK':str(signer/'promotion.sock'),'PLUTO_PROMOTION_SIGNER_CMD':'/usr/local/bin/node '+runtime+'/extensions/dist/state/promotion-sign-client.js '+str(signer/'promotion.sock'),'PLUTO_PROMOTION_PUBKEY':'/etc/cyber-pluto/promotion_ed25519.pub','PI_CODING_AGENT_DIR':str(eng/'pi-agent'),'PLUTO_SANDBOX_MODE':'requested','PLUTO_LAUNCHER':'1','PLUTO_READINESS_ONLY':'1','PLUTO_READINESS_UID':str(uid),'PLUTO_READINESS_KEY_DENY_PATH':'/etc/cyber-pluto/promotion_ed25519.key','PLUTO_QA_ENGAGEMENT':str(eng),'PLUTO_UID':'pluto'}
 init="import {DatabaseSync} from 'node:sqlite';import {SCHEMA_SQL} from '/opt/cyber-pluto/extensions/dist/state/schema.js';const db=new DatabaseSync(process.env.PLUTO_STATE_DIR+'/pluto.db');db.exec(SCHEMA_SQL);db.close()"
 command(['/usr/local/bin/node','--input-type=module','-e',init],env=env)
 os.chown(eng/'state/pluto.db',uid,gid);(eng/'state/pluto.db').chmod(0o600)
 command([runtime+'/sandbox/egress.sh','apply','127.0.0.1'],env=policyenv);policy=True
 daemon=subprocess.Popen(['/usr/local/bin/node','--require',str(monitor),runtime+'/extensions/dist/state/promotion-sign-daemon.js',str(signer/'promotion.sock')],env={**env,'PLUTO_SIGNER_STRICT':'1','PLUTO_PROMOTION_PRIVKEY':'/etc/cyber-pluto/promotion_ed25519.key'},start_new_session=True)
 deadline=time.time()+5
 while not (signer/'promotion.sock').exists():
  assert daemon.poll() is None,'daemon exited';assert time.time()<deadline,'signer timeout';time.sleep(.05)
 command([runtime+'/sandbox/run-sandboxed.sh',str(eng),'--','/usr/local/bin/node',runtime+'/extensions/dist/launcher/sandbox-probe.js'],env=env,cwd=runtime)
 # Force a cold saved WAL ledger: terminate signer, clean-close a pluto writer.
 os.killpg(daemon.pid,signal.SIGTERM);daemon.wait(timeout=5)
 close_code="import {DatabaseSync} from 'node:sqlite';const db=new DatabaseSync(process.env.PLUTO_STATE_DIR+'/pluto.db');db.exec('PRAGMA journal_mode=WAL');db.close()"
 command([runtime+'/sandbox/run-sandboxed.sh',str(eng),'--','/usr/local/bin/node','--input-type=module','-e',close_code],env=env,cwd=runtime)
 assert not pathlib.Path(str(eng/'state/pluto.db')+'-wal').exists(),'not a cold WAL ledger'
 assert not pathlib.Path(str(eng/'state/pluto.db')+'-shm').exists(),'not a cold WAL ledger'
 command([runtime+'/sandbox/run-sandboxed.sh',str(eng),'--','/usr/local/bin/node',runtime+'/extensions/dist/launcher/ledger-probe.js'],env=env,cwd=runtime)
 for suffix in ['-wal','-shm']:
  side=pathlib.Path(str(eng/'state/pluto.db')+suffix);assert side.exists() and side.stat().st_uid==uid and side.stat().st_nlink==1,'bad prepared sidecar'
 daemon=subprocess.Popen(['/usr/local/bin/node','--require',str(monitor),runtime+'/extensions/dist/state/promotion-sign-daemon.js',str(signer/'promotion.sock')],env={**env,'PLUTO_SIGNER_STRICT':'1','PLUTO_PROMOTION_PRIVKEY':'/etc/cyber-pluto/promotion_ed25519.key'},start_new_session=True)
 deadline=time.time()+5
 while not (signer/'promotion.sock').exists():
  assert daemon.poll() is None,'cold signer exited';assert time.time()<deadline,'cold signer timeout';time.sleep(.05)
 command([runtime+'/sandbox/run-sandboxed.sh',str(eng),'--','/usr/local/bin/node',runtime+'/extensions/dist/launcher/sandbox-probe.js'],env=env,cwd=runtime)
 print(json.dumps({'coldWalResume':'passed','plutoSidecarOwner':uid,'rootSignerAfterPrewarm':True,'subsequentPlutoWriterAndPromotion':True}))
 child=subprocess.Popen([runtime+'/sandbox/run-sandboxed.sh',str(eng),'--','/usr/local/bin/node',str(fixture)],env=env,cwd=runtime,start_new_session=True)
 rc=child.wait(timeout=60);assert rc==0,'SDK fixture failed: '+str(rc)
 success=True
finally:
 if child and child.poll() is None:
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=3)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
 if daemon and daemon.poll() is None:
  os.killpg(daemon.pid,signal.SIGTERM);daemon.wait(timeout=5)
 if acquired and quiet():
  if policy:command([runtime+'/sandbox/egress.sh','teardown'],env=policyenv)
  (lock/'owner.json').unlink();lock.rmdir()
  if base.exists():shutil.rmtree(base)
 elif acquired:print('RESTRICTIVE POLICY/LOCK RETAINED: unconfirmed workloads')
 if success:print(json.dumps({'localFullProfileOrchestration':'passed','cleanup':'verified','liveTargetOrProvider':'none'}))
