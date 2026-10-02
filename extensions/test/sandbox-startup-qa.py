#!/usr/bin/env python3
"""Explicit serial root-host QA; no live provider or target calls."""
import os,pathlib,subprocess,json,time,signal,uuid,hashlib
runtime='/opt/cyber-pluto'; cli=runtime+'/cyberpluto'; tag='qa-'+uuid.uuid4().hex[:10]
run=pathlib.Path('/run/cyber-pluto'); control=pathlib.Path('/var/lib/cyber-pluto/control'); engagements=pathlib.Path('/var/lib/cyber-pluto/engagements')
uid=int(subprocess.check_output(['id','-u','pluto']))
def quiet():
 for p in pathlib.Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   for line in (p/'status').read_text().splitlines():
    if line.startswith('Uid:') and uid in map(int,line.split()[1:]):return False
  except FileNotFoundError:pass
 return True
def clean():
 assert quiet(),'uid workload retained'
 assert not (run/'launch.lock').exists(),'lock retained'
 assert not (control/'RECOVERY_REQUIRED.json').exists(),'recovery hold'
 rules=json.loads(subprocess.check_output(['nft','-j','list','tables']))
 assert not any(x.get('table',{}).get('name')=='pluto_egress' for x in rules['nftables']),'table retained'
 assert not list(engagements.glob('readiness-*')),'scratch retained'
 assert not list(run.glob('signers/*/promotion.sock')),'socket retained'
def invoke(label,extra=[],env=None):
 return subprocess.run([cli,'127.0.0.1','--label',label,'--sandbox-check',*extra],capture_output=True,text=True,env=env,timeout=30)
clean()
disabled=invoke(tag,env={**os.environ,'PLUTO_BWRAP':'0'})
assert disabled.returncode!=0 and 'PLUTO_BWRAP=0' in disabled.stderr;clean()
legacy=pathlib.Path('/root/cyber-pluto/engagements/ica1-test/sessions/2026-10-01T13-56-51-969Z_01a0f7c0-f080-72e9-87a0-1512c5ea1adf.jsonl')
before=hashlib.sha256(legacy.read_bytes()).hexdigest()
refusal=invoke(tag,['--session',str(legacy)])
assert refusal.returncode!=0 and 'relocation/conversion is unsupported' in refusal.stderr,refusal.stderr
assert hashlib.sha256(legacy.read_bytes()).hexdigest()==before
assert not (engagements/tag).exists();clean()
lock=run/'launch.lock';lock.mkdir(mode=0o700);owner=lock/'owner.json';owner.write_text(json.dumps({'qa':tag}));original=owner.read_bytes()
try:
 concurrent=invoke(tag);assert concurrent.returncode!=0 and 'EEXIST' in concurrent.stderr,concurrent.stderr
 assert owner.read_bytes()==original
finally:owner.unlink();lock.rmdir()
clean()
staleDir=run/'signers'/tag;staleDir.mkdir(mode=0o755);stale=staleDir/'promotion.sock';stale.write_text('root QA sentinel');original=stale.read_bytes()
try:
 failure=invoke(tag);assert failure.returncode!=0 and 'Existing signer endpoint' in failure.stderr,failure.stderr
 assert stale.read_bytes()==original
finally:stale.unlink();staleDir.rmdir()
clean()
# Actual SIGTERM when strict signer is listening, before/around health handoff.
process=subprocess.Popen([cli,'127.0.0.1','--label',tag,'--sandbox-check'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
deadline=time.time()+30;endpoint=run/'signers'/tag/'promotion.sock'
while not endpoint.exists():
 assert process.poll() is None,'process exited before signal fixture';assert time.time()<deadline,'startup timeout';time.sleep(.002)
process.send_signal(signal.SIGTERM)
out,err=process.communicate(timeout=15)
assert process.returncode!=0,'signal must not report success'
clean()
(run/'signers'/tag).rmdir()
print(json.dumps({'productionStartupFailures':'passed','disabledBubblewrapRefused':True,'legacyRelocationRefusedUnchanged':True,'concurrentLockUntouched':True,'staleEndpointUntouched':True,'signalAtSignerStartup':True,'cleanupVerified':True,'targetOrProvider':'none'}))
