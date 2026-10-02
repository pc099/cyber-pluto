import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, renameSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { createFindingsRepo } from "./findings-repo.js";
import { createPromotionAuthority } from "./promotion-sign-core.js";
import { verifyPromotion } from "./promotion.js";
import { SCHEMA_SQL } from "./schema.js";
import { checkSignerHealth, requestOperatorStop, signerRequest, SIGNER_MAX_BYTES } from "./signer-health.js";
import { createTargetsRepo } from "./targets-repo.js";
import { createValidationsRepo } from "./validations-repo.js";

const DAEMON = fileURLToPath(new URL("./promotion-sign-daemon.js", import.meta.url));
function fixture() {
	const dir = mkdtempSync(join(tmpdir(), "pluto-health-"));
	const keys = generateKeyPairSync("ed25519");
	const key = join(dir, "private.key"); const pub = join(dir, "public.pub");
	writeFileSync(key, keys.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o400 });
	writeFileSync(pub, keys.publicKey.export({ format: "pem", type: "spki" }), { mode: 0o444 });
	const state = join(dir, "state"); mkdirSync(state);
	const ledger = join(state, "pluto.db"); const db = new DatabaseSync(ledger);
	db.exec(SCHEMA_SQL); db.exec("PRAGMA journal_mode=WAL");
	const target = createTargetsRepo(db).create({ label: "health" });
	const finding = createFindingsRepo(db).create({ targetId: target.id, service: "http" });
	const validations = createValidationsRepo(db);
	const validation = validations.create({ findingId: finding.id, validator: "sqli", passed: true, baselineRef: "evidence/b.json", diffSummary: "fixture only" });
	const fail = validations.create({ findingId: finding.id, validator: "sqli", passed: false, diffSummary: "no" });
	const socket = join(dir, "sign.sock"); const kill = join(dir, "KILL_SWITCH");
	const env: NodeJS.ProcessEnv = { ...process.env, PLUTO_SIGNER_STRICT: "1", PLUTO_SIGNER_RUN_ID: "fixture-launch",
		PLUTO_CWD: dir, PLUTO_STATE_DIR: state, PLUTO_PROMOTION_PRIVKEY: key, PLUTO_PROMOTION_PUBKEY: pub,
		PLUTO_UID: String(process.getuid?.() ?? 0), PLUTO_KILL_FILE: kill };
	const health = { socketPath: socket, ledgerPath: ledger, runId: env.PLUTO_SIGNER_RUN_ID!, publicKeyPath: pub };
	return { dir, keys, key, pub, state, ledger, db, finding, validation, fail, socket, kill, env, health };
}
async function start(f: ReturnType<typeof fixture>): Promise<ChildProcess> {
	const daemon = spawn(process.execPath, [DAEMON, f.socket], { env: f.env, stdio: "ignore" });
	for (let n = 0; n < 100; n++) {
		if (daemon.exitCode !== null) throw new Error(`daemon exited ${daemon.exitCode}`);
		try { await checkSignerHealth(f.health); return daemon; } catch { await sleep(20); }
	}
	daemon.kill("SIGTERM"); throw new Error("daemon failed readiness");
}
async function stop(daemon: ChildProcess): Promise<void> {
	if (daemon.exitCode !== null) return;
	const exited = new Promise<void>(resolve => daemon.once("exit", () => resolve()));
	daemon.kill("SIGTERM"); await exited;
}

test("strict authority uses supplied env, signs only passed DB claims, separates health from promotion", () => {
	const f = fixture(); const authority = createPromotionAuthority(f.env);
	try {
		const c = { findingId: f.finding.id, validationId: f.validation.id, validator: "sqli", targetId: f.finding.target_id, evidenceRef: "evidence/b.json" };
		const signature = authority.sign(JSON.stringify({ ...c, validator: "forged" }));
		assert.equal(verifyPromotion(c, signature, f.keys.publicKey), true);
		assert.throws(() => authority.sign(JSON.stringify({ ...c, validationId: f.fail.id })), /did not pass/);
		const health = authority.health("a".repeat(64));
		assert.equal(verifyPromotion(c, health.signature, f.keys.publicKey), false);
		assert.throws(() => authority.health("invalid"), /challenge/);
		f.db.prepare("UPDATE validations SET baseline_ref = ? WHERE id = ?").run("x".repeat(4097), f.validation.id);
		assert.throws(() => authority.sign(JSON.stringify(c)), /size or type/);
	} finally { authority.close(); f.db.close(); }
});

test("strict authority rejects mismatched or unsafe keys and absent launch identity", () => {
	const f = fixture();
	try {
		const wrong = generateKeyPairSync("ed25519").publicKey;
		writeFileSync(f.pub, wrong.export({ format: "pem", type: "spki" }));
		assert.throws(() => createPromotionAuthority(f.env), /do not match/);
		chmodSync(f.key, 0o644);
		assert.throws(() => createPromotionAuthority(f.env), /ownership or permissions/);
		assert.throws(() => createPromotionAuthority({ ...f.env, PLUTO_SIGNER_RUN_ID: "" }), /launch identity/);
	} finally { f.db.close(); }
});

test("pinned readonly authority observes fresh workspace switching to WAL after startup", () => {
	const f = fixture();
	f.db.exec("PRAGMA journal_mode=DELETE");
	const authority = createPromotionAuthority(f.env);
	try {
		f.db.exec("PRAGMA journal_mode=WAL");
		f.db.prepare("UPDATE validations SET baseline_ref='evidence/after-startup.json' WHERE id=?").run(f.validation.id);
		const claim = { findingId: f.finding.id, validationId: f.validation.id, validator: "sqli", targetId: f.finding.target_id, evidenceRef: "evidence/after-startup.json" };
		assert.equal(verifyPromotion(claim, authority.sign(JSON.stringify(claim)), f.keys.publicKey), true);
	} finally { authority.close(); f.db.close(); }
});

test("strict authority refuses symlink/hardlink sidecars before open and after startup without touching sentinels", () => {
	for (const suffix of ["-wal", "-shm", "-journal"]) for (const hardlink of [false, true]) {
		const f = fixture();
		f.db.exec("PRAGMA journal_mode=DELETE");
		const authority = createPromotionAuthority(f.env);
		const sentinel = join(f.dir, "root-sentinel");
		const bytes = Buffer.alloc(32768, 0x5a);
		writeFileSync(sentinel, bytes, { mode: 0o600 });
		const sidecar = `${f.ledger}${suffix}`;
		try {
			if (hardlink) linkSync(sentinel, sidecar); else symlinkSync(sentinel, sidecar);
			assert.throws(() => createPromotionAuthority(f.env), /unsafe signer ledger sidecar/);
			assert.throws(() => authority.health("a".repeat(64)), /unsafe signer ledger sidecar/);
			assert.throws(() => authority.sign(JSON.stringify({ findingId: f.finding.id, validationId: f.validation.id })), /unsafe signer ledger sidecar/);
			assert.deepEqual(readFileSync(sentinel), bytes);
		} finally { unlinkSync(sidecar); authority.close(); f.db.close(); }
	}
});

test("pinned authority refuses database inode, symlink and parent replacement", () => {
	for (const mutation of ["inode", "symlink", "parent"]) {
		const f = fixture(); const authority = createPromotionAuthority(f.env);
		try {
			if (mutation === "parent") { renameSync(f.state, `${f.state}.old`); mkdirSync(f.state); writeFileSync(f.ledger, "replacement"); }
			else { renameSync(f.ledger, `${f.ledger}.old`); if (mutation === "symlink") symlinkSync(`${f.ledger}.old`, f.ledger); else writeFileSync(f.ledger, "replacement"); }
			assert.throws(() => authority.health("a".repeat(64)), /replaced|symlink/);
			assert.throws(() => authority.sign(JSON.stringify({ findingId: 1, validationId: 1 })), /replaced|symlink/);
		} finally { authority.close(); f.db.close(); }
	}
});

test("real strict daemon health authenticates ledger/run/key and promotion still verifies", async () => {
	const f = fixture(); const daemon = await start(f);
	try {
		const health = await checkSignerHealth(f.health);
		assert.equal(health.ledgerPath, f.ledger);
		await assert.rejects(checkSignerHealth({ ...f.health, ledgerPath: `${f.ledger}.wrong` }), /binding failed/);
		await assert.rejects(checkSignerHealth({ ...f.health, runId: "wrong" }), /binding failed/);
		const wrongKey = join(f.dir, "wrong.pub");
		writeFileSync(wrongKey, generateKeyPairSync("ed25519").publicKey.export({ format: "pem", type: "spki" }));
		await assert.rejects(checkSignerHealth({ ...f.health, publicKeyPath: wrongKey }), /binding failed/);
		assert.match(await signerRequest(f.socket, JSON.stringify({ op: "health", challenge: "invalid" })), /^ERR /);
		const c = { findingId: f.finding.id, validationId: f.validation.id, validator: "sqli", targetId: f.finding.target_id, evidenceRef: "evidence/b.json" };
		const reply = await signerRequest(f.socket, JSON.stringify(c));
		assert.equal(verifyPromotion(c, reply.slice(3), f.keys.publicKey), true);
		assert.match(await signerRequest(f.socket, JSON.stringify({ ...c, validationId: f.fail.id })), /^ERR /);
		assert.equal(lstatSync(f.socket).mode & 0o777, 0o660);
	} finally { await stop(daemon); f.db.close(); }
	assert.equal(existsSync(f.socket), false);
});

test("strict daemon refuses existing endpoint and does not remove someone else's file", async () => {
	const f = fixture(); writeFileSync(f.socket, "existing");
	const daemon = spawn(process.execPath, [DAEMON, f.socket], { env: f.env, stdio: "ignore" });
	await new Promise<void>(resolve => daemon.once("exit", () => resolve()));
	assert.equal(daemon.exitCode, 1); assert.equal(readFileSync(f.socket, "utf8"), "existing"); f.db.close();
});

test("daemon shutdown removes only its own socket inode", async () => {
	const f = fixture(); const daemon = await start(f);
	unlinkSync(f.socket); writeFileSync(f.socket, "replacement");
	await stop(daemon);
	assert.equal(readFileSync(f.socket, "utf8"), "replacement"); f.db.close();
});

test("strict daemon refuses a live socket and unsafe socket parents without replacing either", async () => {
	const f = fixture();
	const server = net.createServer(conn => conn.end("original endpoint"));
	await new Promise<void>(resolve => server.listen(f.socket, resolve));
	try {
		const originalInode = lstatSync(f.socket).ino;
		const daemon = spawn(process.execPath, [DAEMON, f.socket], { env: f.env, stdio: "ignore" });
		await new Promise<void>(resolve => daemon.once("exit", () => resolve()));
		assert.equal(daemon.exitCode, 1); assert.equal(lstatSync(f.socket).ino, originalInode);
	} finally { await new Promise<void>(resolve => server.close(() => resolve())); }
	chmodSync(f.dir, 0o777);
	const unsafe = spawn(process.execPath, [DAEMON, f.socket], { env: f.env, stdio: "ignore" });
	await new Promise<void>(resolve => unsafe.once("exit", () => resolve()));
	assert.equal(unsafe.exitCode, 1); assert.equal(existsSync(f.socket), false);
	chmodSync(f.dir, 0o700); f.db.close();
});

test("health client rejects a correctly signed stale request challenge", async () => {
	const f = fixture(); const authority = createPromotionAuthority(f.env);
	const server = net.createServer({ allowHalfOpen: true }, conn => {
		conn.on("data", () => conn.end(JSON.stringify(authority.health("a".repeat(64)))));
		conn.on("error", () => conn.destroy());
	});
	await new Promise<void>(resolve => server.listen(f.socket, resolve));
	try { await assert.rejects(checkSignerHealth(f.health), /binding failed/); }
	finally { await new Promise<void>(resolve => server.close(() => resolve())); authority.close(); f.db.close(); }
});

test("strict stop only creates the root-selected sentinel, cannot write caller paths or follow symlinks", async () => {
	const f = fixture(); const daemon = await start(f);
	try {
		const arbitrary = join(f.dir, "caller-selected");
		assert.equal(await signerRequest(f.socket, JSON.stringify({ op: "stop", path: arbitrary })), "OK STOP");
		assert.equal(existsSync(arbitrary), false); assert.equal(existsSync(f.kill), true);
		await requestOperatorStop(f.socket);
		unlinkSync(f.kill); symlinkSync(arbitrary, f.kill);
		await assert.rejects(requestOperatorStop(f.socket), /unsafe existing/);
		assert.equal(existsSync(arbitrary), false);
	} finally { await stop(daemon); f.db.close(); }
});

test("client bounds response bytes and total elapsed time", async () => {
	for (const mode of ["oversize", "stall", "wrong-challenge"]) {
		const f = fixture();
		const sockets = new Set<net.Socket>();
		const server = net.createServer({ allowHalfOpen: true }, conn => {
			sockets.add(conn); conn.once("close", () => sockets.delete(conn));
			conn.on("data", () => { if (mode === "oversize") conn.end("x".repeat(SIGNER_MAX_BYTES + 1)); else if (mode === "wrong-challenge") conn.end(JSON.stringify({ claim: { schema: 1, challenge: "stale" }, signature: "fake" })); });
			conn.on("error", () => conn.destroy());
		});
		await new Promise<void>(resolve => server.listen(f.socket, resolve));
		try {
			await assert.rejects(checkSignerHealth({ ...f.health, timeoutMs: 100 }), /size limit|timed out|binding failed/);
		} finally { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())); f.db.close(); }
	}
});

test("daemon enforces input size and total connection deadline", async () => {
	const f = fixture(); const daemon = await start(f);
	try {
		await assert.rejects(signerRequest(f.socket, "x".repeat(SIGNER_MAX_BYTES + 1)), /size limit/);
		for (const oversized of [true, false]) {
			await new Promise<void>((resolve, reject) => {
				const conn = net.connect(f.socket); const started = Date.now();
				const timer = setTimeout(() => { conn.destroy(); reject(new Error("server failed to close bounded connection")); }, 3000);
				conn.on("connect", () => conn.write(oversized ? "x".repeat(SIGNER_MAX_BYTES + 1) : "{"));
				conn.on("error", () => conn.destroy());
				conn.on("close", () => { clearTimeout(timer); assert.ok(Date.now() - started < 2800); resolve(); });
			});
		}
	} finally { await stop(daemon); f.db.close(); }
});
