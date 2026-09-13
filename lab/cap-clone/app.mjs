/**
 * INTENTIONALLY VULNERABLE local lab target — a "Cap"-shaped box (HTB Cap
 * clone) for the Session 12 end-to-end dry run. 127.0.0.1 only. Deliberately
 * insecure; never deploy/expose.
 *
 * Mirrors Cap's crux: a network-capture dashboard where each visitor gets a
 * session and a numeric capture id, and `/data/<id>` serves the pcap for that
 * id WITHOUT checking the id belongs to you (IDOR). Capture id 0 is the
 * admin's snapshot, whose pcap contains plaintext FTP credentials — the
 * foothold. (Demo credentials, not the real box's.)
 *
 * Run: node lab/cap-clone/app.mjs [port]   (default 8892)
 */
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";

// --- build a minimal libpcap file whose TCP payload carries an FTP login ---
function buildPcapWithFtpLogin(user, pass) {
	const payload = Buffer.from(
		`220 cap.htb FTP server ready\r\nUSER ${user}\r\n331 Password required\r\nPASS ${pass}\r\n230 Login successful\r\n`,
		"ascii",
	);
	const eth = Buffer.alloc(14);
	eth.writeUInt16BE(0x0800, 12); // IPv4
	const ip = Buffer.alloc(20);
	ip[0] = 0x45; // v4, ihl5
	ip.writeUInt16BE(20 + 20 + payload.length, 2); // total length
	ip[8] = 64; // ttl
	ip[9] = 6; // TCP
	ip.writeUInt32BE(0x0a0a0a05, 12); // src 10.10.10.5
	ip.writeUInt32BE(0x0a0a0a01, 16); // dst 10.10.10.1
	const tcp = Buffer.alloc(20);
	tcp.writeUInt16BE(50210, 0); // src port
	tcp.writeUInt16BE(21, 2); // dst port (FTP)
	tcp[12] = 0x50; // data offset 5
	tcp[13] = 0x18; // PSH+ACK
	const packet = Buffer.concat([eth, ip, tcp, payload]);

	const global = Buffer.alloc(24);
	global.writeUInt32LE(0xa1b2c3d4, 0); // magic
	global.writeUInt16LE(2, 4); // major
	global.writeUInt16LE(4, 6); // minor
	global.writeUInt32LE(65535, 16); // snaplen
	global.writeUInt32LE(1, 20); // linktype ETHERNET
	const rec = Buffer.alloc(16);
	rec.writeUInt32LE(Math.floor(Date.now() / 1000), 0);
	rec.writeUInt32LE(0, 4);
	rec.writeUInt32LE(packet.length, 8);
	rec.writeUInt32LE(packet.length, 12);
	return Buffer.concat([global, rec, packet]);
}

const ADMIN_PCAP = buildPcapWithFtpLogin("nathan", "Cap5t0ne_demo_pw!");
const EMPTY_PCAP = (() => {
	const g = Buffer.alloc(24);
	g.writeUInt32LE(0xa1b2c3d4, 0);
	g.writeUInt16LE(2, 4);
	g.writeUInt16LE(4, 6);
	g.writeUInt32LE(65535, 16);
	g.writeUInt32LE(1, 20);
	return g; // valid header, no packets
})();

const sessions = new Map(); // cookie -> capture id
let nextId = 3; // visitors get ids starting at 3; id 0 is the admin's

function parseCookie(req) {
	const raw = req.headers.cookie ?? "";
	const m = /session=([a-f0-9]+)/.exec(raw);
	return m ? m[1] : null;
}

export function createCapApp() {
	return createServer((req, res) => {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");

		if (url.pathname === "/") {
			let sid = parseCookie(req);
			if (!sid || !sessions.has(sid)) {
				sid = randomBytes(8).toString("hex");
				sessions.set(sid, nextId++);
				res.setHeader("Set-Cookie", `session=${sid}; Path=/; HttpOnly`);
			}
			const myId = sessions.get(sid);
			res.writeHead(200, { "content-type": "text/html" });
			res.end(
				`<html><head><title>Security Dashboard</title></head><body>` +
					`<h1>Network Security Dashboard</h1>` +
					`<p>Your security snapshot id: <b>${myId}</b></p>` +
					`<ul><li><a href="/data/${myId}">View your snapshot</a></li>` +
					`<li><a href="/capture">Run a new capture</a></li></ul>` +
					`</body></html>`,
			);
			return;
		}

		if (url.pathname === "/capture") {
			const sid = parseCookie(req);
			const myId = sid && sessions.get(sid);
			res.writeHead(302, { location: `/data/${myId ?? 3}` });
			res.end();
			return;
		}

		const dataMatch = /^\/data\/(\d+)$/.exec(url.pathname);
		if (dataMatch) {
			// Requires a session (identity-scoped) — but does NOT check the id
			// belongs to the caller. That missing check IS the IDOR.
			const sid = parseCookie(req);
			if (!sid || !sessions.has(sid)) {
				res.writeHead(401, { "content-type": "text/plain" });
				res.end("unauthorized: no session");
				return;
			}
			const id = Number(dataMatch[1]);
			const pcap = id === 0 ? ADMIN_PCAP : EMPTY_PCAP;
			res.writeHead(200, {
				"content-type": "application/vnd.tcpdump.pcap",
				"content-disposition": `attachment; filename="${id}.pcap"`,
			});
			res.end(pcap);
			return;
		}

		res.writeHead(404, { "content-type": "text/plain" });
		res.end("not found");
	});
}

if (import.meta.url === `file://${process.argv[1]}`) {
	const port = Number(process.argv[2] ?? 8892);
	createCapApp().listen(port, "127.0.0.1", () => {
		console.log(`[cap-clone] INTENTIONALLY VULNERABLE Cap-shaped lab on http://127.0.0.1:${port}`);
		console.log(`[cap-clone]   IDOR: /data/<id> (id 0 = admin's pcap with plaintext FTP creds)`);
	});
}
