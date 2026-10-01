/** Explicit scratch identity and ephemeral attestation dependencies for local tests. */
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { join } from "node:path";
import { startEngagement, resetEngagement } from "../state/engagement.js";
import { createFindingsRepo } from "../state/findings-repo.js";
import { signPromotion, verifyPromotion } from "../state/promotion.js";
import { bindSession } from "../state/session-binding.js";

export function engagementFixture(cwd: string, label = "fixture", host = "127.0.0.1", scope = host) {
	resetEngagement();
	for (const key of ["PLUTO_PARENT_BINDING_PATH", "PLUTO_DELEGATE_ID", "PLUTO_PROMOTION_SIGNER_CMD", "PLUTO_PROMOTION_PRIVKEY"]) delete process.env[key];
	Object.assign(process.env, {
		PLUTO_TARGET_LABEL: label, PLUTO_TARGET_HOST: host, PLUTO_SCOPE_HOSTS: `${host},${scope}`,
		PLUTO_STATE_DIR: join(cwd, "state"), PLUTO_LOG_DIR: join(cwd, "logs"), PLUTO_EVIDENCE_DIR: join(cwd, "evidence"),
		PLUTO_SANDBOX_MODE: "disabled", PLUTO_LAUNCHER: "1", PLUTO_PROMOTION_PUBKEY: join(cwd, "absent-fixture-pubkey"),
	});
	bindSession({ cwd, sessionFile: join(cwd, "sessions", `${randomUUID()}.jsonl`), sessionId: randomUUID(), entries: [], reason: "startup" });
	const engagement = startEngagement(cwd);
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	// Injected dependencies prove consumer semantics, not a privileged boundary.
	engagement.repos.findings = createFindingsRepo(engagement.db, {
		signer: claim => signPromotion(claim, privateKey),
		verifier: (claim, signature) => verifyPromotion(claim, signature, publicKey),
	});
	return engagement;
}
