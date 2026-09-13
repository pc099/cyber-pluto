/**
 * Architecture §5.1's per-service decision tree, as data: for a newly
 * fingerprinted service, what to check first (cheap, reliable) versus what
 * the CVE path looks like. A generic fallback covers services the
 * reference table doesn't name — the same "starting reference set, easy to
 * extend" philosophy as the §4.5 validator table and tool-log's ATT&CK map.
 */

export interface ServiceChecklist {
	checkFirst: string;
	cvePath: string;
}

const SERVICE_CHECKLISTS: Record<string, ServiceChecklist> = {
	"microsoft-ds": {
		checkFirst: "Null session on IPC$; default/weak creds",
		cvePath: "EternalBlue-class, SMBGhost, version-specific RCEs",
	},
	"netbios-ssn": {
		checkFirst: "Null session on IPC$; default/weak creds",
		cvePath: "EternalBlue-class, SMBGhost, version-specific RCEs",
	},
	ssh: {
		checkFirst: "Default/weak creds, credential reuse from elsewhere",
		cvePath: "Version-specific CVEs; weak host/user keys",
	},
	ftp: {
		checkFirst: "Anonymous login",
		cvePath: "Version-specific backdoors (e.g. vsFTPd-class)",
	},
	snmp: {
		checkFirst: "Default community strings (public/private)",
		cvePath: "RW-string RCE, vendor-specific CVEs",
	},
	"ms-wbt-server": {
		checkFirst: "Credential stuffing / reuse",
		cvePath: "BlueKeep-class pre-auth RCEs",
	},
	http: {
		checkFirst: "Default admin creds on any panel found",
		cvePath: "Known-CMS / known-component CVEs",
	},
	https: {
		checkFirst: "Default admin creds on any panel found",
		cvePath: "Known-CMS / known-component CVEs",
	},
	mysql: { checkFirst: "Default credentials", cvePath: "Version-specific CVEs; injection" },
	postgresql: { checkFirst: "Default credentials", cvePath: "Version-specific CVEs; injection" },
	"ms-sql-s": { checkFirst: "Default credentials", cvePath: "Version-specific CVEs; injection" },
	oracle: { checkFirst: "Default credentials", cvePath: "Version-specific CVEs; injection" },
	mongodb: { checkFirst: "Default credentials", cvePath: "Version-specific CVEs; injection" },
};

const GENERIC_CHECKLIST: ServiceChecklist = {
	checkFirst: "Default/weak credentials and common misconfigurations",
	cvePath: "Version-specific CVE search",
};

export function checklistForService(service: string): ServiceChecklist {
	return SERVICE_CHECKLISTS[service.toLowerCase()] ?? GENERIC_CHECKLIST;
}
