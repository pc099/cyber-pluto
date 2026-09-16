/**
 * The capability manifest — the whitelist that makes adaptive provisioning
 * SAFE. Pluto can decide *which* engagement domain it faces, but it can only
 * ever install the pre-vetted toolset declared here for that domain; it can
 * never pass an arbitrary package name. Adaptive in the choice of domain,
 * controlled in what actually gets installed (no supply-chain hole, and it
 * can't be prompt-injected into `apt-get install <malware>`).
 *
 * Each entry maps an engagement class to its doctrine skill, the exact apt/pip
 * packages it needs, when to reach for it (detect hints), and a verify command
 * that proves readiness.
 */
export interface Capability {
	/** The engagement class the model requests by name. */
	domain: string;
	description: string;
	/** Signals that this domain applies (surfaced to the model so it knows when to provision). */
	detect: string[];
	/** Doctrine skill to surface into context on provision (repo-relative). */
	skill?: string;
	/** Whitelisted apt packages — the ONLY apt installs this domain may perform. */
	apt: readonly string[];
	/** Whitelisted pip packages — the ONLY pip installs this domain may perform. */
	pip: readonly string[];
	/** A shell command that exits 0 once the capability is ready. */
	verify: string;
}

export const CAPABILITIES: readonly Capability[] = [
	{
		domain: "binary-exploitation",
		description: "Memory-corruption / pwn: stack overflow, ROP, format string, heap; raw or networked binaries.",
		detect: ["elf binary", "raw tcp service with a binary", "nc host port", "buffer overflow", "pwn", "checksec", "ret2", "rop"],
		skill: "runtime-skills/binary-exploitation/SKILL.md",
		apt: ["gdb", "binutils"],
		pip: ["pwntools", "ROPgadget"],
		verify: `python3 -c "import pwn" && gdb --version >/dev/null`,
	},
	{
		domain: "cryptography",
		description: "Crypto challenges: RSA/AES/ECC weaknesses, oracle attacks, custom cipher analysis.",
		detect: ["rsa", "aes", "cipher", "encryption challenge", "modulus", "padding oracle", "ecc"],
		skill: undefined,
		apt: [],
		pip: ["pycryptodome", "sympy", "gmpy2"],
		verify: `python3 -c "import Crypto, sympy"`,
	},
	{
		domain: "forensics",
		description: "Forensics / stego: pcap analysis, file carving, memory dumps, embedded-data extraction.",
		detect: ["pcap", "packet capture", "memory dump", "disk image", "steganography", "carve file"],
		skill: undefined,
		apt: ["tshark", "binwalk", "foremost", "exiftool"],
		pip: [],
		verify: `command -v tshark && command -v binwalk`,
	},
	{
		domain: "web",
		description: "Web application testing — already the core toolset (nmap, curl, chromium, the Gate 1 validators).",
		detect: ["http", "https", "web app", "url", "api endpoint", "vhost"],
		skill: undefined,
		apt: [],
		pip: [],
		verify: `command -v curl && command -v nmap`,
	},
];

export function findCapability(domain: string): Capability | undefined {
	const d = domain.trim().toLowerCase();
	return CAPABILITIES.find((c) => c.domain === d);
}
