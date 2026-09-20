import assert from "node:assert/strict";
import { test } from "node:test";
import { mayDiscloseIp } from "./disclosure.js";

test("an in-scope exact IP may be disclosed", () => {
	assert.equal(mayDiscloseIp("10.129.1.5", "10.129.1.5").allowed, true);
	assert.equal(mayDiscloseIp("10.129.1.5", "example.com, 10.129.1.5, 10.0.0.1").allowed, true);
});

test("an IP within an in-scope CIDR may be disclosed", () => {
	assert.equal(mayDiscloseIp("10.129.1.55", "10.129.1.0/24").allowed, true);
	assert.equal(mayDiscloseIp("10.129.2.1", "10.129.1.0/24").allowed, false, "outside the /24");
});

test("an out-of-scope IP is REFUSED (disclosure to a third party)", () => {
	const d = mayDiscloseIp("8.8.8.8", "10.129.1.0/24, example.com");
	assert.equal(d.allowed, false);
	assert.match(d.reason, /NOT in scope/);
});

test("fail-closed: no scope configured means nothing may be disclosed", () => {
	assert.equal(mayDiscloseIp("10.129.1.5", undefined).allowed, false);
	assert.equal(mayDiscloseIp("10.129.1.5", "").allowed, false);
	assert.equal(mayDiscloseIp("", "10.129.1.5").allowed, false);
});
