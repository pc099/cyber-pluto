"""MSF bridge tests against the MOCK RPC (python-patterns: never hit a live
Metasploit in unit tests). Covers the §2.3.2 decision both ways and that the
bridge is a mechanism (it acts only when called; gating is upstream)."""

from __future__ import annotations

from pluto_services.msf_bridge.bridge import MsfBridge
from pluto_services.msf_bridge.decide import plan_exploit
from pluto_services.msf_bridge.records import ExploitTarget, PayloadMode
from pluto_services.msf_bridge.rpc import MockMsfRpc


def _bridge() -> MsfBridge:
    return MsfBridge(MockMsfRpc())


def test_metasploit_first_uses_a_fitting_module():
    target = ExploitTarget(host="10.0.0.5", port=21, service="ftp", product="vsftpd", version="2.3.4")
    plan = plan_exploit(_bridge(), target, lhost="10.0.0.1")
    assert plan.mode is PayloadMode.METASPLOIT_MODULE
    assert plan.module is not None
    assert plan.module.fullname == "exploit/unix/ftp/vsftpd_234_backdoor"
    assert plan.payload is None
    assert "maintained module" in plan.rationale


def test_custom_on_demand_when_no_module_fits():
    target = ExploitTarget(
        host="10.0.0.5",
        port=80,
        service="http",
        product="AcmePortal",
        version="1.0",
        mechanism="authenticated file upload accepting .php",
    )
    plan = plan_exploit(_bridge(), target, lhost="10.0.0.1", lport=4444)
    assert plan.mode is PayloadMode.CUSTOM_PAYLOAD
    assert plan.module is None
    assert plan.payload is not None
    # The generated delivery code is retained (evidence) and references the target path/transport.
    assert "msfvenom" in plan.payload.generated_code
    assert plan.payload.lport == 4444
    assert "http-file-upload" in plan.payload.generated_code


def test_run_module_opens_a_session_via_backend():
    target = ExploitTarget(host="10.0.0.5", port=21, service="ftp", product="vsftpd", version="2.3.4")
    bridge = _bridge()
    match = bridge.find_module(target)
    assert match is not None
    result = bridge.run_module(match, target, payload="cmd/unix/interact")
    assert result.ok is True
    assert result.mode is PayloadMode.METASPLOIT_MODULE
    assert result.session_opened is True
    assert result.session_id == 1


def test_find_module_returns_none_for_unknown_target():
    target = ExploitTarget(host="10.0.0.5", service="ssh", product="OpenSSH", version="10.0p2")
    assert _bridge().find_module(target) is None
