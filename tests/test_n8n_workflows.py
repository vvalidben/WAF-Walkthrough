"""n8n workflows: structure, and their Code nodes executed with Node.js.

The feedback loop is security-relevant: a forged "false positive" click would
write an attack string into the training data as safe. These tests run the
real Code nodes (tests/n8n_code_node.js stands in for n8n) to check Slack's
signature verification, and that the alert's button values are exactly what
the feedback workflow parses.
"""

import hashlib
import hmac
import json
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ALERT = ROOT / "n8n_sqli_alert.json"
FEEDBACK = ROOT / "n8n_feedback_loop.json"
HARNESS = Path(__file__).with_name("n8n_code_node.js")
SECRET = "test-slack-signing-secret"
RESPONSE_URL = "https://hooks.slack.com/actions/T000/1/abc"

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="Node.js not installed")


@pytest.mark.parametrize("path", [ALERT, FEEDBACK], ids=lambda p: p.name)
def test_workflow_structure(path: Path) -> None:
    workflow = json.loads(path.read_text(encoding="utf-8"))
    names = [node["name"] for node in workflow["nodes"]]
    assert len(names) == len(set(names)), "node names must be unique"
    for source, outputs in workflow["connections"].items():
        assert source in names
        for branch in outputs["main"]:
            for target in branch:
                assert target["node"] in names
    # Credentials live in n8n, never in the exported file.
    text = path.read_text(encoding="utf-8")
    for marker in ("xoxb-", "xoxp-", "hooks.slack.com/services/"):
        assert marker not in text


def run_code_node(workflow: Path, node: str, **request) -> dict:
    payload = json.dumps({"workflow": str(workflow), "node": node, **request})
    done = subprocess.run([NODE, str(HARNESS)], input=payload, capture_output=True, text=True,
                          encoding="utf-8", timeout=30, check=True)
    return json.loads(done.stdout)


def _alert(**overrides) -> dict:
    return {
        "event": "sqli_detected", "action": "block", "source_engine": "ml", "ip": "203.0.113.7",
        "host": "shop.example", "method": "GET", "path": "/search", "probability": 0.91, "threshold": 0.5,
        "request_id": "req123", "source": "arg:q", "flagged_count": 2, "ts": "2026-10-30T10:00:00Z",
        "blocked_values": [
            {"source": "arg:q", "probability": 0.91, "value": "1' OR '1'='1"},
            {"source": "header:user-agent", "probability": 0.85, "value": "Mozilla/5.0 <!channel> `x`"},
        ],
        **overrides,
    }


def build_alert(alert: dict, lookup: dict | None = None) -> dict:
    result = run_code_node(ALERT, "Build alert", input=[lookup or {"data": {"abuseConfidenceScore": 80}}],
                           nodes={"WAF alert webhook": {"body": alert}})
    assert "error" not in result, result
    return result["ok"][0]["json"]


def _texts(node: object) -> list[str]:
    """Every rendered text in a Block Kit structure."""
    if isinstance(node, dict):
        found = [node["text"]] if isinstance(node.get("text"), str) else []
        return found + [t for key, value in node.items() if key != "value" for t in _texts(value)]
    if isinstance(node, list):
        return [t for item in node for t in _texts(item)]
    return []


def _buttons(message_json: str) -> list[dict]:
    blocks = json.loads(message_json)["attachments"][0]["blocks"]
    return [block["accessory"] for block in blocks if "accessory" in block]


@needs_node
def test_alert_escapes_attacker_text_and_routes_by_abuse_score() -> None:
    out = build_alert(_alert())
    assert out["abuse_score"] == 80
    high = json.loads(out["slack_high"])
    assert high["text"].startswith("<!here>")
    # Everything Slack renders (button values are not rendered: they carry
    # the raw value to the feedback workflow).
    rendered = json.dumps([_texts(block) for block in high["attachments"][0]["blocks"]])
    assert "<!channel>" not in rendered
    assert "&lt;!channel&gt;" in rendered
    assert [b["action_id"] for b in _buttons(out["slack_standard"])] == ["waf_fp_0", "waf_fp_1"]


@needs_node
def test_alert_without_buttons_for_regex_hits_and_huge_values() -> None:
    regex = build_alert(_alert(source_engine="regex", signature={"id": "union_select"},
                               blocked_values=[{"source": "arg:q", "signature": "union_select", "value": "1 union select 2"}]))
    assert _buttons(regex["slack_standard"]) == []
    huge = build_alert(_alert(blocked_values=[{"source": "body:x", "probability": 0.9, "value": "a" * 2500}]))
    assert _buttons(huge["slack_standard"]) == []  # over Slack's 2000-char button limit


def slack_click(button: dict, timestamp: int | None = None, secret: str = SECRET,
                response_url: str = RESPONSE_URL) -> tuple[dict, str]:
    """A Slack block_actions request for `button`: (headers, raw form body), signed with `secret`."""
    payload = {
        "type": "block_actions",
        "user": {"id": "U012ABC", "username": "analyst"},
        "actions": [{"action_id": button["action_id"], "value": button["value"]}],
        "response_url": response_url,
        "message": {"text": "alert"},
    }
    raw = "payload=" + urllib.parse.quote(json.dumps(payload))
    ts = str(int(time.time()) if timestamp is None else timestamp)
    signature = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:{raw}".encode(), hashlib.sha256).hexdigest()
    headers = {"x-slack-request-timestamp": ts, "x-slack-signature": signature}
    return headers, raw


def verify_click(headers: dict, raw: str, tamper_body: bool = False) -> dict:
    """Run Prepare signature check -> Crypto (HMAC, as n8n's Crypto node) -> Verify & parse click."""
    body = {"payload": urllib.parse.parse_qs(raw)["payload"][0]}
    prepared = run_code_node(FEEDBACK, "Prepare signature check", input=[{"headers": headers, "body": body}],
                             raw_body=raw + ("&x=1" if tamper_body else ""))
    if "error" in prepared:
        return prepared
    item = prepared["ok"][0]["json"]
    item["expected_signature"] = hmac.new(SECRET.encode(), item["base_string"].encode(), hashlib.sha256).hexdigest()
    return run_code_node(FEEDBACK, "Verify & parse click", input=[item])


@needs_node
def test_feedback_accepts_a_genuine_click_and_round_trips_the_value() -> None:
    button = _buttons(build_alert(_alert())["slack_standard"])[1]
    result = verify_click(*slack_click(button))
    assert "error" not in result, result
    row = result["ok"][0]["json"]
    # Exactly the value the WAF flagged, unescaped, ready for POST /feedback.
    assert row["query"] == "Mozilla/5.0 <!channel> `x`"
    assert row["label"] == 0
    assert row["source"] == "header:user-agent"
    assert row["request_id"] == "req123"
    assert row["flagged_by"] == "analyst (U012ABC)"


@needs_node
@pytest.mark.parametrize("attack", ["wrong_secret", "tampered_body", "stale_timestamp", "short_signature", "foreign_response_url"])
def test_feedback_rejects_forged_clicks(attack: str) -> None:
    button = _buttons(build_alert(_alert())["slack_standard"])[0]
    if attack == "wrong_secret":
        result = verify_click(*slack_click(button, secret="attacker-guess"))
    elif attack == "tampered_body":
        result = verify_click(*slack_click(button), tamper_body=True)
    elif attack == "stale_timestamp":
        result = verify_click(*slack_click(button, timestamp=int(time.time()) - 600))
    elif attack == "short_signature":
        headers, raw = slack_click(button)
        headers["x-slack-signature"] = "v0="
        result = verify_click(headers, raw)
    else:
        result = verify_click(*slack_click(button, response_url="https://attacker.example/hook"))
    assert "error" in result and result["error"].startswith("Rejected"), result
