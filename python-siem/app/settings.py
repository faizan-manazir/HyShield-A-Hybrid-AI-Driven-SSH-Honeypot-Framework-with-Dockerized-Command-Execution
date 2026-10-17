"""Platform settings, saved in data/settings.json so they survive a restart."""
import json

from . import config

DEFAULTS = {
    "alertLevel": 7, "logRetention": 90,
    "arEnabled": True, "arCommand": "firewall-drop", "arTimeout": 600,
    "vtEnabled": True, "vtKey": "", "otxEnabled": False,
}
AR_COMMANDS = ["firewall-drop", "host-deny", "route-null"]


def load():
    settings = dict(DEFAULTS)
    try:
        settings.update(json.loads(config.SETTINGS_PATH.read_text()))
    except (OSError, ValueError):
        pass
    return settings


def save(settings):
    config.SETTINGS_PATH.write_text(json.dumps(settings, indent=2))


def public(settings):
    """Copy that is safe to show: the API key is never sent back to the browser."""
    shown = dict(settings)
    shown["vtKeySet"] = bool(shown.pop("vtKey", ""))
    return shown


def raw_config(s):
    """The ossec-style text shown on the 'Raw Configuration' tab (key stays hidden)."""
    key = "************" if s["vtKey"] and s["vtEnabled"] else ""
    return f"""<!-- HyShield / SIEM Configuration -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>yes</logall_json>
    <email_notification>yes</email_notification>
    <memory_size>2048</memory_size>
  </global>

  <alerts>
    <log_alert_level>{s['alertLevel']}</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <active-response>
    <disabled>{'no' if s['arEnabled'] else 'yes'}</disabled>
    <command>{s['arCommand']}</command>
    <location>local</location>
    <level>8</level>
    <timeout>{s['arTimeout']}</timeout>
  </active-response>

  <integration>
    <name>virustotal</name>
    <api_key>{key}</api_key>
    <rule_id>100202,100203</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>"""
