"""v1.3a permission import (DESIGN-v1.3a §5): never deletes, marks missing deprecated."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest
from django.contrib.auth.models import Permission

from application.models import Application, ApplicationPermissionRecord
from sso.models import AdminAuditLog, ServiceClient

from .test_admin_api_v13a import A, H, admin_user, at, basic, perm  # noqa: F401

URL = f"{A}/apps/gateway/permissions"


def payload(version=1, perms=None):
    return {"app_name": "Smart Gateway MCP", "description": "Broker", "version": version,
            "permissions": perms if perms is not None else [
                {"codename": "gateway_trade", "name": "Trade", "description": "paper"},
                {"codename": "gateway_live", "name": "Trade live"}]}


def test_import_create_idempotent_deprecate_never_delete(api, at, user):
    r = api.put(URL + "?dry_run=true", payload(), format="json", **H(at))
    assert r.status_code == 200 and r.json()["created"] == ["gateway", "gateway_trade", "gateway_live"]
    assert not Permission.objects.filter(codename="gateway_trade").exists()  # dry run wrote nothing
    assert not AdminAuditLog.objects.filter(action__startswith="app.import").exists()
    r = api.put(URL, payload(), format="json", **H(at)).json()
    assert r["created"] == ["gateway", "gateway_trade", "gateway_live"] and not r["dry_run"]
    assert Application.objects.get(app_codename="gateway").version == 1
    r = api.put(URL, payload(), format="json", **H(at)).json()
    assert r["unchanged"] == ["gateway", "gateway_trade", "gateway_live"] and not r["created"] + r["updated"]
    assert AdminAuditLog.objects.filter(action="app.import_noop").count() == 1
    user.user_permissions.add(perm("gateway_live"))
    r = api.put(URL, payload(2, [{"codename": "gateway_trade", "name": "Trade (paper/sim)", "description": "paper"}]),
                format="json", **H(at)).json()
    assert r["updated"] == ["gateway_trade"] and r["missing"] == ["gateway_live"] and r["deprecated"] == ["gateway_live"]
    # still exists, still granted, still in perms
    assert Permission.objects.filter(codename="gateway_live").exists()
    assert ApplicationPermissionRecord.objects.get(codename="gateway_live").deprecated_at is not None
    assert user.user_permissions.filter(codename="gateway_live").exists()
    listed = api.get(f"{A}/permissions?app=gateway&deprecated=true", **H(at)).json()["results"]
    assert [p["codename"] for p in listed] == ["gateway_live"] and listed[0]["deprecated"]
    # again: missing but not newly deprecated
    r = api.put(URL, payload(2, [{"codename": "gateway_trade", "name": "Trade (paper/sim)", "description": "paper"}]),
                format="json", **H(at)).json()
    assert r["missing"] == ["gateway_live"] and r["deprecated"] == []
    # listed again: un-deprecated
    r = api.put(URL, payload(3), format="json", **H(at)).json()
    assert "gateway_live" in r["updated"]
    assert ApplicationPermissionRecord.objects.get(codename="gateway_live").deprecated_at is None
    detail = api.get(f"{A}/apps/gateway", **H(at)).json()
    assert detail["version"] == 3 and {p["codename"] for p in detail["permissions"]} == {
        "gateway", "gateway_trade", "gateway_live"}
    assert api.get(f"{A}/apps", **H(at)).json()["count"] == 1


@pytest.mark.parametrize("bad", [
    {"codename": "other_x", "name": "x"},
    {"codename": "gateway_X", "name": "x"},
    {"codename": "gateway_trade", "name": ""},
    "nope",
])
def test_import_validation(api, at, bad):
    r = api.put(URL, payload(perms=[bad]), format="json", **H(at))
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    assert not Application.objects.exists()


def test_import_duplicate_and_bad_app(api, at):
    p = {"codename": "gateway_a", "name": "a"}
    assert api.put(URL, payload(perms=[p, p]), format="json", **H(at)).status_code == 400
    assert api.put(f"{A}/apps/Bad-App/permissions", payload(), format="json", **H(at)).status_code == 400
    assert api.put(URL, {**payload(), "version": 0}, format="json", **H(at)).status_code == 400


def test_import_version_conflict_and_force(api, at):
    api.put(URL, payload(5), format="json", **H(at))
    r = api.put(URL, payload(4), format="json", **H(at))
    assert r.status_code == 409 and r.json()["error"] == "version_conflict"
    assert api.put(URL + "?force=true", payload(4), format="json", **H(at)).status_code == 200


def test_import_by_own_service_client_only(api, db, admin_user):  # noqa: F811
    own = ServiceClient(client_id="sgmcp", name="SG", app_codename="gateway")
    own.set_secret("s1")
    own.save()
    other = ServiceClient(client_id="wiki", name="W", app_codename="llmwiki")
    other.set_secret("s2")
    other.save()
    assert api.put(URL, payload(), format="json", **basic("sgmcp", "s1")).status_code == 200
    row = AdminAuditLog.objects.get(action="app.import")
    assert row.actor_type == "service" and row.actor_id == "svc:sgmcp"
    r = api.put(URL, payload(), format="json", **basic("wiki", "s2"))
    assert r.status_code == 403 and r.json()["error"] == "admin_forbidden"
    assert api.put(URL, payload(), format="json", **basic("sgmcp", "wrong")).status_code == 401
    # the service client cannot use other admin endpoints
    assert api.get(f"{A}/users", **basic("sgmcp", "s1")).status_code in (401, 403)


def test_sso_permissions_to_json_never_executes(tmp_path):
    f = tmp_path / "sso_permissions.py"
    f.write_text('APP_CODENAME = "gateway"\nAPP_NAME = "Smart Gateway MCP"\nAPP_DESCRIPTION = "B"\n'
                 'PERMISSIONS_VERSION = 3\nPERMISSIONS = [\n  ("gateway_trade", "Trade", "paper"),\n]\n')
    out = subprocess.run([sys.executable, "scripts/sso_permissions_to_json.py", str(f)], capture_output=True,
                         text=True, check=True).stdout
    data = json.loads(out)
    assert data == {"app_codename": "gateway", "app_name": "Smart Gateway MCP", "description": "B", "version": 3,
                    "permissions": [{"codename": "gateway_trade", "name": "Trade", "description": "paper"}]}
    evil = tmp_path / "evil.py"
    marker = tmp_path / "pwned"
    evil.write_text(f'import os\nos.system("touch {marker}")\nAPP_CODENAME = "x"\n')
    r = subprocess.run([sys.executable, "scripts/sso_permissions_to_json.py", str(evil)], capture_output=True, text=True)
    assert r.returncode != 0 and not marker.exists()
