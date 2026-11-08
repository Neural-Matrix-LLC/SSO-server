"""v1.3f (decision 2026-11-04): app permissions are data, not SSO code. SGMCP's nine permissions.

``application.sgmcp`` (may use SGMCP), ``sgmcp_trade`` / ``sgmcp_live`` (paper / live, every broker) and
``sgmcp_{ib,webull,futu}_{trade,live}`` (per broker) come from SGMCP's ``sso_permissions.py`` import or the admin
tools. Nothing is defined in SSO code, and adding a broker needs no SSO change. Introspect ``require`` is all-of, so
SGMCP evaluates its "either one" rule on ``perms`` (API-REFERENCE-MANUAL §8.4).
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import pytest
from django.contrib.auth.models import Group

from application.models import ApplicationAccess
from application.permissions import code_defined_codenames, user_app_perms

from .conftest import login
from .test_admin_api_v13a import A, H, admin_user, at, basic, perm, reauth  # noqa: F401
from .test_session_bound_jobs_v13e import svc  # noqa: F401

pytestmark = pytest.mark.django_db

ROOT = pathlib.Path(__file__).resolve().parents[2]
BROKERS = ("ib", "webull", "futu")
NINE = ["sgmcp", "sgmcp_trade", "sgmcp_live"] + [f"sgmcp_{b}_{k}" for b in BROKERS for k in ("trade", "live")]


def ecosystem_example() -> str:
    """SGMCP's ``sso_permissions.py`` exactly as ECOSYSTEM-INTEGRATION.md §2.1 shows it (keeps the doc honest)."""
    doc = (ROOT / "docs/ECOSYSTEM-INTEGRATION.md").read_text()
    m = re.search(r"```python\n(# <app repo>/sso_permissions\.py.*?)```", doc, re.S)
    assert m, "ECOSYSTEM §2.1 example not found"
    return m.group(1)


def sgmcp_payload(tmp_path) -> dict:
    f = tmp_path / "sso_permissions.py"
    f.write_text(ecosystem_example())
    out = subprocess.run([sys.executable, str(ROOT / "scripts/sso_permissions_to_json.py"), str(f)],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


@pytest.fixture
def imported(api, at, tmp_path):  # noqa: F811
    data = sgmcp_payload(tmp_path)
    r = api.put(f"{A}/apps/sgmcp/permissions", data, format="json", **H(at))
    assert r.status_code == 200, r.content
    return data, r.json()


def may_trade(perms, broker: str, live: bool) -> bool:
    """SGMCP's rule, as documented in API-REFERENCE-MANUAL §8.4."""
    kind = "live" if live else "trade"
    return "application.sgmcp" in perms and (
        f"application.sgmcp_{kind}" in perms or f"application.sgmcp_{broker}_{kind}" in perms)


def introspect(api, token, require=None):
    body = {"token": token}
    if require is not None:
        body["require"] = require
    r = api.post("/api/v1/auth/introspect", body, format="json", **basic("sgmcp", "sec"))
    assert r.status_code == 200, r.content
    return r.json()


def test_import_of_the_documented_file_creates_all_nine_none_in_code(imported):
    data, result = imported
    assert data["app_codename"] == "sgmcp"
    assert sorted(result["created"]) == sorted(NINE)
    assert perm("sgmcp").name == "Can use Smart Gateway MCP"
    assert not set(NINE) & code_defined_codenames()
    assert not any(code.startswith("sgmcp") for code, _ in ApplicationAccess._meta.permissions)


def test_imported_permissions_can_be_deleted(api, at, reauth, imported):  # noqa: F811
    assert api.delete(f"{A}/permissions/sgmcp_futu_live", **H(at, reauth)).status_code == 204
    assert api.get(f"{A}/permissions/sgmcp_futu_live", **H(at)).status_code == 404


def test_grants_reach_perms_and_paper_live_are_separate(api, svc, user, make_user, imported):  # noqa: F811
    user.user_permissions.add(perm("sgmcp"), perm("sgmcp_ib_trade"))
    body = introspect(api, login(api).json()["access_token"], ["application.sgmcp"])
    assert body["active"] and body["allowed"]
    perms = set(body["perms"])
    assert may_trade(perms, "ib", live=False)
    assert not may_trade(perms, "ib", live=True)          # paper does not include live
    assert not may_trade(perms, "futu", live=False)       # other broker

    # live everywhere through a group, still no paper on futu
    ann = make_user(username="ann", email="ann@example.org", groups=("live-traders",))
    Group.objects.get(name="live-traders").permissions.add(perm("sgmcp"), perm("sgmcp_live"))
    perms = set(introspect(api, login(api, username="ann").json()["access_token"])["perms"])
    assert may_trade(perms, "futu", live=True) and may_trade(perms, "webull", live=True)
    assert not may_trade(perms, "futu", live=False)       # live does not include paper
    assert "application.sgmcp_live" in user_app_perms(ann)

    # every broker permission without application.sgmcp: not allowed at all
    bob = make_user(username="bob", email="bob@example.org", groups=())
    bob.user_permissions.add(perm("sgmcp_trade"), perm("sgmcp_live"))
    t = login(api, username="bob").json()["access_token"]
    assert introspect(api, t, ["application.sgmcp"])["allowed"] is False
    assert not may_trade(set(introspect(api, t)["perms"]), "ib", live=False)


def test_require_is_all_of(api, svc, user, imported):  # noqa: F811
    user.user_permissions.add(perm("sgmcp"), perm("sgmcp_ib_live"))
    t = login(api).json()["access_token"]
    assert introspect(api, t, ["application.sgmcp", "application.sgmcp_ib_live"])["allowed"] is True
    # "sgmcp_live OR sgmcp_ib_live" cannot be sent as require: it would demand both
    assert introspect(api, t, ["application.sgmcp_live", "application.sgmcp_ib_live"])["allowed"] is False


def test_new_broker_needs_no_sso_code(api, at, svc, user, imported, tmp_path):  # noqa: F811
    data, _ = imported
    data = dict(data, version=data["version"] + 1, permissions=data["permissions"] + [
        {"codename": "sgmcp_schwab_trade", "name": "Schwab paper trade", "description": "Paper orders on Schwab"}])
    r = api.put(f"{A}/apps/sgmcp/permissions", data, format="json", **H(at))
    assert r.status_code == 200 and r.json()["created"] == ["sgmcp_schwab_trade"]
    # or one at a time from the admin API / UI
    r = api.post(f"{A}/permissions", {"codename": "sgmcp_schwab_live", "name": "Schwab live trade"}, format="json",
                 **H(at))
    assert r.status_code == 201, r.content
    user.user_permissions.add(perm("sgmcp"), perm("sgmcp_schwab_live"))
    perms = set(introspect(api, login(api).json()["access_token"])["perms"])
    assert may_trade(perms, "schwab", live=True) and not may_trade(perms, "schwab", live=False)


def test_codenames_are_lowercase_without_dots(api, at):  # noqa: F811
    bad = {"app_name": "Smart Gateway MCP", "version": 1,
           "permissions": [{"codename": "SGMCP.IB.trade", "name": "IB paper"}]}
    assert api.put(f"{A}/apps/sgmcp/permissions", bad, format="json", **H(at)).status_code == 400
    assert api.post(f"{A}/permissions", {"codename": "sgmcp.ib.trade", "name": "x"}, format="json",
                    **H(at)).status_code == 400
