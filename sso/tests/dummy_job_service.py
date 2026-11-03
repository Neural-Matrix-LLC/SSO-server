"""A "dummy job" service for testing v1.3e session-bound jobs (DESIGN-v1.3e-session-bound-jobs.md §5).

It stands in for SGMCP / FUND auto-trade: a user starts long-running jobs; the service records ``owner_sub`` and
``owner_sid`` from introspect, runs the jobs under its own identity, and stops them when the SSO says the session
ended (signed ``token.revoked`` webhook, or the ``/service/sessions/status`` sweep). It is also the reference
implementation for real job services: the event handling in ``_on_*`` and ``sweep()`` is what they must do.

Transport is injected, so tests drive it in-process: ``sso(path, body) -> (status, json)`` calls the SSO with the
service's Basic credentials; webhooks arrive through ``receive_webhook(raw_body, headers)`` (the SSO worker's real
signed POST). The webhook check uses the shipped ``sso_client.WebhookReceiver`` (signature, timestamp, dedupe).
"""
from __future__ import annotations

import itertools
import os
import sys
from dataclasses import dataclass, field
from typing import Callable

try:  # the shipped client library; not installed in the SSO test venv, so use the copy in this repo
    from sso_client import WebhookReceiver, WebhookVerificationError
except ModuleNotFoundError:  # pragma: no cover - depends on the venv
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clients", "python", "src"))
    from sso_client import WebhookReceiver, WebhookVerificationError

RUNNING, STOPPED, DELETED = "RUNNING", "STOPPED", "DELETED"
SWEEP_BATCH = 100  # SSO limit per /service/sessions/status request

SSOCall = Callable[[str, dict], "tuple[int, dict]"]


class JobRefused(Exception):
    """The user's token could not start a job (inactive, revoked, IP mismatch, missing permission)."""


@dataclass
class DummyJob:
    id: int
    name: str
    owner_sub: str
    owner_sid: str
    state: str = RUNNING
    stop_reason: str | None = None  # SSO reason: logout, password_change, logout_all, expired, suspended, …
    stopped_by: str | None = None  # "webhook" or "sweep"
    ticks: int = 0  # units of work done; only grows while RUNNING

    def tick(self) -> None:
        if self.state == RUNNING:
            self.ticks += 1


@dataclass
class DummyJobService:
    sso: SSOCall
    webhook_secret: str
    sweep_batch: int = SWEEP_BATCH
    jobs: dict[int, DummyJob] = field(default_factory=dict)
    notifications: list[tuple[str, str]] = field(default_factory=list)  # (owner_sub, message) sent to the user
    webhook_calls: int = 0

    def __post_init__(self):
        self._ids = itertools.count(1)
        self._rx = WebhookReceiver(self.webhook_secret)
        self._rx.on("token.revoked")(self._on_token_revoked)
        self._rx.on("user.suspended")(self._on_user_gone)
        self._rx.on("user.deleted")(self._on_user_gone)

    # ------------------------------------------------------------------ start
    def start_job(self, user_token: str, *, name: str = "job", client_ip: str | None = None,
                  require: str | None = None, actor_token: str | None = None) -> DummyJob:
        """Authorize once with the user's token (introspect), then bind the job to the user's session."""
        body: dict = {"token": user_token}
        if client_ip:
            body["ip"] = client_ip
        if require:
            body["require"] = require
        if actor_token:  # an agent / service acting on behalf of the user (v1.3b)
            body["actor_token"] = actor_token
        status, data = self.sso("/api/v1/auth/introspect", body)
        if status != 200 or not data.get("active"):
            raise JobRefused("token_inactive")
        if require and not data.get("allowed"):
            raise JobRefused("forbidden")
        if not data.get("sid"):
            raise JobRefused("no_session")  # nothing to bind to: refuse rather than run unbounded
        job = DummyJob(id=next(self._ids), name=name, owner_sub=data["sub"], owner_sid=data["sid"])
        self.jobs[job.id] = job
        return job  # the user token is NOT kept

    # ------------------------------------------------------------------ webhooks
    def receive_webhook(self, body: bytes, headers: dict) -> int:
        """The service's webhook endpoint: 2xx on success or duplicate, 401 on a bad signature (SSO retries)."""
        self.webhook_calls += 1
        try:
            self._rx.handle(body, headers)
        except WebhookVerificationError:
            return 401
        return 200

    def _on_token_revoked(self, ev: dict) -> None:
        sub, sid, reason = ev.get("sub"), ev.get("sid"), ev.get("reason", "revoked")
        for job in self._running(sub):
            if sid is None or job.owner_sid == sid:  # no sid: every session of the user ended
                self._stop(job, reason, "webhook")

    def _on_user_gone(self, ev: dict) -> None:
        reason = "suspended" if ev["type"] == "user.suspended" else "deleted"
        for job in [j for j in self.jobs.values() if j.owner_sub == ev.get("sub") and j.state != DELETED]:
            if job.state == RUNNING:
                self._stop(job, reason, "webhook")
            job.state = DELETED  # suspend / delete: stop AND delete (ECOSYSTEM §5.6), history kept

    # ------------------------------------------------------------------ sweep
    def sweep(self) -> list[DummyJob]:
        """Backstop, every 60 s in a real service: ask the SSO which job sessions are still alive."""
        running = [j for j in self.jobs.values() if j.state == RUNNING]
        pairs = sorted({(j.owner_sub, j.owner_sid) for j in running})
        ended: dict[tuple[str, str], str] = {}
        for i in range(0, len(pairs), self.sweep_batch):
            batch = pairs[i:i + self.sweep_batch]
            status, data = self.sso("/api/v1/service/sessions/status",
                                    {"sessions": [{"sub": s, "sid": d} for s, d in batch]})
            if status != 200:
                return []  # SSO unavailable: keep running, try again next round (webhooks still work)
            for row in data["sessions"]:
                if not row["active"]:
                    ended[(row["sub"], row["sid"])] = row["reason"]
        stopped = []
        for job in running:
            reason = ended.get((job.owner_sub, job.owner_sid))
            if reason:
                self._stop(job, reason, "sweep")
                stopped.append(job)
        return stopped

    # ------------------------------------------------------------------ helpers
    def tick_all(self) -> None:
        for job in self.jobs.values():
            job.tick()

    def _running(self, sub) -> list[DummyJob]:
        return [j for j in self.jobs.values() if j.owner_sub == sub and j.state == RUNNING]

    def _stop(self, job: DummyJob, reason: str, by: str) -> None:
        job.state, job.stop_reason, job.stopped_by = STOPPED, reason, by
        self.notifications.append((job.owner_sub, f"job {job.name} stopped: session ended ({reason})"))

    def states(self) -> dict[str, tuple]:
        """name -> (state, stop_reason, stopped_by), for compact assertions."""
        return {j.name: (j.state, j.stop_reason, j.stopped_by) for j in self.jobs.values()}
