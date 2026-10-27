"""Founder Desk read model and execution kill switch."""
import importlib
import importlib.util
from datetime import datetime, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app import enums, main, models, registry


def _backup_verified_event(db, backup, *, target=None):
    db.add(models.Event(
        event_type="BACKUP_VERIFIED", source="company-backup",
        payload={"target": target or backup.target, "status": "VERIFIED", "backup_run_id": backup.id},
    ))


def _modules():
    # Break caught: the page becomes a second source of truth instead of consuming one
    # bounded DB read model and one persistent control state.
    assert importlib.util.find_spec("app.desk") is not None, "desk read model missing"
    assert importlib.util.find_spec("app.control") is not None, "control state missing"
    return importlib.import_module("app.desk"), importlib.import_module("app.control")


def _company(db):
    ceo = models.Agent(key="ceo", role="Coordination", enabled=True)
    developer = models.Agent(key="developer", role="Software", enabled=True)
    supervisor = models.Agent(key="supervisor", role="Quality", enabled=True)
    research = models.Agent(key="research", role="Research", enabled=True)
    unit = models.BusinessUnit(
        key="seerxo", name="Seerxo", status=enums.BusinessUnitStatus.ACTIVE,
        priority=enums.Priority.P1,
    )
    db.add_all([ceo, developer, supervisor, research, unit])
    db.flush()
    project = models.Project(
        key="seerxo-api", name="Seerxo API", business_unit_id=unit.id,
        status=enums.ProjectStatus.ACTIVE, priority=enums.Priority.P1,
    )
    db.add(project)
    db.flush()
    dependency = models.Task(
        key="TASK-0041", title="Reproduce", success_criteria="reproduction recorded",
        status=enums.TaskStatus.DONE, priority=enums.Priority.P1,
        risk_level=enums.RiskLevel.LOW, assigned_agent_id=developer.id,
        business_unit_id=unit.id, project_id=project.id,
    )
    task = models.Task(
        key="TASK-0042", title="Fix checkout", description="Checkout fails",
        objective="Restore conversion", success_criteria="tests pass",
        status=enums.TaskStatus.IN_PROGRESS, priority=enums.Priority.P1,
        risk_level=enums.RiskLevel.MEDIUM, assigned_agent_id=developer.id,
        business_unit_id=unit.id, project_id=project.id,
        context={"required_files": ["app/checkout.py"]}, artifacts={"report": "r.md"},
    )
    db.add_all([dependency, task])
    db.flush()
    db.add_all([
        models.TaskDependency(task_id=task.id, depends_on_id=dependency.id),
        models.AgentRun(
            agent_id=developer.id, task_id=task.id,
            status=enums.AgentRunStatus.STARTED, provider="herdr",
            model="standard", estimated_cost_usd=0,
        ),
        models.AgentNote(
            agent_id=developer.id, task_id=task.id, project_id=project.id,
            note="Migration first", fingerprint="migration-first",
        ),
        models.Learning(
            title="Checkout learning", lesson="Verify webhook after deploy",
            project_id=project.id,
        ),
        models.Incident(
            key="INC-0042", severity=enums.IncidentSeverity.SEV2,
            title="Checkout degraded", description="Payment path errors",
            started_at=task.created_at, detected_by="watchdog",
            status=enums.IncidentStatus.INVESTIGATING, project_id=project.id,
        ),
        models.Approval(
            key="APR-0042", action="Deploy checkout fix", reason="Restore revenue",
            expected_effect="Checkout succeeds", risk_level=enums.RiskLevel.MEDIUM,
            rollback="Redeploy previous image", requested_by="developer",
            task_id=task.id,
        ),
        models.Service(
            key="seerxo-api", name="Seerxo API", status=enums.ServiceStatus.DEGRADED,
            risk=enums.RiskLevel.MEDIUM, business_unit_id=unit.id,
        ),
        models.Event(
            event_type="TASK_STARTED", source="developer", severity=enums.Severity.INFO,
            task_id=task.id, payload={"title": "Developer started TASK-0042"},
        ),
    ])
    db.commit()
    return task


def test_desk_state_uses_real_rows_and_marks_missing_metrics_unknown():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        incident = db.scalar(select(models.Incident))
        task_started = db.scalar(select(models.Event).where(
            models.Event.event_type == "TASK_STARTED"))
        tied_at = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
        task_started.occurred_at = tied_at
        db.add(models.Event(
            event_type="YOUTUBE_PIPELINE_STOPPED", source="watchdog",
            severity=enums.Severity.HIGH, incident_id=incident.id, notified=True,
            occurred_at=tied_at,
        ))
        db.commit()
        state = desk.build_state(db, registry.load(), control.agents_paused(db))

        assert state["overview"] == {
            "revenue_today": None,
            "revenue_month": None,
            "active_projects": 1,
            "running_agents": 1,
            "open_tasks": 1,
            "blocked_tasks": 0,
            "incidents": 1,
            "pending_approvals": 1,
            "system_health": "DEGRADED",
        }
        developer = next(a for a in state["agents"] if a["key"] == "developer")
        assert developer["status"] == "RUNNING"
        assert developer["current_task"]["key"] == "TASK-0042"
        assert developer["reports_to"] == "ceo"
        assert state["health"]["resources"] == {
            "cpu_percent": None, "ram_percent": None, "disk_percent": None, "at": None,
        }
        assert state["health"]["collection"] == {
            "containers": "UNKNOWN", "container_health": "UNKNOWN",
        }
        from app.watchdog import record_host_metrics
        record_host_metrics(db, {"cpu_used_pct": 7, "mem_used_pct": 61, "disk_used_pct": 40})
        resources = desk.build_state(db, registry.load(), False)["health"]["resources"]
        assert (resources["cpu_percent"], resources["ram_percent"], resources["disk_percent"]) == (7, 61, 40)
        assert resources["at"]
        updated_health = desk.build_state(db, registry.load(), False)["health"]
        assert updated_health["collection"] == {
            "containers": "UNKNOWN", "container_health": "UNKNOWN",
        }
        assert state["tasks"][0]["agent"] == "developer"
        activity_titles = [event["title"] for event in state["activity"]]
        assert activity_titles[:2] == ["YOUTUBE_PIPELINE_STOPPED", "Developer started TASK-0042"]
        assert state["incidents"][0]["founder_notified"] is True
        # Break caught: the attention queue drops a pending approval or a missing backup.
        kinds = [i["kind"] for i in state["needs_you"]]
        # No metric source reported: the unit is UNAVAILABLE with no values, never zeros.
        [seerxo] = [u for u in state["portfolio"] if u["key"] == "seerxo"]
        assert seerxo["freshness"] == "UNAVAILABLE" and seerxo["metrics"] == []
        assert "APPROVAL" in kinds and "STOPPED" in kinds
        assert kinds == sorted(kinds, key=["SEV0", "SECURITY", "SEV1", "STOPPED", "APPROVAL",
                                           "BLOCKED_P0", "BLOCKED_P1", "PROVIDER", "OTHER"].index)
        # Break caught: the trend chart skips empty days and draws a misleading line.
        series = state["run_series"]
        assert len(series) == 14 and series[0]["day"] < series[-1]["day"]
        assert sum(d["STARTED"] for d in series) == 1
        assert series[-1]["STARTED"] == 1 and series[-1]["FAILED"] == 0


def test_route_failure_is_visible_as_a_founder_action():
    desk, _ = _modules()
    state = models.NotificationState(scope_key="watchdog-condition:failed", active=True,
                                     episode=1, event_id=99, attempted_at=datetime.now(timezone.utc),
                                     delivery_status="route_failed")
    actions = desk.needs_you([], [], [], {}, None, False, notifications=[state])
    [action] = [item for item in actions if item["title"] == "Watchdog could not open incident work"]
    assert action["kind"] == "STOPPED"
    assert action["title"] == "Watchdog could not open incident work"
    assert "three bounded attempts" in action["why"]


def test_activity_exposes_latest_watchdog_evidence_without_mutating_event():
    from datetime import timedelta
    from app import watchdog

    desk, _ = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    finding = watchdog.Finding("TASK_FAILED_REPEATEDLY", enums.Severity.HIGH,
                               "2 tasks exhausted retries", "TASK-0101, TASK-0102",
                               dedupe="deadletter")
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        _company(db)
        watchdog.emit(db, [finding], {"collected_at": now.isoformat()})
        original = db.scalar(select(models.Event).where(
            models.Event.event_type == "TASK_FAILED_REPEATEDLY"))
        later = watchdog.Finding("TASK_FAILED_REPEATEDLY", enums.Severity.HIGH,
                                "3 tasks exhausted retries", "TASK-0101, TASK-0102, TASK-0103",
                                dedupe="deadletter")
        watchdog.emit(db, [later], {"collected_at": (now + timedelta(minutes=1)).isoformat()})

        assert original.payload["title"] == finding.title
        state = desk.build_state(db, registry.load(), False)
        activity = next(item for item in state["activity"] if item["id"] == original.id)
        assert activity["title"] == finding.title
        assert activity["latest_observation"] == {
            "title": later.title, "detail": later.detail, "severity": "HIGH",
            "observed_at": (now + timedelta(minutes=1)).isoformat(),
        }

        # Even after the source event falls out of the recent activity window, the
        # durable active-condition read model keeps it visible to the operator.
        for minute in range(2, 47):
            db.add(models.Event(event_type="SCHEDULE_TICK", source="scheduler",
                                severity=enums.Severity.INFO,
                                occurred_at=now + timedelta(minutes=minute), payload={"title": "tick"}))
        recovery = models.Event(event_type="WATCHDOG_CONDITION_RECOVERED", source="watchdog",
                                severity=enums.Severity.INFO,
                                notify_reason="recovery delivery pending",
                                occurred_at=now + timedelta(minutes=48),
                                payload={"condition_key": "deadletter"})
        uncertain_recovery = models.Event(
            event_type="WATCHDOG_CONDITION_RECOVERED", source="watchdog",
            severity=enums.Severity.INFO,
            notify_reason="recovery blocked by uncertain alert delivery",
            occurred_at=now + timedelta(minutes=49),
            payload={"condition_key": "uncertain-alert"},
        )
        exhausted_recovery = models.Event(
            event_type="WATCHDOG_CONDITION_RECOVERED", source="watchdog",
            severity=enums.Severity.INFO,
            notify_reason="recovery dispatch retries exhausted; founder review required",
            occurred_at=now + timedelta(minutes=50),
            payload={"condition_key": "exhausted-recovery"},
        )
        db.add_all([recovery, uncertain_recovery, exhausted_recovery])
        db.commit()
        state = desk.build_state(db, registry.load(), False)
        condition = next(row for row in state["health"]["watchdog_conditions"]
                         if row["event_id"] == original.id)
        assert condition["title"] == later.title
        assert all(event["id"] != original.id for event in state["activity"])
        assert any(item["title"] == "Recovery alert delivery needs review"
                   for item in state["needs_you"])
        assert any("original alert may have reached Telegram" in item["why"]
                   for item in state["needs_you"])
        assert any("No recovery send began" in item["why"]
                   for item in state["needs_you"])


def test_active_watchdog_desk_reports_when_condition_list_is_truncated():
    desk, _ = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        for index in range(105):
            scope = f"watchdog-condition:test-{index:03d}"
            event = models.Event(
                event_type="DISK_CRITICAL", source="watchdog", severity=enums.Severity.CRITICAL,
                payload={"condition_key": f"test-{index}", "title": f"Condition {index}"},
            )
            db.add(event)
            db.flush()
            db.add(models.NotificationState(
                scope_key=scope, active=True, episode=1, event_id=event.id,
                delivery_status="sent",
            ))
        db.commit()

        state = desk.build_state(db, registry.load(), False)
        health = state["health"]
        assert len(health["watchdog_conditions"]) == 100
        assert health["watchdog_conditions_total"] == 105
        assert health["watchdog_conditions_truncated"] is True


def test_desk_backup_and_restore_evidence_keep_source_and_latest_failure_visible():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        db.add_all([
            models.BackupRun(target="company-db", started_at=datetime(2026, 10, 13, tzinfo=timezone.utc),
                             ok=True, uploaded=True, integrity_verified=True, destination="r2://db/one",
                             size_bytes=10, checksum="a" * 64),
            models.BackupRun(target="company-db", started_at=datetime(2026, 10, 11, tzinfo=timezone.utc),
                             restore_tested_at=datetime(2026, 10, 11, tzinfo=timezone.utc),
                             ok=True, uploaded=False, integrity_verified=True,
                             destination="local:/backups/old.dump"),
            models.BackupRun(target="company-db", started_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
                             restore_tested_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
                             ok=False, uploaded=False, integrity_verified=False,
                             destination="local:/backups/new.dump"),
            models.BackupRun(target="renders", started_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
                             restore_tested_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
                             ok=False, uploaded=False, integrity_verified=False),
        ])
        db.flush()
        _backup_verified_event(db, db.scalar(select(models.BackupRun).where(
            models.BackupRun.target == "company-db", models.BackupRun.restore_tested_at.is_(None))))
        db.commit()

        state = desk.build_state(db, registry.load(), control.agents_paused(db))

    assert state["health"]["backup"] == {
        "target": "company-db", "ok": True, "uploaded": True, "integrity_verified": True,
        "verified": True,
        "at": "2026-10-13T00:00:00+00:00",
    }
    assert state["health"]["last_restore"] == {
        "target": "company-db", "ok": False, "uploaded": False, "integrity_verified": False,
        "at": "2026-10-12T00:00:00+00:00",
    }


def test_local_only_backup_is_not_presented_as_verified_off_site_recovery():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        db.add(models.BackupRun(target="company-db", ok=True, uploaded=False,
                                integrity_verified=True))
        db.commit()

        state = desk.build_state(db, registry.load(), control.agents_paused(db))

    assert state["health"]["backup"]["uploaded"] is False
    backup_attention = next(n for n in state["needs_you"]
                            if n["title"] == "Latest database backup is not verified off-site")
    assert "verified_event=False" in backup_attention["evidence"]


def test_non_database_backup_cannot_satisfy_or_replace_database_health_evidence():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        database_backup = models.BackupRun(
            target="company-db", started_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
            ok=True, uploaded=True, integrity_verified=True, destination="r2://db/one",
            size_bytes=10, checksum="a" * 64,
        )
        other_backup = models.BackupRun(
            target="renders", started_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
            ok=True, uploaded=True, integrity_verified=True,
        )
        db.add_all([
            database_backup, other_backup,
        ])
        db.flush()
        _backup_verified_event(db, database_backup)
        _backup_verified_event(db, other_backup)
        db.commit()

        state = desk.build_state(db, registry.load(), control.agents_paused(db))

    assert state["health"]["backup"]["target"] == "company-db"
    assert state["health"]["backup"]["verified"] is True
    assert not any(n["title"] == "No verified off-site database backup" for n in state["needs_you"])


def test_backup_event_with_matching_run_id_but_wrong_target_is_not_proof():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        database_backup = models.BackupRun(
            target="company-db", started_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
            ok=True, uploaded=True, integrity_verified=True, destination="r2://db/one",
            size_bytes=10, checksum="a" * 64,
        )
        db.add(database_backup)
        db.flush()
        _backup_verified_event(db, database_backup, target="renders")
        db.commit()

        state = desk.build_state(db, registry.load(), control.agents_paused(db))

    assert state["health"]["backup"]["verified"] is False
    backup_attention = next(n for n in state["needs_you"]
                            if n["title"] == "Latest database backup is not verified off-site")
    assert "verified_event=False" in backup_attention["evidence"]


def test_newer_non_database_backup_cannot_hide_missing_database_backup():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        db.add(models.BackupRun(target="renders", started_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
                                ok=True, uploaded=True, integrity_verified=True))
        db.commit()

        state = desk.build_state(db, registry.load(), control.agents_paused(db))

    assert state["health"]["backup"] is None
    backup_attention = next(n for n in state["needs_you"]
                            if n["title"] == "No verified off-site database backup")
    assert backup_attention["evidence"] == "never recorded"


def test_unverified_latest_company_backup_never_inherits_an_older_proof():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        older = models.BackupRun(target="company-db", started_at=datetime(2026, 10, 12, tzinfo=timezone.utc),
                                 ok=True, uploaded=True, integrity_verified=True,
                                 destination="r2://db/older", size_bytes=10, checksum="a" * 64)
        newest = models.BackupRun(target="company-db", started_at=datetime(2026, 10, 13, tzinfo=timezone.utc),
                                  ok=True, uploaded=True, integrity_verified=True,
                                  destination=None, size_bytes=None, checksum=None)
        db.add_all([older, newest])
        db.flush()
        _backup_verified_event(db, older)
        db.commit()

        state = desk.build_state(db, registry.load(), control.agents_paused(db))

    assert state["health"]["backup"]["at"] == "2026-10-13T00:00:00+00:00"
    assert state["health"]["backup"]["verified"] is False
    assert any(n["title"] == "Latest database backup is not verified off-site"
               for n in state["needs_you"])


def test_company_brief_labels_checkpoint_action_as_recorded_not_current(monkeypatch):
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "metrics", lambda _db: {
        "agent_runs_24h": 0, "agent_success_rate_24h": None, "ai_cost_24h_usd": 0.0,
        "alerts_delivered_24h": 0, "events_24h": 446,
    })
    with Session(engine) as db:
        checkpoint_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
        db.add(models.Checkpoint(actor="founder", summary="old snapshot", created_at=checkpoint_at,
                                 next_action="Founder merges PR #130"))
        db.commit()

        brief = main.company_brief(db)

        assert "Next action" not in brief
        assert "Notifications 24h 0 delivered; 446 events recorded" in brief
        assert "0 delivered / 446 events" not in brief
        at = checkpoint_at.replace(tzinfo=None).isoformat()
        assert f"Recorded checkpoint ({at}, founder): Founder merges PR #130" in brief


def test_agent_and_task_details_are_bounded_to_persistent_state():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        task = _company(db)
        specs = registry.load()
        agent = db.execute(select(models.Agent).where(models.Agent.key == "developer")).scalar_one()

        a = desk.agent_detail(db, agent, specs["developer"], control.agents_paused(db))
        t = desk.task_detail(db, task)

        assert a["identity"]["skills"] == [
            "company-state", "git", "server-health", "postgres-backup"
        ]
        assert a["recent_tasks"][0]["key"] == "TASK-0042"
        assert a["notebook"][0]["note"] == "Migration first"
        assert a["recent_learnings"][0]["title"] == "Checkout learning"
        assert t["dependencies"] == [{"key": "TASK-0041", "status": "DONE"}]
        assert t["runs"][0]["status"] == "STARTED"
        assert t["artifacts"] == {"report": "r.md"}
        # Break caught: reconciler/router work looks the same as the founder's own.
        assert t["origin"]["by"] == task.created_by and t["goal"] is None


def test_pause_is_persistent_audited_and_stops_dispatch_until_resumed():
    _, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        task = _company(db)
        task.status = enums.TaskStatus.READY
        db.commit()

        control.set_agents_paused(db, True, actor="founder", reason="maintenance")
        stopped = main.run_outer_loop(db)
        assert stopped["paused"] is True
        assert stopped["model_calls"] == 0
        assert stopped["work"] == []
        assert stopped["skipped"] == [{"task": "TASK-0042", "reason": "agents_paused"}]
        assert db.execute(select(func.count()).select_from(models.AuditLog)).scalar_one() == 2

        control.set_agents_paused(db, False, actor="founder", reason="maintenance done")
        resumed = main.run_outer_loop(db)
        assert resumed["paused"] is False
        assert resumed["work_count"] == 1


def test_command_becomes_ready_ceo_task_once_and_is_visible_in_activity():
    import pytest
    from fastapi import HTTPException
    from app import schemas

    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        out = main.founder_desk_command(
            schemas.DeskCommand(text="  youtube sorununu   araştır "), db)
        task = db.execute(select(models.Task).where(models.Task.key == out["key"])).scalar_one()
        assert task.status == enums.TaskStatus.READY
        assert task.title == "youtube sorununu araştır"
        assert db.get(models.Agent, task.assigned_agent_id).key == "ceo"
        assert task.created_by == "founder"
        # Break caught: the founder's request sits READY forever because nothing opted it in.
        from app import worker
        assert task.context["autonomous"] is True and task.objective == "youtube sorununu araştır"
        assert worker._admission_gate(db, task, registry.load())[0] is None
        dev = main.founder_desk_command(schemas.DeskCommand(text="fix the flaky goals test",
                                                            agent="developer"), db)
        dev_task = db.execute(select(models.Task).where(models.Task.key == dev["key"])).scalar_one()
        assert dev_task.context["autonomous"] is False  # code work stays attended / Stage C

        # Break caught: repeated clicks would flood the queue with identical work.
        with pytest.raises(HTTPException) as dup:
            main.founder_desk_command(schemas.DeskCommand(text="YouTube sorununu araştır"), db)
        assert dup.value.status_code == 409

        desk, control = _modules()
        state = desk.build_state(db, registry.load(), control.agents_paused(db))
        assert any(out["key"] in a["title"] for a in state["activity"])


def test_memory_view_reads_persistent_rows():
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        db.add(models.Decision(key="DEC-0001", title="Keep YouTube", decision="Do not rebuild",
                               reason="It works", approved_by="founder"))
        db.commit()
        memory = main.founder_desk_memory(db)
        assert memory["decisions"][0]["key"] == "DEC-0001"
        assert memory["learnings"][0]["title"] == "Checkout learning"
        assert memory["notes"][0]["note"] == "Migration first"
        assert "FACT-" in memory["permanent"]


def test_the_hosts_real_facts_win_and_are_never_replaced_by_the_repository_file(tmp_path, monkeypatch):
    mount = tmp_path / "company-facts"
    mount.mkdir()
    real = mount / "PERMANENT_FACTS.md"
    monkeypatch.setattr(main, "_HOST_FACTS", real)
    real.write_text("FACT-REAL: only on the host\n")
    assert main._permanent_facts() == "FACT-REAL: only on the host\n"
    real.unlink()                                                         # mount present, file missing
    assert main._permanent_facts().startswith("## Permanent facts unavailable")
    real.mkdir()                                                          # present but unreadable as a file
    assert main._permanent_facts().startswith("## Permanent facts unavailable")
    monkeypatch.setattr(main, "_HOST_FACTS", tmp_path / "no-mount" / "PERMANENT_FACTS.md")   # development: no mount
    monkeypatch.delenv("COMPANY_OS_GIT_SHA", raising=False)
    assert "FACT-" in main._permanent_facts()
    monkeypatch.setenv("COMPANY_OS_GIT_SHA", "a" * 40)                   # deployed but the mount is missing
    assert main._permanent_facts().startswith("## Permanent facts unavailable")


def test_assigning_an_owner_makes_a_ready_task_dispatchable():
    from app import schemas
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        task = _company(db)
        task.status = enums.TaskStatus.READY
        task.assigned_agent_id = None
        db.commit()
        # Break caught: an ownerless READY task is silently skipped forever.
        assert main.run_outer_loop(db)["work_count"] == 0

        main.assign_task("TASK-0042", schemas.TaskAssign(agent="developer"), db)
        assert main.run_outer_loop(db)["work"][0]["task"] == "TASK-0042"
        entry = db.execute(select(models.AuditLog).where(models.AuditLog.action == "task.assign")).scalar_one()
        assert entry.actor == "anonymous" and entry.after["client_claimed_actor"] == "founder"  # no request: no identity


def test_phase_moves_only_with_evidence_and_complete_is_founder_only():
    import pytest
    from fastapi import HTTPException
    from app import schemas
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(models.Phase(number=4, name="Agent core", status=enums.PhaseStatus.NOT_STARTED))
        db.commit()
        with pytest.raises(Exception):  # evidence is mandatory
            schemas.PhaseUpdate(status=enums.PhaseStatus.IN_PROGRESS, evidence="")
        # Break caught: an agent declaring a phase finished, or a client claiming actor="founder".
        from types import SimpleNamespace
        from app import approval_identity
        for claimed in ("developer", "founder"):
            with pytest.raises(HTTPException) as denied:  # no verified principal: authority is never the actor string
                main.update_phase(4, schemas.PhaseUpdate(status=enums.PhaseStatus.COMPLETE,
                                                         evidence="worker live", actor=claimed), db)
            assert denied.value.status_code == 401
        verified = SimpleNamespace(state=SimpleNamespace(principal=approval_identity.founder("founder@example.invalid")))
        out = main.update_phase(4, schemas.PhaseUpdate(
            status=enums.PhaseStatus.COMPLETE, evidence="Stage-B worker verified live 2026-10-01"), db, verified)
        assert out["status"] == "COMPLETE"
        assert db.execute(select(func.count()).select_from(models.AuditLog)).scalar_one() == 1


def test_agent_detail_separates_unattended_gates_from_historical_errors():
    desk, control = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        agent = db.execute(select(models.Agent).where(models.Agent.key == "research")).scalar_one()
        agent.last_error = "You've hit your session limit"
        for key, context, approval, status in (
            ("TASK-0022", None, False, enums.TaskStatus.READY),
            ("TASK-0023", {"autonomous": True, "scope": "youtube"}, True, enums.TaskStatus.READY),
            ("TASK-0100", {"autonomous": True, "scope": "youtube"}, False, enums.TaskStatus.READY),
            ("TASK-0033", None, False, enums.TaskStatus.WAITING_EXTERNAL),
            ("TASK-0101", {"autonomous": True, "scope": "youtube"}, False, enums.TaskStatus.QUEUED),
        ):
            db.add(models.Task(key=key, title=key, objective="Analyze verified evidence",
                               success_criteria="Report findings with evidence", context=context,
                               assigned_agent_id=agent.id, risk_level=enums.RiskLevel.LOW,
                               approval_required=approval, status=status))
        db.commit()
        specs = registry.load()
        before = db.execute(select(func.count()).select_from(models.AgentRun)).scalar_one()
        detail = desk.agent_detail(db, agent, specs["research"], False)
        checks = {t["task"]: t["reason"] for t in detail["unattended_tasks"]}
        assert checks == {"TASK-0022": "not_opted_in", "TASK-0023": "needs_human_gate",
                          "TASK-0100": None, "TASK-0033": "waiting_external",
                          "TASK-0101": "awaiting_ready"}
        assert detail["last_error"] == "You've hit your session limit"
        assert db.execute(select(func.count()).select_from(models.AgentRun)).scalar_one() == before
        assert all(t["reason"] == "agents_paused" for t in
                   desk.agent_detail(db, agent, specs["research"], True)["unattended_tasks"])


def test_recovered_capacity_failure_is_history_not_a_current_agent_failure():
    desk, _ = _modules()
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        agent = db.execute(select(models.Agent).where(models.Agent.key == "research")).scalar_one()
        task = models.Task(key="TASK-0100", title="Research", objective="Analyze evidence",
                           success_criteria="Report verified findings", assigned_agent_id=agent.id,
                           status=enums.TaskStatus.READY, risk_level=enums.RiskLevel.LOW,
                           context={"autonomous": True, "scope": "youtube"})
        db.add(task); db.flush()
        db.add(models.AgentRun(agent_id=agent.id, task_id=task.id,
                               status=enums.AgentRunStatus.FAILED, provider="claude",
                               error="session limit", tool_calls={"capacity_failure": True}))
        db.commit()
        detail = desk.agent_detail(db, agent, registry.load()["research"], False)
        assert detail["status"] == "SLEEPING"
        assert detail["last_error"] == "session limit"
        assert detail["unattended_tasks"][0]["reason"] is None
        # A real terminal task failure must still be visible.
        task.status = enums.TaskStatus.FAILED; db.commit()
        assert desk.agent_detail(db, agent, registry.load()["research"], False)["status"] == "FAILED"


def test_structured_command_carries_the_work_contract_and_refuses_a_mismatched_project():
    import pytest
    from fastapi import HTTPException
    from app import schemas

    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    with Session(engine) as db:
        _company(db)
        project = db.execute(select(models.Project)).scalars().first()
        unit = db.get(models.BusinessUnit, project.business_unit_id)
        goal = models.Goal(title="Seerxo revenue baseline", metric="mrr", target="verified",
                           project_id=project.id, status=enums.GoalStatus.ACTIVE)
        db.add(goal)
        db.add(models.BusinessUnit(key="other", name="Other", status=enums.BusinessUnitStatus.ACTIVE,
                                   priority=enums.Priority.P3))
        db.commit()

        out = main.founder_desk_command(schemas.DeskCommand(
            text="Polar MRR should reach the Desk", title="  Connect   Polar revenue ",
            objective="Revenue is visible", success_criteria="MRR shown with source",
            business_unit=unit.key, project=project.key, goal=goal.id, priority="P1",
            risk_level="MEDIUM"), db)
        task = db.execute(select(models.Task).where(models.Task.key == out["key"])).scalar_one()
        assert (task.title, task.objective, task.success_criteria) == (
            "Connect Polar revenue", "Revenue is visible", "MRR shown with source")
        assert (task.business_unit_id, task.project_id, task.goal_id) == (unit.id, project.id, goal.id)
        assert task.risk_level == enums.RiskLevel.MEDIUM and task.status == enums.TaskStatus.READY
        assert not (task.context or {}).get("autonomous")  # the form cannot grant autonomy

        with pytest.raises(HTTPException) as bad:
            main.founder_desk_command(schemas.DeskCommand(
                text="another request", business_unit="other", project=project.key), db)
        assert bad.value.status_code == 422

        desk, control = _modules()
        catalog = desk.build_state(db, registry.load(), control.agents_paused(db))["catalog"]
        assert {"key": project.key, "name": project.name, "business_unit": unit.key} in catalog["projects"]
        assert [g["id"] for g in catalog["goals"]] == [goal.id]
