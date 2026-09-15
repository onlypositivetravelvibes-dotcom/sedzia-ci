#!/usr/bin/env python3
"""Pinned M14 R8 installer. Only Braun applies it on the host behind the house stop."""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

PACKAGE = Path(__file__).resolve().parent
RUNTIME = "products/quorum-brain/runtime/"
STATE = "products/quorum-brain/runtime_state/m14"
MARKER = "products/quorum-brain/feniks/state/HAKI_WYLACZONE"
LAUNCHER = "braun_boot/start_tlo.sh"
SETTINGS = ".claude/settings.json"
M13_LINE = 'krok "m13-worker"        120 "$KORZEN"  python3 products/quorum-brain/runtime/m13_worker.py --root "$KORZEN"\n'
NEXT_LINE = 'krok_mierzacy "przyrzady-p1p8"    450 "$KORZEN"  python3 braun_boot/przyrzady.py --full\n'
M14_LINE = 'krok "m14-worker"        120 "$KORZEN"  python3 products/quorum-brain/runtime/m14_worker.py --root "$KORZEN"\n'
HOOK_ENTRY = {
    "matcher": "*",
    "hooks": [{
        "type": "command", "timeout": 2,
        "command": "bash -c 'P=\"${CLAUDE_PROJECT_DIR:-.}\"; W=\"$P/.claude/hooks/wlacznik.sh\"; if [ -s \"$W\" ] && bash -n \"$W\" 2>/dev/null && [ \"$(bash \"$W\" --autotest 2>/dev/null)\" != \"\" ]; then exec bash \"$W\" Stop \"$@\"; fi; S=\"$P/products/quorum-brain/feniks/state/HAKI_WYLACZONE\"; if [ -e \"$S\" ] || [ -L \"$S\" ] || [ \"${BRAUN_HOOK:-}\" = 0 ]; then exit 0; fi; exec bash -c \"$@\"' _ \"python3 \\\"${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/m14_hak.py\\\"\""
    }],
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        mode = (path.stat().st_mode & 0o7777) if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def stage(path: Path, data: bytes, mode: int, transaction_id: str) -> Path:
    """Create one durable, non-visible stage file; never replace the target here."""
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.parent / ("." + path.name + ".m14-stage-" + transaction_id)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(staged, flags, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    return staged


def _record(root: Path) -> tuple[Path, dict | None]:
    path = root / STATE / "install.json"
    if not path.is_file():
        return path, None
    try:
        value = json.loads(path.read_text())
    except Exception as exc:
        raise ValueError("INSTALL_RECORD_CORRUPT") from exc
    if value.get("schema") not in {"m14.install/1", "m14.install/2", "m14.install/3"}:
        raise ValueError("INSTALL_RECORD_CORRUPT")
    return path, value


def _staged_path(root: Path, value: str, target_value: str) -> Path:
    if not isinstance(value, str):
        raise ValueError("INSTALL_RECORD_CORRUPT")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("INSTALL_RECORD_CORRUPT")
    path = root / relative
    target = root / target_value
    expected_prefix = "." + target.name + ".m14-stage-"
    if path.parent != target.parent or not path.name.startswith(expected_prefix):
        raise ValueError("INSTALL_RECORD_CORRUPT")
    return path


def _write_record(path: Path, record: dict) -> None:
    atomic(path, json.dumps(record, sort_keys=True, indent=2).encode() + b"\n")


def _record_digest(record: dict) -> str:
    return sha(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())


def _record_matches(root: Path, record: dict) -> bool:
    return all(
        (root / path).is_file() and not (root / path).is_symlink()
        and sha((root / path).read_bytes()) == digest
        for path, digest in record.get("after_sha256", {}).items()
    )


def _rollback_marker_matches(root: Path, record: dict) -> bool:
    history = root / STATE / "rollback_history"
    digest = _record_digest(record)
    if not history.is_dir():
        return False
    for path in history.glob("*.json"):
        try:
            if json.loads(path.read_text()).get("restored_parent_sha256") == digest:
                return True
        except Exception:
            continue
    return False


def _rollback_transaction(root: Path, record: dict) -> None:
    """Restore both committed targets and uncommitted stages after an interrupted apply."""
    for path, expected in record["after_sha256"].items():
        target = root / path
        encoded = record["before"][path]
        before = base64.b64decode(encoded) if encoded is not None else None
        staged_value = record.get("staged", {}).get(path)
        staged = _staged_path(root, staged_value, path) if staged_value else None
        if staged is not None and (staged.exists() or staged.is_symlink()):
            if not staged.is_file() or staged.is_symlink() or sha(staged.read_bytes()) != expected:
                raise ValueError("ROLLBACK_DRIFT:" + staged_value)
        if target.exists() or target.is_symlink():
            if not target.is_file() or target.is_symlink():
                raise ValueError("ROLLBACK_DRIFT:" + path)
            current = target.read_bytes()
            if sha(current) == expected:
                if before is None:
                    target.unlink()
                else:
                    atomic(target, before, record.get("before_mode", {}).get(path))
            elif before is None or current != before:
                raise ValueError("ROLLBACK_DRIFT:" + path)
        elif before is not None:
            raise ValueError("ROLLBACK_DRIFT:" + path)
        if staged is not None and staged.exists():
            staged.unlink()


@contextlib.contextmanager
def install_lock(root: Path):
    """Serialize check/write sequences without weakening pin or house-stop checks."""
    path = root / STATE / "install.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _span(text: str, start: int, wanted: str):
    decoder = json.JSONDecoder(); i = start + 1
    while True:
        while text[i] in " \t\r\n": i += 1
        if text[i] == "}": raise ValueError("SETTINGS_MEMBER_MISSING:" + wanted)
        key, i = decoder.raw_decode(text, i)
        while text[i] in " \t\r\n": i += 1
        if text[i] != ":": raise ValueError("SETTINGS_SYNTAX")
        i += 1
        while text[i] in " \t\r\n": i += 1
        value_start = i; _, i = decoder.raw_decode(text, i)
        if key == wanted: return value_start, i
        while text[i] in " \t\r\n": i += 1
        if text[i] == ",": i += 1


def patch_settings(data: bytes) -> bytes:
    text = data.decode("utf-8")
    parsed = json.loads(text)
    stop = parsed.get("hooks", {}).get("Stop")
    if not isinstance(stop, list) or len(stop) != 6:
        raise ValueError("STOP_GROUP_COUNT_DRIFT")
    if "m14_hak.py" in text:
        raise ValueError("DUPLICATE_M14_HOOK")
    hooks_start, _ = _span(text, len(text) - len(text.lstrip()), "hooks")
    _, stop_end = _span(text, hooks_start, "Stop")
    insert = ("," if stop else "") + json.dumps(HOOK_ENTRY, ensure_ascii=False, separators=(",", ":"))
    updated = text[:stop_end - 1] + insert + text[stop_end - 1:]
    expected = json.loads(data); expected["hooks"]["Stop"].append(HOOK_ENTRY)
    if json.loads(updated) != expected:
        raise ValueError("SETTINGS_STRUCTURE_CHANGED")
    return updated.encode()


def patch_launcher(data: bytes) -> bytes:
    text = data.decode("utf-8")
    anchor = M13_LINE + "\n" + NEXT_LINE
    if text.count(anchor) != 1 or "m14-worker" in text:
        raise ValueError("LAUNCHER_ANCHOR_OR_DUPLICATE")
    return text.replace(anchor, M13_LINE + M14_LINE + "\n" + NEXT_LINE).encode()


def targets() -> dict[str, bytes]:
    result = {}
    for source in sorted((PACKAGE / "src").glob("*.py")):
        target = ".claude/hooks/m14_hak.py" if source.name == "m14_hak.py" else RUNTIME + source.name
        result[target] = source.read_bytes()
    return result


def inspect(root: Path) -> dict:
    contract = json.loads((PACKAGE / "KONTRAKT_R1.json").read_text())
    holds, changes = [], {}
    install_record = root / STATE / "install.json"
    active_record = None
    active_matches = False
    if install_record.is_file():
        try:
            _, rec = _record(root)
            if rec and not rec.get("rolled_back"):
                active_record = rec
                active_matches = _record_matches(root, rec)
                if not active_matches:
                    holds.append("INSTALL_INCOMPLETE")
        except ValueError as exc:
            holds.append(str(exc))
    if active_record is None:
        for path, expected in contract["host_pins"].items():
            p = root / path
            if not p.is_file() or p.is_symlink() or sha(p.read_bytes()) != expected:
                holds.append("PIN_MISSING_OR_DRIFT:" + path)
    for path, content in targets().items():
        p = root / path
        if p.exists() or p.is_symlink():
            if active_record is None:
                holds.append("NEW_TARGET_EXISTS:" + path)
            elif not p.is_file() or p.is_symlink():
                holds.append("NEW_TARGET_CONFLICT:" + path)
            elif active_matches and sha(p.read_bytes()) != sha(content):
                changes[path] = content
        else:
            changes[path] = content
        for staged in p.parent.glob("." + p.name + ".m14-stage-*"):
            if active_record is None:
                holds.append("NEW_TARGET_EXISTS:" + str(staged.relative_to(root)))
    if active_record is None:
        launcher, settings = root / LAUNCHER, root / SETTINGS
        if launcher.is_file() and sha(launcher.read_bytes()) == contract["host_pins"][LAUNCHER]:
            try: changes[LAUNCHER] = patch_launcher(launcher.read_bytes())
            except Exception as exc: holds.append(str(exc))
        if settings.is_file() and sha(settings.read_bytes()) == contract["host_pins"][SETTINGS]:
            try: changes[SETTINGS] = patch_settings(settings.read_bytes())
            except Exception as exc: holds.append(str(exc))
    if not holds and active_record is not None and not changes:
        return {"state": "INSTALLED", "holds": [], "changes": {}, "mode": "DIAGNOSTIC_ONLY"}
    state = "HOLD" if holds else ("READY_UPGRADE" if active_record is not None else "READY")
    return {"state": state, "holds": holds, "changes": changes, "mode": "DIAGNOSTIC_ONLY", "parent_record": active_record if state == "READY_UPGRADE" else None}


def apply(root: Path) -> dict:
    marker = root / MARKER
    if not (marker.exists() or marker.is_symlink()):
        raise ValueError("HOUSE_STOP_REQUIRED")
    with install_lock(root):
        plan = inspect(root)
        if plan["state"] == "INSTALLED":
            return {"state": "INSTALL_ALREADY_RECORDED", "mode": "DIAGNOSTIC_ONLY", "changed": False}
        if plan["state"] not in {"READY", "READY_UPGRADE"}:
            raise ValueError("INSTALL_NOT_READY:" + plan["state"])
        before, before_mode = {}, {}
        for path, after in plan["changes"].items():
            p = root / path
            before[path] = base64.b64encode(p.read_bytes()).decode() if p.exists() else None
            before_mode[path] = (p.stat().st_mode & 0o7777) if p.exists() else None
        state = root / STATE / "install.json"
        transaction_id = secrets.token_hex(8)
        staged = {
            path: str(((root / path).parent / ("." + (root / path).name + ".m14-stage-" + transaction_id)).relative_to(root))
            for path in plan["changes"]
        }
        record = {
            "schema": "m14.install/3", "package_generation": "M14-R8", "transaction_id": transaction_id, "phase": "PREPARED",
            "before": before, "before_mode": before_mode, "staged": staged,
            "after_sha256": {p: sha(v) for p, v in plan["changes"].items()}, "rolled_back": False,
            "parent_record": plan.get("parent_record"),
        }
        _write_record(state, record)
        for path, content in plan["changes"].items():
            p = root / path
            if path in {LAUNCHER, SETTINGS}:
                expected = json.loads((PACKAGE / "KONTRAKT_R1.json").read_text())["host_pins"][path]
                if sha(p.read_bytes()) != expected: raise ValueError("PIN_DRIFT_DURING_APPLY:" + path)
            mode = before_mode[path] if before_mode[path] is not None else 0o600
            actual = stage(p, content, mode, transaction_id)
            if str(actual.relative_to(root)) != staged[path]: raise ValueError("STAGE_PATH_MISMATCH")
        record["phase"] = "STAGED"
        _write_record(state, record)
        for path in plan["changes"]:
            p = root / path
            encoded = before[path]
            if encoded is None:
                if p.exists() or p.is_symlink(): raise ValueError("NEW_TARGET_EXISTS:" + path)
            elif not p.is_file() or p.is_symlink() or p.read_bytes() != base64.b64decode(encoded):
                raise ValueError("PIN_DRIFT_DURING_APPLY:" + path)
        for path in plan["changes"]:
            os.replace(_staged_path(root, staged[path], path), root / path)
        record["phase"] = "COMMITTED"
        _write_record(state, record)
        return {"state": "APPLIED", "mode": "DIAGNOSTIC_ONLY", "changed": sorted(plan["changes"])}


def rollback(root: Path) -> dict:
    marker = root / MARKER
    if not (marker.exists() or marker.is_symlink()): raise ValueError("HOUSE_STOP_REQUIRED")
    with install_lock(root):
        state, rec = _record(root)
        if rec is None:
            return {"state": "NOTHING_INSTALLED", "changed": False}
        if rec.get("rolled_back"):
            return {"state": "ALREADY_ROLLED_BACK", "changed": False}
        if rec.get("package_generation") != "M14-R8" and _rollback_marker_matches(root, rec):
            return {"state": "ALREADY_ROLLED_BACK", "changed": False}
        _rollback_transaction(root, rec)
        parent = rec.get("parent_record")
        if isinstance(parent, dict):
            marker = root / STATE / "rollback_history" / (rec.get("transaction_id", "unknown") + ".json")
            atomic(marker, json.dumps({"schema": "m14.rollback/1", "transaction_id": rec.get("transaction_id"), "restored_parent_sha256": _record_digest(parent)}, sort_keys=True, indent=2).encode() + b"\n", 0o600)
            _write_record(state, parent)
            return {"state": "ROLLED_BACK_TO_PARENT", "changed": True, "restored": sorted(rec["before"])}
        rec["rolled_back"] = True
        rec["phase"] = "ROLLED_BACK"
        _write_record(state, rec)
        return {"state": "ROLLED_BACK", "changed": True, "restored": sorted(rec["before"])}


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("action", choices=("check", "apply", "rollback")); ap.add_argument("--root", required=True); args = ap.parse_args()
    root = Path(args.root).resolve()
    try:
        result = inspect(root) if args.action == "check" else (apply(root) if args.action == "apply" else rollback(root))
    except Exception as exc:
        result = {"state": "HOLD", "reason": str(exc)}
    serializable = dict(result); serializable.pop("changes", None)
    print(json.dumps(serializable, ensure_ascii=False, sort_keys=True))
    return 0 if result["state"] in {"READY", "READY_UPGRADE", "INSTALLED", "APPLIED", "INSTALL_ALREADY_RECORDED", "ROLLED_BACK", "ROLLED_BACK_TO_PARENT", "NOTHING_INSTALLED", "ALREADY_ROLLED_BACK"} else 2


if __name__ == "__main__": raise SystemExit(main())
