"""Evaluator, not solver. Raw bytes + exact task identity; no correctness bit from caller.

Lean profile is deliberately tiny: only three fixed tactic bodies. Arbitrary Lean code
must be executed in a separately secured worker, NOT through this small local runner.
"""
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
from common import sha, strict_loads, finite, result
from wzorzec_zdolnosci import physics_target, genetics_target

UNITS = {"m/s": ((0,1,-1,0),1), "km/h": ((0,1,-1,0),1/3.6),
         "N": ((1,1,-2,0),1), "kN": ((1,1,-2,0),1000),
         "J": ((1,2,-2,0),1), "kJ": ((1,2,-2,0),1000),
         "C": ((0,0,1,1),1), "mC": ((0,0,1,1),.001),
         "Pa": ((1,-1,-2,0),1), "kPa": ((1,-1,-2,0),1000),
         "m": ((0,1,0,0),1), "s": ((0,0,1,0),1)}


def lean_source(case, answer):
    proof = answer.get("proof")
    if set(answer) != {"proof"} or proof not in {"by omega", "by intros; omega", "by decide"}:
        raise ValueError("PROOF_OUTSIDE_FROZEN_PROFILE")
    statement = case["input"]["statement"]
    # Header comes from evaluator's immutable task manifest, never from submitted output.
    return "import Std\ntheorem expected : (" + statement + ") := " + proof + "\n#print axioms expected\n"


def verify_lean(case, answer, lean_bin=None):
    try: source = lean_source(case, answer)
    except ValueError as e: return result("FAIL", str(e))
    exe = lean_bin or os.environ.get("BRAUN_LEAN_BIN")
    if not exe or not Path(exe).is_file(): return result("NOT_RUN", "LEAN_EXECUTABLE_MISSING")
    try:
        version = subprocess.run([exe,"--version"],capture_output=True,text=True,timeout=10)
        if version.returncode:
            return result("NOT_RUN", "LEAN_STARTUP_FAILED", version=version.stdout,stderr=version.stderr,rc=version.returncode)
        if not re.search(r"Lean \(version 4\.19\.0[,)]",version.stdout):
            return result("NOT_RUN", "TOOLCHAIN_MISMATCH", version=version.stdout)
        with tempfile.TemporaryDirectory(prefix="braun-proof-") as d:
            p = Path(d)/"Main.lean"; p.write_text(source)
            done = subprocess.run([exe,"-T","200000","-M","512",str(p)],cwd=d,
                                  capture_output=True,text=True,timeout=20,
                                  env={k:v for k,v in os.environ.items() if k not in {"LEAN_PATH", "LEAN_SRC_PATH"}})
        output = done.stdout + done.stderr
        # Only known print-axioms shape. No caller-supplied stdout can reach here.
        m = re.search(r"'expected' depends on axioms: \[([^]]*)\]", output)
        pure = "'expected' does not depend on any axioms" in output
        axioms = [a.strip() for a in m.group(1).split(",") if a.strip()] if m else []
        allowed = {"propext", "Quot.sound", "Classical.choice"}
        ok = done.returncode == 0 and (pure or bool(m)) and not(set(axioms)-allowed)
        return result("PASS" if ok else "FAIL", "LEAN_KERNEL_AND_AXIOMS" if ok else "LEAN_REJECTED",
                      axioms=axioms, source_sha256=sha(source.encode()), stdout=output, rc=done.returncode)
    except subprocess.TimeoutExpired: return result("TIMEOUT", "LEAN_BUDGET_EXCEEDED")


def evaluate(case, raw, lean_bin=None):
    if sha(case["input"]) != case["input_sha256"]: return result("INVALID_TEST", "TASK_CHANGED")
    try:
        a = strict_loads(raw)
        if not isinstance(a,dict): raise ValueError("OUTPUT_NOT_OBJECT")
        if case["domain"] == "MAT": return verify_lean(case,a,lean_bin)
        if case["domain"] == "FIZ":
            if set(a) != {"value","unit"}: raise ValueError("OUTPUT_SCHEMA")
            value = finite(a["value"]); unit = a["unit"]
            expected, target_unit = physics_target(case["input"])
            if unit not in UNITS: return result("FAIL", "UNRECOGNIZED_UNIT")
            dim,scale = UNITS[unit]; tdim,tscale = UNITS[target_unit]
            if dim != tdim: return result("FAIL", "WRONG_DIMENSION")
            ok = math.isclose(value*scale, float(expected)*tscale, rel_tol=1e-9, abs_tol=1e-10)
            return result("PASS" if ok else "FAIL", "VALUE_AND_UNIT" if ok else "WRONG_VALUE_WITH_VALID_UNIT")
        if set(a) != {"answer"}: raise ValueError("OUTPUT_SCHEMA")
        expected = genetics_target(case["input"])
        # JSON equality, avoiding bool == int and float/string coercions.
        return result("PASS" if sha(a["answer"]) == sha(expected) else "FAIL", "SEQUENCE_OR_COORDINATES")
    except (ValueError,KeyError,TypeError,ZeroDivisionError,OverflowError) as e:
        return result("FAIL", "INVALID_OUTPUT:" + str(e))


def measure(plan, rows, *, phase, artifact_sha256, descriptor_sha256, authority, lean_bin=None):
    """Evaluator-side receipt. `authority` is an injected trusted issuer, never LLM JSON."""
    tasks = {c["task_id"]: c for c in plan["tasks"]}
    if len(tasks) != len(plan["tasks"]) or not tasks: raise ValueError("INVALID_PLAN")
    by_id = {}
    for r in rows:
        if r["task_id"] not in tasks or r["task_id"] in by_id: raise ValueError("EXTRA_OR_DUPLICATE_ROW")
        if r["artifact_sha256"] != artifact_sha256: raise ValueError("WRONG_ARTIFACT")
        by_id[r["task_id"]] = r
    verdicts=[]; cost=0.; complete=True
    for tid,c in tasks.items():
        r=by_id.get(tid)
        if not r:
            verdicts.append({"task_id":tid,"family_id":c["family_id"],"status":"MISSING"}); complete=False; continue
        if r.get("cost_units") is None: complete=False
        else: cost += finite(r["cost_units"],0)
        if sha(r["raw_answer"].encode()) != r["raw_answer_sha256"]: raise ValueError("ANSWER_BYTES_MISMATCH")
        v=evaluate(c,r["raw_answer"],lean_bin)
        if v["status"] in {"NOT_RUN","INVALID_TEST"}: complete=False
        verdicts.append({"task_id":tid,"family_id":c["family_id"],**v})
    domain = {c["domain"] for c in tasks.values()}
    if len(domain)!=1: raise ValueError("NO_CROSS_DOMAIN_AVERAGE")
    successes=sum(v["status"]=="PASS" for v in verdicts)
    receipt={"schema":"braun.measurement/2", "kind":"MEASUREMENT", "phase":phase,
             "artifact_sha256":artifact_sha256,"descriptor_sha256":descriptor_sha256,
             "plan_sha256":sha(plan),"endpoint":f"{next(iter(domain))}.verified_completion/all_planned.v1",
             "unit":"fraction","direction":"higher", "source":"EXTERNAL_OUTCOME",
             "scope":plan["scope"],"sample_ids":sorted(tasks),"n":len(tasks),
             "family_ids":sorted({c["family_id"] for c in tasks.values()}),
             "numerator":successes,"denominator":len(tasks),"value":successes/len(tasks),
             "cost_units":cost if complete else None,"known_cost_lower_bound":cost,
             "status":"COMPLETE" if complete else "INCOMPLETE",
             "synthetic":True,"exposure":"PUBLIC_FIXTURE","verdicts":verdicts,
             "activation_eligible":False}
    return authority.issue(receipt)
