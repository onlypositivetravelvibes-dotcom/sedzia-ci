#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Port `measure:*` dla modułu 14 — PRAWDZIWY pomiar zdolności wykonawcy (Z3 Astry, `braun.measurement/2`, 08.09.2026).

Weryfikator = ZAMROŻONY `zdolnosci.py` Astry (import z jej paczki, nie kopia — żeby nie było drugiego egzemplarza).
Zadania = jej 72 (ziarno 8092026, PUBLIC_FIXTURE). Odpowiedzi = plik wykonawcy (Braun liczył w głowie, bez kodu).
Wystawca receiptów = `WystawcaLokalny` (dysk, jedna domena kontroli — jawnie). Koszt nieobserwowany ⇒ `cost_units=None`
⇒ receipt INCOMPLETE; nie wymyślamy kosztu. MAT tylko z działającym Lean 4.19.0 (inaczej NOT_RUN ⇒ INCOMPLETE).
"""
from __future__ import annotations
import argparse, glob, hashlib, json, os, sys, time
TU = os.path.dirname(os.path.abspath(__file__))
KORZEN = os.environ.get("CLAUDE_PROJECT_DIR", os.path.abspath(os.path.join(TU, "..", "..", "..")))
PACZKA = os.path.join(KORZEN, "products/quorum-brain/koncept/astra_Z1Z6_0809/ASTRA_Z1_Z6_20260908")
RS = os.path.join(KORZEN, "products/quorum-brain/runtime_state")
RECEIPTS = os.path.join(RS, "measurements", "receipts")
sys.path.insert(0, os.path.join(PACZKA, "src")); sys.path.insert(0, TU)
import zdolnosci_adapter as Z      # noqa: E402  — zamrożony weryfikator Astry + adaptacja flag Lean
from common import sha             # noqa: E402


def lean_bin() -> str | None:
    p = os.environ.get("BRAUN_LEAN_BIN")
    if p and os.path.isfile(p):
        return p
    for c in glob.glob(os.path.expanduser("~/.elan/toolchains/*4.19.0*/bin/lean")):
        return c
    return None


def _sha_pliku(p: str) -> str | None:
    try:
        return hashlib.sha256(open(p, "rb").read()).hexdigest()
    except OSError:
        return None


def code_sha() -> str:
    h = hashlib.sha256()
    for f in sorted(glob.glob(os.path.join(TU, "*.py"))):
        if os.path.basename(f).startswith("test_"):
            continue
        h.update(os.path.basename(f).encode()); h.update(open(f, "rb").read())
    return h.hexdigest()


class WystawcaLokalny:
    """Port wystawcy: zapisuje receipt na dysk pod ref `measure:<sha>`. JEDNA domena kontroli (ten kontener) — nie udaje niezależnego audytora."""
    def __init__(self, katalog: str = RECEIPTS):
        self.katalog = katalog; os.makedirs(katalog, exist_ok=True)

    def issue(self, body: dict) -> dict:
        body = dict(body, issuer="WystawcaLokalny/kontener-lokalny", control_domain="kontener-lokalny")
        ref = "measure:" + sha(body)
        body = dict(body, issued_at=time.time())
        with open(os.path.join(self.katalog, ref.split(":", 1)[1] + ".json"), "w", encoding="utf-8") as f:
            json.dump({"ref": ref, "body": body}, f, ensure_ascii=False, indent=1, sort_keys=True)
        return {"ref": ref, "body": body}


def tasks(domain: str) -> list:
    return [json.loads(l) for l in open(os.path.join(PACZKA, "data", f"{domain}_tasks.jsonl"), encoding="utf-8") if l.strip()]


MAT_PROCEDURA = {"id": "procedure:linear-omega-v1", "proof": "by intros; omega"}


def rows_z_odpowiedzi(domain: str, odpowiedzi: dict, artifact: str, cost=None, mat_procedura: bool = False, billing_group: str | None = None) -> list:
    """Wiersze do pomiaru. Producent odpowiedzi jest JAWNY (§2.3.3 Astry): FIZ/GEN = plik wykonawcy; MAT = STAŁA PROCEDURA
    `linear-omega-v1` tylko gdy `mat_procedura=True` — jej sukces przypisuje się procedurze, nie 24 dowodom modelu. Pusty plik
    odpowiedzi nie produkuje wierszy MAT. Koszt (§17.6): `cost_units` per wiersz to ALLOCATED_ESTIMATE z jednej grupy naliczenia
    (`billing_group_id`), której suma jest liczona RAZ; nie jest to pomiar per zadanie."""
    out = []
    for c in tasks(domain):
        a = odpowiedzi.get(c["task_id"])
        podana = isinstance(a, dict) and bool(a) and (domain != "MAT" or (isinstance(a.get("proof"), str) and a["proof"].strip()))   # K05: obecność klucza ≠ odpowiedź; null/pusta = BRAK
        if domain == "MAT":
            if podana:
                producent = "executor-file"
            elif mat_procedura:
                a = {"proof": MAT_PROCEDURA["proof"]}; producent = MAT_PROCEDURA["id"]     # generator TYLKO z jawnej flagi, z własnym producentem
            else:
                continue                                        # brak/niepoprawna odpowiedź = MISSING w mianowniku (nie fabrykuję)
        else:
            producent = "executor-file"
            if not podana:
                continue                                        # brak odpowiedzi = MISSING w mianowniku (nie fabrykuję)
        raw = json.dumps(a, ensure_ascii=False, sort_keys=True)
        row = {"task_id": c["task_id"], "artifact_sha256": artifact, "raw_answer": raw, "raw_answer_sha256": sha(raw.encode()), "cost_units": cost, "producer": producent}
        if cost is not None:
            row.update(cost_kind="ALLOCATED_ESTIMATE", billing_group_id=billing_group)
        out.append(row)
    return out


def zmierz(domain: str, rows: list, phase: str, artifact: str, generation: str, wystawca=None, lean=None) -> dict:
    plan = {"tasks": tasks(domain), "scope": f"{domain}.closed_tasks.astra_8092026", "generation": generation}
    desc = sha({"artifact": artifact, "generation": generation, "plan": sha(plan), "purpose": "BRAUN_EXECUTOR_REAL_ANSWERS"})
    rec = Z.measure(plan, rows, phase=phase, artifact_sha256=artifact, descriptor_sha256=desc, authority=wystawca or WystawcaLokalny(), lean_bin=lean)
    rec["body"].setdefault("generation", generation)
    return {"plan_sha256": sha(plan), "descriptor_sha256": desc, "rows": rows, "receipt": rec}


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--odpowiedzi", required=True); ap.add_argument("--phase", default="BEFORE")
    ap.add_argument("--generation", default=None); ap.add_argument("--out", required=True)
    ap.add_argument("--koszt", default=None, help="JSON z koszt_obserwator.py (koszt tury produkującej odpowiedzi FIZ/GEN; MAT bez kosztu)")
    ap.add_argument("--mat-procedura", action="store_true", help="MAT: użyj STAŁEJ procedury linear-omega-v1 (sukces = procedury, nie modelu)")
    a = ap.parse_args()
    koszt = json.load(open(a.koszt, encoding="utf-8")).get("koszt") if a.koszt else None
    per_row = koszt.get("cost_per_row") if isinstance(koszt, dict) else None
    odp = json.load(open(a.odpowiedzi, encoding="utf-8")); art = code_sha(); gen = a.generation or f"R-code:{art[:12]}"
    os.makedirs(a.out, exist_ok=True); lean = lean_bin(); podsum = []
    for d in ("FIZ", "GEN", "MAT"):
        rows = rows_z_odpowiedzi(d, odp.get(d, {}) if isinstance(odp.get(d), dict) else {}, art, cost=(per_row if d != "MAT" else None),
                                 mat_procedura=a.mat_procedura, billing_group=(koszt or {}).get("msg_id"))
        w = zmierz(d, rows, a.phase, art, gen, lean=lean); b = w["receipt"]["body"]
        w["execution_receipt"] = {"executor": "Braun (model sesji, odpowiedzi w głowie)" if d != "MAT" else ("executor-file" if any(r["producer"] == "executor-file" for r in rows) else MAT_PROCEDURA["id"]),
                                  "verifier_sha256": _sha_pliku(os.path.join(PACZKA, "src", "zdolnosci.py")), "adapter_sha256": _sha_pliku(os.path.join(TU, "zdolnosci_adapter.py")),
                                  "toolchain": ("Lean 4.19.0 core-only, flagi: -DmaxHeartbeats=200000" if d == "MAT" else None), "plan_sha256": w["plan_sha256"], "runtime_code_sha256": art}
        if per_row is not None and d != "MAT":
            w["cost_observation"] = dict(koszt, cost_kind="ALLOCATED_ESTIMATE", billing_group_counted_once=True, note="suma alokacji = koszt grupy; nie pomiar per zadanie (§17.6 Astry)")
        json.dump(w, open(os.path.join(a.out, f"POMIAR_{d}.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, sort_keys=True)
        zle = [v["task_id"] + ":" + v["status"] + ":" + str(v.get("reason")) for v in b["verdicts"] if v["status"] != "PASS"]
        podsum.append({"domain": d, "ref": w["receipt"]["ref"], "value": b["value"], "numerator": b["numerator"], "denominator": b["denominator"],
                       "status": b["status"], "cost_units": b["cost_units"], "activation_eligible": b["activation_eligible"], "nie_PASS": zle[:30],
                       "lean": lean if d == "MAT" else None})
    json.dump({"scope": "REAL_EXECUTOR_ANSWERS_PUBLIC_FIXTURE_ONE_CONTROL_DOMAIN", "artifact_sha256": art, "generation": gen, "phase": a.phase,
               "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "domeny": podsum},
              open(os.path.join(a.out, "PODSUMOWANIE.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(podsum, ensure_ascii=False, indent=1)); return 0


if __name__ == "__main__":
    sys.exit(main())


# ───────────────────────── 09.09.2026 — POMIAR UKRYTY: solver WYKONANY z bajtów generacji, koszt OBSERWOWANY per zadanie
HOLDOUT = os.path.join(RS, "measurements", "holdout")
WORK_EXEC = os.path.join(RS, "work", "exec")
CENNIK_CPU_US = {"GEN": 20_000, "FIZ": 20_000, "MAT": 5_000_000, "COL": 50_000}     # PRZYDZIAŁ zasobu per zadanie (µs CPU) — nie cennik pieniężny, nie dowód górnej granicy
DOMENY_WLASNE = ("COL",)     # domeny z WŁASNYM zamrożonym weryfikatorem (nie zdolnosci.py Astry): COL = kolatz_weryfikator


class WystawcaUkryty(WystawcaLokalny):
    """Wystawca receiptu pomiaru na ODŁOŻONYM zbiorze. Zamrożony `measure()` Astry wpisuje `PUBLIC_FIXTURE`/`activation_eligible=False`,
    bo jej plan pochodzi z publicznej paczki; TU o ekspozycji wie WYSTAWCA (wie, skąd jest plan) i podpisuje ją osobnymi OSIAMI (§5 Astry,
    09.09): relacja rodzin, czy przykłady służyły do dopasowania kandydata, dostęp wykonawcy do ziarna, izolacja golda i weryfikatora.
    Etykieta: `HELD_OUT_SAME_FAMILIES` — ten sam generator, inne ziarno; NIE „ukryty ewaluator". Jedna domena kontroli (ten kontener)."""
    def __init__(self, katalog: str = RECEIPTS, *, effect_receipt: str, generation: str, exposure_axes: dict, cost_scope: dict, new_critical_errors=None):
        super().__init__(katalog); self.e, self.g, self.ax, self.cs, self.nce = effect_receipt, generation, exposure_axes, cost_scope, new_critical_errors

    def issue(self, body: dict) -> dict:
        body = dict(body, exposure="HELD_OUT_SAME_FAMILIES", activation_eligible=True, exposure_axes=self.ax, effect_receipt=self.e, generation=self.g,
                    cost_kind="OBSERVED_CPU_US_SOLVE", cost_scope=self.cs, new_critical_errors=self.nce,
                    exposure_note="ten sam generator, inne ziarno; dostęp kandydata do ziarna NIE odcięty (ten sam użytkownik); weryfikator w osobnym procesie od kandydata")
        return super().issue(body)


class WystawcaKosztuCPU:
    """Wystawca ROZLICZENIA kosztu CPU wykonania (S01–S04 Astry: księga przyjmuje DOKUMENT wystawcy, nie liczbę callera). Klucz w pliku
    `runtime_state/budzet/wystawca_cpu.key` (0600); rejestruje go w księdze WŁAŚCICIEL cyklu (`Budzet.zaufaj_wystawcy`), nie sam wystawca.
    Jedna domena kontroli (nadzorca pomiaru = wystawca; kandydat biegnie w osobnym procesie bez dostępu do klucza przez env — plik nadal
    czytelny dla tego samego użytkownika) — zapisane, nie ukryte. `evidence_sha256` = sha skutku wykonania."""
    PRINCIPAL = "wykonawca-lokalny-cpu"

    def __init__(self, plik: str | None = None):
        self.plik = plik or os.path.join(RS, "budzet", "wystawca_cpu.key"); os.makedirs(os.path.dirname(self.plik), exist_ok=True)
        if not os.path.isfile(self.plik):
            import secrets
            with open(self.plik, "w") as f:
                f.write(secrets.token_hex(32))
            os.chmod(self.plik, 0o600)
        self.key_hex = open(self.plik).read().strip()

    def zaufaj(self, budzet, dodal: str) -> dict:
        return budzet.zaufaj_wystawcy(self.PRINCIPAL, self.key_hex, dodal)

    def oswiadczenie(self, exec_id: str, cpu_us: int, effect_sha256: str, waluta: str = "CPU_US") -> dict:
        import budzet as B
        return B.Budzet.podpisz_rozliczenie({"source": "provider-statement", "issuer_principal": self.PRINCIPAL, "statement_id": f"cpu:{exec_id}", "provider_request_id": exec_id,
                                             "final": True, "currency": waluta, "amount_microunits": int(cpu_us), "billing_status": "BILLED" if cpu_us else "NO_CHARGE",
                                             "evidence_sha256": effect_sha256}, self.key_hex)


def ziarno_holdoutu(domain: str) -> dict:
    """Ziarno ukrytego zbioru: tworzone RAZ z os.urandom, potem stałe (żeby PRZED/SHADOW/PO mierzyły TEN SAM zbiór)."""
    os.makedirs(HOLDOUT, exist_ok=True); p = os.path.join(HOLDOUT, f"{domain}.json")
    if os.path.isfile(p):
        return json.load(open(p, encoding="utf-8"))
    import secrets
    z = {"domain": domain, "seed": secrets.randbelow(2**31 - 1) + 1, "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "zrodlo": "os.urandom via secrets"}
    json.dump(z, open(p, "w", encoding="utf-8"), indent=1); return z


def zadania_ukryte(domain: str, seed: int) -> list:
    if domain == "COL":
        import kolatz_fixtures as KF
        return KF.generate(seed, split="HELD_OUT")                     # transfer: NOWE rodziny (j=6,7), nie inne liczby z przećwiczonych
    import fixtures_zdolnosci as F
    return [c for c in F.generate(seed) if c["domain"] == domain]


def zadania_publiczne(domain: str) -> list:
    """Zbiór ROZWOJOWY (incydenty, użycie): GEN/FIZ/MAT = 72 zadania Astry (ziarno 8092026); COL = LEARN (j=3,4,5)."""
    if domain == "COL":
        import kolatz_fixtures as KF
        return KF.generate(split="LEARN")
    import fixtures_zdolnosci as F
    return [c for c in F.generate() if c["domain"] == domain]


def weryfikator(domain: str):
    """(evaluate, scorer_sha256) — zamrożony sędzia domeny. Kandydat nigdy nie dostaje tego obiektu (biegnie w osobnym procesie)."""
    if domain == "COL":
        import kolatz_weryfikator as KW
        return KW.evaluate, KW.sha_weryfikatora()
    import uczenie_porty as UP
    return Z.evaluate, UP._SCORER_SHA


def measure_generic(plan: dict, rows: list, *, phase: str, artifact_sha256: str, descriptor_sha256: str, authority, evaluate_fn, scorer_sha256: str, lean_bin=None) -> dict:
    """Pomiar w schemacie `braun.measurement/2` Astry (te same pola i reguły co jej `measure`), z wtykanym weryfikatorem i jego sha.
    Dla GEN/FIZ/MAT nadal woła się jej zamrożone `Z.measure`; to jest dla domen własnych (COL)."""
    tasks = {c["task_id"]: c for c in plan["tasks"]}
    if len(tasks) != len(plan["tasks"]) or not tasks:
        raise ValueError("INVALID_PLAN")
    by_id = {}
    for r in rows:
        if r["task_id"] not in tasks or r["task_id"] in by_id:
            raise ValueError("EXTRA_OR_DUPLICATE_ROW")
        if r["artifact_sha256"] != artifact_sha256:
            raise ValueError("WRONG_ARTIFACT")
        by_id[r["task_id"]] = r
    verdicts, cost, complete = [], 0.0, True
    for tid, c in tasks.items():
        r = by_id.get(tid)
        if not r:
            verdicts.append({"task_id": tid, "family_id": c["family_id"], "status": "MISSING"}); complete = False; continue
        if r.get("cost_units") is None:
            complete = False
        else:
            cost += float(r["cost_units"])
        if sha(r["raw_answer"].encode()) != r["raw_answer_sha256"]:
            raise ValueError("ANSWER_BYTES_MISMATCH")
        v = evaluate_fn(c, r["raw_answer"], lean_bin)
        if v["status"] in {"NOT_RUN", "INVALID_TEST"}:
            complete = False
        verdicts.append({"task_id": tid, "family_id": c["family_id"], **v})
    domain = {c["domain"] for c in tasks.values()}
    if len(domain) != 1:
        raise ValueError("NO_CROSS_DOMAIN_AVERAGE")
    succ = sum(v["status"] == "PASS" for v in verdicts)
    receipt = {"schema": "braun.measurement/2", "kind": "MEASUREMENT", "phase": phase, "artifact_sha256": artifact_sha256, "descriptor_sha256": descriptor_sha256,
               "plan_sha256": sha(plan), "endpoint": f"{next(iter(domain))}.verified_completion/all_planned.v1", "unit": "fraction", "direction": "higher", "source": "EXTERNAL_OUTCOME",
               "scope": plan["scope"], "sample_ids": sorted(tasks), "n": len(tasks), "family_ids": sorted({c["family_id"] for c in tasks.values()}),
               "numerator": succ, "denominator": len(tasks), "value": succ / len(tasks), "cost_units": cost if complete else None, "known_cost_lower_bound": cost,
               "status": "COMPLETE" if complete else "INCOMPLETE", "synthetic": True, "exposure": "PUBLIC_FIXTURE", "verdicts": verdicts, "activation_eligible": False,
               "scorer_sha256": scorer_sha256, "scorer": "kolatz_weryfikator" if next(iter(domain)) == "COL" else "zdolnosci"}
    return authority.issue(receipt)


def plan_ukryty(domain: str, seed: int, scope: str) -> dict:
    """Plan BEZ generacji — ten sam plan (frontier_sha) dla PRZED/SHADOW/PO, inaczej moduł 14 słusznie mówi INCOMPARABLE."""
    return {"tasks": zadania_ukryte(domain, seed), "scope": scope, "holdout_seed_sha256": sha(str(seed).encode())}


def zaladuj_solver(sciezka: str):
    """UWAGA (ZP02): ładuje kandydata W TYM procesie — tylko do narzędzi zaufanych (nie do kandydatów). Pomiar i użycie idą przez `wykonawca.py`."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("solver_wykonywany_" + hashlib.sha256(sciezka.encode()).hexdigest()[:8], sciezka)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def wykonaj_i_zmierz(domain: str, generation: str, artifact_path: str, phase: str, scope: str, *, operation_id: str, attempt_id: str,
                     budzet=None, root_task_id: str | None = None, grant_ref: str | None = None, lean=None, regresja_z: dict | None = None,
                     cpu_allowance_us: int | None = None) -> dict:
    """WYKONUJE kandydata z `artifact_path` (bajty generacji) na odłożonym zbiorze — w IZOLOWANYM DZIECKU (`wykonawca.py`, ZP01/ZP02):
    weryfikator, gold, klucz wystawcy i księga zostają u nadzorcy. Koszt: `cpu_us_solve` per zadanie (dziecko) OSOBNO od `cpu_us_job`/`wall_ms_job`
    całego wykonawcy z importem (nadzorca, ZP05) — do księgi idzie KOSZT CAŁEGO ZADANIA. Skutek `exec:<id>` = bajty artefaktu + produktu.
    `regresja_z` = verdicts pomiaru PRZED ⇒ `new_critical_errors` (było PASS, jest nie-PASS). `cpu_allowance_us` = PRZYDZIAŁ zasobu
    per zadanie (nie cennik pieniężny, nie dowód górnej granicy) — domyślnie z `CENNIK_CPU_US`."""
    import wykonawca as W
    z = ziarno_holdoutu(domain); plan = plan_ukryty(domain, z["seed"], scope); art = _sha_pliku(artifact_path)
    if art is None:
        raise FileNotFoundError(artifact_path)
    n = len(plan["tasks"]); przydzial = cpu_allowance_us if cpu_allowance_us is not None else CENNIK_CPU_US[domain]; bound = n * przydzial
    exec_id = f"{operation_id}--{attempt_id}"; katalog = os.path.join(WORK_EXEC, exec_id)
    desc = sha({"artifact": art, "plan": sha(plan), "phase": phase, "purpose": "HELD_OUT_EXECUTION", "generation": generation})
    if os.path.isfile(os.path.join(katalog, "effect.json")):                                   # ZP04: ten sam exec_id = ten sam deskryptor albo konflikt
        stary = json.load(open(os.path.join(katalog, "effect.json"), encoding="utf-8"))
        if stary.get("descriptor_sha256") != desc:
            return {"status": "EXEC_ID_CONFLICT", "exec_id": exec_id, "why": "istnieje skutek o tym samym id z INNYM deskryptorem — nie nadpisuję produktu"}
        return {"status": "EXISTS", "exec_id": exec_id, "effect_receipt": f"exec:{exec_id}", "why": "ten sam deskryptor — wynik już istnieje, nie wykonuję drugi raz"}
    os.makedirs(katalog, exist_ok=True); rez = None
    if budzet is not None:
        rez = budzet.reserve(root_task_id, attempt_id, f"{exec_id}:call", bound, grant_ref)
        if rez.get("decision") not in ("RESERVED", "EXISTS"):
            return {"status": "REFUSED_BY_BUDGET", "reservation": rez, "bound": bound}
        d = budzet.dispatch_once(rez["reservation_id"], desc)
        if d.get("decision") != "DISPATCH":
            return {"status": "REFUSED_AT_DISPATCH", "dispatch": d, "reservation": rez}
        wiaz = budzet.running(rez["reservation_id"], exec_id, d.get("dispatch_token"), binding_evidence_sha256=desc)   # dispatcher (ten proces) wiąże ID z tokenem
        if wiaz.get("decision") != "BOUND":
            return {"status": "REFUSED_AT_BINDING", "binding": wiaz, "reservation": rez}
    wyk = W.wykonaj(artifact_path, [{"id": c["task_id"], "input": c["input"]} for c in plan["tasks"]], os.path.join(katalog, "proba"),
                    cpu_limit_s=max(2, bound // 1_000_000 + 2), wall_s=120.0)
    odpowiedzi = wyk.get("answers") or {}; koszty = {k: int(v) for k, v in (wyk.get("cpu_us_solve") or {}).items()}
    prod = os.path.join(katalog, "odpowiedzi.json")
    with open(prod, "x", encoding="utf-8") as f:                                              # 'x': produkt niezmienny, nigdy nadpisany (ZP04)
        json.dump(odpowiedzi, f, ensure_ascii=False, sort_keys=True, indent=1)
    suma_solve = sum(koszty.values()); cpu_job = int(wyk["cpu_us_job"])
    cost_scope = {"cpu_us_solve_total": suma_solve, "cpu_us_import": wyk.get("cpu_us_import"), "cpu_us_job": cpu_job, "wall_ms_job": wyk.get("wall_ms_job"),
                  "measured_by": {"solve": "child process_time_ns", "job": "supervisor getrusage(RUSAGE_CHILDREN) user+sys"},
                  "excluded_costs": ["tokeny rozmowy autora patcha", "czas nadzorcy poza dzieckiem", "I/O receiptów"], "billed_unit": "cpu_us_job",
                  "executor_status": wyk["status"], "isolation": wyk.get("isolation")}
    eff = {"operation_id": operation_id, "attempt_id": attempt_id, "kind": "execution", "subject": scope, "generation": generation,
           "artifact_ref": os.path.abspath(artifact_path), "artifact_sha256": art, "product_ref": prod, "product_sha256": _sha_pliku(prod), "descriptor_sha256": desc,
           "cpu_us_total": cpu_job, "cpu_us_per_task": koszty, "cost_scope": cost_scope, "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "solver_id": wyk.get("solver_id")}
    with open(os.path.join(katalog, "effect.json"), "x", encoding="utf-8") as f:
        json.dump(eff, f, ensure_ascii=False, indent=1, sort_keys=True)
    effect_sha = _sha_pliku(os.path.join(katalog, "effect.json"))
    rows = []
    for c in plan["tasks"]:
        if c["task_id"] not in odpowiedzi:
            continue                                                                          # brak odpowiedzi (timeout/awaria) = MISSING w mianowniku, nie zero
        raw = json.dumps(odpowiedzi[c["task_id"]], ensure_ascii=False, sort_keys=True)
        rows.append({"task_id": c["task_id"], "artifact_sha256": art, "raw_answer": raw, "raw_answer_sha256": sha(raw.encode()),
                     "cost_units": koszty.get(c["task_id"]), "cost_kind": "OBSERVED_CPU_US_SOLVE", "producer": f"exec:{exec_id}"})
    osie = {"family_relation": "SAME_FAMILIES", "examples_used_for_candidate_adaptation": "UNKNOWN", "seed_accessible_to_executor": True,
            "gold_isolated_from_candidate": False, "verifier_isolated_from_candidate": "PROCESS_ONLY", "candidate_frozen_before_final_test": True,
            "scope": f"{domain}_SYNTHETIC_SIX_FAMILIES", "holdout_seed_sha256": plan["holdout_seed_sha256"]}
    # ocena WYŁĄCZNIE u nadzorcy: zamrożony weryfikator Astry na DANYCH odpowiedzi (nie na obiektach wykonawcy)
    w = WystawcaUkryty(effect_receipt=f"exec:{exec_id}", generation=generation, exposure_axes=osie, cost_scope=cost_scope)
    ev_fn, scorer_sha = weryfikator(domain)
    if domain in DOMENY_WLASNE:
        rec = measure_generic(plan, rows, phase=phase, artifact_sha256=art, descriptor_sha256=desc, authority=w, evaluate_fn=ev_fn, scorer_sha256=scorer_sha, lean_bin=lean)
    else:
        rec = Z.measure(plan, rows, phase=phase, artifact_sha256=art, descriptor_sha256=desc, authority=w, lean_bin=lean)
    if regresja_z:
        przed_ok = {v["task_id"] for v in regresja_z.get("verdicts", []) if v.get("status") == "PASS"}
        nce = sum(1 for v in rec["body"]["verdicts"] if v["task_id"] in przed_ok and v["status"] != "PASS")
        w2 = WystawcaUkryty(effect_receipt=f"exec:{exec_id}", generation=generation, exposure_axes=osie, cost_scope=cost_scope, new_critical_errors=nce)
        rec = w2.issue({k: v for k, v in rec["body"].items() if k not in ("issuer", "control_domain", "issued_at")})
        # pierwszy receipt (bez new_critical_errors) zostaje na dysku jako ślad; kanoniczny jest ten z regresją — ref zwracany niżej
    rozl = None; ksiega = None
    if budzet is not None:
        budzet.observe_usage(f"{exec_id}:call", {"cpu_us_per_task_solve": koszty, "cost_scope": cost_scope}, cpu_job, "PER_CALL", counter_epoch=exec_id, price_version="cpu_allowance_us/1", adapter_version="zdolnosci_pomiar/09.09-b")
        try:
            rozl = budzet.reconcile(f"{exec_id}:call", settlement=WystawcaKosztuCPU().oswiadczenie(exec_id, cpu_job, effect_sha))   # dokument wystawcy: KOSZT CAŁEGO ZADANIA
        except Exception as exc:  # noqa: BLE001 — awaria księgowania NIE kasuje pomiaru; jest osobnym faktem (PR1)
            rozl = {"decision": "ERROR", "reason": f"{type(exc).__name__}: {str(exc)[:120]}"}
        ksiega = budzet.stan_wywolania(f"{exec_id}:call")                                            # PR1: cost_status Z KSIĘGI, nie ze słownika rozliczenia
    # PR1 (Astra): pomiar jakości i rozliczenie to OSOBNE fakty. `measurement_status` = COMPLETE/INCOMPLETE; `cost_status` z zapisu księgi
    # (SETTLED_FINAL / ESTIMATED / PENDING / REFUSED:<powód> / NOT_RESERVED); `eligible_for_activation` liczy ZAUFANY CALLER z księgi — tu tylko podpowiedź.
    cost_status = ("NOT_RESERVED" if budzet is None else (ksiega or {}).get("cost_status", "PENDING"))
    if budzet is not None and cost_status not in ("SETTLED_FINAL", "RELEASED_FINAL"):
        cost_status = f"REFUSED:{(rozl or {}).get('reason') or (rozl or {}).get('decision')}" if (rozl or {}).get("decision") not in ("SETTLED", "CORRECTED", "RELEASED") else cost_status
    with open(os.path.join(katalog, "koszt.json"), "w", encoding="utf-8") as f:                       # utrwalony powód i rezerwacja (PR1.2)
        json.dump({"cost_status": cost_status, "settlement_result": rozl, "ledger": ksiega, "reservation": rez}, f, ensure_ascii=False, indent=1, default=str)
    return {"status": "OK" if wyk["status"] == "OK" else f"EXECUTOR_{wyk['status']}", "measurement_status": rec["body"]["status"], "quality_receipt_ref": rec["ref"],
            "cost_status": cost_status, "cost_ledger_ref": (ksiega or {}).get("cost_ledger_ref"), "cost_receipt_sha256": (hashlib.sha256(json.dumps(rozl, sort_keys=True, default=str).encode()).hexdigest() if rozl else None),
            "eligible_for_activation_hint": rec["body"]["status"] == "COMPLETE" and cost_status == "SETTLED_FINAL", "admission_reason": (None if cost_status == "SETTLED_FINAL" else "REQUIRED_SETTLEMENT_MISSING"),
            "receipt": rec, "plan_sha256": sha(plan), "artifact_sha256": art, "effect_receipt": f"exec:{exec_id}",
            "cpu_us_total": cpu_job, "cpu_us_solve_total": suma_solve, "cost_scope": cost_scope, "bound": bound, "reservation": rez, "settlement": rozl,
            "value": rec["body"]["value"], "receipt_status": rec["body"]["status"], "new_critical_errors": rec["body"].get("new_critical_errors"),
            "nie_PASS": [v["task_id"] + ":" + v["status"] for v in rec["body"]["verdicts"] if v["status"] != "PASS"]}
