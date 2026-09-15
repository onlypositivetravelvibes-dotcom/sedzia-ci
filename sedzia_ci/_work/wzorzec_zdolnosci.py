"""Trusted reference oracle for a narrow, explicit synthetic domain. NOT an LLM."""
from fractions import Fraction
import math

_BASES = "TCAG"
_AA = "FFLLSSSSYY**CC*WLLLLPPPPHHQQRRRRIIIMTTTTNNKKSSRRVVVVAAAADDEEGGGG"
CODONS = {a+b+c: _AA[i] for i,(a,b,c) in enumerate(
    (a,b,c) for a in _BASES for b in _BASES for c in _BASES)}
COMP = str.maketrans("ACGT", "TGCA")


def physics_target(t):
    raw=t["parameters"]
    if any(type(v) not in (int,float) or not math.isfinite(v) for v in raw.values()):
        raise ValueError("INVALID_PHYSICS_PARAMETER")
    # Inputs declare exact decimal constants. Normalize each before rational arithmetic.
    p = {key:Fraction(str(value)) for key,value in raw.items()}; k = t["kind"]
    if k == "speed": return Fraction(p["distance_m"], p["time_s"]), "m/s"
    if k == "force": return Fraction(p["mass_kg"] * p["acceleration_m_s2"]), "N"
    if k == "kinetic_energy": return Fraction(p["mass_kg"] * p["speed_m_s"]**2, 2), "J"
    if k == "charge": return Fraction(p["current_A"] * p["time_s"]), "C"
    if k == "pressure": return Fraction(p["force_N"], p["area_m2"]), "Pa"
    if k == "work": return Fraction(p["force_N"] * p["distance_m"]), "J"
    raise ValueError("UNSUPPORTED_PHYSICS_MODEL")


def genetics_target(t):
    s, k = t["sequence"], t["kind"]
    if set(s) - set("ACGT") or t.get("table") != 1 or t.get("alphabet") != "DNA":
        raise ValueError("UNSUPPORTED_SEQUENCE_OR_TABLE")
    if k == "reverse_complement": return s.translate(COMP)[::-1]
    if k == "transcribe_coding": return s.replace("T", "U")
    if k == "transcribe_template":
        if t["orientation"] != "3to5": raise ValueError("ORIENTATION")
        return s.translate(COMP).replace("T", "U")
    if k == "translate":
        if t["orientation"] != "5to3" or t["frame"] not in (0,1,2): raise ValueError("FRAME")
        return "".join(CODONS[s[i:i+3]] for i in range(t["frame"], len(s)-2, 3))
    if k == "orf":
        found = []
        for start in range(len(s)-2):
            if s[start:start+3] != "ATG": continue
            for stop in range(start+3, len(s)-2, 3):
                if s[stop:stop+3] in {"TAA", "TAG", "TGA"}:
                    found.append([start, stop+3]); break
        return found
    if k == "hamming":
        other = t["other"]
        if len(s) != len(other) or set(other) - set("ACGT"): raise ValueError("HAMMING_DOMAIN")
        return sum(a != b for a,b in zip(s, other))
    raise ValueError("UNSUPPORTED_GENETICS_OPERATION")


def solve(case):
    if case["domain"] == "MAT": return {"proof": "by intros; omega"}
    if case["domain"] == "FIZ":
        v,u = physics_target(case["input"])
        return {"value": float(v), "unit": u}
    return {"answer": genetics_target(case["input"])}
