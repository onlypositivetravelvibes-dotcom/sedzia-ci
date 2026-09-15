"""72 public synthetic tasks: 24/domain, SIX template families/domain, four variants.

DEV and TEST do not share template families. Public TEST in this package is exposed:
it validates an apparatus, never supplies a secret production confirmation set.
Gold/reference artifacts belong to the evaluator, not the solver's input directory.
"""
import random
from common import sha


def generate(seed=8092026):
    rng = random.Random(seed)
    cases = []
    for domain in ("MAT", "FIZ", "GEN"):
        for family in range(6):
            for variant in range(4):
                a, b, c = rng.randint(2, 17), rng.randint(2, 13), rng.randint(2, 9)
                fid = f"{domain}-template-{family}"
                case = {"schema": "braun.task/1", "task_id": f"{fid}-v{variant}",
                        "family_id": fid, "split": "DEV" if family < 3 else "TEST_EXPOSED",
                        "domain": domain, "synthetic": True, "seed": seed,
                        "instruction_language": "pl"}
                if domain == "MAT":
                    # Universal statements, trusted frozen header; proof is the only variable.
                    statements = [
                        f"∀ x : Nat, x + {a} = {a} + x",
                        f"∀ x : Nat, x + {a} + {b} = x + {a+b}",
                        f"∀ x y : Nat, x + {a} = y + {a} → x = y",
                        f"∀ x : Int, x + {a} ≤ {b} → x ≤ {b-a}",
                        f"∀ x : Nat, x ≥ {a} → x - {a} + {a} = x",
                        f"∀ x : Int, {a} * x + {b} = {a*c+b} → x = {c}"]
                    case["input"] = {"statement": statements[family], "allowed_profile": "linear-omega-v1",
                                     "toolchain": "leanprover/lean4:v4.19.0"}
                    case["instruction"] = "Udowodnij dokładnie podane twierdzenie w Lean 4. Nie zmieniaj założeń."
                elif domain == "FIZ":
                    names = ["speed", "force", "kinetic_energy", "charge", "pressure", "work"]
                    params = [{"distance_m": a*b, "time_s": b}, {"mass_kg": a, "acceleration_m_s2": b},
                              {"mass_kg": 2*a, "speed_m_s": b}, {"current_A": a, "time_s": b},
                              {"force_N": a*b, "area_m2": b}, {"force_N": a, "distance_m": b}]
                    case["input"] = {"kind": names[family], "parameters": params[family],
                                     "model": "classical_exact_constants", "assumptions":
                                     "Dane dokładne; ruch prostoliniowy; dla pracy stała siła równoległa do przemieszczenia."}
                    case["instruction"] = "Oblicz wielkość z kind; oddaj JSON z value oraz unit."
                else:
                    seq = "".join(rng.choice("ACGT") for _ in range(18))
                    kinds = ["reverse_complement", "transcribe_coding", "transcribe_template", "translate", "orf", "hamming"]
                    case["input"] = {"kind": kinds[family], "sequence": seq, "orientation": "5to3",
                                     "alphabet": "DNA", "table": 1, "frame": 0}
                    if family == 2:
                        case["input"]["orientation"] = "3to5"
                    if family == 3:
                        # STOP semantics explicit: translate all full codons, '*' retained.
                        case["input"]["sequence"] = "ATG" + rng.choice(["GCT", "TGG", "AAA", "TGT"]) * (variant+1) + "TAA"
                    if family == 4:
                        case["input"]["sequence"] = "CC" + "ATG" + "GCT" * (variant+1) + "TAA" + "ATGTAG"
                        case["input"]["orfs"] = "plus_strand_all_ATG_starts_first_in_frame_stop_0based_halfopen_stop_included"
                    if family == 5:
                        seq2 = list(seq)
                        for j in range(variant+1):
                            seq2[j] = {"A":"C", "C":"G", "G":"T", "T":"A"}[seq2[j]]
                        case["input"]["other"] = "".join(seq2)
                    case["instruction"] = "Wykonaj operację kind zgodnie z orientacją i tabelą; JSON z answer."
                case["input_sha256"] = sha(case["input"])
                cases.append(case)
    return cases


def calibration_controls():
    return [{"family_id": f"cal-{i}", "p": float(i % 2), "y": i % 2} for i in range(40)]
