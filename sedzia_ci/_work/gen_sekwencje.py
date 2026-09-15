# -*- coding: utf-8 -*-
"""Solver GEN (genetyka sekwencyjna) — R0, pierwsza wersja Brauna, 09.09.2026.
Wejście: `case["input"]` w schemacie braun.task/1 (kind, sequence, orientation, alphabet, table, frame, other).
Wyjście: {"answer": ...}. Nie czyta wzorca Astry (`wzorzec_zdolnosci.py`) — to byłby przepisany klucz, nie solver."""
SOLVER_ID = "gen_sekwencje/R1"
COMP = str.maketrans("ACGT", "TGCA")
_B = "TCAG"
_AA = "FFLLSSSSYY**CC*WLLLLPPPPHHQQRRRRIIIMTTTTNNKKSSRRVVVVAAAADDEEGGGG"
CODONS = {a + b + c: _AA[16 * i + 4 * j + k] for i, a in enumerate(_B) for j, b in enumerate(_B) for k, c in enumerate(_B)}
STOP = {"TAA", "TAG", "TGA"}


def solve(inp: dict) -> dict:
    s, k = inp["sequence"], inp["kind"]
    if k == "reverse_complement":
        return {"answer": s.translate(COMP)[::-1]}
    if k == "transcribe_coding":
        return {"answer": s.replace("T", "U")}
    if k == "transcribe_template":
        # R1: zadanie podaje matrycę już w orientacji 3'→5' (orientation=3to5) — RNA to komplement pozycja po pozycji, BEZ odwracania
        if inp.get("orientation") != "3to5":
            raise ValueError("ORIENTATION")
        return {"answer": s.translate(COMP).replace("T", "U")}
    if k == "translate":
        # R1: „wykonaj operację zgodnie z tabelą" = przetłumacz WSZYSTKIE pełne kodony od ramki; STOP zapisany jako '*', nie ucina
        f = int(inp.get("frame", 0))
        return {"answer": "".join(CODONS[s[i:i + 3]] for i in range(f, len(s) - 2, 3))}
    if k == "orf":
        found = []; i = 0
        while i < len(s) - 2:
            if s[i:i + 3] == "ATG":
                for j in range(i + 3, len(s) - 2, 3):
                    if s[j:j + 3] in STOP:
                        found.append([i, j + 3]); i = j + 3; break
                else:
                    i += 3
            else:
                i += 1
        return {"answer": found}
    if k == "hamming":
        o = inp["other"]
        return {"answer": sum(a != b for a, b in zip(s, o))}
    raise ValueError("UNSUPPORTED_KIND")
