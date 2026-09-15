# M14 E24 — niezmienne wejścia pierwszego pełnego cyklu GEN (Braun, 15.09.2026, ~08:35Z)

- **Świeży holdout**: nowe ziarno (`os.urandom`), zapisane na hoście w `runtime_state/measurements/holdout/GEN.json`; ziarno pilota 09.09 zarchiwizowane jako `GEN_pilot_2026-09-09_SPALONE.json` (24 próbki widziane w cyklu KEPT). Kontrola: wejścia z nowego ziarna ≠ wejścia z pilota.
- `E24_MANIFEST.json`: 24 zadania (`GEN-template-{0..5}-v{0..3}`), per zadanie `task_id`, `family_id`, `input_sha256`, `split` (DEV 0–2 / SHADOW 3–4 / FINAL 5 — z KONTRAKT_R1), `holdout_seed_sha256`, `sample_manifest_sha256` (sha kanonicznej listy), sha256 solvera, scorera, wyroczni złota, generatora, `common.py`, portu pomiaru, protokół `braun.measurement/2`.
- `bajty/`: dokładne pliki, z których sędzia odtwarza bieg u siebie (czysty Python, zero tokenów): `fixtures_zdolnosci.generate(seed)` → zadania; `gen_sekwencje.solve(input)` → odpowiedź; `zdolnosci.py` + `wzorzec_zdolnosci.py` → werdykt/złoto. Sha w manifeście = sha tych bajtów.
- `HOLDOUT_SEED_GEN_v2.txt`: ziarno dla sędziów. Residual (jawny): kandydat biegnie w piaskownicy z wyczyszczonym env, ale na tym samym użytkowniku FS — `seed_accessible_to_executor: True` jak w R1.
- Czego tu NIE ma: złota (liczy je wzorzec u sędziego), odpowiedzi, wyników.

Statement MEASUREMENT sędziego: `phase BEFORE`, `n 24` (albo per split), `sample_ids` = `task_id` z manifestu, `sample_manifest_sha256` = z manifestu, `evaluator_sha256` = sha `zdolnosci.py`, `protocol_sha256` = sha256("braun.measurement/2"), `candidate_sha256` = sha generacji solvera. AFTER — dopiero po kandydacie z cyklu (PREPARED/OCEŃ), tym samym manifestem.
