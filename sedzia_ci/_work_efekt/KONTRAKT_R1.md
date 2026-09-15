# M14 R1 — zamrożony kontrakt

Zamrożono przed implementacją na wejściu Brauna `4d83e173…`. R1 dostarcza lekką kolejkę Stop, workera poza hakiem, wąski adapter do istniejącego `samonaprawa_cykl.cykl()`, diagnostykę DSSE i uczciwy baner. Nie przepisuje `uczenie.py`, `uczenie_porty.py`, M11/M12/I3 ani istniejących haków.

## Granica wykonania

Hak tylko hashuje stabilne identyfikatory i kolejkuje. Nie czyta transkryptu, nie uruchamia modelu, nie mierzy, nie tworzy grantu i zawsze jest fail-open. Worker najpierw wywołuje `uczenie.wznow()` dla zapisanych cykli, a dopiero potem dokładnie `samonaprawa_cykl.cykl()`. Nigdy nie woła `main()` ani `dokument_wlasciciela()`.

Plan wykonania musi wiązać `source_event_id`, `cycle_id`, hashe R0/R1, generacje, manifest próbek i bieżący `owner:<record>:<candidate>` grant. Ten sam identyfikator z innym payloadem jest konfliktem. Kolejka jest at-least-once; autorytet efektu oraz idempotencja aktywacji pozostają w `uczenie.py` i rejestrze publikacji.

## Granica zaufania

Na przekazanym hoście Braun jest jednocześnie autorem, sędzią i pisarzem wyniku. Dlatego R1 ma status `DIAGNOSTIC_ONLY`. Poprawny podpis udowadnia pochodzenie bajtów, a nie prawdziwość twierdzenia. `EFFECT_VERIFIED` wymaga dwóch zweryfikowanych twierdzeń EFFECT z różnych chronionych domen i linii pochodzenia, poza domeną kandydata. Astra może niezależnie poświadczyć tylko fakty odtworzone z niezmiennych blobów, nie wykonanie ani wynik hosta.

## Holdout i pomiar

Jednostką jest szablon, nie raport. Split R1: DEV 0–2, SHADOW 3–4, FINAL 5; po cztery warianty. FINAL jest jednorazowy i nie wraca do generatora. `M13 ACCEPT` nie jest wynikiem liczbowym. BEFORE i AFTER muszą mieć różne wykonania, identyczny scorer/protokół/manifest/jednostkę/kierunek i jawny koszt. Brak porównywalności pozostaje `MEASUREMENT_PENDING`.

## Stany

`CONCEPT_READY`, `CODE_VERIFIED`, `HOST_INSTALLED` i `EFFECT_VERIFIED` są rozłączne. Lokalna zieleń R1 nie jest zielenią M14. M15 może wystartować dopiero po pełnym, dowodowym GREEN M14 określonym w karcie modułu.
