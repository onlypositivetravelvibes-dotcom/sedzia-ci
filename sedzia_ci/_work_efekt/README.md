# M14 R9 — producent EFFECT z podpisanych pomiarów

R9 dodaje RUN_EFFECT.py. src/, RUN_BEFORE.py i installer.py są bajtowo identyczne z R8; niczego nie trzeba reinstalować na hoście. Instalator w paczce nadal opisuje generację M14-R8. Workflow pobiera pełną paczkę R9 pod dokładnym commitem, uruchamia producent i podpisuje jego wynik bez podmiany pól.

## Uruchomienie

W świeżej kopii paczki ustaw MODE=EFFECT, BEFORE_ENVELOPE, AFTER_ENVELOPE, PLAN_PATH, STATEMENT_ID, ISSUER_REF, LINEAGE_REF, ISSUED_AT i publiczne klucze BRAUN_ASTRA_CI_PUBKEY oraz BRAUN_SEDZIA_CI_PUBKEY. Uruchom python RUN_EFFECT.py. Dla astra-ci użyj ci-astra-r0 i ci-astra-r1b; dla sedzia-ci ci-before-r0 i ci-after-r1. Podpisywanie i sekrety zostają w osobnych jobach CI.

Wyjścia: out/EFFECT_BODY_UNSIGNED.json, EFFECT_EVIDENCE.json i dokładne bajty obu kopert EFFECT_BEFORE.dsse.json / EFFECT_AFTER.dsse.json. Pole raw_evidence_sha256 liczy SHA256 kanonicznej pary hashy kopert, nie SHA256 sformatowanego pliku EFFECT_EVIDENCE.json. Producent zapisuje ciało jako ostatni plik, wyłącznie create-only. Po awarii użyj świeżego katalogu; częściowe dowody pozostają, nie są nadpisywane.

## Sprawdzenia

Podpisy R8, fazy i ta sama domena pomiarów; różne statement ID, dowody i biegi; zamrożone R0/R1, E24, scorer, protocol, accuracy/higher i 24 próbki. Plan: kanoniczny hash, PREPARE_ONLY, rollback, artefakty, próbki, owner binding i samodzielnie wyliczony subject. Tożsamość wyniku z env musi należeć do domeny pary; statement ID musi znajdować się w planie. Wygasłe pomiary nie wytwarzają aktualnego EFFECT; jego ważność nie przekracza ważności wejść.

Delta opisuje podpisany wynik E24. Nie jest dowodem nowego uruchomienia solvera, aktywacji ani niezależności administracyjnej. Oba CI korzystają z tego samego kodu producenta EFFECT i wspólnej administracji, choć z różnych kluczy i kodów pomiaru.

## Dwa jawne doprecyzowania wejścia Brauna

1. Przekazany plan nie ma operation_id. Producent przyjmuje jawne plan.operation_id, jeśli istnieje, w przeciwnym razie plan.cycle_id. Dla obecnego planu operation_id=M14-E24-GEN-1. Nie traktuje grant_ref jako wydanego grantu.
2. Pomiary sedzia-ci mają cycle C-GEN-E24-1, a plan ma M14-E24-GEN-1. Pary muszą być wewnętrznie zgodne; EFFECT wiąże ponowne użycie tych pomiarów z planem i zachowuje measurement_cycle_id. Nie twierdzi, że pomiary wykonano podczas przyszłego naturalnego cyklu hosta. Plan/source event wymagają weryfikacji na hoście przez Brauna.

## Wyniki

70/70 testów i 38/38 mutantów (evidence/R9_LOCAL_RESULTS_01.json). Cztery rzeczywiste koperty VERIFIED; obie pary dają +0.33333333333333337 (arytmetyka float) i subject b18629c4f529c7d2643d381dec7eb2673168d18eba1bc014ac7b65b69cd76f48. Pełny zapis: evidence/R9_OPERATIONAL_VERIFICATION.json. Testowe podpisy dwóch wygenerowanych EFFECT przechodzą niezmieniony verify_effect_bundle R8.

Operacyjne podpisy EFFECT: NOT_RUN. Odbiór workflow, naturalny host i grant: NOT_RUN/NOT_ISSUED. M14 nie jest jeszcze GREEN.
