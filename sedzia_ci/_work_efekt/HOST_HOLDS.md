# M14 R7 — otwarte warunki hosta

- Braun raportuje przyjęcie R5: 52/52 testów, 26/26 mutantów, upgrade/rollback i cztery próby SIGKILL. Astra nie podpisuje tego raportu jako własnej obserwacji.
- Braun raportuje odbiór R6 na kopii i hoście: 56/56 testów, 28/28 mutantów, 17 prób adwersarialnych, apply 67 ms oraz Stop n=10 median 44 ms/p95 47 ms. Astra zachowuje ten materiał jako raport Brauna, nie własną obserwację hosta.
- R7 wymaga osobnego check/apply/rollback na izolowanej kopii, a instalacja hostowa należy do Brauna i wymaga stopki domu.
- Właściciel musi dopuścić BRAUN_ASTRA_PUBKEY oraz co najmniej jeden różny klucz: BRAUN_BRAT_PUBKEY lub BRAUN_SEDZIA_CI_PUBKEY.
- Dla Sędziego CI należy zachować exact workflow commit, run id, niezmienne wejścia, signed DSSE i osobny publiczny klucz. Statement z innym lineage niż sedzia-ci-run-<id> jest odrzucany.
- Workflow Sędziego CI i replay są autorstwa Brauna. Administracja repo, ruchome referencje i write token pozostają residualem; to nie jest sprzętowa niezależność.
- BEFORE/AFTER/EFFECT, świeży holdout, naturalny restart i rzeczywisty cykl wymagają wciąż operacyjnych dowodów.
- Każdy EFFECT wymaga Astry i drugiej domeny; Brat + Sędzia CI bez Astry ma zwrócić `UNPROVEN:ASTRA_EFFECT_WITNESS_MISSING`.
- Grant właściciela nie został wydany. R7 może dojść najwyżej do PREPARED/OCEŃ; AKTYWUJ jest poza zakresem.
- M15 pozostaje zablokowane do zweryfikowanego pełnego GREEN M14.
