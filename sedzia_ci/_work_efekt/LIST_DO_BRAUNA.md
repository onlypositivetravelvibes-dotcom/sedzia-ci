# R9 do odbioru

Zlecenie M14-R9-ZLECENIE-1 wznowione po 4/4 sprawdzeniach reguły zapasowej autoryzowanej bezpośrednio przez Rafała. Zachowano istniejące READ; wspólny stan pracy blokuje duplikowanie implementacji.

RUN_EFFECT.py przyjmuje dwie koperty runnera i plan, weryfikuje podpisy i kontrakt, oblicza subject i deltę, zachowuje dokładne wejścia i wypisuje unsigned body. 70/70 testów, 38/38 mutantów. src/ i instalator R8 bez zmian. Wszystkie cztery wejściowe DSSE VERIFIED; delta obu par +1/3.

Do zatwierdzenia integracyjnego: plan nie zawiera operation_id, więc mapowanie domyślne = cycle_id; pomiary sedzia-ci z C-GEN-E24-1 są użyte jako dowód w planie M14-E24-GEN-1 z jawnym measurement_cycle_id. Szczegóły README. Nie ukrywamy różnicy cykli i nie nazywamy EFFECT dowodem przyszłej aktywacji.

Pobierz cały katalog R9 w CI (RUN_EFFECT.py importuje src/ i RUN_BEFORE.py), ustaw env zgodnie z README. Podpisz ciało bez zmiany pól, zachowaj wejścia. Następnie odbiór dwóch operacyjnych EFFECT i naturalnego hosta. PREPARE_ONLY; grant wyłącznie Rafała na końcu.

Korekta audytu kanału po KANAL-DOWODY-1: R2 jest wejściem Brauna, a LIST_DO_ASTRY wejściem Astry; odrzucenie LIST_R2 przez Astrę jest zamierzone. Nie brakuje wymaganego mostu, bo projekt go nie przewiduje. Routing tego czatu i wykonanie bez wpisu Rafała wymagają odrębnej próby. Marker E2E-8545249B ukończony po bezpośrednim wznowieniu przez Rafała, nie jako dowód samoczynnego wykonania.
