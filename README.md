# E-Voting Crittografico — Carlo & Michele

Prototipo stand-alone del protocollo di voto elettronico a lista chiusa. Tutto il codice è in `main.py`: nessun server di rete, nessun database esterno. Le entità del protocollo sono classi Python che comunicano in memoria.

---

## Requisiti e avvio

- Python 3.10+
- Libreria `cryptography`

```bash
cd Carlo-Michele
pip install -r requirements.txt
python main.py
python main.py --elettori 5
python main.py --elettori 20 --extra 50
```

| Opzione | Default | Descrizione |
|---------|---------|-------------|
| `--elettori` | 10 | Elettori che si registrano e votano |
| `--extra` | 0 | Schede sintetiche aggiuntive (stress test spoglio) |

---

## Architettura

```
                    ┌─────────┐
                    │   CA    │  Trust anchor — CERT_CA
                    └─────────┘

       ┌─────────────┐       ┌─────────────┐
       │     AR      │       │     AE      │
       │ Registrazione│──────▶│    Urna     │
       │ token OOB   │ IDAR  │  Merkle BB  │
       │ CERT_E (SK_AR)      │ ricevute    │
       └──────┬──────┘       └──────┬──────┘
              │                     │
              │                     │ SK_AE → Shamir (5, 3)
              ▼                     ▼
       ┌─────────────┐       ┌─────────────┐
       │  Elettore   │──────▶│  Custodi    │
       │  (client)   │  CV   │  (share)    │
       └─────────────┘       └─────────────┘
```

| Entità | Classe | Ruolo |
|--------|--------|-------|
| CA | `SimulatedCA` | Certificato radice `CERT_CA` |
| AR | `AutoritaRegistrazione` | Token OOB, IDAR, `CERT_E` firmato con SK_AR |
| AE | `AutoritaElettorale` | Urna cifrata, auth, ricevute firmate, spoglio |
| Custodi | `TrusteeManager` | Share Shamir di `SK_AE` |
| Elettore | `Elettore` | Chiavi locali, voto, verifica ricevuta e Merkle |

---

## Struttura di `main.py`

1. **Configurazione** — RSA, Shamir, candidati, TTL
2. **Output** — `_banner()`, `_fase()`, `_log()` per console uniforme
3. **Utility** — token OOB, `IDAR`, `IDpepper`
4. **RSA** — OAEP, PSS
5. **Shamir** — `TrusteeManager`
6. **Merkle** — bulletin board append-only
7. **CA X.509** — `CERT_CA` (radice PKI)
8. **Attori** — AR (`issue_cert_e`), AE, Elettore
9. **`run_simulation()`** — orchestrazione fasi

---

## Protocollo (sintesi)

### Registrazione
- AR genera token OOB (128 bit + checksum) e calcola `IDAR = SHA256(CF || salt)`
- L'elettore genera `(SK_E, PK_E)` in locale
- AR emette `CERT_E` firmato con **SK_AR** (`issue_cert_e`) e invia all'AE solo la lista IDAR
- AE memorizza `IDpepper = SHA256(IDAR || pepper)`

### Voto
- Challenge-response con nonce firmato; AE verifica `CERT_E` con la chiave pubblica dell'AR
- Flag voto → 1 prima del deposito scheda
- `CV = RSA-OAEP(PK_AE, vettore || padding || timestamp)`
- `H(CV)` inserito nel Merkle tree
- AE restituisce **ricevuta firmata** su `H(CV) || timestamp` (chiave dedicata, perché `SK_AE` è su Shamir)

### Verifica e spoglio
- Ogni elettore verifica la firma AE sulla ricevuta (`verifica_ricevuta`) e la Merkle proof (`verifica_merkle`)
- A urne chiuse: ricostruzione Shamir, ordinamento per `H(CV)`, decifratura, conteggio

---

## Output in console

Esempio con `python main.py --elettori 3`:

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  E-VOTING CRITTOGRAFICO  |  prototipo stand-alone
  APS Unisa 2025/26       |  Carlo & Michele
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  SYS   Avvio simulazione | 17/06/2026 22:46:22
  AE    Chiave urna spezzata: 5 custodi, soglia 3
  SYS   CA radice e AR operativi

>> Registrazione elettori (n=3)
--------------------------------------------------------------------
  AR    Token monouso inviato (canale OOB): 3f335ff5d70137eceb22...
  V01   Coppia RSA-2048 generata sul client
  AR    Certificato CERT_E firmato da AR | IDAR 4de2b645814497ca...
  AE    Registro elettorale: 3 IDpepper caricati

>> Autenticazione e deposito schede
--------------------------------------------------------------------
  AE    Challenge-response superato | flag voto impostato
  AE    Scheda depositata in urna | H(CV) ac01b0c25b6fbb5d...
  V01   Voto registrato (Candidato A) | cifratura 0.1 ms
  ...

>> Controllo anti doppio voto
--------------------------------------------------------------------
  TEST  Secondo voto bloccato come previsto (...)

>> Verifica individuale (ricevuta AE + Merkle proof)
--------------------------------------------------------------------
  V01   Verifica firma ricevuta AE: valida
  V01   Verifica inclusione urna: confermata
  SYS   Ricevute AE valide: 3/3
  SYS   Proof valide: 3/3

>> Scrutinio elettronico
--------------------------------------------------------------------
  AE    Urne chiuse - bulletin board congelata
  AE    SK_AE ricostruita, usata e cancellata dalla memoria

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  ESITO ELEZIONE
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Candidato A            1 voti  (  33%)  ###
  Candidato B            1 voti  (  33%)  ###
  ...
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  SYS   Simulazione terminata
```

---

## Meccanismi crittografici

| Meccanismo | Uso |
|------------|-----|
| RSA-OAEP | Cifratura voti con `PK_AE` |
| RSA-PSS | Firma nonce elettore; firma ricevuta AE |
| X.509 | `CERT_CA` (CA), `CERT_E` firmato dall'AR |
| SHA-256 | IDAR, IDpepper, Merkle, ricevute |
| Shamir (5,3) | `SK_AE` tra i custodi |
| Merkle tree | Urna verificabile |

---

## Limiti del prototipo

- Nessuna rete reale (TLS, server separati)
- Chiavi in RAM, non in HSM
- Token OOB simulato su console
- Ricevuta firmata con chiave AE dedicata (non `SK_AE`, distribuita via Shamir)
- Nessuna equazione di bilancio automatica né `CERT_AE` dell'urna
- Nessuna mitigazione traffic analysis

---

## Autori

Carlo & Michele — APS, Università degli Studi di Salerno, A.A. 2025/2026
