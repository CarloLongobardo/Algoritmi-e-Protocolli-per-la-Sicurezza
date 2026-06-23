"""
Simulazione e-voting crittografico.
Protocollo monolitico: X.509, Shamir, Merkle, RSA-OAEP.

Autori: Carlo & Michele — APS Unisa A.A. 2025/2026
"""

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
import argparse
import datetime
import hashlib
import random
import secrets
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
RSA_KEY_SIZE = 2048
SHAMIR_N = 5
SHAMIR_T = 3
# Primo di Mersenne: modulo del campo finito GF(p) usato dal polinomio di Shamir
SHAMIR_PRIME = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
SESSION_TOKEN_TTL = 300
CANDIDATES = ["Candidato A", "Candidato B", "Candidato C"]
BLANK_LABEL="Scheda Bianca"
NUM_OPZIONI = len(CANDIDATES) + 1
CHUNK_SIZE = 31

_OUT_W = 68


def _banner() -> None:
  """Stampa il banner iniziale della simulazione."""
  print("+" * _OUT_W)
  print("  E-VOTING CRITTOGRAFICO  |  prototipo stand-alone")
  print("  APS Unisa 2025/26       |  Carlo & Michele")
  print("+" * _OUT_W)


def _fase(titolo: str) -> None:
  """Stampa l'intestazione di una fase del protocollo."""
  print(f"\n>> {titolo}")
  print("-" * _OUT_W)


def _log(ente: str, messaggio: str) -> None:
  """Stampa una riga di log con ente a sinistra e messaggio a destra."""
  print(f"  {ente:<5} {messaggio}")


def _esito(etichetta: str, valore: str) -> None:
  """Stampa una riga del riepilogo finale dei risultati."""
  print(f"  {etichetta:<22} {valore}")


# =============================================================================
# UTILITY — token, pseudonimizzazione, identificativi
# =============================================================================

def generate_token() -> str:
  """
  Genera un token di attivazione monouso ad alta entropia.
  Il token viene recapitato all'elettore su canale OOB (out-of-band),
  separato dal canale di voto: qui viene stampato a video.
  """
  raw = secrets.token_hex(16)
  checksum = hashlib.sha256(raw.encode()).hexdigest()[:4]
  return raw + checksum


def validate_token(token: str) -> bool:
  """Verifica lunghezza e checksum del token prima di accedere al database AR."""
  if len(token) != 36:
    return False
  raw = token[:32]
  chk = token[32:]
  expected = hashlib.sha256(raw.encode()).hexdigest()[:4]
  return secrets.compare_digest(chk, expected)


def compute_idar(cf: str, salt: bytes) -> str:
  """
  Calcola l'IDAR, identificativo pseudonimo dell'elettore presso l'AR.
  Formula: IDAR = SHA-256(CF || salt). Il codice fiscale non transita verso l'AE.
  """
  digest = hashlib.sha256(cf.encode() + salt)
  return digest.hexdigest()


def compute_idpepper(idar: str, pepper: bytes) -> str:
  """
  Calcola l'IDpepper, secondo strato di pseudonimizzazione lato AE.
  Formula: IDpepper = SHA-256(IDAR || pepper). Il pepper resta segreto nell'AE.
  """
  digest = hashlib.sha256(idar.encode() + pepper)
  return digest.hexdigest()


# =============================================================================
# RSA — chiavi, cifratura OAEP, firme PSS
# =============================================================================

def generate_keypair(key_size: int = RSA_KEY_SIZE) -> tuple[RSAPrivateKey, RSAPublicKey]:
  """Genera una coppia di chiavi RSA con esponente pubblico 65537."""
  sk = rsa.generate_private_key(65537, key_size, default_backend())
  pk = sk.public_key()
  return sk, pk


def sk_to_bytes(sk: RSAPrivateKey) -> bytes:
  """Serializza la chiave privata in formato DER PKCS#8 (per lo split Shamir)."""
  return sk.private_bytes(
    serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
  )


def sk_from_bytes(data: bytes) -> RSAPrivateKey:
  """Ricarica una chiave privata RSA da byte DER."""
  return serialization.load_der_private_key(data, password=None, backend=default_backend())


def pk_to_pem(pk: RSAPublicKey) -> str:
  """Esporta la chiave pubblica in formato PEM (testo ASCII)."""
  pem = pk.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
  )
  return pem.decode()


def pk_from_pem(pem: str) -> RSAPublicKey:
  """Importa una chiave pubblica RSA da stringa PEM."""
  return serialization.load_pem_public_key(pem.encode(), backend=default_backend())


def encrypt_oaep(pk: RSAPublicKey, pt: bytes) -> bytes:
  """
  Cifra il plaintext con RSA-OAEP e SHA-256.
  Schema probabilistico (IND-CPA): voti uguali producono crittogrammi CV diversi.
  pk: chiave pubblica urna PK_AE. pt: vettore voto || padding || timestamp.
  """
  return pk.encrypt(
    pt,
    padding.OAEP(
      mgf=padding.MGF1(hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None,
    ),
  )


def decrypt_oaep(sk: RSAPrivateKey, ct: bytes) -> bytes:
  """Decifra un crittogramma RSA-OAEP (usato in fase di spoglio)."""
  return sk.decrypt(
    ct,
    padding.OAEP(
      mgf=padding.MGF1(hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None,
    ),
  )


def sign_data(sk: RSAPrivateKey, data: bytes) -> bytes:
  """Firma digitale RSA-PSS con SHA-256 (nonce elettore, eventuali ricevute)."""
  return sk.sign(
    data,
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
  )


def verify_sig(pk: RSAPublicKey, data: bytes, sig: bytes) -> bool:
  """Verifica una firma RSA-PSS; ritorna False se la firma non è valida."""
  try:
    pk.verify(
      sig,
      data,
      padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
      ),
      hashes.SHA256(),
    )
    return True
  except Exception:
    return False


# =============================================================================
# SHAMIR SECRET SHARING — distribuzione della chiave privata dell'urna
# =============================================================================

def _mod_inv(a: int, p: int = SHAMIR_PRIME) -> int:
  """Calcola l'inverso modulare di a in Z_p con l'algoritmo di Euclide esteso."""
  t, new_t = 0, 1
  r, new_r = p, a % p
  while new_r != 0:
    q = r // new_r
    t, new_t = new_t, t - q * new_t
    r, new_r = new_r, r - q * new_r
  return t % p


def shamir_split(secret: int, n: int, t: int) -> List[Tuple[int, int]]:
  """
  Divide un intero segreto in n share con soglia t.
  Costruisce un polinomio di grado t-1 con il segreto come termine noto.
  """
  secret = secret % SHAMIR_PRIME
  coeffs = [secret] + [secrets.randbelow(SHAMIR_PRIME - 1) + 1 for _ in range(t - 1)]
  shares: List[Tuple[int, int]] = []
  for x in range(1, n + 1):
    y = 0
    power = 1
    for c in coeffs:
      y = (y + c * power) % SHAMIR_PRIME
      power = (power * x) % SHAMIR_PRIME
    shares.append((x, y))
  return shares


def shamir_join(shares: List[Tuple[int, int]]) -> int:
  """Ricostruisce il segreto (f(0)) tramite interpolazione di Lagrange."""
  secret = 0
  for i, (xi, yi) in enumerate(shares):
    num, den = 1, 1
    for j, (xj, _) in enumerate(shares):
      if i != j:
        num = (num * (-xj)) % SHAMIR_PRIME
        den = (den * (xi - xj)) % SHAMIR_PRIME
    secret = (secret + yi * num * _mod_inv(den)) % SHAMIR_PRIME
  return secret


class TrusteeManager:
  """
  Gestisce la distribuzione Shamir della chiave privata dell'urna (SK_AE).

  La chiave viene spezzata in N share e consegnata a N custodi indipendenti.
  Per lo spoglio servono almeno T share: con T-1 il segreto resta irrecuperabile.
  Questo impedisce a un singolo custode (o all'AE) di decifrare i voti da solo.

  Attributi:
    n            — numero totale di custodi (N)
    t            — soglia minima di share per la ricostruzione (T)
    trustees     — lista (id_custode, share) consegnata ai custodi
    original_len — lunghezza in byte della chiave DER prima dello split
  """

  def __init__(self, n: int = SHAMIR_N, t: int = SHAMIR_T) -> None:
    """Inizializza il gestore con N custodi e soglia T."""
    self.n = n
    self.t = t
    self.trustees: List[Tuple[int, Tuple]] = []
    self.original_len = 0

  def distribute(self, key_bytes: bytes) -> None:
    """
    Divide SK_AE in share Shamir e li assegna ai custodi.
    key_bytes: chiave privata dell'urna serializzata in formato DER.
    """
    self.original_len = len(key_bytes)
    chunks = [key_bytes[i : i + CHUNK_SIZE] for i in range(0, len(key_bytes), CHUNK_SIZE)]
    per_trustee: List[List] = [[] for _ in range(self.n)]
    for ci, chunk in enumerate(chunks):
      secret = int.from_bytes(chunk.ljust(CHUNK_SIZE, b"\x00"), "big")
      for i, (x, y) in enumerate(shamir_split(secret, self.n, self.t)):
        per_trustee[i].append((ci, x, y))
    self.trustees = [(i + 1, tuple(s)) for i, s in enumerate(per_trustee)]

  def collect(self, closed: bool) -> List[Tuple]:
    """
    Raccoglie gli share dai primi T custodi.
    Gli share vengono rilasciati solo dopo la chiusura delle urne.
    """
    if not closed:
      raise PermissionError("Urne ancora aperte")
    return [s for _, s in self.trustees[: self.t]]

  @staticmethod
  def reconstruct(shares: List[Tuple], original_len: int) -> bytes:
    """Ricostruisce i byte della chiave privata dagli share dei custodi."""
    n_chunks = (original_len + CHUNK_SIZE - 1) // CHUNK_SIZE
    cmap: Dict[int, List] = {i: [] for i in range(n_chunks)}
    for share in shares:
      for ci, x, y in share:
        cmap[ci].append((x, y))
    out = bytearray()
    for ci in range(n_chunks):
      val = shamir_join(cmap[ci][:SHAMIR_T])
      out.extend(val.to_bytes(CHUNK_SIZE,"big"))
    return bytes(out[:original_len])


# =============================================================================
# MERKLE TREE — bulletin board append-only
# =============================================================================

def _h_pair(left: str, right: str) -> str:
  """Hash di due nodi adiacenti: SHA-256(left_bytes || right_bytes) in hex."""
  return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


class MerkleTree:
  """
  Bulletin board append-only: ogni voto cifrato diventa foglia H(CV) = SHA-256(CV).

  La Merkle root riassume l'intera urna: una modifica a qualsiasi foglia
  cambia la root e diventa rilevabile. La Merkle proof consente a ogni elettore
  di verificare l'inclusione del proprio voto senza fidarsi ciecamente dell'AE.

  Attributi:
    leaves — hash delle foglie H(CV), in ordine di inserimento
    root   — Merkle root pubblicata dopo ogni deposito
  """

  def __init__(self) -> None:
    """Crea un albero Merkle vuoto, senza foglie."""
    self.leaves: List[str] = []
    self.root=""

  def add_leaf(self, data: bytes) -> str:
    """
    Aggiunge un crittogramma all'urna.
    Calcola H(CV), lo appende alle foglie e aggiorna la root.
    """
    h = hashlib.sha256(data).hexdigest()
    self.leaves.append(h)
    self.root = self._root(self.leaves)
    return h

  def _root(self, leaves: List[str]) -> str:
    """Calcola la Merkle root risalendo l'albero dal livello foglie."""
    if not leaves:
      return""
    level = list(leaves)
    while len(level) > 1:
      if len(level) % 2:
        level.append(level[-1])
      level = [_h_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]

  def get_proof(self, leaf: str) -> List[Dict[str, str]]:
    """
    Costruisce la Merkle proof per dimostrare che H(CV) è nell'urna.
    leaf: hash SHA-256 del crittogramma depositato.
    """
    if leaf not in self.leaves:
      raise ValueError("Foglia non trovata")
    proof: List[Dict[str, str]] = []
    idx = self.leaves.index(leaf)
    level = list(self.leaves)
    while len(level) > 1:
      if len(level) % 2:
        level = level + [level[-1]]
      sib = level[idx ^ 1]
      direction = "right" if idx % 2 == 0 else "left"
      proof.append({"hash": sib, "direction": direction})
      level = [_h_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
      idx //= 2
    return proof

  @staticmethod
  def verify(leaf: str, proof: List[Dict], root: str) -> bool:
    """
    Verifica offline che una foglia appartenga all'albero con la data root.
    L'elettore può eseguire questo controllo senza fidarsi ciecamente dell'AE.
    """
    cur = leaf
    for step in proof:
      sib=step["hash"]
      if step["direction"] == "left":
        cur = _h_pair(sib, cur)
      else:
        cur = _h_pair(cur, sib)
    return cur == root


# =============================================================================
# CERTIFICATION AUTHORITY — infrastruttura a chiave pubblica X.509
# =============================================================================

class SimulatedCA:
  """
  Certification Authority (CA): radice di fiducia della PKI.

  Genera la chiave radice e il certificato auto-firmato CERT_CA.
  I certificati elettore CERT_E sono invece firmati dall'AR (vedi AutoritaRegistrazione).

  Attributi:
    sk     — chiave privata CA (firma CERT_CA)
    pk     — chiave pubblica CA
    _cert  — certificato radice auto-firmato della CA
  """

  def __init__(self) -> None:
    """Genera la chiave radice della CA e il certificato auto-firmato CERT_CA."""
    self.sk, self.pk = generate_keypair()
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"E-Voting CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (
      x509.CertificateBuilder()
      .subject_name(subj)
      .issuer_name(subj)
      .public_key(self.pk)
      .serial_number(x509.random_serial_number())
      .not_valid_before(now)
      .not_valid_after(now + datetime.timedelta(days=1))
      .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    )
    self._cert = b.sign(self.sk, hashes.SHA256(), default_backend())

  def verify(self, cert: x509.Certificate) -> bool:
    """Verifica la firma della CA sul certificato e la validità temporale."""
    try:
      self.pk.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
      )
    except Exception:
      return False
    now = datetime.datetime.now(datetime.timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

  @staticmethod
  def to_pem(cert: x509.Certificate) -> str:
    """Converte un certificato X.509 in stringa PEM (formato testuale standard)."""
    return cert.public_bytes(serialization.Encoding.PEM).decode()

  @staticmethod
  def from_pem(pem: str) -> x509.Certificate:
    """Carica un certificato X.509 da stringa PEM ricevuta dal client."""
    return x509.load_pem_x509_certificate(pem.encode(), default_backend())

  @staticmethod
  def idar_of(cert: x509.Certificate) -> Optional[str]:
    """Estrae il campo IDAR (USER_ID) dal subject del certificato."""
    for a in cert.subject:
      if a.oid == NameOID.USER_ID:
        return a.value
    return None


# =============================================================================
# AUTORITÀ DI REGISTRAZIONE (AR)
# =============================================================================

class AutoritaRegistrazione:
  """
  Autorità di Registrazione (AR): gestisce identità ed eleggibilità.

  Riceve il codice fiscale, calcola IDAR e invia un token monouso su canale OOB.
  Dopo la validazione del token rilascia CERT_E firmato con SK_AR.
  All'AE trasmette solo la lista degli IDAR: mai voti, mai urna.

  Attributi:
    _sk_ar      — chiave privata AR per firmare CERT_E
    _pk_ar      — chiave pubblica AR (l'AE verifica i certificati elettore)
    _ar_subject — nome emittente X.509 dell'AR
    _salt       — sale segreto per IDAR = SHA-256(CF || salt)
    _voters     — registro locale: idar → {token, used, expiry}
    lista_idar  — elenco pseudonimi inviato all'AE dopo la registrazione
  """

  def __init__(self) -> None:
    """Inizializza l'AR con chiavi per firmare CERT_E."""
    self._sk_ar, self._pk_ar = generate_keypair()
    self._ar_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "E-Voting AR")])
    self._salt = secrets.token_bytes(32)
    self._voters: Dict[str, Dict[str, Any]] = {}
    self.lista_idar: List[str] = []

  def issue_cert_e(self, idar: str, pk_e: RSAPublicKey) -> x509.Certificate:
    """
    Emette CERT_E firmato dall'AR: Sign_SK-AR(IDAR, PK_E) in formato X.509.
    idar: pseudonimo nel subject. pk_e: chiave pubblica RSA dell'elettore.
    """
    subj = x509.Name([
      x509.NameAttribute(NameOID.COMMON_NAME, f"voter_{idar[:12]}"),
      x509.NameAttribute(NameOID.USER_ID, idar),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (
      x509.CertificateBuilder()
      .subject_name(subj)
      .issuer_name(self._ar_subject)
      .public_key(pk_e)
      .serial_number(x509.random_serial_number())
      .not_valid_before(now)
      .not_valid_after(now + datetime.timedelta(hours=24))
      .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    return b.sign(self._sk_ar, hashes.SHA256(), default_backend())

  def verify_cert_e(self, cert: x509.Certificate) -> bool:
    """Verifica che CERT_E sia firmato dall'AR e sia temporalmente valido."""
    try:
      self._pk_ar.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
      )
    except Exception:
      return False
    now = datetime.datetime.now(datetime.timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

  def emetti_token(self, cf: str) -> Tuple[str, str]:
    """
    Genera un token monouso per l'elettore e lo recapità su canale OOB.
    Ritorna (token, idar).
    """
    idar = compute_idar(cf, self._salt)
    if idar in self._voters:
      raise ValueError("[AR] Elettore gia' registrato")
    token = generate_token()
    self._voters[idar] = {
      "token":token,
      "used":False,
      "expiry": int(time.time()) + 3600,
    }
    _log("AR", f"Token monouso inviato (canale OOB): {token[:20]}...")
    return token, idar

  def registra(self, token: str, pk_pem: str) -> dict:
    """
    Completa la registrazione: valida il token, brucia il token monouso,
    emette CERT_E firmato dall'AR e aggiorna la lista IDAR.
    """
    if not validate_token(token):
      raise ValueError("[AR] Token non valido")
    idar: Optional[str] = None
    rec: Optional[dict] = None
    for i, r in self._voters.items():
      if r["token"] == token:
        idar, rec = i, r
        break
    if not rec or rec["used"]:
      raise ValueError("[AR] Token non trovato o gia' usato")
    if time.time() > rec["expiry"]:
      raise ValueError("[AR] Token scaduto")
    pk = pk_from_pem(pk_pem)
    cert = self.issue_cert_e(idar, pk)
    rec["used"]=True
    if idar not in self.lista_idar:
      self.lista_idar.append(idar)
    _log("AR", f"Certificato CERT_E firmato da AR | IDAR {idar[:16]}...")
    return {"certificate_pem": SimulatedCA.to_pem(cert), "idar": idar}


# =============================================================================
# AUTORITÀ ELETTORALE (AE)
# =============================================================================

class AutoritaElettorale:
  """
  Autorità Elettorale (AE): urna cifrata, autenticazione e scrutinio.

  Autentica gli elettori con CERT_E e challenge-response, riceve i crittogrammi CV
  e li inserisce nel Merkle tree. A urne chiuse ricostruisce SK_AE via Shamir
  e conta i voti. L'AE non conosce l'identità reale grazie a IDpepper.

  Attributi:
    ar         — AR per verificare CERT_E firmato dall'AR
    _pepper    — segreto per calcolare IDpepper (anonimato verso l'AE)
    _eligible  — registro: idpepper → {voted, session, exp}
    _ballots   — urna: lista dei crittogrammi CV in byte
    merkle     — bulletin board Merkle append-only
    _nonces    — nonce delle sfide challenge-response per certificato
    closed     — False = urne aperte, True = urne chiuse (spoglio)
    pk         — PK_AE: chiave pubblica per cifrare i voti
    pk_receipt — chiave pubblica AE per verificare le ricevute firmate
    _trustees  — gestore dei custodi Shamir di SK_AE
  """

  def __init__(self, ar: AutoritaRegistrazione) -> None:
    """Inizializza l'AE: pepper, urna Merkle, PK_AE, split Shamir di SK_AE."""
    self.ar = ar
    self._pepper = secrets.token_bytes(32)
    self._eligible: Dict[str, dict] = {}
    self._ballots: List[bytes] = []
    self.merkle = MerkleTree()
    self._nonces: Dict[str, bytes] = {}
    self.closed = False

    self._sk_receipt, self.pk_receipt = generate_keypair()
    sk, self.pk = generate_keypair()
    sk_bytes = sk_to_bytes(sk)
    self._trustees = TrusteeManager()
    self._trustees.distribute(sk_bytes)
    del sk, sk_bytes
    _log("AE", f"Chiave urna spezzata: {SHAMIR_N} custodi, soglia {SHAMIR_T}")

  def carica_elettori(self, lista_idar: List[str]) -> None:
    """
    Riceve da AR la lista IDAR e crea le entry con flag voto = 0.
    Ogni IDAR viene convertito in IDpepper prima di essere memorizzato.
    """
    for idar in lista_idar:
      ip = compute_idpepper(idar, self._pepper)
      if ip not in self._eligible:
        self._eligible[ip] = {
          "voted":0,
          "session":None,
          "exp":0,
        }
    _log("AE", f"Registro elettorale: {len(lista_idar)} IDpepper caricati")

  def challenge(self, cert_pem: str) -> bytes:
    """
    Prima fase del challenge-response: l'AE invia un nonce casuale.
    cert_pem: certificato elettore in formato PEM.
    L'elettore dovrà firmarlo con SK_E per dimostrare il possesso della chiave.
    """
    if self.closed:
      raise ValueError("[AE] Elezione chiusa")
    cert = SimulatedCA.from_pem(cert_pem)
    if not self.ar.verify_cert_e(cert):
      raise ValueError("[AE] Certificato non valido")
    idar = SimulatedCA.idar_of(cert)
    if not idar:
      raise ValueError("[AE] IDAR mancante")
    voter = self._eligible.get(compute_idpepper(idar, self._pepper))
    if not voter or voter["voted"]:
      raise ValueError("[AE] Non eleggibile o gia' votato")
    nonce = secrets.token_bytes(32)
    self._nonces[cert_pem] = nonce
    return nonce

  def verify_auth(self, cert_pem: str, nonce: bytes, sig: bytes) -> str:
    """
    Seconda fase del challenge-response: verifica la firma RSA-PSS sul nonce.
    Imposta voted=1 prima di rilasciare il session token (mitigazione timing attack).
    Ritorna un session token monouso per inviare il crittogramma CV.
    """
    if self._nonces.get(cert_pem) != nonce:
      raise ValueError("[AE] Nonce non valido")
    cert = SimulatedCA.from_pem(cert_pem)
    if not verify_sig(cert.public_key(), nonce, sig):
      raise ValueError("[AE] Firma non valida")
    idar = SimulatedCA.idar_of(cert)
    voter = self._eligible.get(compute_idpepper(idar, self._pepper))
    if not voter or voter["voted"]:
      raise ValueError("[AE] Double-vote")
    voter["voted"]=1
    token = secrets.token_hex(32)
    voter["session"]=token
    voter["exp"] = int(time.time()) + SESSION_TOKEN_TTL
    del self._nonces[cert_pem]
    _log("AE","Challenge-response superato | flag voto impostato")
    return token

  def ricevi_voto(self, session: str, cv: bytes) -> dict:
    """
    Deposita il crittogramma CV in urna e aggiorna il Merkle tree.
    session: token monouso rilasciato da verify_auth.
    cv: crittogramma RSA-OAEP del voto.
    Ritorna ricevuta con H(CV), Merkle root e firma AE su H(CV)||timestamp.
    """
    if self.closed:
      raise ValueError("[AE] Elezione chiusa")
    voter = None
    for v in self._eligible.values():
      if v.get("session") == session:
        voter = v
        break
    if not voter or time.time() > voter["exp"]:
      raise ValueError("[AE] Session token invalido")
    voter["session"]=None
    self._ballots.append(cv)
    h = hashlib.sha256(cv).hexdigest()
    self.merkle.add_leaf(cv)
    ts = str(int(time.time()))
    sig = sign_data(self._sk_receipt, bytes.fromhex(h) + ts.encode())
    _log("AE", f"Scheda depositata in urna | H(CV) {h[:16]}...")
    return {
      "ballot_hash": h,
      "merkle_root": self.merkle.root,
      "timestamp": ts,
      "receipt_sig": sig.hex(),
    }

  def _rebuild_sk(self) -> RSAPrivateKey:
    """Ricostruisce SK_AE dagli share Shamir (solo a urne chiuse)."""
    shares = self._trustees.collect(self.closed)
    key_bytes = TrusteeManager.reconstruct(shares, self._trustees.original_len)
    return sk_from_bytes(key_bytes)

  def spoglio(self) -> dict:
    """
    Scrutinio elettronico: chiude le urne, ricostruisce SK_AE dagli share Shamir,
    ordina i crittogrammi per H(CV), decifra, valida il vettore binario e conta.
    Ritorna risultati aggregati, schede nulle e Merkle root finale.
    """
    if not self.closed:
      self.closed = True
      _log("AE","Urne chiuse - bulletin board congelata")
    _log("AE", f"Richiesta frammenti ai custodi ({SHAMIR_T}/{SHAMIR_N})...")
    sk = self._rebuild_sk()
    sorted_cv = sorted(self._ballots, key=lambda c: hashlib.sha256(c).hexdigest())
    risultati = {c: 0 for c in CANDIDATES}
    risultati[BLANK_LABEL] = 0
    nulli = 0
    for cv in sorted_cv:
      try:
        pt = decrypt_oaep(sk, cv)
        if len(pt) < NUM_OPZIONI + 40:
          nulli += 1
          continue
        vec = list(pt[:NUM_OPZIONI])
        if sum(vec) != 1 or not all(b in (0, 1) for b in vec):
          nulli += 1
          continue
        risultati[(CANDIDATES + [BLANK_LABEL])[vec.index(1)]] += 1
      except Exception:
        nulli += 1
    del sk
    _log("AE", "SK_AE ricostruita, usata e cancellata dalla memoria")
    return {"results": risultati, "null_ballots": nulli, "merkle_root": self.merkle.root}


# =============================================================================
# ELETTORI
# =============================================================================

class Elettore:
  """
  Client elettore: genera chiavi, si registra, vota e verifica l'inclusione in urna.

  SK_E resta sempre sul dispositivo dell'elettore. Il codice fiscale serve solo
  in fase di registrazione presso l'AR e non viene mai inviato all'AE.

  Attributi:
    nome      — etichetta per i log (es. V01)
    cf        — codice fiscale (solo fase AR)
    token     — token OOB ricevuto dall'AR
    sk        — SK_E: chiave privata RSA dell'elettore
    pk        — PK_E: chiave pubblica inviata all'AR
    cert_pem  — CERT_E per autenticarsi presso l'AE
    receipt   — ricevuta con ballot_hash, merkle_root, timestamp e firma AE
  """

  def __init__(self, nome: str, cf: str) -> None:
    """Crea un elettore con nome (per log) e codice fiscale."""
    self.nome = nome
    self.cf = cf
    self.token: Optional[str] = None
    self.sk: Optional[RSAPrivateKey] = None
    self.pk: Optional[RSAPublicKey] = None
    self.cert_pem: Optional[str] = None
    self.receipt: Optional[dict] = None

  def genera_chiavi(self) -> None:
    """Genera (SK_E, PK_E) RSA in locale; SK_E non lascia mai il dispositivo."""
    self.sk, self.pk = generate_keypair()
    _log(self.nome,f"Coppia RSA-{RSA_KEY_SIZE} generata sul client")

  def registrazione(self, ar: AutoritaRegistrazione) -> None:
    """Flusso completo di registrazione: token OOB, chiavi locali, CERT_E."""
    self.token, _ = ar.emetti_token(self.cf)
    self.genera_chiavi()
    data = ar.registra(self.token, pk_to_pem(self.pk))
    self.cert_pem = data["certificate_pem"]

  def vota(self, ae: AutoritaElettorale, scelta: int) -> None:
    """
    Flusso completo di voto: autenticazione, cifratura RSA-OAEP e deposito in urna.
    scelta: indice 1..NUM_OPZIONI (candidato o scheda bianca nella demo).
    """
    nonce = ae.challenge(self.cert_pem)
    session = ae.verify_auth(
      self.cert_pem, nonce, sign_data(self.sk, nonce)
    )
    vec = [0] * NUM_OPZIONI
    vec[scelta - 1] = 1
    padding = secrets.token_bytes(32)
    ts=struct.pack(">Q",int(time.time()))
    pt = bytes(vec) + padding + ts
    t0 = time.perf_counter()
    cv = encrypt_oaep(ae.pk, pt)
    ms = (time.perf_counter() - t0) * 1000
    self.receipt = ae.ricevi_voto(session, cv)
    etichetta = (CANDIDATES + [BLANK_LABEL])[scelta - 1]
    _log(self.nome, f"Voto registrato ({etichetta}) | cifratura {ms:.1f} ms")

  def verifica_ricevuta(self, ae: AutoritaElettorale) -> bool:
    """Verifica la firma RSA-PSS dell'AE sulla ricevuta Sign(H(CV)||timestamp)."""
    if not self.receipt or "receipt_sig" not in self.receipt:
      return False
    payload = bytes.fromhex(self.receipt["ballot_hash"]) + self.receipt["timestamp"].encode()
    sig = bytes.fromhex(self.receipt["receipt_sig"])
    ok = verify_sig(ae.pk_receipt, payload, sig)
    stato = "valida" if ok else "NON VALIDA"
    _log(self.nome, f"Verifica firma ricevuta AE: {stato}")
    return ok

  def verifica_merkle(self, ae: AutoritaElettorale) -> bool:
    """
    Verifica individuale: ricostruisce la Merkle root dalla proof
    e la confronta con la root ufficiale pubblicata dall'AE.
    """
    if not self.receipt:
      return False
    h=self.receipt["ballot_hash"]
    proof = ae.merkle.get_proof(h)
    ok = MerkleTree.verify(h, proof, ae.merkle.root)
    stato = "confermata" if ok else "FALLITA"
    _log(self.nome, f"Verifica inclusione urna: {stato}")
    return ok


# =============================================================================
# ORCHESTRAZIONE DELLA SIMULAZIONE
# =============================================================================

def run_simulation(num_elettori: int = 10, extra: int = 0) -> None:
  """
  Esegue la simulazione automatica end-to-end del protocollo.

  Parametri:
    num_elettori — quanti elettori V01..VN registrare e far votare
    extra        — schede sintetiche extra in urna (stress test dello spoglio)

  Fasi in ordine:
    1. Registrazione (AR + CA)
    2. Voto (challenge-response AE + crittogramma cifrato)
    3. Test anti doppio voto
    4. Verifica Merkle proof
    5. Spoglio Shamir e risultati aggregati
  """
  _banner()
  avvio=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
  _log("SYS",f"Avvio simulazione | {avvio}")

  ca = SimulatedCA()
  ar = AutoritaRegistrazione()
  ae = AutoritaElettorale(ar)
  _log("SYS", "CA radice e AR operativi")

  # --- Fase 1: registrazione ---
  _fase(f"Registrazione elettori (n={num_elettori})")
  elettori: List[Elettore] = []
  for i in range(num_elettori):
    cf=f"CF{secrets.token_hex(4).upper()}"
    e = Elettore(f"V{i + 1:02d}", cf)
    e.registrazione(ar)
    elettori.append(e)
  ae.carica_elettori(ar.lista_idar)

  # --- Fase 2: voto ---
  _fase("Autenticazione e deposito schede")
  for e in elettori:
    scelta = random.randint(1, NUM_OPZIONI)
    e.vota(ae, scelta)

  # --- Schede extra per stress test ---
  if extra > 0:
    _log("TEST",f"Inserimento di {extra} schede sintetiche nell'urna...")
    for _ in range(extra):
      vec = [0] * NUM_OPZIONI
      vec[random.randint(0, NUM_OPZIONI - 1)] = 1
      pt=bytes(vec)+secrets.token_bytes(32)+struct.pack(">Q",int(time.time()))
      cv = encrypt_oaep(ae.pk, pt)
      ae._ballots.append(cv)
      ae.merkle.add_leaf(cv)
    _log("TEST", f"Urna aggiornata: {len(ae._ballots)} schede totali")

  # --- Test anti doppio voto ---
  _fase("Controllo anti doppio voto")
  try:
    elettori[0].vota(ae, 1)
    _log("TEST", "ERRORE: il secondo voto e' stato accettato")
  except ValueError as ex:
    _log("TEST",f"Secondo voto bloccato come previsto ({ex})")

  # --- Verifica ricevuta firmata e Merkle proof ---
  _fase("Verifica individuale (ricevuta AE + Merkle proof)")
  rcpt_count = sum(1 for e in elettori if e.verifica_ricevuta(ae))
  ok_count = sum(1 for e in elettori if e.verifica_merkle(ae))
  _log("SYS", f"Ricevute AE valide: {rcpt_count}/{len(elettori)}")
  _log("SYS", f"Proof valide: {ok_count}/{len(elettori)}")
  _log("SYS",f"Merkle root: {ae.merkle.root[:40]}...")

  # --- Spoglio ---
  _fase("Scrutinio elettronico")
  t0 = time.perf_counter()
  res = ae.spoglio()
  dt = time.perf_counter() - t0

  total=sum(res["results"].values())
  print("\n" + "+" * _OUT_W)
  print("  ESITO ELEZIONE")
  print("+" * _OUT_W)
  for nome, n in res["results"].items():
    pct = (n / total * 100) if total else 0
    barra = "#" * int(pct / 10) if pct else ""
    _esito(nome,f"{n:3d} voti  ({pct:4.0f}%)  {barra}")
  _esito("Schede nulle",str(res["null_ballots"]))
  _esito("Schede in urna",str(len(ae._ballots)))
  _esito("Tempo scrutinio",f"{dt:.3f} s")
  _esito("Merkle root",res["merkle_root"][:48]+"...")
  print("+" * _OUT_W)
  _log("SYS","Simulazione terminata")


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
if __name__ == "__main__":
  p=argparse.ArgumentParser(description="Simulazione protocollo e-voting")
  p.add_argument("--elettori", type=int, default=10, help="numero elettori")
  p.add_argument("--extra", type=int, default=0, help="schede extra per test")
  args = p.parse_args()
  run_simulation(args.elettori, args.extra)
