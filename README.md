# Brine — Désérialisation pickle non sécurisée (CWE-502)

Petit projet pédagogique en deux parties : une application Flask
**volontairement vulnérable** à une RCE par désérialisation `pickle`, et
la **même application corrigée**, pour comparer concrètement le problème
et sa solution.

> Application volontairement vulnérable. À exécuter uniquement en local
> ou dans un environnement isolé (VM / conteneur). Ne jamais exposer
> `vulnerable/` sur Internet : l'exécution de code obtenue est totale.

## Contexte

Conçu à l'origine comme challenge CTF interne à l'ENSA Tétouan, retravaillé
ici comme démonstration de la vulnérabilité **CWE-502 (Deserialization of
Untrusted Data)**, de son exploitation, et de sa correction.

## Structure

```
pickle_deserialization/
├── vulnerable/        # app vulnérable : panier stocké en pickle
│   ├── app.py
│   ├── templates/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── requirements.txt
├── fixed/              # même app : panier en JSON signé (itsdangerous)
│   ├── app.py
│   ├── templates/
│   ├── Dockerfile
│   └── requirements.txt
├── exploit/
│   └── exploit.py      # preuve de concept RCE contre vulnerable/
├── docker-compose.yml  # lance les deux versions en parallèle
└── WRITEUP.md           # analyse détaillée de la faille et du correctif
```

## Lancer le projet

```bash
docker compose up --build -d
```

- Version vulnérable : http://localhost:5000
- Version corrigée : http://localhost:5001

## Reproduire l'exploitation (contre la version vulnérable uniquement)

```bash
python3 exploit/exploit.py http://localhost:5000 "cat /flag.txt"
```

Le même script lancé contre `http://localhost:5001` (version corrigée)
échoue : le cookie n'est plus un pickle mais un JSON signé par HMAC, donc
aucune classe Python n'est jamais instanciée à partir d'une donnée
envoyée par le client.

## Le mécanisme en bref

1. **Fuite de code source (CWE-200)** : une route de debug ne devrait
   répondre qu'en local, mais elle se fie à un header HTTP falsifiable
   (`X-Forwarded-For`) au lieu de l'adresse réseau réelle.
2. **Désérialisation non sécurisée (CWE-502)** : le panier est stocké
   dans un cookie `pickle`. La classe censée limiter les dégâts
   (`RestrictedUnpickler`) autorise `__import__` et `getattr`, ce qui
   suffit, combiné, à reconstruire n'importe quel appel Python —
   y compris `os.popen(...).read()`.

Le détail de la chaîne d'exploitation et le correctif appliqué sont dans
[`WRITEUP.md`](./WRITEUP.md).

## Ce que ça montre

- Pourquoi `pickle.loads()` ne doit jamais être appelé sur une donnée
  venant du client, même avec une liste blanche de classes.
- Comment une liste blanche "raisonnable" peut quand même être contournée.
- Un correctif réaliste : remplacer le format de sérialisation (JSON) et
  signer le cookie (HMAC via `itsdangerous`) plutôt que de tenter de
  sécuriser `pickle`.
