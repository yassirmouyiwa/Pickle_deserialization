import base64
import builtins
import io
import os
import pickle

from flask import Flask, Response, make_response, redirect, render_template, request, url_for

app = Flask(__name__)

COOKIE_NAME = "pickle_cart"
FLAG_FILE = os.environ.get("FLAG_FILE", "/flag.txt")

# Liste blanche de noms "autorisés" pour la désérialisation pickle.
# Volontairement incomplète : __import__ + getattr suffisent à reconstruire
# n'importe quel appel Python (voir WRITEUP.md pour la chaîne complète).
ALLOWED_BUILTINS = {
    "list", "dict", "set", "tuple", "frozenset",
    "str", "bytes", "bytearray", "int", "float", "bool", "complex",
    "__import__", "getattr",
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins" and name in ALLOWED_BUILTINS:
            return getattr(builtins, name)
        raise pickle.UnpicklingError(f"Classe non autorisee : {module}.{name}")


def restricted_loads(data: bytes):
    return RestrictedUnpickler(io.BytesIO(data)).load()


PRODUCTS = [
    {
        "id": "cornichon-classique",
        "name": "Cornichon classique",
        "price": 2.50,
        "emoji": "\U0001F952",
        "desc": "L'incontournable : croquant, vinaigre, parfait a toute heure.",
    },
    {
        "id": "cornichon-piquant",
        "name": "Cornichon piquant",
        "price": 3.00,
        "emoji": "\U0001F336\uFE0F",
        "desc": "Pour les palais qui aiment les defis... et les defis qui piquent.",
    },
    {
        "id": "pickles-aneth",
        "name": "Pickles a l'aneth",
        "price": 3.50,
        "emoji": "\U0001F33F",
        "desc": "Preparation traditionnelle, recette secrete de la maison.",
    },
    {
        "id": "mega-pot",
        "name": "Mega Pot - Edition Collector",
        "price": 13.37,
        "emoji": "\U0001F3C6",
        "desc": "Edition limitee. Quantite tres restreinte.",
    },
]


def load_cart():
    raw = request.cookies.get(COOKIE_NAME, "")
    if not raw:
        return [], None
    try:
        items = restricted_loads(base64.b64decode(raw))
    except Exception as exc:
        return [], f"Panier illisible — nos cornichons sont confus : {exc}"

    if isinstance(items, tuple):
        items = list(items)
    if not isinstance(items, list):
        items = [items]
    return items, None


def normalize_items(items):
    display, total = [], 0.0
    for it in items:
        if isinstance(it, dict):
            try:
                price = float(it.get("price", 0) or 0)
            except (TypeError, ValueError):
                price = 0.0
            try:
                qty = max(0, int(it.get("qty", 1) or 1))
            except (TypeError, ValueError):
                qty = 1
            display.append({"name": str(it.get("name", "Article")), "price": price, "qty": qty})
            total += price * qty
        else:
            display.append({"name": str(it), "price": None, "qty": None})
    return display, total


def save_cart(resp, items):
    payload = base64.b64encode(pickle.dumps(items)).decode()
    resp.set_cookie(
        COOKIE_NAME,
        payload,
        max_age=24 * 3600,
        path="/",
        httponly=False,
        samesite="Lax",
    )


@app.context_processor
def inject_cart_count():
    items, _ = load_cart()
    return {"cart_count": len(items)}


@app.route("/")
def home():
    return render_template("index.html", products=PRODUCTS)


@app.route("/add", methods=["POST"])
def add():
    pid = request.form.get("product", "")
    product = next((p for p in PRODUCTS if p["id"] == pid), None)
    if product is None:
        return redirect(url_for("cart"))

    items, _ = load_cart()
    items.append({"name": product["name"], "price": product["price"], "qty": 1})

    resp = make_response(redirect(url_for("cart")))
    save_cart(resp, items)
    return resp


@app.route("/cart")
def cart():
    items, err = load_cart()
    if err:
        return render_template("cart.html", items=[], total=0.0, error=err, has_mystery=False)

    display, total = normalize_items(items)
    has_mystery = any(i["price"] is None for i in display)
    return render_template("cart.html", items=display, total=total, error=None, has_mystery=has_mystery)


@app.route("/reset")
def reset():
    resp = make_response(redirect(url_for("cart")))
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.route("/debug/source")
def debug_source():
    # Vulnérabilité 1 (CWE-200, fuite d'information) : cette route ne devrait
    # répondre qu'à l'appelant local, mais elle se fie à un header HTTP
    # entièrement contrôlé par le client au lieu de l'adresse réseau réelle.
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip != "127.0.0.1":
        return "Interdit", 403
    return Response(open(__file__, "r", encoding="utf-8").read(), mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True, debug=False)
