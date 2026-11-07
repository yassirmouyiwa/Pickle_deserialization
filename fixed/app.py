import os

from flask import Flask, make_response, redirect, render_template, request, url_for
from itsdangerous import BadSignature, URLSafeSerializer

app = Flask(__name__)

# En production, SECRET_KEY doit venir d'une variable d'environnement ou
# d'un secret manager — jamais une valeur en dur dans le code.
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

COOKIE_NAME = "json_cart"
serializer = URLSafeSerializer(app.secret_key, salt="cart-v1")

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
    """Lit le panier depuis le cookie. Aucune désérialisation pickle :
    serializer.loads() ne fait que vérifier une signature HMAC et parser
    du JSON — il ne peut instancier aucune classe Python arbitraire."""
    raw = request.cookies.get(COOKIE_NAME, "")
    if not raw:
        return [], None
    try:
        items = serializer.loads(raw)
    except BadSignature:
        return [], "Panier invalide ou falsifié — cookie rejeté."
    if not isinstance(items, list):
        return [], None
    # Les données viennent toujours de JSON standard (dict/str/float/int),
    # donc inutile de gérer un cas "objet mystère" comme dans la version
    # vulnérable : la structure est garantie par le format lui-même.
    return items, None


def compute_total(items):
    total = 0.0
    for it in items:
        total += float(it.get("price", 0) or 0) * max(0, int(it.get("qty", 1) or 1))
    return total


def save_cart(resp, items):
    payload = serializer.dumps(items)
    resp.set_cookie(
        COOKIE_NAME,
        payload,
        max_age=24 * 3600,
        path="/",
        httponly=True,   # inutile au client, autant le protéger de JS/XSS
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

    total = compute_total(items)
    return render_template("cart.html", items=items, total=total, error=None, has_mystery=False)


@app.route("/reset")
def reset():
    resp = make_response(redirect(url_for("cart")))
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True, debug=False)
