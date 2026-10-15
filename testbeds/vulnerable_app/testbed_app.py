"""Intentional-vulnerable test app for VulnScan demo/development.

Deliberately reintroduces OWASP-class vulnerabilities so the scanner has a
legitimate, authorized target to exercise against. NOT for production use.

Each vulnerability lives on its own endpoint so the scanner modules are
independently testable:
  /api/products?q=   -> SQL injection (boolean/error) via raw string interpol.
  /search?q=         -> reflected XSS (echoes input, no encoding)
  /comments (POST)   -> stored XSS (saves comment, renders unescaped)
  /login             -> weak cookie flags (no HttpOnly/Secure)
  /login (POST)      -> no rate limiting + predictable session ids
  /js/app.js         -> leaked API secret

Run: python -m uvicorn testbed_app:app --port 8080
"""
from __future__ import annotations

import sqlite3
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

app = FastAPI(title="Testbed Vulnerable App")

COMMENTS: list[str] = []


def _conn():
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT)")
    c.execute("INSERT INTO items (name) VALUES ('laptop')")
    c.execute("INSERT INTO items (name) VALUES ('phone')")
    c.execute("INSERT INTO items (name) VALUES ('monitor')")
    c.commit()
    return c


DB = _conn()


def _render(inner: str) -> str:
    return f"""<!DOCTYPE html><html><head><title>Testbed</title>
    <script src="/js/app.js"></script>
    </head>
    <body>
    <nav>
      <a href="/">Home</a> | <a href="/search">Search</a> |
      <a href="/comments">Comments</a> | <a href="/login">Login</a> |
      <a href="/api/products">Products API</a>
    </nav>
    {inner}
    </body></html>"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return _render(
        "<h1>Welcome</h1><p>Test app for authorized scanning.</p>"
        "<h2>Product search</h2>"
        "<form method='get' action='/api/products'>"
        "<input type='text' name='q' placeholder='Search products'>"
        "<input type='submit' value='Search'></form>"
    )


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = ""):
    """Reflected XSS sink - echoes q without encoding. No SQL here."""
    form = f"""
    <form method="get" action="/search">
        <input type="text" name="q" value="{q}">
        <input type="submit" value="Search">
    </form>
    """
    if q:
        form += f"<h3>Results for: {q}</h3>"  # XSS sink
    return _render(form)


@app.get("/api/products")
async def api_products(q: str = ""):
    """Boolean/error SQL injection via raw string interpolation."""
    items = []
    if q:
        cur = DB.execute(f"SELECT name FROM items WHERE name LIKE '%{q}%'")
        items = [r[0] for r in cur.fetchall()]
    return {"count": len(items), "items": items}


@app.get("/comments", response_class=HTMLResponse)
async def comments_page():
    """Stored XSS render - comments rendered unescaped."""
    list_html = "".join(
        f"<li>{c}</li>" for c in COMMENTS
    ) or "<li>no comments yet</li>"
    form = """
    <form method="post" action="/comments">
        <input type="text" name="comment" placeholder="Add a comment">
        <input type="submit" value="Post">
    </form>
    """
    return _render(form + "<h2>Comments</h2><ul>" + list_html + "</ul>")


@app.post("/comments", response_class=HTMLResponse)
async def comments_post(comment: str = ""):
    """Stored XSS sink - saves comment unescaped."""
    COMMENTS.append(comment)
    list_html = "".join(
        f"<li>{c}</li>" for c in COMMENTS
    ) or "<li>no comments yet</li>"
    form = """
    <form method="post" action="/comments">
        <input type="text" name="comment" placeholder="Add a comment">
        <input type="submit" value="Post">
    </form>
    """
    return _render(form + "<h2>Comments</h2><ul>" + list_html + "</ul>")


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Weak session cookie flags (missing HttpOnly/Secure)."""
    resp = Response(
        content=_render(
            "<h1>Login</h1>"
            "<form method='post' action='/login'>"
            "<input type='text' name='username'><input type='password' name='password'>"
            "<input type='submit' value='Login'></form>"
        )
    )
    resp.set_cookie("session", uuid.uuid4().hex, httponly=False, secure=False)
    return resp


@app.post("/login", response_class=HTMLResponse)
async def login_post(username: str = "", password: str = ""):
    """No rate limiting; predictable/sequential session ids."""
    sid = f"seq-{len(COMMENTS)}-{uuid.uuid4().hex[:6]}"
    resp = Response(content=_render(f"<h1>Welcome {username}</h1>"))
    resp.set_cookie("session", sid)
    return resp


@app.get("/js/app.js")
async def js_bundle():
    """Leaked API secret in JS bundle."""
    js = "const API_KEY = 'AKIAIOSFODNN7ABCDEFG'; // leaked AWS key\nfunction doThing(){}\n"
    return Response(content=js, media_type="application/javascript")
