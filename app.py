"""
Securinets ISI - "Captcha of the President" - Web CTF challenge (beginner track)
----------------------------------------------------------------------------
Intended vulnerability chain (do not read if you are a player!):

  1. /robots.txt disallows /dev-notes.txt and /flag -> curious players fetch
     /dev-notes.txt and learn (a) you need 50 successful verifications in the
     same session, and (b) the dev never got around to invalidating a solved
     captcha token.
  2. The player solves ONE captcha by hand (text is genuinely annoying to
     read: skewed, noisy, low-contrast navy/teal theme -> doing this 50x by
     hand realistically takes 45-90 minutes).
  3. They notice (via Burp Repeater) that resending the exact same
     POST /verify request (same token + same answer) keeps succeeding and
     keeps incrementing their counter, because the server never rotates or
     marks the token as used.
  4. They send that request to Intruder (Sniper, "Null payloads", 50
     repeats) to blast out 50 successes in seconds.
  5. GET /flag now returns the flag.

Red herrings / jokes:
  - GET /admin -> "Nice try, the president is also doing 50 captchas."
  - An HTML comment references a `?skip=50` debug param that does nothing,
    for players who go looking for a shortcut instead of doing the replay.
  - A decoy `fast_track` cookie is read but intentionally ignored.

Run:  pip install flask pillow
      python3 app.py
"""

import hashlib
import io
import os
import random
import secrets
import string
import threading
import time

from flask import Flask, request, session, send_file, Response, redirect, url_for
from PIL import Image, ImageDraw, ImageFont, ImageFilter

app = Flask(__name__)
# Fixed via the FLASK_SECRET env var on the host (Render) so a worker
# restart doesn't invalidate every player's session cookie mid-event.
# Falls back to a random key for local runs where that doesn't matter.
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

STATE_LOCK = threading.Lock()  # gunicorn runs this with --threads, not just 1 request at a time

REQUIRED_SOLVES = 50
FLAG = "Securinets{the_prez_is_not_a_robot_in_the_end_0a076d}"

# Server-side state, keyed by a random session id we hand out ourselves.
# (Deliberately NOT trusting a client-editable cookie for the counter.)
STATE = {}  # sid -> {"count": int, "token": str, "answer": str, "done": bool}

# Club palette (navy / teal / silver), matches the Securinets ISI logo.
NAVY_DARK = (10, 20, 34)
NAVY = (15, 30, 54)
TEAL = (64, 224, 208)
TEAL_DIM = (40, 140, 135)
SILVER = (210, 220, 225)

ALPHABET = "".join(c for c in string.ascii_uppercase + string.digits if c not in "O0I1L")


def get_sid():
    sid = session.get("sid")
    if not sid or sid not in STATE:
        sid = secrets.token_hex(16)
        session["sid"] = sid
        with STATE_LOCK:
            STATE[sid] = {"count": 0, "token": None, "answer": None, "done": False}
    return sid


def find_font(size):
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    ]
    for c in candidates:
        if os.path.exists(c):
            return ImageFont.truetype(c, size)
    return ImageFont.load_default()


def make_captcha_image(text):
    """Renders `text` into a deliberately hostile-to-read PNG:
    gradient navy background, teal clutter lines, per-character jitter/
    rotation/scale, and a light blur + noise pass. Still solvable, just
    slow and annoying by eye."""
    W, H = 260, 90
    img = Image.new("RGB", (W, H), NAVY_DARK)
    draw = ImageDraw.Draw(img)

    # Diagonal gradient-ish background bands
    for y in range(H):
        blend = y / H
        r = int(NAVY_DARK[0] + (NAVY[0] - NAVY_DARK[0]) * blend)
        g = int(NAVY_DARK[1] + (NAVY[1] - NAVY_DARK[1]) * blend)
        b = int(NAVY_DARK[2] + (NAVY[2] - NAVY_DARK[2]) * blend)
        draw.line([(0, y), (W, y)], fill=(r, g, b))

    # Clutter: random teal-ish arcs/lines crossing through the text band
    for _ in range(14):
        x1, y1 = random.randint(0, W), random.randint(0, H)
        x2, y2 = random.randint(0, W), random.randint(0, H)
        shade = random.choice([TEAL_DIM, SILVER, TEAL])
        shade = tuple(max(0, min(255, c + random.randint(-30, 30))) for c in shade)
        draw.line([(x1, y1), (x2, y2)], fill=shade, width=1)

    # Scatter dot noise
    for _ in range(260):
        x, y = random.randint(0, W - 1), random.randint(0, H - 1)
        shade = random.choice([TEAL_DIM, SILVER])
        img.putpixel((x, y), shade)

    # Draw each character on its own tiny canvas, then rotate/scale/jitter
    # and paste it, so no two captchas (and no two letters) look alike.
    n = len(text)
    slot_w = W // n
    for i, ch in enumerate(text):
        size = random.randint(30, 40)
        font = find_font(size)
        glyph = Image.new("RGBA", (70, 70), (0, 0, 0, 0))
        gdraw = ImageDraw.Draw(glyph)
        fill = random.choice([SILVER, TEAL, (225, 230, 232)])
        gdraw.text((15, 10), ch, font=font, fill=fill + (255,))
        angle = random.randint(-32, 32)
        glyph = glyph.rotate(angle, resample=Image.BICUBIC, expand=True)
        scale = random.uniform(0.85, 1.15)
        glyph = glyph.resize((int(glyph.width * scale), int(glyph.height * scale)))

        px = i * slot_w + random.randint(-6, 6) + 8
        max_py = max(5, H - glyph.height - 5)
        py = random.randint(min(5, max_py), max_py)
        img.paste(glyph, (px, py), glyph)

    # A couple of overlapping "fake" faint glyphs as distractors
    for _ in range(2):
        ch = random.choice(ALPHABET)
        size = random.randint(22, 30)
        font = find_font(size)
        glyph = Image.new("RGBA", (60, 60), (0, 0, 0, 0))
        gdraw = ImageDraw.Draw(glyph)
        gdraw.text((10, 8), ch, font=font, fill=(*NAVY, 90))
        glyph = glyph.rotate(random.randint(-45, 45), expand=True)
        max_x = max(0, W - glyph.width)
        max_y = max(0, H - glyph.height)
        img.paste(glyph, (random.randint(0, max_x), random.randint(0, max_y)), glyph)

    img = img.filter(ImageFilter.GaussianBlur(0.6))
    return img


def new_captcha(sid):
    text = "".join(random.choice(ALPHABET) for _ in range(6))
    token = secrets.token_hex(8)
    STATE[sid]["token"] = token
    STATE[sid]["answer"] = text
    return token


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Securinets ISI :: Captcha of the President</title>
<style>
  :root {{
    --navy-dark: #0a1422;
    --navy: #0f1e36;
    --teal: #40e0d0;
    --teal-dim: #288c87;
    --silver: #d2dce1;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: radial-gradient(circle at 50% 0%, var(--navy) 0%, var(--navy-dark) 70%);
    font-family: 'Segoe UI', system-ui, sans-serif;
    color: var(--silver);
  }}
  .card {{
    background: rgba(15, 30, 54, 0.85);
    border: 1px solid var(--teal-dim);
    border-radius: 14px;
    padding: 2rem 2.5rem;
    width: 420px;
    box-shadow: 0 0 40px rgba(64, 224, 208, 0.08);
    text-align: center;
  }}
  h1 {{
    font-size: 1.15rem;
    letter-spacing: .04em;
    color: var(--teal);
    margin: 0 0 .25rem 0;
  }}
  .subtitle {{ font-size: .8rem; opacity: .65; margin-bottom: 1.4rem; }}
  .progress-wrap {{
    background: rgba(255,255,255,0.06);
    border-radius: 999px;
    height: 10px;
    margin: 0 0 1.4rem 0;
    overflow: hidden;
    border: 1px solid rgba(64,224,208,0.25);
  }}
  .progress-bar {{
    height: 100%;
    background: linear-gradient(90deg, var(--teal-dim), var(--teal));
    width: {pct}%;
    transition: width .3s ease;
  }}
  .count {{ font-size: .78rem; opacity: .75; margin-bottom: 1.2rem; }}
  img.captcha {{ border-radius: 8px; border: 1px solid var(--teal-dim); margin-bottom: 1rem; }}
  input[type=text] {{
    width: 100%;
    padding: .6rem .8rem;
    border-radius: 8px;
    border: 1px solid var(--teal-dim);
    background: rgba(255,255,255,0.04);
    color: var(--silver);
    font-size: 1rem;
    letter-spacing: .12em;
    text-align: center;
    text-transform: uppercase;
    margin-bottom: 1rem;
  }}
  input[type=text]:focus {{ outline: none; border-color: var(--teal); }}
  button {{
    width: 100%;
    padding: .65rem;
    border-radius: 8px;
    border: none;
    background: var(--teal);
    color: var(--navy-dark);
    font-weight: 700;
    letter-spacing: .04em;
    cursor: pointer;
  }}
  button:hover {{ background: #5bead9; }}
  .msg {{ margin-top: 1rem; font-size: .85rem; min-height: 1.2rem; }}
  .msg.ok {{ color: var(--teal); }}
  .msg.bad {{ color: #e06c6c; }}
  .msg.win {{ color: #ffd56b; font-weight: 700; }}
  footer {{ margin-top: 1.4rem; font-size: .68rem; opacity: .4; }}
</style>
</head>
<body>
  <div class="card">
    <h1>SECURINETS ISI &mdash; "Not a Robot" Checkpoint</h1>
    <div class="subtitle">prove your humanity {required} times to see the flag</div>
    <div class="progress-wrap"><div class="progress-bar"></div></div>
    <div class="count">{count} / {required} verified</div>

    <img class="captcha" src="/captcha.png?cb={cb}" alt="captcha">
    <br>
    <form id="f" method="POST" action="/verify">
      <input type="hidden" name="token" value="{token}">
      <input type="text" name="answer" maxlength="8" autocomplete="off" placeholder="type what you see" autofocus>
      <button type="submit">Verify</button>
    </form>
    <div class="msg {msgclass}">{msg}</div>
    <footer>Securinets ISI &middot; web/beginner &middot; <!-- debug: ?skip=50 was removed before launch, right? --></footer>
  </div>
</body>
</html>"""


@app.route("/", methods=["GET"])
def index():
    sid = get_sid()
    st = STATE[sid]
    token = new_captcha(sid)
    pct = min(100, int(st["count"] / REQUIRED_SOLVES * 100))
    return PAGE.format(
        pct=pct,
        required=REQUIRED_SOLVES,
        count=st["count"],
        token=token,
        cb=int(time.time() * 1000),
        msg="",
        msgclass="",
    )


@app.route("/captcha.png")
def captcha_png():
    sid = get_sid()
    st = STATE[sid]
    if not st["answer"]:
        new_captcha(sid)
        st = STATE[sid]
    img = make_captcha_image(st["answer"])
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    resp = send_file(buf, mimetype="image/png")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/verify", methods=["POST"])
def verify():
    sid = get_sid()
    st = STATE[sid]

    token = request.form.get("token", "")
    answer = request.form.get("answer", "").strip().upper()

    # Intentional bug: a solved (token, answer) pair is never rotated or
    # marked "used" -- it stays valid for as long as the session lives,
    # which is exactly what makes this replayable with Repeater/Intruder.
    if token and st["token"] == token and answer and st["answer"] == answer:
        with STATE_LOCK:
            if not st["done"]:
                st["count"] += 1
                if st["count"] >= REQUIRED_SOLVES:
                    st["done"] = True
        pct = min(100, int(st["count"] / REQUIRED_SOLVES * 100))
        msg = "correct. keep going." if not st["done"] else "threshold reached. check /flag"
        return PAGE.format(
            pct=pct, required=REQUIRED_SOLVES, count=st["count"], token=st["token"],
            cb=int(time.time() * 1000), msg=msg, msgclass="ok" if not st["done"] else "win",
        )

    pct = min(100, int(st["count"] / REQUIRED_SOLVES * 100))
    new_captcha(sid)  # wrong answers DO rotate, correct ones don't
    return PAGE.format(
        pct=pct, required=REQUIRED_SOLVES, count=st["count"], token=STATE[sid]["token"],
        cb=int(time.time() * 1000), msg="nope, try again.", msgclass="bad",
    )


@app.route("/flag")
def flag():
    sid = get_sid()
    if STATE[sid]["done"]:
        return Response(FLAG, mimetype="text/plain")
    left = REQUIRED_SOLVES - STATE[sid]["count"]
    return Response(f"not yet. {left} more verified captchas to go.\n", mimetype="text/plain")


@app.route("/admin")
def admin():
    return Response("Nice try, the president is also doing 50 captchas.\n", mimetype="text/plain")


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /flag\n"
        "Disallow: /dev-notes.txt\n"
    )
    return Response(body, mimetype="text/plain")


@app.route("/dev-notes.txt")
def dev_notes():
    body = (
        "todo before launch (bureau web team):\n"
        "- [x] gate the flag behind 50 successful captcha verifications per session\n"
        "- [ ] invalidate / rotate the captcha token+answer once it's been verified\n"
        "      correctly (low priority -- who's going to resend the same solved\n"
        "      request fifty times by hand lol)\n"
        "- [ ] rate limit /verify\n"
        "- [ ] remove the ?skip= debug param from index before launch -- wait did\n"
        "      we ever actually wire that up? check with the president\n"
        "- president wants this live before Securicon, ping him on Discord if\n"
        "  the counter resets on refresh, it shouldn't (server-side, not cookie)\n"
    )
    return Response(body, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
