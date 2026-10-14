import os
import random
import string
from io import BytesIO

from flask import (
    Flask, request, session,
    render_template, send_file, jsonify, make_response
)
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageEnhance
import secrets
import base64

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me-in-production-please-use-env")

# In-memory stores (single worker recommended)
progress = {}                 # session_id -> successful verification count
pending_tokens = {}           # token -> expected answer (fresh captchas)
verified_tokens = {}          # token -> answer  (once correct, NEVER invalidated — the bug)

REQUIRED_SOLVES = 100
FLAG = "Securinets{thE_preZ_is_n0t_4_R0b0t_iN_tHe_enD}"

def get_session_id():
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)
    return session["sid"]

def get_progress():
    sid = get_session_id()
    return progress.get(sid, 0)

def increment_progress():
    sid = get_session_id()
    progress[sid] = progress.get(sid, 0) + 1
    return progress[sid]

def generate_captcha_text(length=5):
    # Mix of similar-looking characters to make it harder
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(random.choices(chars, k=length))

def create_captcha_image(text):
    """Generate a deliberately hard-to-read captcha image."""
    width, height = 280, 90
    # Dark navy background matching theme
    bg_color = (10, 20, 40)
    image = Image.new("RGB", (width, height), bg_color)
    draw = ImageDraw.Draw(image)

    # Try to load a font, fall back to default
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 42)
    except Exception:
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", 42)
        except Exception:
            font = ImageFont.load_default()

    # Draw noise lines (teal-ish)
    for _ in range(18):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        color = (
            random.randint(0, 40),
            random.randint(120, 200),
            random.randint(140, 220),
        )
        draw.line([(x1, y1), (x2, y2)], fill=color, width=random.randint(1, 2))

    # Draw dots / speckles
    for _ in range(120):
        x, y = random.randint(0, width - 1), random.randint(0, height - 1)
        color = (
            random.randint(20, 60),
            random.randint(80, 160),
            random.randint(100, 180),
        )
        draw.point((x, y), fill=color)

    # Draw each character with jitter, slight rotation simulation via offset, and varying color
    char_width = width // (len(text) + 1)
    for i, char in enumerate(text):
        x = 20 + i * char_width + random.randint(-8, 8)
        y = random.randint(8, 25)
        # Teal / silver-ish text with variation
        color = (
            random.randint(180, 255),
            random.randint(200, 255),
            random.randint(210, 255),
        )
        # Draw multiple times with slight offset for "jitter"
        for dx, dy in [(-1, 0), (1, 0), (0, -1), (0, 1), (0, 0)]:
            draw.text((x + dx, y + dy), char, font=font, fill=color)

    # Add distractor characters faintly
    for _ in range(4):
        distractor = random.choice(string.ascii_uppercase + string.digits)
        x = random.randint(10, width - 30)
        y = random.randint(5, height - 30)
        color = (30, 60, 90)
        draw.text((x, y), distractor, font=font, fill=color)

    # Mild blur / noise to make OCR harder and human reading annoying
    image = image.filter(ImageFilter.GaussianBlur(radius=0.6))
    enhancer = ImageEnhance.Contrast(image)
    image = enhancer.enhance(1.3)

    # Final noise layer
    pixels = image.load()
    for _ in range(80):
        x, y = random.randint(0, width - 1), random.randint(0, height - 1)
        r, g, b = pixels[x, y]
        pixels[x, y] = (
            min(255, r + random.randint(-20, 20)),
            min(255, g + random.randint(-20, 20)),
            min(255, b + random.randint(-20, 20)),
        )

    return image

@app.route("/")
def index():
    return render_template("index.html", progress=get_progress(), required=REQUIRED_SOLVES)

@app.route("/new")
def new_captcha():
    """Return JSON with token + base64 image."""
    text = generate_captcha_text()
    token = secrets.token_urlsafe(24)
    pending_tokens[token] = text.upper()

    img = create_captcha_image(text)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode()

    return jsonify({
        "token": token,
        "image": f"data:image/png;base64,{b64}"
    })

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or request.form
    token = data.get("token") or data.get("captcha_token")
    answer = (data.get("answer") or data.get("captcha_answer") or "").strip().upper()

    if not token or not answer:
        return jsonify({"success": False, "message": "Missing token or answer"}), 400

    # Intentional design flaw:
    # Once a (token, answer) pair has been verified correctly it is never
    # invalidated. The same POST can be replayed indefinitely and each
    # replay still counts as a successful verification.
    expected = pending_tokens.get(token) or verified_tokens.get(token)

    if expected is None:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 400

    if answer == expected:
        # Permanently keep the token valid (the bug players must discover)
        verified_tokens[token] = expected
        pending_tokens.pop(token, None)

        increment_progress()
        return jsonify({
            "success": True,
            "message": "Correct!"
        })
    else:
        return jsonify({"success": False, "message": "Wrong answer. Try a new captcha."}), 400

@app.route("/flag")
def flag():
    if get_progress() >= REQUIRED_SOLVES:
        return jsonify({"flag": FLAG})
    return jsonify({
        "error": "Not enough verifications yet.",
        "progress": get_progress(),
        "required": REQUIRED_SOLVES
    }), 403

@app.route("/admin")
def admin():
    return "Nice try, the president is also doing 100 captchas.", 403

@app.route("/robots.txt")
def robots():
    return """User-agent: *
Disallow: /admin
Disallow: /flag
Disallow: /dev-notes.txt
""", 200, {"Content-Type": "text/plain"}

@app.route("/dev-notes.txt")
def dev_notes():
    # Only tell them they need 100 successful verifications.
    # No mention of the token-reuse bug — they must discover it themselves.
    notes = """
Players must successfully verify the captcha 100 times in the same session before the flag is released.

"""
    return notes, 200, {"Content-Type": "text/plain"}

@app.route("/progress")
def progress_endpoint():
    return jsonify({
        "progress": get_progress(),
        "required": REQUIRED_SOLVES
    })

if __name__ == "__main__":
    # For local testing
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

