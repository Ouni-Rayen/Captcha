# Not a Robot Checkpoint

Beginner web CTF challenge — Securinets ISI style.

## What it is

Players must get **100** successful captcha verifications in one session to unlock the flag.

The intended (and much faster) solve is:

1. Check `/robots.txt` → find `/dev-notes.txt`
2. Read the notes (they only say “you need 100 verifications”)
3. Solve **one** captcha by hand
4. Replay the same `POST /verify` request 99 more times with Burp Intruder (Null payloads)
5. `GET /flag`

The bug: once a `(token, answer)` pair is verified correctly, the server never invalidates it. Replaying the exact same request keeps incrementing the counter.

## Local run

```bash
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
export FLASK_SECRET="something-long-and-random"
python app.py
```

Open http://127.0.0.1:5000

## Deploy on Render (free tier)

1. Push this folder to a GitHub repo.
2. Create a new **Web Service** on Render, connect the repo.
3. Settings:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT`
   - **Environment variable**: `FLASK_SECRET` = any long random string
4. Important: use **exactly 1 worker**. Multiple workers = progress is split across processes and players lose counts.

### Free-tier caveats

- Spins down after ~15 min of inactivity → in-memory progress is wiped.
- For the real CTF window, move to a paid instance or your own `.com` so the process stays alive.

## Custom domain

Once you have a domain pointed at the Render service (or your own VPS), just update DNS. No code changes needed.

## Flag

```
Securinets{the_prez_is_not_a_robot_in_the_end_0a076d}
```

## Hint ladder (for organizers only)

1. Have you checked this site’s robots.txt?
2. There’s a file the dev probably didn’t mean to leave reachable. Read it.
3. You only need to solve the captcha once correctly. After that, think about what makes a request “replayable”.
4. Burp has a tool that resends one request many times automatically. It’s not Repeater.
5. Intruder → Sniper → Null payloads → generate 100 → Start attack.
