# SessionGuard — Attack & Defense Simulator

A mini project demonstrating Session Hijacking attacks and detection.

## What this project demonstrates

- **Phase 1 — The Attack**: XSS injection to steal session cookies and hijack admin sessions
- **Phase 2 — The Defense**: IP + User-Agent fingerprinting to detect hijacked sessions
- **Phase 3 — The Kill Switch**: Security alert page + Admin dashboard with attack logs

## Tech Stack

- Python (Flask)
- SQLite
- HTML/CSS

## Test Accounts

| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin123 | Admin |
| alice    | user123  | User  |

## How to run
```bash
pip install flask
python3 app.py
```

Visit `http://127.0.0.1:5000`

## Demo Flow

1. Login as `admin` in Chrome
2. Login as `alice` in Edge
3. As Alice — post XSS script in comments
4. As Admin — visit comments page — cookie stolen silently
5. Paste stolen cookie into Edge DevTools — logged in as Admin
6. Enable detection — repeat attack — security alert triggers
7. Check Admin Dashboard for attack log
