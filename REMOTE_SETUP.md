# SecureMonitor AI remote monitoring (starter)

## What this adds
- `/remote`: password-token protected remote-device dashboard.
- `POST /api/remote/ingest`: accepts system usage metrics from a consent-based agent.
- `GET /api/remote/devices`: requires the admin bearer token.
- `monitor_agent.py`: reports CPU, RAM, disk, network throughput, and optional battery state.

This is a starter for a college demonstration. It reports usage anomalies, not malware detection. The SQLite database must be placed on persistent storage when hosted; otherwise a hosting restart may erase readings. Use HTTPS and never commit tokens to GitHub.

## Server environment variables
Set these in your hosting provider's secret/environment settings:
- `SECUREMONITOR_ADMIN_TOKEN`: a long random secret used to open `/remote`.
- `SECUREMONITOR_DEVICE_TOKENS`: JSON object mapping device labels to unique tokens, e.g. `{"sirisha-laptop":"PASTE_A_LONG_RANDOM_DEVICE_TOKEN","friend-laptop":"PASTE_ANOTHER_LONG_RANDOM_TOKEN"}`.
- `SECUREMONITOR_DB`: optional path to a persistent SQLite file on a mounted disk.

Generate secrets locally in Windows Command Prompt with `py -c "import secrets; print(secrets.token_urlsafe(32))"`. Run it separately for the admin token and each device token. Keep them private. Never paste actual secrets into chat or commit them.

## Agent setup (each consenting computer)
Install Python, then in Command Prompt run:
`py -m pip install psutil requests`
Set environment variables in that Command Prompt (replace placeholders):
`set SECUREMONITOR_SERVER_URL=https://YOUR-HOSTED-SITE`
`set SECUREMONITOR_DEVICE_TOKEN=PASTE_THIS_DEVICE_TOKEN`
`set SECUREMONITOR_DEVICE_ID=friend-laptop`
Then run:
`py monitor_agent.py`

The device token must match one entry in the server's `SECUREMONITOR_DEVICE_TOKENS` mapping. The device label shown in the dashboard is assigned by the server token mapping, not trusted from the agent. For localhost-only testing, `http://127.0.0.1:5000` is allowed; remote use requires HTTPS.

## Run the website locally
Install dependencies: `py -m pip install -r requirements.txt`
Run: `py app.py`
Open `http://127.0.0.1:5000` for the original dashboard and `http://127.0.0.1:5000/remote` for the remote dashboard. Remote endpoints remain unusable until the environment tokens are configured.

## Before public deployment
- Set strong, unique tokens in hosting environment settings; do not put them in source code.
- Use HTTPS, a production WSGI server (for example Gunicorn on supported hosts), and persistent storage for SQLite.
- Limit who can access `/remote`; the admin token grants access to all reported device metrics.
- Tell each device owner exactly what metrics are collected and obtain consent. Do not run the agent on another person's device without their informed permission.
