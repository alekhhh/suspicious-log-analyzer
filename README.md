# Automated Suspicious Activity Log Analyzer

This project analyzes authentication logs for suspicious activity such as:

- multiple failed login attempts from the same IP
- brute-force style behavior against user accounts
- successful logins at unusual times

It includes:

- log parser
- detection engine
- alert output
- CSV report generator
- minimal web UI for uploads

## Supported Log Formats

The parser supports multiple real-world formats:

- Custom format:
  - `YYYY-MM-DD HH:MM:SS IP=<ip> USER=<username> ACTION=<login_success|login_failed>`
- Linux SSH auth logs (`auth.log`):
  - `Mar 31 02:41:11 host sshd[1001]: Failed password for admin from 172.16.0.7 port 22 ssh2`
  - `Mar 31 10:02:30 host sshd[1005]: Accepted password for frank from 192.168.1.44 port 22 ssh2`
- Apache access logs (login endpoints):
  - `203.0.113.10 - - [31/Mar/2026:11:01:01 +0000] "POST /login HTTP/1.1" 401 512`

## Web UI (Minimal)

Install dependencies:

```bash
pip install -r requirements.txt
```

Start server:

```bash
python app.py
```

Open:

`http://localhost:8000`

Use the form to upload one or more `.log` files and download the generated CSV report.
Use the form to upload `.log`, `.txt`, or `.csv` files and download the generated CSV report.

CSV input schema:

- `timestamp` (e.g. `2026-03-31 09:14:20` or ISO format)
- `ip`
- `user`
- `action` (`login_success` or `login_failed`)
- optional `endpoint` (defaults to `/login`)

Generated CSV columns:

- `IP Address`
- `Total Attempts`
- `Failed Attempts`
- `Threat Type`
- `Details`
- `Timestamp range`
- `Endpoint`
- `Severity`

## Optional Batch Mode

You can still run batch mode using local `input_logs/`:

```bash
python main.py
```

## Configuration

Edit defaults in `config.py`:

- thresholds (`failed_limit`, `brute_force_user_limit`, etc.)
- unusual login window
- output paths
- input directory

## Container Run (Docker)

Build image:

```bash
docker build -t log-analyzer .
```

Run container:

```bash
docker run --rm -p 8000:8000 log-analyzer
```
