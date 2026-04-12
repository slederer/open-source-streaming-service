# Security Fix Instructions — Encoding Intel

Drop this into `/Users/slederer/encoding-customers/` and run with Claude Code.

---

## HIGH: Restrict Security Group

**Problem:** Security group `sg-028f2c09fbca733a9` allows ports 22 and 8081 from `0.0.0.0/0`. While the app has basic auth, SSH should not be open to the entire internet.

**Fix:**
```bash
MY_IP=$(curl -s ifconfig.me)/32
aws ec2 revoke-security-group-ingress --group-id sg-028f2c09fbca733a9 --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 revoke-security-group-ingress --group-id sg-028f2c09fbca733a9 --protocol tcp --port 8081 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-028f2c09fbca733a9 --protocol tcp --port 22 --cidr $MY_IP
aws ec2 authorize-security-group-ingress --group-id sg-028f2c09fbca733a9 --protocol tcp --port 8081 --cidr $MY_IP
```

## MEDIUM: Server Header Disclosure

**Problem:** `Server: gunicorn` header is exposed, revealing the WSGI server.

**Fix in `src/encoding_intel/web.py`:** Add after-request handler:
```python
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers.pop("Server", None)
    return response
```

## MEDIUM: No TLS

**Problem:** The app runs on plain HTTP (`http://54.175.156.169:8081`). Basic auth credentials are sent in cleartext.

**Fix:** Add nginx as a TLS-terminating reverse proxy (same pattern as ctv-scraper), or add TLS directly to gunicorn:
```bash
# Option A: self-signed (at minimum)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /opt/encoding-intel/ssl/key.pem -out /opt/encoding-intel/ssl/cert.pem \
  -subj "/CN=54.175.156.169" -addext "subjectAltName=IP:54.175.156.169"

# Update systemd unit to use gunicorn with SSL:
gunicorn -w 2 -b 0.0.0.0:8081 --certfile=/opt/encoding-intel/ssl/cert.pem --keyfile=/opt/encoding-intel/ssl/key.pem "encoding_intel.web:app"
```

## LOW: SSH HMAC SHA1 Algorithms

**Problem:** SSH accepts `hmac-sha1` MAC algorithms.

**Fix on EC2:** Edit `/etc/ssh/sshd_config`:
```
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
```
Then `sudo systemctl restart sshd`.

## Deploy & Verify

1. Run tests: `pytest`
2. Deploy via rsync + `sudo systemctl restart encoding-intel`
3. Verify headers: `curl -sI -u bitmovin:vodencodingintel2026 http://54.175.156.169:8081/ | grep -i server` → should NOT show "gunicorn"
4. Verify security headers present: `curl -sI -u bitmovin:vodencodingintel2026 http://54.175.156.169:8081/ | grep -i "x-content-type\|x-frame"` → should show both
