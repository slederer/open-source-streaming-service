# Security Fix Instructions — CTV App Scraper

Drop this into `/Users/slederer/ctv-app-scraper/` and run with Claude Code.

---

## HIGH: Self-Signed TLS Certificate with IP Mismatch

**Problem:** The nginx TLS cert at `54.237.146.188:443` is self-signed with `CN=44.208.167.139` — a different IP than the current Elastic IP (`54.237.146.188`). No SAN entries. This means:
- No server identity verification is possible
- Browsers show security warnings
- Vulnerable to MITM attacks

**Fix:** Replace the self-signed cert with a Let's Encrypt certificate. Since this is an IP-only service (no domain), options are:

Option A (recommended): Register a cheap domain (or use a subdomain of an existing one) and point it at `54.237.146.188`, then use certbot:
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d ctv-intel.yourdomain.com
```

Option B: If staying IP-only, regenerate the self-signed cert with the correct IP:
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/ctv-selfsigned.key \
  -out /etc/ssl/certs/ctv-selfsigned.crt \
  -subj "/CN=54.237.146.188" \
  -addext "subjectAltName=IP:54.237.146.188"
sudo systemctl restart nginx
```

## HIGH: nginx 1.18.0 is End-of-Life

**Problem:** `Server: nginx/1.18.0 (Ubuntu)` — this version reached EOL in April 2023. Multiple known CVEs exist for 1.18.x.

**Fix on EC2:**
```bash
sudo apt update && sudo apt install -y nginx
nginx -v  # should be 1.26+ on Ubuntu 22.04+ repos
sudo systemctl restart nginx
```

If the Ubuntu repos don't have a recent version, use the nginx mainline PPA:
```bash
sudo add-apt-repository ppa:ondrej/nginx-mainline
sudo apt update && sudo apt install -y nginx
```

## HIGH: Restrict Security Group

**Problem:** Security group `sg-00749d1e539df23bc` allows ports 22, 443, and 8080 from `0.0.0.0/0`.

**Fix:**
```bash
MY_IP=$(curl -s ifconfig.me)/32
for port in 22 443 8080; do
  aws ec2 revoke-security-group-ingress --group-id sg-00749d1e539df23bc --protocol tcp --port $port --cidr 0.0.0.0/0
  aws ec2 authorize-security-group-ingress --group-id sg-00749d1e539df23bc --protocol tcp --port $port --cidr $MY_IP
done
```

## MEDIUM: Werkzeug Development Server Exposed on Port 8080

**Problem:** Port 8080 runs `Werkzeug/3.1.6 Python/3.10.12` (Flask's development server) directly exposed to the internet. The `Server` header discloses the exact framework and Python version.

**What to check:** The web process is managed by systemd (`ctv-web.service`). Verify whether it's running Flask's dev server or gunicorn. If it's the dev server:

**Fix:** Switch to gunicorn in the systemd unit:
```bash
# In ctv-web.service ExecStart:
ExecStart=/home/ubuntu/ctv-app-scraper/venv/bin/gunicorn -w 2 -b 0.0.0.0:8080 "ctv_scraper.web:app"
```

Since nginx already proxies 443 → 8080, also consider closing port 8080 in the security group entirely and only exposing 443. Then the Werkzeug header is never visible externally.

## MEDIUM: Suppress Server Headers

**Fix in `src/ctv_scraper/web.py`:** Add after-request handler:
```python
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers.pop("Server", None)
    return response
```

Also configure nginx to suppress its version:
```nginx
# In /etc/nginx/nginx.conf, inside http block:
server_tokens off;
```

## Deploy & Verify

1. Run tests: `python3 -m pytest -q`
2. Deploy via scp + `sudo systemctl restart ctv-web` (and `sudo systemctl restart nginx` for nginx changes)
3. Verify cert: `echo | openssl s_client -connect 54.237.146.188:443 2>/dev/null | openssl x509 -noout -subject` → should show correct IP or domain
4. Verify nginx version hidden: `curl -skI https://54.237.146.188/ | grep -i server` → should NOT show version number
5. Verify auth: `curl -sk -o /dev/null -w "%{http_code}" https://54.237.146.188/` → `401`
6. Verify with creds: `curl -sk -o /dev/null -w "%{http_code}" -u bitmovin:ctvintel2026 https://54.237.146.188/` → `200`
