# Security Fix Instructions — Startup Tracker

Drop this into `/Users/slederer/startup_tracker/` and run with Claude Code.

---

## MEDIUM: No TLS — Plain HTTP Only

**Problem:** The Next.js app at `http://54.235.166.159:3000` serves everything over plain HTTP. All traffic — including any session tokens, cookies, or auth credentials — is transmitted in cleartext. Anyone on the network path can intercept data.

**Fix — Option A (nginx reverse proxy with Let's Encrypt):**
```bash
# On EC2:
sudo yum install -y nginx
sudo amazon-linux-extras install epel
sudo yum install -y certbot python3-certbot-nginx

# If using a domain:
sudo certbot --nginx -d startups.yourdomain.com

# If IP-only, self-signed (at minimum):
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/startup.key -out /etc/ssl/certs/startup.crt \
  -subj "/CN=54.235.166.159" -addext "subjectAltName=IP:54.235.166.159"
```

Configure nginx to proxy 443 → 3000:
```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/startup.crt;
    ssl_certificate_key /etc/ssl/private/startup.key;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Then update the security group to allow 443 instead of (or in addition to) 3000.

**Fix — Option B (quick, no nginx):** Use Node's built-in HTTPS in a custom server, or add TLS termination at the PM2 level.

## MEDIUM: No Rate Limiting

**Problem:** 30 rapid sequential requests to `/login` all returned 200 with no throttling. No 429 responses ever sent. This enables brute-force attacks against the login page.

**Fix:** Add rate limiting middleware in Next.js. Options:

1. **nginx rate limiting** (if adding nginx per TLS fix above):
   ```nginx
   limit_req_zone $binary_remote_addr zone=login:10m rate=5r/s;
   
   location /login {
       limit_req zone=login burst=10 nodelay;
       proxy_pass http://127.0.0.1:3000;
   }
   ```

2. **Next.js middleware** (`src/middleware.ts`):
   ```typescript
   import { NextResponse } from 'next/server';
   import type { NextRequest } from 'next/server';
   
   const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
   
   export function middleware(request: NextRequest) {
     if (request.nextUrl.pathname === '/login') {
       const ip = request.headers.get('x-forwarded-for') || 'unknown';
       const now = Date.now();
       const record = rateLimitMap.get(ip);
       
       if (record && now < record.resetTime) {
         record.count++;
         if (record.count > 10) {
           return new NextResponse('Too Many Requests', { status: 429 });
         }
       } else {
         rateLimitMap.set(ip, { count: 1, resetTime: now + 60000 });
       }
     }
     return NextResponse.next();
   }
   ```

## MEDIUM: Missing Security Headers + Info Disclosure

**Problem:** Response headers are:
- `X-Powered-By: Next.js` — reveals framework
- Missing `Strict-Transport-Security`
- Missing `Content-Security-Policy`
- Missing `X-Frame-Options`
- Missing `X-Content-Type-Options`

**Fix in `next.config.ts`:**
```typescript
const nextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'X-DNS-Prefetch-Control', value: 'on' },
          // Add after enabling HTTPS:
          // { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
        ],
      },
    ];
  },
};
```

## HIGH: Restrict Security Group

**Problem:** Security group `sg-0a6896ae4256672d4` allows ports 22, 80, and 3000 from `0.0.0.0/0`.

**Fix:**
```bash
MY_IP=$(curl -s ifconfig.me)/32
for port in 22 80 3000; do
  aws ec2 revoke-security-group-ingress --group-id sg-0a6896ae4256672d4 --protocol tcp --port $port --cidr 0.0.0.0/0
  aws ec2 authorize-security-group-ingress --group-id sg-0a6896ae4256672d4 --protocol tcp --port $port --cidr $MY_IP
done
```

## Deploy & Verify

1. Run tests: `npm test`
2. Deploy via rsync + rebuild on EC2
3. Verify `X-Powered-By` gone: `curl -sI http://54.235.166.159:3000/dashboard | grep -i powered` → should return nothing
4. Verify security headers: `curl -sI http://54.235.166.159:3000/dashboard | grep -i "x-content-type\|x-frame"` → should show both headers
5. If TLS added: `curl -sI https://54.235.166.159/dashboard` → `200` with `Strict-Transport-Security` header
