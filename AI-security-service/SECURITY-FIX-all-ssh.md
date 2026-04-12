# Security Fix Instructions — SSH Hardening (All 6 Instances)

Apply this to every EC2 instance via SSH.

---

## Applies to All 6 Instances

| Instance | IP | SSH Key |
|---|---|---|
| encoding-intel | 54.175.156.169 | `~/encoding-customers/deploy/encoding-intel-key.pem` |
| streaming-finder | 18.204.208.132 | `~/.ssh/streaming-finder-key.pem` |
| ctv-scraper | 54.237.146.188 | `~/encoding-customers/deploy/encoding-intel-key.pem` |
| personal-assistant | 18.234.99.71 | `~/.ssh/personal-assistant-key.pem` |
| startup-tracker | 54.235.166.159 | `~/.ssh/startup-tracker-key.pem` |
| trading-bot | 98.81.17.160 | `~/.ssh/trading-bot-key.pem` |

## Fix 1: Disable SHA1 HMAC Algorithms

**Problem:** All 6 instances accept `hmac-sha1` and `hmac-sha1-etm@openssh.com` MAC algorithms. SHA1 is deprecated.

**Fix:** On each instance, add to `/etc/ssh/sshd_config`:
```
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
```

Then restart: `sudo systemctl restart sshd`

**Script to apply to all instances:**
```bash
for host in \
  "ubuntu@54.175.156.169:~/encoding-customers/deploy/encoding-intel-key.pem" \
  "ubuntu@18.204.208.132:~/.ssh/streaming-finder-key.pem" \
  "ubuntu@54.237.146.188:~/encoding-customers/deploy/encoding-intel-key.pem" \
  "ec2-user@18.234.99.71:~/.ssh/personal-assistant-key.pem" \
  "ec2-user@54.235.166.159:~/.ssh/startup-tracker-key.pem" \
  "ec2-user@98.81.17.160:~/.ssh/trading-bot-key.pem"
do
  user_host=$(echo $host | cut -d: -f1)
  key=$(echo $host | cut -d: -f2)
  echo "=== Hardening SSH on $user_host ==="
  ssh -i "$key" "$user_host" 'grep -q "^MACs " /etc/ssh/sshd_config && echo "MACs line already exists — check manually" || echo "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512" | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart sshd && echo "Done"'
done
```

## Fix 2: Disable GSSAPI (3 instances)

**Problem:** 3 instances (trading-bot, personal-assistant, startup-tracker) accept `gssapi-keyex` and `gssapi-with-mic` authentication. This is unnecessary and expands the attack surface.

**Fix:** On those 3 instances, add to `/etc/ssh/sshd_config`:
```
GSSAPIAuthentication no
```

Then restart: `sudo systemctl restart sshd`

## Fix 3: Restrict SSH in Security Groups

**Problem:** All 6 security groups allow SSH from `0.0.0.0/0`.

**Fix:** See each project's individual SECURITY-FIX file for the specific `aws ec2 revoke/authorize` commands. The pattern is the same: replace `0.0.0.0/0` with your known IPs.

**Alternative:** Set up AWS SSM Session Manager to eliminate SSH exposure entirely:
```bash
# Install SSM agent (already pre-installed on Amazon Linux 2023)
# Attach AmazonSSMManagedInstanceCore IAM policy to the instance role
# Then connect via:
aws ssm start-session --target i-INSTANCEID
```
This removes the need for port 22 in security groups entirely.
