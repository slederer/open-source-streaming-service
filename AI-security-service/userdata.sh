#!/bin/bash
set -ex

# Update system
dnf update -y

# Install core tools
dnf install -y git python3 python3-pip nmap nmap-ncat golang openssl bind-utils whois traceroute jq unzip tar wget

# Install pip-based security tools
pip3 install sqlmap requests beautifulsoup4 paramiko

# Install Nuclei (latest)
NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name)
wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" -O /tmp/nuclei.zip
unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei
chmod +x /usr/local/bin/nuclei

# Install Nikto
cd /opt
git clone https://github.com/sullo/nikto.git
ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install ffuf (fast fuzzer)
FFUF_VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | jq -r .tag_name)
wget -q "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz
tar xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf
chmod +x /usr/local/bin/ffuf

# Install testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl

# Install httpx
HTTPX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | jq -r .tag_name)
wget -q "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip" -O /tmp/httpx.zip
unzip -o /tmp/httpx.zip -d /usr/local/bin/ httpx
chmod +x /usr/local/bin/httpx

# Update Nuclei templates
su - ec2-user -c "nuclei -update-templates" || true

# Create targets file with all 6 instances
cat > /home/ec2-user/targets.txt << 'TARGETS'
54.175.156.169  # encoding-intel
18.204.208.132  # streaming-finder
54.237.146.188  # ctv-scraper
18.234.99.71    # personal-assistant
54.235.166.159  # startup-tracker
98.81.17.160    # trading-bot
TARGETS

chown ec2-user:ec2-user /home/ec2-user/targets.txt

# Signal completion
touch /home/ec2-user/.setup-complete
echo "SECSCAN SETUP COMPLETE" >> /var/log/cloud-init-output.log
