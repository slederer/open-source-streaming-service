#!/bin/bash
# setup-ec2.sh — Run once on a fresh EC2 instance to install dependencies.
# Usage: ssh ec2-user@<IP> 'bash -s' < infra/scripts/setup-ec2.sh

set -euo pipefail

echo "==> Updating system packages..."
sudo dnf update -y

echo "==> Installing Docker..."
sudo dnf install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker ec2-user

echo "==> Installing Docker Compose..."
COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep tag_name | cut -d '"' -f 4)
sudo curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

echo "==> Installing Git..."
sudo dnf install -y git

echo "==> Installing Nginx + Certbot (for TLS)..."
sudo dnf install -y nginx certbot python3-certbot-nginx

echo "==> Installing ffmpeg (for live channel loop)..."
sudo dnf install -y ffmpeg || {
    echo "ffmpeg not in default repos, installing from RPM Fusion..."
    sudo dnf install -y https://download1.rpmfusion.org/free/el/rpmfusion-free-release-$(rpm -E %rhel).noarch.rpm || true
    sudo dnf install -y ffmpeg
}

echo "==> Creating app directory..."
sudo mkdir -p /opt/streaming/media
sudo chown -R ec2-user:ec2-user /opt/streaming

echo "==> Setup complete. Log out and back in for Docker group to take effect."
