#!/bin/bash
# deploy.sh — Deploy the streaming service to the EC2 instance.
# Usage: ./infra/scripts/deploy.sh <EC2_IP>

set -euo pipefail

EC2_IP="${1:?Usage: deploy.sh <EC2_IP>}"
EC2_USER="ec2-user"
APP_DIR="/opt/streaming/app"

echo "==> Deploying to ${EC2_USER}@${EC2_IP}..."

# Sync code to EC2 (excluding large/sensitive files)
rsync -avz --delete \
    --exclude '.git' \
    --exclude 'node_modules' \
    --exclude '.next' \
    --exclude '.terraform' \
    --exclude '*.tfstate*' \
    --exclude '.env' \
    --exclude 'ios/' \
    . "${EC2_USER}@${EC2_IP}:${APP_DIR}/"

echo "==> Building and starting services on EC2..."
ssh "${EC2_USER}@${EC2_IP}" "cd ${APP_DIR} && docker-compose build && docker-compose up -d"

echo "==> Deployment complete."
echo "    App: http://${EC2_IP}"
echo "    API: http://${EC2_IP}/api/videos"
