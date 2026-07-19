#!/bin/bash
# ====================================================================
# 开发环境 TLS 自签名证书生成脚本
# 生产环境请使用 Let's Encrypt / 商业 CA 签发的正式证书
# ====================================================================
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$CERT_DIR"

CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    # 检查证书是否过期
    EXPIRY=$(openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -n "$EXPIRY" ]; then
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || true)
        NOW_EPOCH=$(date +%s)
        if [ -n "$EXPIRY_EPOCH" ] && [ "$EXPIRY_EPOCH" -gt "$NOW_EPOCH" ]; then
            echo "✅ 证书有效，过期时间: $EXPIRY"
            exit 0
        fi
    fi
    echo "⚠️  证书已过期，重新生成..."
fi

echo "🔐 生成自签名 TLS 证书 (RSA 4096, 有效期 365 天)..."
openssl req -x509 -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 -nodes \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=UserManagement/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$KEY_FILE"  # 私钥仅所有者可读
echo "✅ 证书已生成: $CERT_DIR/"
echo "   证书文件: $CERT_FILE"
echo "   私钥文件: $KEY_FILE (权限 600)"
