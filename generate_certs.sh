#!/bin/bash

set -e

echo "========================================"
echo " Crypto Keys & Certificates Generator"
echo "========================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${SCRIPT_DIR}/certs"
PASSWORD="changeit"
JAVA_HOME="C:/Users/User/.jdks/corretto-17.0.13"

mkdir -p "${BASE_DIR}"

echo "[1/8] Генерация RSA ключа сервера (4096 bit)..."
openssl genrsa -out "${BASE_DIR}/server.key" 4096
echo "  OK: server.key"

echo "[2/8] Генерация самоподписанного сертификата сервера..."
openssl req -new -x509 \
    -key "${BASE_DIR}/server.key" \
    -out "${BASE_DIR}/server.crt" \
    -days 365 \
    -subj "//C=RU/ST=Moscow/L=Moscow/O=CryptoServices/OU=Server/CN=localhost"
echo "  OK: server.crt"

echo "[3/8] Создание PKCS12 хранилища (keystore)..."
openssl pkcs12 -export \
    -out "${BASE_DIR}/keystore.p12" \
    -inkey "${BASE_DIR}/server.key" \
    -in "${BASE_DIR}/server.crt" \
    -name "server" \
    -passout pass:${PASSWORD}
echo "  OK: keystore.p12"

echo "[4/8] Создание JKS хранилища..."
"$JAVA_HOME/bin/keytool.exe" -importkeystore \
    -deststorepass "${PASSWORD}" \
    -destkeystore "${BASE_DIR}/keystore.jks" \
    -deststoretype JKS \
    -srckeystore "${BASE_DIR}/keystore.p12" \
    -srcstoretype PKCS12 \
    -srcstorepass "${PASSWORD}" \
    -alias server \
    -noprompt
echo "  OK: keystore.jks"

echo "[5/8] Создание Truststore..."
"$JAVA_HOME/bin/keytool.exe" -import \
    -alias server \
    -file "${BASE_DIR}/server.crt" \
    -storepass "${PASSWORD}" \
    -keystore "${BASE_DIR}/truststore.jks" \
    -storetype JKS \
    -noprompt
echo "  OK: truststore.jks"

echo "[6/8] Генерация RSA ключа клиента (2048 bit)..."
openssl genrsa -out "${BASE_DIR}/client.key" 2048
echo "  OK: client.key"

echo "[7/8] Создание клиентского сертификата..."
openssl req -new \
    -key "${BASE_DIR}/client.key" \
    -out "${BASE_DIR}/client.csr" \
    -subj "//C=RU/ST=Moscow/L=Moscow/O=CryptoServices/OU=Client/CN=client"

openssl x509 -req \
    -in "${BASE_DIR}/client.csr" \
    -CA "${BASE_DIR}/server.crt" \
    -CAkey "${BASE_DIR}/server.key" \
    -CAcreateserial \
    -out "${BASE_DIR}/client.crt" \
    -days 365
echo "  OK: client.crt"

echo "[8/8] Создание клиентского PKCS12..."
openssl pkcs12 -export \
    -out "${BASE_DIR}/client.p12" \
    -inkey "${BASE_DIR}/client.key" \
    -in "${BASE_DIR}/client.crt" \
    -name "client" \
    -passout pass:${PASSWORD}
echo "  OK: client.p12"

echo ""
echo "========================================"
echo " Генерация завершена успешно"
echo "========================================"
echo ""
echo " Каталог: ${BASE_DIR}"
echo ""
echo " Сервер:"
echo "   server.key       - RSA приватный ключ (4096 bit)"
echo "   server.crt       - X.509 сертификат сервера"
echo "   keystore.p12     - PKCS12 хранилище (пароль: ${PASSWORD})"
echo "   keystore.jks     - Java KeyStore (пароль: ${PASSWORD})"
echo "   truststore.jks   - Trust Store (пароль: ${PASSWORD})"
echo ""
echo " Клиент:"
echo "   client.key       - RSA приватный ключ (2048 bit)"
echo "   client.crt       - X.509 сертификат клиента"
echo "   client.p12       - PKCS12 клиента (пароль: ${PASSWORD})"
echo ""
echo "========================================"
