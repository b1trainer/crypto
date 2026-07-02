package com.cryptoservice.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class HashService {

    public HashService() {
    }

    public String sha256(String message) throws Exception {
        return sha256(message.getBytes(StandardCharsets.UTF_8));
    }

    public String sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
        byte[] hash = md.digest(data);
        return bytesToHex(hash);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
