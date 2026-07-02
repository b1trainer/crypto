package com.cryptoservice.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class EncryptionService {
    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public EncryptionService(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * Encrypt data with AES-GCM, encrypt AES key with RSA.
     * Output: [encrypted AES key length (4B)] [encrypted AES key] [IV (12B)] [encrypted data]
     */
    public byte[] encrypt(byte[] data) throws Exception {
        // Создаем генератор AES-ключей
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

        //Настраиваем на 256 бит (максимальная стойкость), используем криптостойкий генератор случайных чисел
        keyGen.init(AES_KEY_SIZE, new SecureRandom());
        SecretKey aesKey = keyGen.generateKey();

        // IV (вектор инициализации) — 12 случайных байт
        byte[] iv = new byte[GCM_IV_LENGTH];

        // В GCM-режиме IV должен быть уникальным для каждого шифрования (даже с одним ключом!)
        new SecureRandom().nextBytes(iv);

        // Создаем шифратор AES в режиме GCM
        Cipher aesCipher = Cipher.getInstance(AES_ALGO, BouncyCastleProvider.PROVIDER_NAME);

        // Настраиваем параметры GCM: 128-битный тег аутентификации и IV
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // инициализируем в режиме шифрования
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        // Шифруем все данные
        // todo потоковое шифрование для больших файлов чтобы не получить OOM
        byte[] encryptedData = aesCipher.doFinal(data);

        // Создаем RSA-шифратор с PKCS#1 дополнением
        // PKCS#1 добавляет случайные байты, делая каждый шифротекст уникальным
        Cipher rsaCipher = Cipher.getInstance("RSA/None/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);

        // инициализируем публичным ключом (может шифровать, но не расшифровывать)
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Получаем байты AES-ключа (32 байта) и шифруем эти 32 байта RSA. На выходе ~256 байт
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Сборка финального сообщения
        int totalLen = 4 + encryptedAesKey.length + iv.length + encryptedData.length;
        ByteBuffer buffer = ByteBuffer.allocate(totalLen);

        // Пишем длину зашифрованного AES-ключа (чтобы при расшифровке знать, сколько читать)
        buffer.putInt(encryptedAesKey.length);

        // Пишем сам зашифрованный AES-ключ
        buffer.put(encryptedAesKey);

        // Пишем IV (нужен для расшифровки)
        buffer.put(iv);

        // Пишем зашифрованные данные
        buffer.put(encryptedData);

        return buffer.array();
    }

    /**
     * Decrypt data: decrypt AES key with RSA, decrypt data with AES-GCM.
     */
    public byte[] decrypt(byte[] encryptedInput) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encryptedInput);

        // Читаем первые 4 байта — это длина зашифрованного AES-ключа
        int aesKeyLen = buffer.getInt();
        byte[] encryptedAesKey = new byte[aesKeyLen];
        buffer.get(encryptedAesKey);

        // Читаем IV (ровно 12 байт)
        byte[] iv = new byte[GCM_IV_LENGTH];
        buffer.get(iv);

        // Читаем оставшиеся зашифрованные данные
        byte[] encryptedData = new byte[buffer.remaining()];
        buffer.get(encryptedData);

        // Decrypt AES key with RSA private key
        Cipher rsaCipher = Cipher.getInstance("RSA/None/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);

        // инициализируем приватным ключом (может расшифровать только владелец)
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Расшифровываем AES-ключ. На выходе 32 байта исходного ключа
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);

        // Восстанавливаем AES-ключ из байт
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Decrypt data with AES-GCM
        Cipher aesCipher = Cipher.getInstance(AES_ALGO, BouncyCastleProvider.PROVIDER_NAME);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // инициализируем в режиме расшифровки с тем же IV
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        // Расшифровываем данные. Если данные повреждены → исключение
        return aesCipher.doFinal(encryptedData);
    }
}
