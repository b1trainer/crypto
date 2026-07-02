package com.cryptoservice;

import com.cryptoservice.crypto.CryptoUtil;
import com.cryptoservice.db.DBConnPool;
import com.cryptoservice.db.DBMigrator;
import com.cryptoservice.service.EncryptionService;
import com.cryptoservice.service.HashService;
import com.cryptoservice.service.SignatureService;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoTest {

    private static HashService hashService;
    private static EncryptionService encryptionService;
    private static SignatureService signatureService;

    @BeforeAll
    static void setUp() throws Exception {
        CryptoUtil.registerProviders();

        String ksPath = "src/test/resources/certs/keystore.jks";
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksPath)) {
            ks.load(fis, "changeit".toCharArray());
        }

        PublicKey pub = ks.getCertificate("server").getPublicKey();
        PrivateKey pk = (PrivateKey) ks.getKey("server", "changeit".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("server");

        hashService = new HashService();
        encryptionService = new EncryptionService(pub, pk);
        signatureService = new SignatureService(pk, cert);
    }

    @Test
    public void testSignAttached() throws Exception {
        String original = "Hello, World!";
        byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);

        byte[] signed = signatureService.sign(originalBytes, Sign.ATTACHED);
        assertFalse(new CMSSignedData(signed).isDetachedSignature());
        assertNotNull(signed);

        boolean verified = signatureService.verify(originalBytes, signed);
        assertTrue(verified);
    }

    @Test
    public void testSignDetached() throws Exception {
        String original = "Hello, World!";
        byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);

        byte[] signed = signatureService.sign(originalBytes, Sign.DETACHED);
        assertTrue(new CMSSignedData(signed).isDetachedSignature());
        assertNotNull(signed);

        boolean verified = signatureService.verify(originalBytes, signed);
        assertTrue(verified);
    }

    @Test
    public void testSignNotVerifiedAttached() throws Exception {
        String original = "Hello, World!";
        byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);

        String corrupted = "Goodbye, World!";
        byte[] corruptedBytes = corrupted.getBytes(StandardCharsets.UTF_8);

        byte[] signed = signatureService.sign(originalBytes, Sign.ATTACHED);
        assertFalse(new CMSSignedData(signed).isDetachedSignature());
        assertNotNull(signed);

        boolean verified = signatureService.verify(corruptedBytes, signed);
        assertFalse(verified);
    }

    @Test
    public void testSignNotVerifiedDetached() throws Exception {
        String original = "Hello, World!";
        byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);

        String corrupted = "Goodbye, World!";
        byte[] corruptedBytes = corrupted.getBytes(StandardCharsets.UTF_8);

        byte[] signed = signatureService.sign(originalBytes, Sign.DETACHED);
        assertTrue(new CMSSignedData(signed).isDetachedSignature());
        assertNotNull(signed);

        boolean verified = signatureService.verify(corruptedBytes, signed);
        assertFalse(verified);
    }

    @Test
    public void testSha256Hash() throws Exception {
        String input = "Hello, World!";
        String hash = hashService.sha256(input);

        assertNotNull(hash);
        assertEquals(64, hash.length()); // SHA-256 = 64 hex chars

        assertEquals(hash, hashService.sha256(input));
    }

    @Test
    public void testSha256HashBytes() throws Exception {
        byte[] data = "test data".getBytes(StandardCharsets.UTF_8);
        String hash = hashService.sha256(data);

        assertNotNull(hash);
        assertEquals(64, hash.length());
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        String original = "Secret message for encryption test";
        byte[] data = original.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = encryptionService.encrypt(data);
        assertNotEquals(data.length, encrypted.length);

        byte[] decrypted = encryptionService.decrypt(encrypted);
        assertArrayEquals(data, decrypted);
        assertEquals(original, new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    public void testEncryptDecryptWithBase64() throws Exception {
        String original = "Test message";
        byte[] data = original.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = encryptionService.encrypt(data);
        String encoded = Base64.getEncoder().encodeToString(encrypted);

        byte[] decoded = Base64.getDecoder().decode(encoded);
        byte[] decrypted = encryptionService.decrypt(decoded);

        String decodedEncoded = new String(decrypted, StandardCharsets.UTF_8);
        assertEquals(original, decodedEncoded);
    }
}
