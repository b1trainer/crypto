package com.cryptoservice.service;

import com.cryptoservice.Sign;
import com.cryptoservice.dao.ClearDocumentDao;
import com.cryptoservice.dao.CryptedDocumentDao;
import com.cryptoservice.dao.OperationLogDao;
import com.cryptoservice.dto.CryptoRequest;
import com.cryptoservice.dto.CryptoResponse;
import com.cryptoservice.model.ClearDocument;
import com.cryptoservice.model.CryptedDocument;
import com.cryptoservice.model.OperationLog;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

public class CryptoService {

    private final SignatureService signatureService;
    private final HashService hashService;
    private final EncryptionService encryptionService;

    public CryptoService(String ksPath, String ksPass, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksPath)) {
            ks.load(fis, ksPass.toCharArray());
        }
        PublicKey pub = ks.getCertificate(alias).getPublicKey();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, ksPass.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        this.signatureService = new SignatureService(pk, cert);
        this.hashService = new HashService();
        this.encryptionService = new EncryptionService(pub, pk);
    }

    /**
     * Sign PKCS#7
     */
    public CryptoResponse sign(CryptoRequest request) throws Exception {
        long start = System.currentTimeMillis();
        try {
            byte[] data = request.getDocumentData();
            ClearDocument doc = new ClearDocument(request.getDocumentName(), request.getDocumentType(), data);
            Long docId = ClearDocumentDao.save(doc);

            Sign opType = request.isDetached() ? Sign.DETACHED : Sign.ATTACHED;
            byte[] signature = signatureService.sign(data, opType);
            CryptedDocument result = new CryptedDocument(docId, request.getDocumentName(), "SIGN", signature);
            CryptedDocumentDao.save(result);

            logSuccess("SIGN", "SIGNED: " + request.getDocumentName(), System.currentTimeMillis() - start);

            return new CryptoResponse(Base64.getEncoder().encodeToString(signature), "SIGN");
        } catch (Exception e) {
            logError("SIGN", e.getMessage(), System.currentTimeMillis() - start);
            throw e;
        }
    }

    /**
     * Verify PKCS#7
     */
    public CryptoResponse verify(CryptoRequest request) throws Exception {
        long start = System.currentTimeMillis();
        try {
            String stripped = request.getDocumentName().replaceFirst("(?i)\\.p7s$", "");

            CryptedDocument saved = CryptedDocumentDao.getByDocumentName(stripped);
            if (saved == null) {
                throw new RuntimeException("Signed document not found");
            }

            byte[] original = request.getDocumentData();
            byte[] signature = saved.getData();

            boolean valid = signatureService.verify(original, signature);

            if (valid) {
                logSuccess("VERIFY", "VERIFIED: " + request.getDocumentName(), System.currentTimeMillis() - start);
            } else {
                logError("ENCRYPT", "Invalid signature", System.currentTimeMillis() - start);
            }

            return new CryptoResponse(valid ? "VERIFIED" : "INVALID", "VERIFY");
        } catch (Exception e) {
            logError("VERIFY", e.getMessage(), System.currentTimeMillis() - start);
            throw e;
        }
    }

    /**
     * Encrypt data
     */
    public CryptoResponse encrypt(CryptoRequest request) throws Exception {
        long start = System.currentTimeMillis();
        try {
            byte[] data = request.getDocumentData();

            ClearDocument doc = new ClearDocument(request.getDocumentName(), request.getDocumentType(), data);
            Long docId = ClearDocumentDao.save(doc);

            byte[] encrypted = encryptionService.encrypt(data);

            CryptedDocument result = new CryptedDocument(docId, request.getDocumentName(), "ENCRYPT", encrypted);
            CryptedDocumentDao.save(result);

            logSuccess("ENCRYPT", "ENCRYPTED: " + request.getDocumentName(), System.currentTimeMillis() - start);

            return new CryptoResponse(Base64.getEncoder().encodeToString(encrypted), "ENCRYPT");
        } catch (Exception e) {
            logError("ENCRYPT", e.getMessage(), System.currentTimeMillis() - start);
            throw e;
        }
    }

    /**
     * Decrypt data
     */
    public CryptoResponse decrypt(CryptoRequest request) throws Exception {
        long start = System.currentTimeMillis();
        try {
            String stripped = request.getDocumentName().replaceFirst("(?i)\\.p7m$", "");
            String contentType = ClearDocumentDao.getOriginalContentType(stripped);

            byte[] encrypted = Base64.getDecoder().decode(request.getDocumentData());
            byte[] decrypted = encryptionService.decrypt(encrypted);

            logSuccess("DECRYPT", "DECRYPTED: " + request.getDocumentName(), System.currentTimeMillis() - start);

            return new CryptoResponse(new String(decrypted), "DECRYPT", contentType);
        } catch (Exception e) {
            logError("DECRYPT", e.getMessage(), System.currentTimeMillis() - start);
            throw e;
        }
    }


    /**
     * Calculate SHA-256 hash
     */
    public String hash(CryptoRequest request) throws Exception {
        long start = System.currentTimeMillis();
        try {
            byte[] data = request.getDocumentData();

            String hashValue = hashService.sha256(data);

            ClearDocument doc = new ClearDocument(request.getDocumentName(), request.getDocumentType(), data);
            Long docId = ClearDocumentDao.save(doc);

            CryptedDocument result = new CryptedDocument(docId, request.getDocumentName(), "HASH_SHA256", hashValue.getBytes());
            CryptedDocumentDao.save(result);

            logSuccess("HASH_SHA256", "HASHED: " + request.getDocumentName(), System.currentTimeMillis() - start);

            return hashValue;
        } catch (Exception e) {
            logError("HASH_SHA256", e.getMessage(), System.currentTimeMillis() - start);
            throw e;
        }
    }

    public List<OperationLog> getOperations() {
        return OperationLogDao.getAll();
    }

    public boolean deleteDocument(String documentName) {
        return ClearDocumentDao.deleteByName(documentName) && CryptedDocumentDao.deleteByName(documentName);
    }

    private void logSuccess(String opType, String details, long durationMs) {
        OperationLog log = new OperationLog(opType, "SUCCESS", details, durationMs);
        OperationLogDao.save(log);
    }

    private void logError(String opType, String details, long durationMs) {
        OperationLog log = new OperationLog(opType, "ERROR", details, durationMs);
        OperationLogDao.save(log);
    }
}
