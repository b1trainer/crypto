package com.cryptoservice.service;

import com.cryptoservice.crypto.CryptoUtil;
import com.cryptoservice.dao.ClearDocumentDao;
import com.cryptoservice.dao.CryptedDocumentDao;
import com.cryptoservice.db.DBConnPool;
import com.cryptoservice.db.DBMigrator;
import com.cryptoservice.dto.CryptoRequest;
import com.cryptoservice.dto.CryptoResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {

    private static CryptoService cryptoService;

    @BeforeAll
    static void beforeAll() throws Exception {
        CryptoUtil.registerProviders();
        DBMigrator.migrate(DBConnPool.getDataSource());

        String ksPath = "src/test/resources/certs/keystore.jks";
        String ksPass = "changeit";

        cryptoService = new CryptoService(ksPath, ksPass, "server");
    }

    @Test
    void signValid() throws Exception {
        ClearDocumentDao.deleteByName("text.txt");
        CryptedDocumentDao.deleteByName("text.txt");

        CryptoRequest requestSign = new CryptoRequest(
                "text.txt",
                "text/plain",
                "Hello, World!".getBytes(),
                false
        );

        CryptoResponse responseSign = cryptoService.sign(requestSign);
        assertNotNull(responseSign);
        assertEquals("SIGN", responseSign.getOperation());

        CryptoResponse responseVerify = cryptoService.verify(requestSign);
        assertEquals("VERIFIED", responseVerify.getResult());
    }

    @Test
    void signInvalid() throws Exception {
        ClearDocumentDao.deleteByName("text2.txt");
        CryptedDocumentDao.deleteByName("text2.txt");

        CryptoRequest requestSign = new CryptoRequest(
                "text2.txt",
                "text/plain",
                "Hello, World!".getBytes(),
                false
        );

        CryptoResponse responseSign = cryptoService.sign(requestSign);
        assertNotNull(responseSign);
        assertEquals("SIGN", responseSign.getOperation());

        requestSign.setDocumentData("Goodbye, World!".getBytes());

        CryptoResponse responseVerify = cryptoService.verify(requestSign);
        assertEquals("INVALID", responseVerify.getResult());
    }

    @Test
    void encryptDecrypt() throws Exception {
        ClearDocumentDao.deleteByName("text3.txt");
        CryptedDocumentDao.deleteByName("text3.txt");

        String initData = "Hello, World!";

        CryptoRequest requestSign = new CryptoRequest(
                "text3.txt",
                "text/plain",
                initData.getBytes(),
                false
        );

        CryptoResponse responseSign = cryptoService.encrypt(requestSign);
        assertNotNull(responseSign);
        assertEquals("ENCRYPT", responseSign.getOperation());

        requestSign.setDocumentData(responseSign.getResult().getBytes());

        CryptoResponse responseVerify = cryptoService.decrypt(requestSign);
        assertEquals(initData, responseVerify.getResult());
    }
}
