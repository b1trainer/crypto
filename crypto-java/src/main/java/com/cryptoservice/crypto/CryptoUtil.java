package com.cryptoservice.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;

public class CryptoUtil {

    private static final Logger LOG = LoggerFactory.getLogger(CryptoUtil.class);

    private CryptoUtil() {}

    /*
    В Java есть архитектура криптографических провайдеров — это подключаемые модули, которые реализуют криптографические алгоритмы
    SunJCE (встроенный) -> SunEC -> BouncyCastle
    Повторная регистрация вызовет ошибку
     */
    public static void registerProviders() {
        LOG.info("Crypto providers registration ...");

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            LOG.info("BouncyCastle provider registered");
        }
    }
}
