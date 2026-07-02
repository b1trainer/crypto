package com.cryptoservice.service;

import com.cryptoservice.Sign;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class SignatureService {

    // не гарантирует потокобезопасность
    private final CMSSignedDataGenerator generator;

    private final Object signLock = new Object();

    public SignatureService(PrivateKey privateKey, X509Certificate certificate) throws OperatorCreationException, CertificateEncodingException, IOException, CMSException {
        // Зачем: ContentSigner отвечает за криптографическую подпись
        // хеша данных. Он использует приватный ключ и алгоритм.
        // "SHA256withRSA" означает:
        //   - SHA-256 для вычисления хеша документа
        //   - RSA для подписи хеша (с использованием приватного ключа)
        // "BC" - провайдер BouncyCastle (криптографическая библиотека)
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);

        // Зачем: BouncyCastle работает со своими внутренними представлениями
        // X.509 сертификатов (X509CertificateHolder), а не с java.security.X509Certificate.
        // getEncoded() возвращает DER-кодированный сертификат,
        // который парсится в X509CertificateHolder.
        X509CertificateHolder certHolder = new X509CertificateHolder(certificate.getEncoded());

        // Зачем: CMSSignedDataGenerator - основной класс для построения
        // структуры SignedData по стандарту CMS (Cryptographic Message Syntax).
        // Он собирает все компоненты подписи в единую структуру.
        this.generator = new CMSSignedDataGenerator();

        // Зачем: В структуру подписи добавляется SignerInfo - блок, содержащий:
        //   - идентификатор подписанта (SID) - из сертификата
        //   - Алгоритм хеширования (SHA-256)
        //   - Алгоритм подписи (RSA)
        //   - Саму подпись (будет вычислена при генерации)
        //   - Опциональные атрибуты (подпись, время и т.д.)
        // JcaSignerInfoGeneratorBuilder - строит информацию о подписанте
        // DigestCalculatorProvider - вычисляет хеши для атрибутов
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .build()
                ).build(contentSigner, certHolder)
        );

        // Зачем: PKCS#7 подпись может содержать сертификат подписанта
        // и всю цепочку сертификатов (для валидации на клиенте).
        // Здесь мы создаем хранилище, которое будет добавлено в подпись.
        // JcaCertStore - обертка BouncyCastle над коллекцией сертификатов.
        List<X509Certificate> certList = new ArrayList<>();
        certList.add(certificate);
        Store<?> certStore = new JcaCertStore(certList);

        // Зачем: Сертификаты добавляются в контейнер подписи, чтобы
        // проверяющая сторона могла получить публичный ключ для верификации.
        // Это ключевое отличие PKCS#7 от обычной подписи - самодостаточность.
        generator.addCertificates(certStore);
    }

    public byte[] sign(byte[] data, Sign sign) throws Exception {
        // Создаем объект с данными для подписи и генерируем подпись.
        // CMSProcessableByteArray - обертка для данных, которые нужно подписать.
        // generator.generate(cmsData, attached) - основной метод:
        //   - Если sign == Sign.ATTACHED: данные и подпись в одном контейнере (p7m)
        //   - Если sign == Sign.DETACHED: только подпись (p7s), данные отдельно
        //
        // getEncoded() преобразует CMS структуру в бинарный
        // ASN.1 DER формат, который можно сохранять в файл или передавать.
        // DER - Distinguished Encoding Rules - компактный бинарный формат.
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        CMSSignedData signedData;
        synchronized (signLock) {
            signedData = generator.generate(cmsData, sign == Sign.ATTACHED);
            return signedData.getEncoded();
        }
    }

    public boolean verify(byte[] data, byte[] signature) throws Exception {
        // 1. Парсим DER-структуру без внешних данных – так мы узнаем истинный тип подписи
        CMSSignedData signedData = new CMSSignedData(signature);

        // 2. Определяем, detached подпись или attached
        if (signedData.isDetachedSignature()) {
            // detached: данных внутри нет, подставляем переданные data
            signedData = new CMSSignedData(new CMSProcessableByteArray(data), signature);
        } else {
            // attached: данные уже внутри контейнера
            CMSProcessable content = signedData.getSignedContent();
            if (content != null) {
                byte[] embedded = (byte[]) content.getContent();
                // сравниваем встроенные данные с переданными
                if (!Arrays.equals(data, embedded)) {
                    return false;   // данные не совпадают – подпись недействительна
                }
            }
            // если content == null (редкий случай), оставляем signedData как есть;
            // дальнейшая верификация всё равно выдаст ошибку, если данные не соответствуют
        }

        // Зачем: Получаем хранилище сертификатов, которые были вложены
        // в подпись при создании. Это позволяет проверить подпись без
        // внешних источников сертификатов.
        Store<?> certStore = signedData.getCertificates();

        // Зачем: Подпись может содержать несколько подписантов (например,
        // совместная подпись). SignerInformationStore содержит всех.
        // Каждый SignerInformation содержит:
        //   - идентификатор подписанта (SID)
        //   - Алгоритмы
        //   - Саму подпись
        //   - Атрибуты подписи
        for (SignerInformation signer : signedData.getSignerInfos().getSigners()) {

            // Зачем: getSID() возвращает идентификатор (Subject Key Identifier
            // или Issuer+Serial), по которому ищем соответствующий сертификат
            // в хранилище. Это гарантирует, что мы используем правильный
            // сертификат для проверки.
            Collection<?> certCollection = certStore.getMatches(signer.getSID());
            if (certCollection.isEmpty()) {
                continue;
            }

            // Зачем: извлекаем найденный сертификат в формате BouncyCastle
            // и конвертируем его в стандартный Java X509Certificate.
            X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
            X509Certificate cert = (X509Certificate) CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(
                            new ByteArrayInputStream(certHolder.getEncoded())
                    );

            // Зачем: JcaSimpleSignerInfoVerifierBuilder создает верификатор,
            // который использует публичный ключ из сертификата для проверки
            // подписи. Процесс проверки:
            //   1. Вычисляется хеш данных (по алгоритму из подписи)
            //   2. Расшифровывается подпись публичным ключом
            //   3. Сравниваются хеши
            try {
                if (signer.verify(
                        new JcaSimpleSignerInfoVerifierBuilder()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .build(cert)
                )) {
                    return true;
                }
            } catch (CMSSignerDigestMismatchException e) {
                return false;
            }
        }

        return false;
    }
}
