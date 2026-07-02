package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"go.mozilla.org/pkcs7"
)

type SignatureService struct {
	privateKey *rsa.PrivateKey
	cert       *x509.Certificate
}

func NewSignatureService(key *rsa.PrivateKey, certificate *x509.Certificate) *SignatureService {
	return &SignatureService{
		privateKey: key,
		cert:       certificate,
	}
}

func (s *SignatureService) Sign(data []byte, attach bool) ([]byte, error) {
	// Подготовка контейнера SignedData
	// Java: CMSSignedDataGenerator + хранилище сертификатов
	// Go:   go.mozilla.org/pkcs7 предоставляет тип SignedData, который выступает как
	//       полноценный генератор CMS. Ему не нужно отдельно передавать хранилище —
	//       достаточно зарегистрировать сертификат подписанта позже.
	var (
		signedData *pkcs7.SignedData
		err        error
	)

	if attach {
		// Прикреплённая подпись (attached): данные будут включены в контейнер.
		// Аналог .p7m, где документ и подпись идут внутри одной DER-структуры.
		signedData, err = pkcs7.NewSignedData(data)
	} else {
		// Откреплённая подпись (detached): данные остаются снаружи контейнера.
		// Аналог .p7s, где подписан только хеш, а исходные данные передаются отдельно.
		signedData, err = pkcs7.NewSignedData(data)
		if err == nil {
			// Переводим контейнер в режим detached
			signedData.Detach()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ошибка создания структуры подписи: %w", err)
	}

	// Добавление подписанта (сертификат + приватный ключ)
	// Java: JcaSignerInfoGeneratorBuilder + JcaContentSignerBuilder("SHA256withRSA")
	// Go:   AddSigner автоматически извлекает SubjectPublicKeyInfo, выбирает
	//       алгоритм хеширования (SHA-256 для RSA) и подготавливает блок SignerInfo.
	//       Криптографическая стойкость обеспечивается стандартным crypto.Signer.
	if err = signedData.AddSigner(s.cert, s.privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("ошибка добавления подписанта: %w", err)
	}

	// Финализация и формирование DER-потока
	// Java: signedData.getEncoded()
	// Go:   Finish() вычисляет подпись, упаковывает SignedData в ASN.1 и
	//       возвращает бинарный DER, пригодный для записи в файл или передачи по сети.
	signedBytes, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("ошибка сериализации подписи: %w", err)
	}

	return signedBytes, nil
}

func (s *SignatureService) Verify(data []byte, signature []byte) (bool, error) {
	// Разбор DER-кодированной CMS/PKCS#7 подписи
	// Java: CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(data), signature);
	// Go:   pkcs7.Parse декодирует ASN.1 и автоматически извлекает:
	//       - вложенные сертификаты (p7.Certificates)
	//       - информацию о подписантах (SignerInfo)
	//       - тип подписи (attached/detached) по OID контента
	p7, err := pkcs7.Parse(signature)
	if err != nil {
		return false, fmt.Errorf("ошибка парсинга PKCS#7 подписи: %w", err)
	}

	// Назначение проверяемых данных
	// Java: signedData.verify(cert) обрабатывает оба случая через внутреннее поле content.
	// Go:   Для универсальной обработки attached и detached подписей достаточно
	//       присвоить data полю p7.Content. Метод p7.Verify() (без аргументов) затем:
	//       • для attached – сверит data со встроенным содержимым и проверит подпись;
	//       • для detached – вычислит хеш от data и проверит подпись (встроенный Content = nil).
	if data != nil {
		p7.Content = data
	}

	// Полная проверка подписи
	// Java: signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))
	// Go:   p7.Verify() перебирает все SignerInfo, сопоставляет SID с сертификатами,
	//       извлекает публичный ключ и выполняет криптографическую верификацию.
	//       Возвращает nil, если хотя бы один подписант валиден.
	if err := p7.Verify(); err != nil {
		// Ошибка означает несовпадение подписи, отсутствие подходящего сертификата
		// или истечение срока действия (если включена проверка валидности сертификата).
		return false, nil
	}

	return true, nil
}
