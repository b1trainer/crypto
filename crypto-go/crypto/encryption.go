package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
)

type EncryptionService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewEncryptionService(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *EncryptionService {
	return &EncryptionService{privateKey: privateKey, publicKey: publicKey}
}

func (e *EncryptionService) Encrypt(data []byte) ([]byte, error) {
	// Генерация AES-256 ключа
	// Java: KeyGenerator.getInstance("AES").init(256, new SecureRandom()).generateKey()
	// Go:   crypto/rand предоставляет CSPRNG, совместимый с FIPS 140-2.
	//       256 бит = 32 байта. Ключ существует только в памяти и будет стёрт GC.
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать AES-ключ: %w", err)
	}

	// Генерация IV (вектора инициализации)
	// Java: byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
	// Go:   В GCM IV должен быть строго уникальным. 12 байт — рекомендуемый размер NIST SP 800-38D.
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать IV: %w", err)
	}

	// Настройка шифратора AES-GCM
	// Java: Cipher.getInstance("AES/GCM/NoPadding", "BC") + GCMParameterSpec(128, iv)
	// Go:   crypto/aes + crypto/cipher.NewGCM автоматически используют 128-битный тег аутентификации
	//       (совпадает с GCMParameterSpec(128, ...)). Go 1.20+ использует AES-NI (аппаратное ускорение).
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Шифрование данных
	// Java: aesCipher.doFinal(data)
	// Go:   gcm.Seal(dst, nonce, plaintext, adata) возвращает [зашифрованные данные + 16B тег]
	//       nil как dst означает выделение нового слайса. adata = nil (нет доп. проверочных данных).
	encryptedData := gcm.Seal(nil, iv, data, nil)

	// Шифрование AES-ключа с помощью RSA
	// Java: Cipher.getInstance("RSA/None/PKCS1Padding", "BC").doFinal(aesKey.getEncoded())
	// Go:   rsa.EncryptPKCS1v15 полностью соответствует RSA/None/PKCS1Padding из BouncyCastle.
	//       Добавляет вероятностную padding, делая каждый зашифрованный ключ уникальным (~256 байт для 2048-битного ключа).
	//
	// todo перейти на RSA-OAEP как более надежную схему
	encryptedAesKey, err := rsa.EncryptPKCS1v15(rand.Reader, e.publicKey, aesKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка шифрования AES-ключа RSA: %w", err)
	}

	// Сборка финального формата
	// Java: ByteBuffer.allocate(totalLen) -> putInt(len) -> put(key) -> put(iv) -> put(data)
	// Go:   bytes.Buffer автоматически управляет памятью. binary.BigEndian гарантирует кроссплатформенную
	//       сериализацию 4-байтового инта (совпадает с Java ByteBuffer.putInt()).
	buf := bytes.Buffer{}
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(encryptedAesKey))); err != nil {
		return nil, fmt.Errorf("ошибка записи длины ключа: %w", err)
	}
	buf.Write(encryptedAesKey)
	buf.Write(iv)
	buf.Write(encryptedData)

	return buf.Bytes(), nil
}

func (e *EncryptionService) Decrypt(encryptedInput []byte) ([]byte, error) {
	// Инициализация читателя байт (аналог ByteBuffer)
	// Java: ByteBuffer buffer = ByteBuffer.wrap(encryptedInput);
	// Go:   bytes.NewReader создаёт потоковый читатель без копирования данных.
	//       Автоматически отслеживает позицию и гарантирует безопасное чтение по порядку.
	reader := bytes.NewReader(encryptedInput)

	// Чтение длины зашифрованного AES-ключа (4 байта, big-endian)
	// Java: int aesKeyLen = buffer.getInt();
	// Go:   binary.Read с binary.BigEndian полностью соответствует Java ByteBuffer.getInt().
	//       Go использует uint32, так как длина не может быть отрицательной.
	var encKeyLen uint32
	if err := binary.Read(reader, binary.BigEndian, &encKeyLen); err != nil {
		return nil, fmt.Errorf("ошибка чтения длины ключа: %w", err)
	}

	// Чтение зашифрованного AES-ключа
	// Java: byte[] encryptedAesKey = new byte[aesKeyLen]; buffer.get(encryptedAesKey);
	// Go:   io.ReadFull гарантирует чтение ровно encKeyLen байт. Вернёт ошибку при EOF или повреждении.
	encKey := make([]byte, encKeyLen)
	if _, err := io.ReadFull(reader, encKey); err != nil {
		return nil, fmt.Errorf("ошибка чтения зашифрованного AES-ключа: %w", err)
	}

	// Чтение IV (вектора инициализации) — ровно 12 байт
	// Java: byte[] iv = new byte[GCM_IV_LENGTH]; buffer.get(iv);
	// Go:   Фиксированный размер массива. GCM строго требует 12-байтный nonce.
	iv := make([]byte, 12)
	if _, err := io.ReadFull(reader, iv); err != nil {
		return nil, fmt.Errorf("ошибка чтения IV: %w", err)
	}

	// Чтение оставшихся зашифрованных данных
	// Java: byte[] encryptedData = new byte[buffer.remaining()]; buffer.get(encryptedData);
	// Go:   reader.Len() возвращает количество оставшихся байт. io.ReadFull читает их полностью.
	encData := make([]byte, reader.Len())
	if _, err := io.ReadFull(reader, encData); err != nil {
		return nil, fmt.Errorf("ошибка чтения зашифрованных данных: %w", err)
	}

	// Расшифровка AES-ключа приватным ключом RSA
	// Java: Cipher rsaCipher = Cipher.getInstance("RSA/None/PKCS1Padding", BC);
	//       rsaCipher.init(DECRYPT_MODE, privateKey);
	//       byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
	// Go:   rsa.DecryptPKCS1v15 полностью соответствует RSA/None/PKCS1Padding.
	//       rand.Reader передаётся для временного ослепления (blinding) — защита от timing-атак.
	//       Возвращает 32-байтный AES-ключ или ошибку при неверном ключе/повреждении padding.
	//
	// todo перейти на RSA-OAEP как более надежную схему
	aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, e.privateKey, encKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки AES-ключа RSA: %w", err)
	}

	// Настройка шифратора AES-GCM для расшифровки
	// Java: Cipher aesCipher = Cipher.getInstance(AES_ALGO, BC);
	//       GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
	//       aesCipher.init(DECRYPT_MODE, aesKey, gcmSpec);
	// Go:   crypto/aes + crypto/cipher.NewGCM автоматически используют 128-битный тег аутентификации.
	//       Никаких явных ParameterSpec не требуется. Go 1.20+ использует аппаратное ускорение AES-NI.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Расшифровка данных
	// Java: return aesCipher.doFinal(encryptedData);
	// Go:   проверка криптографического тега аутентификации.
	//       Если данные повреждены, ключ неверен или тег не совпадает → cipher.InvalidAuthenticationError.
	//       Это строгий аналог Java AEADBadTagException / BadPaddingException.
	plaintext, err := gcm.Open(nil, iv, encData, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки данных (данные повреждены или неверный ключ): %w", err)
	}

	// исходные данные без 16-байтного GCM-тега (был удалён при Open).
	return plaintext, nil
}
