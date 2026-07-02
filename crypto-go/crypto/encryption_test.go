package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestEncrypt_Decrypt(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("не удалось сгенерировать RSA-ключ: %v", err)
	}

	service := &EncryptionService{
		publicKey:  &privateKey.PublicKey,
		privateKey: privateKey,
	}

	t.Run("успешная расшифровка", func(t *testing.T) {
		originalData := []byte("секретное сообщение для тестирования")

		encrypted, err := service.Encrypt(originalData)
		if err != nil {
			t.Fatalf("Encrypt() вернул ошибку: %v", err)
		}

		decrypted, err := service.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decrypt() вернул ошибку: %v", err)
		}

		if !bytes.Equal(decrypted, originalData) {
			t.Errorf("расшифрованные данные не совпадают с исходными.\nОжидалось: %v\nПолучено:  %v", originalData, decrypted)
		}
	})

	t.Run("расшифровка пустых данных", func(t *testing.T) {
		originalData := []byte{}

		encrypted, err := service.Encrypt(originalData)
		if err != nil {
			t.Fatalf("Encrypt() вернул ошибку: %v", err)
		}

		decrypted, err := service.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decrypt() вернул ошибку для пустых данных: %v", err)
		}

		if len(decrypted) != 0 {
			t.Errorf("ожидались пустые данные, получено %d байт", len(decrypted))
		}
	})

	t.Run("повреждённые данные", func(t *testing.T) {
		originalData := []byte("данные для проверки целостности")

		encrypted, err := service.Encrypt(originalData)
		if err != nil {
			t.Fatalf("Encrypt() вернул ошибку: %v", err)
		}

		// Повреждаем зашифрованные данные (меняем последний байт)
		corrupted := make([]byte, len(encrypted))
		copy(corrupted, encrypted)
		corrupted[len(corrupted)-1] ^= 0xFF

		_, err = service.Decrypt(corrupted)
		if err == nil {
			t.Error("Decrypt() должен был вернуть ошибку при повреждённых данных")
		}
	})

	t.Run("неверный формат данных", func(t *testing.T) {
		invalidData := []byte("это не зашифрованные данные")

		_, err := service.Decrypt(invalidData)
		if err == nil {
			t.Error("Decrypt() должен был вернуть ошибку при неверном формате")
		}
	})

	t.Run("слишком короткие данные", func(t *testing.T) {
		tooShort := []byte{0x00, 0x01}

		_, err := service.Decrypt(tooShort)
		if err == nil {
			t.Error("Decrypt() должен был вернуть ошибку для слишком коротких данных")
		}
	})
}
