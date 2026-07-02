package crypto

import (
	"crypto-go/config"
	"testing"
)

func TestSignatureService_Sign_Verify(t *testing.T) {
	certs, err := config.LoadKeystore("testdata/keystore.p12", "changeit")
	if err != nil {
		t.Fatal(err)
	}

	service := NewSignatureService(certs.PrivateKey, certs.X509)

	t.Run("прикреплённая подпись - успешная верификация", func(t *testing.T) {
		data := []byte("документ для подписания")

		signature, err := service.Sign(data, true)
		if err != nil {
			t.Fatalf("Sign() вернул ошибку: %v", err)
		}

		valid, err := service.Verify(nil, signature)
		if err != nil {
			t.Fatalf("Verify() вернул ошибку: %v", err)
		}

		if !valid {
			t.Error("подпись должна быть валидной для attached режима")
		}
	})

	t.Run("откреплённая подпись - успешная верификация", func(t *testing.T) {
		data := []byte("документ для откреплённой подписи")

		signature, err := service.Sign(data, false)
		if err != nil {
			t.Fatalf("Sign() вернул ошибку: %v", err)
		}

		valid, err := service.Verify(data, signature)
		if err != nil {
			t.Fatalf("Verify() вернул ошибку: %v", err)
		}

		if !valid {
			t.Error("подпись должна быть валидной для detached режима")
		}
	})

	t.Run("верификация с неверными данными", func(t *testing.T) {
		originalData := []byte("оригинальный документ")
		modifiedData := []byte("поддельный документ")

		signature, err := service.Sign(originalData, false)
		if err != nil {
			t.Fatalf("Sign() вернул ошибку: %v", err)
		}

		valid, err := service.Verify(modifiedData, signature)
		if err != nil {
			t.Fatalf("Verify() вернул ошибку: %v", err)
		}

		if valid {
			t.Error("подпись не должна быть валидной для изменённых данных")
		}
	})

	t.Run("верификация повреждённой подписи", func(t *testing.T) {
		data := []byte("данные для проверки целостности подписи")

		signature, err := service.Sign(data, true)
		if err != nil {
			t.Fatalf("Sign() вернул ошибку: %v", err)
		}

		corrupted := make([]byte, len(signature))
		copy(corrupted, signature)
		corrupted[len(corrupted)-1] ^= 0xFF

		valid, err := service.Verify(nil, corrupted)
		if err != nil {
			t.Fatalf("Verify() вернул ошибку: %v", err)
		}

		if valid {
			t.Error("повреждённая подпись не должна быть валидной")
		}
	})

	t.Run("подпись пустых данных", func(t *testing.T) {
		emptyData := []byte{}

		signature, err := service.Sign(emptyData, true)
		if err != nil {
			t.Fatalf("Sign() вернул ошибку для пустых данных: %v", err)
		}

		valid, err := service.Verify(nil, signature)
		if err != nil {
			t.Fatalf("Verify() вернул ошибку: %v", err)
		}

		if !valid {
			t.Error("подпись пустых данных должна быть валидной")
		}

		signature, err = service.Sign(emptyData, false)
		if err != nil {
			t.Fatalf("Sign() вернул ошибку для пустых данных (detached): %v", err)
		}

		valid, err = service.Verify(emptyData, signature)
		if err != nil {
			t.Fatalf("Verify() вернул ошибку: %v", err)
		}

		if !valid {
			t.Error("откреплённая подпись пустых данных должна быть валидной")
		}
	})

	t.Run("неверный формат подписи", func(t *testing.T) {
		invalidSignature := []byte("это не PKCS#7 подпись")

		valid, err := service.Verify([]byte("данные"), invalidSignature)
		if err == nil {
			t.Error("Verify() должен был вернуть ошибку для неверного формата подписи")
		}
		if valid {
			t.Error("неверный формат подписи не должен быть валидным")
		}
	})
}
