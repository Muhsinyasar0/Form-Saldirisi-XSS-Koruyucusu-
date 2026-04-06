/// crypto.rs
///
/// ring crate ile AES-256-GCM şifreleme/çözme.
///
/// AES-GCM SEÇİLME NEDENİ:
///   - AES-CBC: Padding oracle saldırılarına açık, authentication yok
///   - AES-CTR: Authentication yok, bit-flipping saldırısı mümkün
///   - AES-GCM: Authenticated Encryption → hem gizlilik hem bütünlük
///              NIST standartı, TLS 1.3'te kullanılıyor
///
/// NONCE KULLANIMI:
///   Her şifreleme için BENZERSİZ nonce kullanılmalı!
///   Aynı key + aynı nonce = felaket (GCM'de key recovery mümkün)
///   Bu projede her encrypt çağrısında random 12-byte nonce üretiyoruz.

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
    NONCE_LEN,
};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

use crate::errors::VaultError;
use crate::secure_mem::SecureKey;

/// Tek kullanımlık nonce üretici
/// Her seal() çağrısında yeni nonce üretir
struct OneTimeNonce {
    nonce: Option<[u8; NONCE_LEN]>,
}

impl OneTimeNonce {
    fn new(bytes: [u8; NONCE_LEN]) -> Self {
        Self {
            nonce: Some(bytes),
        }
    }
}

impl NonceSequence for OneTimeNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.nonce
            .take()
            .map(|n| Nonce::assume_unique_for_key(n))
            .ok_or(Unspecified)
    }
}

/// Şifrelenmiş veri paketi
/// Wire format: [12 byte nonce][ciphertext + 16 byte GCM tag]
pub struct EncryptedPacket {
    /// Nonce (IV) - açık metin olarak saklanır, gizli değil
    pub nonce: [u8; 12],
    /// Şifreli veri + GCM authentication tag (son 16 byte)
    pub ciphertext: Vec<u8>,
}

impl EncryptedPacket {
    /// Paketi tek byte dizisine serialize et
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Byte dizisinden paketi deserialize et
    pub fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        if data.len() < 12 + 16 {
            return Err(VaultError::InvalidPacket(
                "Paket çok kısa (min 28 byte: 12 nonce + 16 tag)".to_string(),
            ));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[..12]);
        let ciphertext = data[12..].to_vec();

        Ok(Self { nonce, ciphertext })
    }

    /// Hex string olarak göster (debug)
    pub fn to_hex_string(&self) -> String {
        format!(
            "NONCE: {}\nCIPHERTEXT: {}",
            hex::encode(self.nonce),
            hex::encode(&self.ciphertext)
        )
    }
}

/// Ana şifreleme motoru
pub struct CryptoEngine {
    rng: SystemRandom,
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Veriyi AES-256-GCM ile şifrele
    ///
    /// # Parametreler
    /// - `key`: 32-byte güvenli anahtar
    /// - `plaintext`: Şifrelenecek veri
    /// - `associated_data`: Authenticate edilecek ama şifrelenmeyecek veri
    ///                      (örn: kullanıcı ID, timestamp - bütünlük kontrolü için)
    pub fn encrypt(
        &self,
        key: &SecureKey,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedPacket, VaultError> {
        // Random 12-byte nonce üret
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| VaultError::RngFailure)?;

        // ring UnboundKey oluştur
        let unbound_key = UnboundKey::new(&AES_256_GCM, key.as_bytes())
            .map_err(|_| VaultError::KeyError("UnboundKey oluşturulamadı".to_string()))?;

        // SealingKey = UnboundKey + NonceSequence
        let nonce_seq = OneTimeNonce::new(nonce_bytes);
        let mut sealing_key = SealingKey::new(unbound_key, nonce_seq);

        // Plaintext'i mutable buffer'a kopyala (ring in-place şifreler)
        // seal_in_place_append_tag GCM tag'ini (16 byte) kendisi ekler,
        // onceden yer acmaya gerek yok.
        let mut buffer = plaintext.to_vec();

        // Sifrele (in-place): buffer = ciphertext + 16 byte GCM tag
        sealing_key
            .seal_in_place_append_tag(Aad::from(associated_data), &mut buffer)
            .map_err(|_| VaultError::EncryptionFailure)?;

        Ok(EncryptedPacket {
            nonce: nonce_bytes,
            ciphertext: buffer,
        })
    }

    /// Şifrelenmiş veriyi çöz
    ///
    /// GCM tag doğrulaması otomatik yapılır.
    /// Tag geçersizse (veri değiştirilmişse) hata döner.
    pub fn decrypt(
        &self,
        key: &SecureKey,
        packet: &EncryptedPacket,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key.as_bytes())
            .map_err(|_| VaultError::KeyError("UnboundKey oluşturulamadı".to_string()))?;

        let nonce_seq = OneTimeNonce::new(packet.nonce);
        let mut opening_key = OpeningKey::new(unbound_key, nonce_seq);

        // Ciphertext'i mutable buffer'a kopyala
        let mut buffer = packet.ciphertext.clone();

        // Çöz ve tag doğrula (in-place)
        let plaintext = opening_key
            .open_in_place(Aad::from(associated_data), &mut buffer)
            .map_err(|_| VaultError::DecryptionFailure)?;

        Ok(plaintext.to_vec())
    }

    /// Yeni rastgele 32-byte AES-256 anahtarı üret
    pub fn generate_key(&self) -> Result<SecureKey, VaultError> {
        let mut key_bytes = [0u8; 32];
        self.rng
            .fill(&mut key_bytes)
            .map_err(|_| VaultError::RngFailure)?;

        Ok(SecureKey::new(key_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (CryptoEngine, SecureKey) {
        let engine = CryptoEngine::new();
        let key = engine.generate_key().expect("Key üretilemedi");
        (engine, key)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (engine, key) = setup();
        let plaintext = b"Gizli mesaj: Anahtar paspas altinda altinda degil!";
        let aad = b"user_id:42";

        let packet = engine.encrypt(&key, plaintext, aad).expect("Şifreleme başarısız");
        let decrypted = engine.decrypt(&key, &packet, aad).expect("Çözme başarısız");

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (engine, key) = setup();
        let plaintext = b"Orijinal veri";
        let aad = b"context";

        let mut packet = engine.encrypt(&key, plaintext, aad).expect("Şifreleme başarısız");
        
        // Ciphertext'i değiştir (saldırı simülasyonu)
        packet.ciphertext[0] ^= 0xFF;

        let result = engine.decrypt(&key, &packet, aad);
        assert!(result.is_err(), "Değiştirilmiş ciphertext kabul edildi! GCM çalışmıyor.");
    }

    #[test]
    fn test_wrong_aad_fails() {
        let (engine, key) = setup();
        let plaintext = b"Veri";
        
        let packet = engine.encrypt(&key, plaintext, b"user_id:42").expect("Şifreleme başarısız");
        
        // Farklı AAD ile çözmeyi dene
        let result = engine.decrypt(&key, &packet, b"user_id:99");
        assert!(result.is_err(), "Yanlış AAD kabul edildi!");
    }

    #[test]
    fn test_different_nonces_each_time() {
        let (engine, key) = setup();
        let plaintext = b"Ayni mesaj";
        let aad = b"";

        let packet1 = engine.encrypt(&key, plaintext, aad).expect("Şifreleme 1 başarısız");
        let packet2 = engine.encrypt(&key, plaintext, aad).expect("Şifreleme 2 başarısız");

        // Aynı plaintext → farklı ciphertext (random nonce sayesinde)
        assert_ne!(packet1.nonce, packet2.nonce, "Nonce'lar aynı! Güvenlik açığı!");
        assert_ne!(packet1.ciphertext, packet2.ciphertext, "Ciphertext'ler aynı! Güvenlik açığı!");
    }

    #[test]
    fn test_packet_serialization() {
        let (engine, key) = setup();
        let plaintext = b"Serialize test";
        let aad = b"";

        let packet = engine.encrypt(&key, plaintext, aad).expect("Şifreleme başarısız");
        let bytes = packet.to_bytes();
        
        let packet2 = EncryptedPacket::from_bytes(&bytes).expect("Deserialize başarısız");
        let decrypted = engine.decrypt(&key, &packet2, aad).expect("Çözme başarısız");

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }
}
