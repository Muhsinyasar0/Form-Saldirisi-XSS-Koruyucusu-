/// key_store.rs
///
/// ANAHTAR SAKLAMA STRATEJİLERİ — Güvenlik Analizi
///
/// "Anahtarı kapının paspasının altına bırakma."
/// Bu modül farklı anahtar saklama yöntemlerini karşılaştırır.
///
/// ┌──────────────────────────────────────────────────────────┐
/// │ YÖNTEMLERİN GÜVENLİK SIRASI (kötüden iyiye)            │
/// ├──────────────────────────────────────────────────────────┤
/// │ 1. Hardcoded kaynak kod          → EN KÖTÜ (paspas)     │
/// │ 2. .env dosyası / config         → KÖTÜ                 │
/// │ 3. Ortam değişkeni               → ORTA                 │
/// │ 4. Memory-only (bu proje)        → İYİ                  │
/// │ 5. OS Keychain / Secret Manager  → DAHA İYİ             │
/// │ 6. Hardware Security Module      → EN İYİ               │
/// └──────────────────────────────────────────────────────────┘

use crate::crypto::CryptoEngine;
use crate::errors::VaultError;
use crate::secure_mem::SecureKey;
use zeroize::Zeroize;

// ============================================================
// YÖNTEM 1: HARDCODED KEY — ASLA YAPMA (Paspas Altı)
// ============================================================

/// Bu fonksiyon YANLIŞI gösteriyor!
/// Reverse engineer için 5 dakika:
///   $ strings crypto-vault-binary | grep -E '^[0-9a-f]{64}$'
///   $ objdump -s --section=.rodata crypto-vault-binary
pub fn bad_hardcoded_key_example() -> &'static [u8; 32] {
    // BUNU ASLA YAPMA! Binary içinde açıkça görünür.
    static HARDCODED_KEY: [u8; 32] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    &HARDCODED_KEY
    // REVERSE ENGINEERING:
    // Ghidra ile açtığında .rodata section'da DEADBEEF... bloğu bulunur.
    // Binary → Defined Strings → 32+ byte entropi bloğu → anahtar bulundu.
}

// ============================================================
// YÖNTEM 2: ORTAM DEĞİŞKENİ — Daha iyi ama hala sorunlu
// ============================================================

/// Ortam değişkeninden key oku
/// 
/// SORUNLARI:
///   - `ps auxe` ile tüm env görülebilir (eski Linux'larda)
///   - /proc/<pid>/environ okunabilir
///   - Şirket log sistemleri env'i loglayabilir
///   - Docker inspect ile görülebilir
pub fn load_key_from_env() -> Result<SecureKey, VaultError> {
    let hex_key = std::env::var("VAULT_KEY")
        .map_err(|_| VaultError::KeyError("VAULT_KEY ortam değişkeni bulunamadı".to_string()))?;

    let bytes = hex::decode(hex_key.trim())
        .map_err(|_| VaultError::KeyError("VAULT_KEY geçerli hex değil".to_string()))?;

    if bytes.len() != 32 {
        return Err(VaultError::KeyError(format!(
            "Key 32 byte olmalı, {} byte verildi",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    
    // hex_key'i hemen temizle (String heap'te kalır)
    // NOT: hex_key.zeroize() burada çağrılabilirdi ama
    // String'in iç buffer'ı reallocate olmuş olabilir.
    // Bu yüzden ortam değişkeni yöntemi hala riskli.

    Ok(SecureKey::new(arr))
}

// ============================================================
// YÖNTEM 3: MEMORY-ONLY KEY STORE — Bu Projenin Yaklaşımı
// ============================================================

/// Runtime'da üretilip memory'de tutulan anahtar deposu.
///
/// AVANTAJLAR:
///   - Disk'e yazılmaz
///   - Hardcoded değil → binary analizi ile bulunamaz
///   - zeroize ile Drop'ta sıfırlanır
///
/// DEZAVANTAJLAR:
///   - Program yeniden başlatılınca key kaybolur
///   - Şifreli veriler tekrar okunamaz hale gelir!
///   - /proc/<pid>/mem ile dump alınabilir (root gerekir)
///
/// ÇÖZÜM: Key'i password-based key derivation (PBKDF2/Argon2) ile
///        kullanıcı şifresinden türet → her başlatmada şifre sor
pub struct MemoryKeyStore {
    key: Option<SecureKey>,
    engine: CryptoEngine,
    /// İstatistik: Bu session'da kaç kez şifreleme yapıldı
    encrypt_count: u64,
}

impl MemoryKeyStore {
    /// Yeni boş key store oluştur
    pub fn new() -> Self {
        Self {
            key: None,
            engine: CryptoEngine::new(),
            encrypt_count: 0,
        }
    }

    /// Runtime'da yeni key üret ve hafızada sakla
    pub fn generate_and_store(&mut self) -> Result<(), VaultError> {
        let key = self.engine.generate_key()?;
        println!(
            "[KeyStore] Yeni key üretildi: {}",
            key.debug_prefix()
        );
        self.key = Some(key);
        Ok(())
    }

    /// Dışarıdan key yükle (örn: ortam değişkeni veya kullanıcı girişi)
    pub fn load_external_key(&mut self, key: SecureKey) {
        self.key = Some(key);
        println!("[KeyStore] Harici key yüklendi.");
    }

    /// Veriyi şifrele (key yoksa hata)
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        context: &str,
    ) -> Result<Vec<u8>, VaultError> {
        let key = self.key.as_ref().ok_or_else(|| {
            VaultError::KeyError("Key store'da anahtar yok! Önce generate_and_store() çağırın.".to_string())
        })?;

        let packet = self.engine.encrypt(key, plaintext, context.as_bytes())?;
        self.encrypt_count += 1;

        println!(
            "[KeyStore] Şifreleme #{}: {} byte → {} byte (context: {})",
            self.encrypt_count,
            plaintext.len(),
            packet.ciphertext.len(),
            context
        );

        Ok(packet.to_bytes())
    }

    /// Veriyi çöz (key yoksa hata)
    pub fn decrypt(
        &self,
        encrypted_bytes: &[u8],
        context: &str,
    ) -> Result<Vec<u8>, VaultError> {
        let key = self.key.as_ref().ok_or_else(|| {
            VaultError::KeyError("Key store'da anahtar yok!".to_string())
        })?;

        let packet = crate::crypto::EncryptedPacket::from_bytes(encrypted_bytes)?;
        self.engine.decrypt(key, &packet, context.as_bytes())
    }

    /// Key'i güvenli şekilde temizle (kullanıcı logout, session bitiş)
    pub fn clear_key(&mut self) {
        if self.key.is_some() {
            self.key = None; // Drop çağrılır → zeroize devreye girer
            println!("[KeyStore] Key temizlendi (zeroized).");
        }
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    pub fn encrypt_count(&self) -> u64 {
        self.encrypt_count
    }
}

impl Drop for MemoryKeyStore {
    fn drop(&mut self) {
        self.clear_key();
        println!("[KeyStore] KeyStore drop edildi, key temizlendi.");
    }
}

// ============================================================
// BONUS: PASSWORD-BASED KEY DERIVATION (PBKDF2 konsept)
// ============================================================

/// Kullanıcı şifresinden deterministik key türet.
///
/// GERÇEK IMPLEMENTASYON: ring::pbkdf2 veya argon2 crate kullanılır.
/// Bu sadece konsept gösterimi.
///
/// AVANTAJI: Key hiç disk'e yazılmaz, her oturumda şifreden türetilir.
/// DEZAVANTAJI: Zayıf şifre = zayıf key. Argon2id kullanılmalı.
pub fn derive_key_from_password_concept(password: &str, salt: &[u8; 16]) -> SecureKey {
    use ring::pbkdf2;
    use std::num::NonZeroU32;

    // 100_000 iterasyon (2024 standartı, Argon2id daha iyi)
    let iterations = NonZeroU32::new(100_000).unwrap();
    let mut key_bytes = [0u8; 32];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        &mut key_bytes,
    );

    let key = SecureKey::new(key_bytes);
    
    // key_bytes'ı temizle (artık SecureKey'de kopyası var)
    key_bytes.zeroize();
    
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_key_store_lifecycle() {
        let mut store = MemoryKeyStore::new();

        assert!(!store.has_key());
        store.generate_and_store().expect("Key üretilemedi");
        assert!(store.has_key());

        let plaintext = b"Gizli veri";
        let encrypted = store.encrypt(plaintext, "test_context").expect("Şifreleme başarısız");
        let decrypted = store.decrypt(&encrypted, "test_context").expect("Çözme başarısız");

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());

        store.clear_key();
        assert!(!store.has_key());

        // Key temizlendikten sonra şifreleme başarısız olmalı
        let result = store.encrypt(plaintext, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_pbkdf2_deterministic() {
        let password = "super_secret_password_123";
        let salt = [0x42u8; 16];

        let key1 = derive_key_from_password_concept(password, &salt);
        let key2 = derive_key_from_password_concept(password, &salt);

        // Aynı şifre + salt → aynı key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_pbkdf2_different_passwords() {
        let salt = [0x42u8; 16];

        let key1 = derive_key_from_password_concept("sifre1", &salt);
        let key2 = derive_key_from_password_concept("sifre2", &salt);

        // Farklı şifre → farklı key
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
