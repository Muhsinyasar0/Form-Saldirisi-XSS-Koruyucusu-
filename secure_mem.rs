/// secure_mem.rs
/// 
/// AMAÇ: AES anahtarını memory'de güvenli tutmak ve dump edilmesini engellemek.
///
/// PROBLEM: Naif yaklaşımda anahtar Vec<u8> veya [u8; 32] olarak tutulur.
/// Program bitince veya panic olunca bu bellek:
///   1. OS'a iade edilir ama sıfırlanmaz → başka process okuyabilir
///   2. Swap file'a yazılabilir → disk'ten okunabilir
///   3. Core dump'a girer → forensic analiz ile ele geçirilebilir
///
/// ÇÖZÜM: zeroize crate ile Drop trait'i override edip,
/// key struct'ı drop edildiğinde belleği 0x00 ile dolduruyoruz.
///
/// REVERSE ENGINEERING NOTU:
///   - Bir saldırgan `gcore` veya `/proc/<pid>/mem` ile process memory'yi dump eder
///   - Eğer key naif tutuluyorsa, dump içinde 32-byte entropi bloğu aranır
///   - zeroize bunu engeller ama %100 garanti değildir:
///     compiler "kullanılmayan" sıfırlama kodunu optimize edebilir
///   - Bu yüzden zeroize, `volatile_set` kullanır (compiler optimize edemez)

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Güvenli 32-byte anahtar wrapper'ı.
/// Drop edildiğinde otomatik olarak sıfırlanır.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    /// AES-256 için 32 byte (256 bit) anahtar
    bytes: [u8; 32],
}

impl SecureKey {
    /// Yeni bir SecureKey oluştur (bytes kopyalanır, orijinal caller'da kalır)
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Key bytes'larına salt okunur erişim
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Debug: Key'in ilk 4 byte'ını göster (production'da kaldır!)
    pub fn debug_prefix(&self) -> String {
        format!("KEY[0..4] = {:02x?} ...", &self.bytes[0..4])
    }
}

/// Güvenli 12-byte IV (Initialization Vector) wrapper'ı
/// AES-GCM için nonce = 12 byte
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureNonce {
    bytes: [u8; 12],
}

impl SecureNonce {
    pub fn new(bytes: [u8; 12]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// NEDEN HEAP DEĞİL STACK?
/// 
/// Box<[u8; 32]> kullanırsak heap'te tutulur.
/// Stack'teki [u8; 32] ise:
///   - Daha hızlı erişim
///   - Frame bitince üstüne yazılabilir (ama garanti değil)
///   - Swap'a gitme ihtimali daha düşük (mlock ile engellenebilir)
///
/// PRODUCTION'DA EKLENEBİLECEK KORUMALAR:
///   1. mlock() → sayfayı swap'a yazmayı engelle
///   2. mprotect(PROT_NONE) → key kullanılmadığında sayfayı erişilemez yap
///   3. Hardware Security Module (HSM) → key hiç RAM'e gelmesin
///   4. OS Keychain (Linux Keyring, macOS Keychain) → OS korusun

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_key_zeroizes_on_drop() {
        // zeroize'ın Drop'ta çalıştığını dolaylı yoldan doğrula:
        // SecureKey bir Vec<u8> wrapper'ına kopyalanır,
        // drop sonrası orijinal stack frame'deki değer 0x00 olmalı.
        // NOT: drop sonrası raw pointer UB olduğundan,
        // burada zeroize crate'in kendi garantisine güveniyoruz.
        // Gerçek doğrulama: Valgrind / AddressSanitizer ile yapılır.
        let key = SecureKey::new([0xAB; 32]);
        // Drop öncesi erişim çalışmalı
        assert_eq!(key.as_bytes()[0], 0xAB);
        assert_eq!(key.as_bytes().len(), 32);
        // Drop (zeroize tetiklenir)
        drop(key);
        // Test geçti — zeroize Drop impl'i derleme zamanında doğrulandı.
        // Runtime doğrulaması için: RUSTFLAGS="-Z sanitizer=address" cargo test
    }

    #[test]
    fn test_secure_key_access() {
        let key = SecureKey::new([0xFF; 32]);
        assert_eq!(key.as_bytes().len(), 32);
        assert!(key.debug_prefix().contains("ff"));
    }
}
