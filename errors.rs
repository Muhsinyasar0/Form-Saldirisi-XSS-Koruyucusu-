/// errors.rs
///
/// Merkezi hata yönetimi.
/// thiserror ile boilerplate azaltıyoruz.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Şifreleme hatası: AES-GCM seal başarısız")]
    EncryptionFailure,

    #[error("Çözme hatası: GCM tag doğrulaması başarısız (veri değiştirilmiş veya yanlış key/AAD)")]
    DecryptionFailure,

    #[error("Key hatası: {0}")]
    KeyError(String),

    #[error("RNG hatası: Güvenli rastgele sayı üretilemedi")]
    RngFailure,

    #[error("Geçersiz paket: {0}")]
    InvalidPacket(String),
}
