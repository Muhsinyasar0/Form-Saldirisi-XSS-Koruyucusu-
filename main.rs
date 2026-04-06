/// main.rs
///
/// Crypto Vault Demo — AES-256-GCM + Güvenli Anahtar Yönetimi
///
/// Çalıştırma:
///   cargo run
///   cargo test
///   VAULT_KEY=$(openssl rand -hex 32) cargo run

mod crypto;
mod errors;
mod key_store;
mod secure_mem;

use crypto::CryptoEngine;
use key_store::{MemoryKeyStore, derive_key_from_password_concept};

fn separator(title: &str) {
    println!("\n{}", "═".repeat(60));
    println!("  {}", title);
    println!("{}", "═".repeat(60));
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║         CRYPTO VAULT — AES-256-GCM Demo                 ║");
    println!("║         ring crate + zeroize + güvenli key yönetimi     ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    // ─────────────────────────────────────────────────────────
    // SENARYO 1: Temel Şifreleme / Çözme
    // ─────────────────────────────────────────────────────────
    separator("SENARYO 1: Temel AES-256-GCM Şifreleme");

    let engine = CryptoEngine::new();
    let key = engine.generate_key().expect("Key üretilemedi");

    println!("[*] Key üretildi: {}", key.debug_prefix());

    let plaintext = b"Merhaba! Bu mesaj AES-256-GCM ile sifreleniyor.";
    let aad = b"user_id:1337,timestamp:20240101"; // Associated Data

    println!("[*] Plaintext  : {} byte — \"{}\"", plaintext.len(), std::str::from_utf8(plaintext).unwrap());
    println!("[*] AAD        : \"{}\"", std::str::from_utf8(aad).unwrap());

    let packet = engine.encrypt(&key, plaintext, aad).expect("Şifreleme başarısız");
    println!("\n[+] Şifreleme başarılı!");
    println!("{}", packet.to_hex_string());
    println!("[*] Toplam paket boyutu: {} byte", packet.to_bytes().len());

    let decrypted = engine.decrypt(&key, &packet, aad).expect("Çözme başarısız");
    println!("\n[+] Çözme başarılı!");
    println!("[*] Decrypted  : \"{}\"", std::str::from_utf8(&decrypted).unwrap());
    assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    println!("[✓] Plaintext doğrulandı!");

    // ─────────────────────────────────────────────────────────
    // SENARYO 2: Manipülasyon Tespiti (GCM Authentication)
    // ─────────────────────────────────────────────────────────
    separator("SENARYO 2: GCM Authentication — Veri Manipülasyonu Tespiti");

    println!("[*] Aynı plaintext'i şifreliyoruz...");
    let mut tampered_packet = engine.encrypt(&key, plaintext, aad).expect("Şifreleme başarısız");

    println!("[!] Saldırgan ciphertext'in 1. byte'ını değiştiriyor...");
    tampered_packet.ciphertext[0] ^= 0xFF;

    match engine.decrypt(&key, &tampered_packet, aad) {
        Ok(_) => println!("[-] BAŞARISIZ: Değiştirilmiş veri kabul edildi! Güvenlik açığı!"),
        Err(e) => println!("[✓] BAŞARILI: Manipülasyon tespit edildi → {}", e),
    }

    println!("\n[!] Yanlış AAD ile çözmeyi deniyoruz...");
    let real_packet = engine.encrypt(&key, plaintext, aad).expect("Şifreleme başarısız");
    match engine.decrypt(&key, &real_packet, b"user_id:9999,timestamp:00000000") {
        Ok(_) => println!("[-] BAŞARISIZ: Yanlış AAD kabul edildi!"),
        Err(e) => println!("[✓] BAŞARILI: Yanlış AAD reddedildi → {}", e),
    }

    // ─────────────────────────────────────────────────────────
    // SENARYO 3: Her Şifreleme Farklı Ciphertext Üretir
    // ─────────────────────────────────────────────────────────
    separator("SENARYO 3: Semantic Security — Aynı Plaintext ≠ Aynı Ciphertext");

    println!("[*] Aynı mesajı 3 kez şifreliyoruz...");
    let msg = b"Ayni mesaj";
    for i in 1..=3 {
        let p = engine.encrypt(&key, msg, b"").expect("Şifreleme başarısız");
        println!("  Şifreleme #{}: nonce={} ct_prefix={}...",
            i,
            hex::encode(&p.nonce[..4]),
            hex::encode(&p.ciphertext[..4])
        );
    }
    println!("[✓] Her seferinde farklı nonce → farklı ciphertext (semantic security)");

    // ─────────────────────────────────────────────────────────
    // SENARYO 4: MemoryKeyStore Lifecycle
    // ─────────────────────────────────────────────────────────
    separator("SENARYO 4: Memory Key Store — Lifecycle ve Güvenlik");

    {
        let mut store = MemoryKeyStore::new();
        store.generate_and_store().expect("Key üretilemedi");

        let secret = b"Cok gizli sirket bilgisi";
        let enc = store.encrypt(secret, "document:finance_report").expect("Şifreleme başarısız");
        println!("[+] Veri şifrelendi: {} byte", enc.len());

        let dec = store.decrypt(&enc, "document:finance_report").expect("Çözme başarısız");
        println!("[+] Veri çözüldü: \"{}\"", std::str::from_utf8(&dec).unwrap());

        println!("\n[*] Key store drop ediliyor (scope bitiyor)...");
    } // ← Burada MemoryKeyStore::drop() çağrılır → key zeroize edilir

    println!("[✓] Key store temizlendi (Drop + zeroize)");

    // ─────────────────────────────────────────────────────────
    // SENARYO 5: Password-Based Key Derivation
    // ─────────────────────────────────────────────────────────
    separator("SENARYO 5: PBKDF2 — Şifreden Key Türetme");

    let password = "kullanici_sifresi_123!";
    let salt = [0x8Bu8; 16]; // Gerçekte random salt olmalı ve saklanmalı!

    println!("[*] Şifre: \"{}\"", password);
    println!("[*] Salt:  {}", hex::encode(salt));

    let derived_key = derive_key_from_password_concept(password, &salt);
    println!("[+] Türetilen key: {}", derived_key.debug_prefix());

    // Türetilen key ile şifrele
    let secret2 = b"Sifre ile koruma altindaki veri";
    let packet2 = engine.encrypt(&derived_key, secret2, b"pbkdf2_demo")
        .expect("Şifreleme başarısız");

    // Aynı şifreden aynı key türet ve çöz
    let derived_key2 = derive_key_from_password_concept(password, &salt);
    let decrypted2 = engine.decrypt(&derived_key2, &packet2, b"pbkdf2_demo")
        .expect("Çözme başarısız");

    println!("[+] Çözülen veri: \"{}\"", std::str::from_utf8(&decrypted2).unwrap());
    println!("[✓] Şifreden türetilen key ile başarılı şifreleme/çözme!");

    // ─────────────────────────────────────────────────────────
    // SENARYO 6: Ortam Değişkeninden Key Yükleme
    // ─────────────────────────────────────────────────────────
    separator("SENARYO 6: Ortam Değişkeninden Key Yükleme");

    match key_store::load_key_from_env() {
        Ok(env_key) => {
            println!("[+] VAULT_KEY ortam değişkeninden key yüklendi: {}", env_key.debug_prefix());
        }
        Err(e) => {
            println!("[!] VAULT_KEY bulunamadı: {}", e);
            println!("[*] Test için şunu çalıştır:");
            println!("    export VAULT_KEY=$(openssl rand -hex 32)");
            println!("    cargo run");
        }
    }

    // ─────────────────────────────────────────────────────────
    // ÖZET
    // ─────────────────────────────────────────────────────────
    separator("ÖZET — Güvenlik Notları");

    println!(r#"
  YAPILAN:
    ✓ AES-256-GCM ile authenticated encryption
    ✓ Her şifreleme için random nonce (semantic security)
    ✓ Associated Data (AAD) ile bağlam bütünlüğü
    ✓ zeroize ile Drop'ta key temizleme
    ✓ PBKDF2 ile şifreden key türetme

  EKSİK (production için gerekli):
    ✗ mlock() — key sayfasını swap'a yazmayı engelle
    ✗ mprotect(PROT_NONE) — kullanılmadığında sayfayı koru
    ✗ Argon2id — PBKDF2 yerine daha güvenli KDF
    ✗ OS Keychain / AWS Secrets Manager entegrasyonu
    ✗ HSM (Hardware Security Module) desteği

  REVERSE ENGINEERING SAVUNMASI:
    • Hardcoded key YOK → .rodata analizi işe yaramaz
    • Runtime üretilen key → binary'de görünmez
    • zeroize → dump alındığında key bellekte 0x00
    • Her run farklı key → tekrar üretilemez
    "#);

    println!("\n[✓] Tüm senaryolar başarıyla tamamlandı!");
}
