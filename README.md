# 🔐 Crypto Vault — Güvenli Şifreleme ve Anahtar Yönetimi

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Security](https://img.shields.io/badge/Security-AES--256--GCM-blue?style=for-the-badge)
![Memory Safe](https://img.shields.io/badge/Memory_Safe-Zeroize-success?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

Modern kriptografi standartları ve Rust'ın bellek güvenliği (memory safety) avantajları kullanılarak geliştirilmiş bir AES-256-GCM şifreleme ve güvenli anahtar yönetimi (Key Management) demo projesidir.

## 👨‍🏫 Danışman
Bu proje, **Keyvan Arasteh Abbasabad** danışmanlığında geliştirilmiştir.

## ✨ Temel Özellikler

* **Authenticated Encryption (AES-256-GCM):** Verilerin sadece gizliliğini değil, bütünlüğünü de (integrity) sağlar. Manipüle edilmiş şifreli metinler (ciphertext) otomatik olarak tespit edilir ve reddedilir.
* **Bellek Güvenliği (Memory-Safe Keys):** `zeroize` kütüphanesi sayesinde bellek üzerindeki şifreleme anahtarları işlevlerini tamamladığında veya program sonlandığında (Drop) bellekten `0x00` ile tamamen silinir. Bu sayede bellek dökümü (memory dump) saldırılarına karşı koruma sağlanır.
* **Semantic Security:** Her şifreleme işleminde benzersiz ve rastgele bir 12-byte "Nonce" (Initialization Vector) üretilir. Aynı metin defalarca şifrelense bile her seferinde farklı bir çıktı (ciphertext) elde edilir.
* **Güvenli Anahtar Saklama Stratejileri:** Proje içerisinde PBKDF2 konseptiyle paroladan deterministik anahtar türetme ve `MemoryKeyStore` üzerinden bellek içi geçici anahtar yönetimi senaryoları mevcuttur.

## 📦 Kullanılan Kütüphaneler (Dependencies)

* **`ring`**: Google tarafından desteklenen, OpenSSL'e modern ve daha güvenli bir alternatif olan yüksek performanslı kriptografi motoru.
* **`zeroize`**: Hassas verileri bellekten güvenli bir şekilde silmek (zeroing) için kullanılan araç.
* **`getrandom`**: İşletim sistemi seviyesinde güvenli rastgele sayı ve Nonce üretimi.
* **`thiserror`**: Merkezi ve temiz hata (Error) yönetimi.

## 📂 Proje Yapısı

* `crypto.rs`: Şifreleme motoru ve paket (EncryptedPacket) mimarisi.
* `secure_mem.rs`: `SecureKey` ve `SecureNonce` yapıları ile bellek güvenliği implementasyonları.
* `key_store.rs`: Anahtar saklama yöntemlerinin güvenlik analizleri ve `MemoryKeyStore` yapısı.
* `errors.rs`: Projeye özgü `VaultError` tanımlamaları.
* `main.rs`: Tüm sistemin test edildiği 6 farklı güvenlik senaryosu.

## 🚀 Kurulum ve Çalıştırma

Projeyi derlemek ve çalıştırmak için sisteminizde [Rust ve Cargo](https://rustup.rs/) kurulu olmalıdır.

**Projeyi Çalıştırmak İçin:**
```bash
cargo run
