# Test Sonuçları — Detaylı Analiz Raporu
> 11 Test Senaryosu • 20 JSON Sonuç Dosyası • 2 Mod (Insecure / Secure)

---

## T1 — Brute Force Attack (Geleneksel Sistem)
**Makale:** Zineddine et al. (CMC 2025)
**Mod:** Sadece Geleneksel (SSO'da merkezi login olduğu için brute-force yüzeyi 1'e düşer)

### Metodoloji
- 50 kelimelik sözlük, doğru şifre 24. sırada
- Her endpoint için **5 ayrı çalıştırma** yapılıp istatistik alındı
- 4 bağımsız endpoint test edildi (Port 3001-3004)

### Sonuçlar

| Endpoint | Ort. Süre | Std Sapma | Deneme Sayısı |
|----------|-----------|-----------|---------------|
| Service A (:3001) | **1,052ms** | ±25ms | 24 |
| Service B (:3002) | **1,038ms** | ±9ms | 24 |
| Admin (:3003) | **1,052ms** | ±13ms | 24 |
| API (:3004) | **1,039ms** | ±8ms | 24 |

### Yorum
Dört bağımsız servisin tamamı ~1 saniyede kırıldı. Standart sapma çok düşük (8-25ms), bu da testin tutarlı ve tekrarlanabilir olduğunu kanıtlıyor. Geleneksel mimaride saldırganın 4 ayrı kapıyı (saldırı yüzeyi) hedefleyebilmesi, Zineddine'in "multiplied attack surface" tezini doğruluyor.

> Rapor cümlesi: *"The brute-force attack succeeded after 24 attempts in 1,045 ± 15ms (n=5, 4 endpoints). All four independent services were compromised, confirming a 4x attack surface multiplication."*

---

## T2 — Password Reuse Attack (Geleneksel Sistem)
**Makale:** Zineddine et al. (CMC 2025)

### Sonuçlar
- Sızdırılan tek credential (`user@test.com:password123`) ile **4/4 servise (%100)** giriş yapıldı
- Hiçbir serviste rate limiting veya anomali algılama yok

### Yorum
Geleneksel sistemde her servisin kendi bağımsız veritabanı olduğu ve kullanıcıların aynı şifreyi tekrar kullandığı senaryoda, bir servisin ihlali diğer tüm servislerin ihlali anlamına gelir.

---

## T3 — Service Isolation / Fault Tolerance (Geleneksel Sistem)
**Makale:** Zineddine et al. (CMC 2025)

### Sonuçlar
- Service A durduruldu (`docker stop trad-service-a`)
- Kalan servislerin durumu: **3/3 hayatta** (%75 erişilebilirlik)
- Service B, Admin, API hizmet vermeye devam etti

### Yorum
Geleneksel mimarinin TEK avantajı budur: merkezi bağımlılık olmadığı için bir servisin çökmesi diğerlerini etkilemez. Bu, T8'deki SSO SPOF sonucuyla doğrudan karşılaştırılıyor.

---

## T4 — JWT Replay & alg:none Attacks (SSO)
**Makale:** Philippaerts et al. (RAID 2022)

### Insecure Mode Sonuçları
| Saldırı | Sonuç |
|---------|-------|
| Replay Attack (aynı token 2 kez) | 🚨 **Başarılı** — JTI kontrolü yok |
| alg:none (imzasız token) | 🚨 **Başarılı** — `jwt.decode()` imza kontrol etmiyor |

### Secure Mode Sonuçları
| Saldırı | Sonuç |
|---------|-------|
| Replay Attack | 🔒 **Engellendi** — JTI blacklist aktif |
| alg:none | 🔒 **Engellendi** — `jwt.verify()` sadece RS256 kabul ediyor |

### Yorum
Philippaerts'in %97 oranında IdP'lerin en az bir kontrolü eksik bıraktığı bulgusu deneysel olarak doğrulandı. İmza doğrulaması (`jwt.verify` vs `jwt.decode`) tek başına iki kritik saldırıyı engelliyor.

---

## T5 — Redirect URI Manipulation (SSO)
**Makale:** Innocenti et al. (ACSAC 2023)

### Insecure Mode Sonuçları
| Varyant | Manipüle URI | Sonuç |
|---------|-------------|-------|
| Path Confusion | `/callback/../evil` | 🚨 **Kabul edildi** |
| OAuth Parameter Pollution | `/callback?redirect_uri=evil.com` | 🚨 **Kabul edildi** |
| Wildcard/Suffix | `/callback.evil.com` | 🚨 **Kabul edildi** |

**3/3 saldırı başarılı** → `startsWith()` tabanlı prefix eşleşme tamamen yetersiz

### Secure Mode Sonuçları
**0/3 saldırı başarılı** → `client.redirect_uris.includes(redirectUri)` exact-match her üçünü engelledi

### Yorum
Innocenti'nin %37.5 path confusion ve %62.5 OPP yaygınlık oranları, bizim PoC'de prefix-based doğrulama kullanıldığında **%100 sömürü garantisine** dönüşüyor. Tek satır kod değişikliği (`startsWith` → `includes`) tüm vektörleri kapatıyor.

---

## T6 — CSRF / Session Fixation (SSO) ⭐ YENİ
**Makale:** Fett et al. (CCS 2016) & Benolli et al. (DIMVA 2021)

### Insecure Mode Sonuçları
| Faz | Ne Oldu | Sonuç |
|-----|---------|-------|
| Phase 1: Saldırgan auth code aldı | Code: `1c72a387...` | ✅ Başarılı |
| Phase 2: Saldırganın code'u kurban adına exchange edildi | Token üretildi! | 🚨 **Session Fixation!** |
| Phase 3: State parametresi atlandı | IdP kabul etti | 🚨 **CSRF mümkün** |

### Secure Mode Sonuçları
| Faz | Ne Oldu | Sonuç |
|-----|---------|-------|
| Phase 1: Saldırgan auth code aldı | Başarılı (state gerekli) | Code alındı |
| Phase 2: Code exchange denendi | `invalid_grant` — PKCE verifier uyuşmuyor | 🔒 **Engellendi** |
| Phase 3: State atlandı | `400 Bad Request` | 🔒 **Engellendi** |

### Yorum
Gerçek CSRF zinciri simüle edildi: saldırgan kendi code'unu kurbanın oturumuna yamamayı denedi. PKCE mekanizması (code_verifier binding) bu saldırıyı imkansız kılıyor çünkü saldırgan kurbanın verifier'ını bilmiyor.

---

## T7 — Identity-Account Mismatch ⭐ DÜZELTILDI
**Makale:** Liu et al. (WWW 2021)

### Reform: Artık Ayrı RSA Key Pair Kullanılıyor
Önceki versiyonda sistemin kendi JWT Service'i ile imzalanıyordu (geçerli imza). Yeni versiyonda **saldırganın kendi RSA 2048-bit key pair'i** ile imzalanıyor.

### Insecure Mode
🚨 **Account Takeover başarılı!**
- Token: `iss=evil-idp.com`, `sub=attacker_001`, `email=victim@test.com`
- İmza: Saldırganın **kendi** private key'i (sisteminkinden tamamen farklı)
- Sonuç: Service A, `jwt.decode()` kullanarak imzayı kontrol etmedi, sadece email'e baktı ve kurbanın dashboard'una erişim verdi

### Secure Mode
🔒 **Engellendi: `token_verification_failed`**
- `jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] })` saldırganın yabancı imzasını ilk adımda reddetti
- İssuer kontrolüne gerek bile kalmadı — kriptografik imza doğrulaması tek başına yeterli

---

## T8 — Single Point of Failure (SPOF) ⭐ NÜANS EKLENDİ
**Makale:** Zineddine et al. (CMC 2025)

### 4 Fazlı Test Sonuçları

| Faz | Senaryo | Sonuç |
|-----|---------|-------|
| Phase 1: Token al (IdP ayakta) | Normal auth flow | ✅ Token alındı |
| Phase 2: IdP çökertildi | `docker stop sso-idp` + 3sn bekleme | IdP DÜŞ |
| Phase 3: **Yeni login** dene | 4 servise giriş denemesi | ❌ **0/4** — tamamen felç |
| Phase 4: **Mevcut tokenla** eriş | Önceden alınan JWT ile | ✅ **4/4** — stateless JWT çalışıyor |

### Kritik Nüans
> **"IdP çöktüğünde yeni oturum açılamaz (0/4), ancak mevcut oturumlar tokenın süresi dolana kadar (%100) çalışmaya devam eder."**

Bu nüans önceki testte yoktu. JWT'ler stateless olduğu için (public key Service Provider'da önbelleğe alındığı için) IdP'ye bağımlılık sadece **yeni token üretimi** içindir. Bu, SPOF'un tam olarak "anında tam çöküş" değil, "aşamalı bozulma" (graceful degradation) olduğunu gösterir.

---

## T9 — Token Expiration Enforcement ⭐ YENİ
**Makale:** Philippaerts et al. (RAID 2022) — Token Lifecycle

### Insecure Mode
| Test | Sonuç |
|------|-------|
| Test A: Süresi 1 saat önce dolmuş token | 🔒 **Reddedildi** (`token_expired`) — her iki modda da exp kontrol ediliyor |
| Test B: Saldırgan key'iyle exp=2030 olarak manipüle edilmiş token | 🚨 **Kabul edildi!** Saldırganın yabancı key'iyle imzalanmış tokenın exp alanı güvenildi |

### Secure Mode
| Test | Sonuç |
|------|-------|
| Test A: Süresi dolmuş token | 🔒 **Reddedildi** (`token_verification_failed`) |
| Test B: Manipüle edilmiş exp | 🔒 **Reddedildi** (`token_verification_failed`) — signature check exp manipulation'ı da engelliyor |

### Yorum
İlginç bir bulgu: RBAC middleware **her iki modda da** `exp` kontrolü yapıyor (satır 76), bu yüzden Test A her zaman reddediliyor. Ancak Test B'de asıl tehlike ortaya çıkıyor: saldırgan kendi key'iyle imzaladığı tokena `exp: 2030` koyduğunda, insecure modda `jwt.decode()` imzayı kontrol etmediği için bu sahte exp bile güveniliyor. T4 ile farkı şudur: **T4 geçerli tokenın tekrar kullanımını (replay), T9 ise tokenın ömrünün manipülasyonunu test ediyor.**

---

## T10 — DoS Bottleneck: Centralization Stress Test ⭐ YENİ
**Makale:** Zineddine et al. (CMC 2025) — Centralization Risk

### 100 Eşzamanlı İstek Sonuçları

| Metrik | Geleneksel (4 sunucu, dağıtık) | SSO (tek IdP, merkezi) | Fark |
|--------|-------------------------------|----------------------|------|
| **Mean** | 376ms | 643ms | **1.71x yavaş** |
| **p50** (Medyan) | 387ms | 643ms | 1.66x |
| **p95** | 636ms | 1,145ms | **1.80x** |
| **p99** | 677ms | 1,191ms | 1.76x |
| **Max** | 677ms | 1,191ms | 1.76x |
| Başarılı | 100/100 | 100/100 | Eşit |
| Başarısız | 0 | 0 | Eşit |

### Yorum
SSO'nun tek merkez noktası (IdP), 100 eşzamanlı istek altında geleneksel dağıtık sistemden **ortalama 1.71 kat, kuyruk latency'de (p95) 1.80 kat** daha yavaş yanıt veriyor. Hiçbir istek başarısız olmadı (sunucu çökmedi), ancak yanıt süreleri belirgin şekilde arttı.

> Rapor cümlesi: *"Under 100 concurrent authentication requests, the centralized SSO IdP exhibited 1.71x mean latency (643ms vs 376ms) and 1.80x p95 latency (1,145ms vs 636ms) compared to the distributed traditional architecture, empirically confirming Zineddine et al.'s centralization bottleneck thesis."*

---

## T11 — RBAC Role Escalation ⭐ YENİ
**Bağımsız Öğrenci Katkısı** — Vertical Privilege Escalation

### Her İki Modda Sonuçlar

| Test | Insecure | Secure |
|------|----------|--------|
| Test A: `user` rolüyle `/admin`'e erişim | 🔒 **403 Forbidden** — RBAC doğru çalışıyor | 🔒 **403 Forbidden** |
| Test B: Sahte `admin` rolüyle token üretip `/admin`'e erişim | 🚨 **200 OK — Privilege Escalation!** | 🚨 **200 OK — Privilege Escalation!** |

### ⚠️ Kritik Bulgu: T11-B Her İki Modda da Zafiyet!
JWT Service (`/sign` endpoint'i) herkesin istediği payload'ı imzalamasına izin veriyor. Saldırgan `role: "admin"` claim'iyle token ürettirdiğinde, **RBAC middleware bunu doğrulayamıyor** çünkü token meşru key ile imzalanmış.

Bu, JWT tabanlı RBAC'ın temel bir zayıflığını ortaya koyuyor: **Role claim'leri token içinde self-asserted (kendi kendine iddia edilen) olduğu sürece, imza doğrulaması tek başına privilege escalation'ı engelleyemez.** Gerçek dünyada çözüm: JWT Service'in (veya token endpoint'inin) role bilgisini kullanıcıdan almak yerine veritabanından çekmesi gerekir.

---

## Genel Sonuç Tablosu

| Test | Insecure | Secure | Nüans |
|------|----------|--------|-------|
| T1 Brute Force | 4/4 kırıldı (1045±15ms) | N/A | 5 run ortalaması |
| T2 Password Reuse | 4/4 ele geçirildi | N/A | — |
| T3 Isolation | 3/3 hayatta | N/A | Geleneksel avantaj |
| T4 Replay/alg:none | 2/2 saldırı başarılı | 0/2 engellendi | ✅ Tam mitigasyon |
| T5 Redirect URI | 3/3 saldırı başarılı | 0/3 engellendi | ✅ Tam mitigasyon |
| T6 CSRF/Fixation | Session Fixation başarılı | PKCE ile engellendi | ✅ Tam mitigasyon |
| T7 Identity Mismatch | Sahte key ile giriş yapıldı | İmza reddedildi | ✅ Tam mitigasyon |
| T8 SPOF | Yeni: 0/4, Mevcut: 4/4 | — | ⚠️ Nüanslı SPOF |
| T9 Token Expiry | Expired ❌, Manipüle ✅ | Her ikisi ❌ | ⚠️ Kısmi zafiyet |
| T10 DoS Bottleneck | SSO 1.71x yavaş | — | Yapısal risk |
| T11 RBAC Escalation | User ❌, Forged Admin ✅ | User ❌, Forged Admin ✅ | ⚠️ Her iki modda açık! |
