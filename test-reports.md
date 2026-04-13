# SSO vs. Traditional Auth: Detailed Security Test Reports (T1-T11)

Bu doküman, Tek Oturum Açma (SSO) ve Geleneksel Çoklu Giriş sistemleri arasında yapılan 11 deneysel güvenlik ve performans testinin derinlemesine sonuçlarını, istatistiksel analizlerini ve zafiyet karşılaştırmalarını içermektedir.

---

## T1 — Brute Force Attack (Geleneksel Sistem)
**Makale Analizi:** Zineddine et al. (CMC 2025)
**Metodoloji:** 4 bağımsız endpoint'e yönelik sözlük saldırısı (correct pw at position 24), her servis için 5 tekrar (n=5).

### Sonuçlar
| Endpoint | Ortalama Kırılma Süresi | Standart Sapma | Deneme |
|----------|-----------------------|----------------|--------|
| Service A | 1,052ms | ±25ms | 24 |
| Service B | 1,038ms | ±9ms  | 24 |
| Admin     | 1,052ms | ±13ms | 24 |
| API       | 1,039ms | ±8ms  | 24 |

**Akademik Kıyaslama:** Tüm servislerin bağımsız olarak kırılabilmesi, geleneksel mimari sistemin saldırı yüzeyini fiziksel olarak 4 katına çıkardığını göstermektedir. (Vulnerability Confirmed)

---

## T2 — Password Reuse Attack (Geleneksel Sistem)
**Makale Analizi:** Zineddine et al. (CMC 2025)

**Sonuç:** Çalınan tek bir şifre (`user@test.com:password123`) kullanılarak, entegrasyonu olmayan diğer 3 servise de %100 oranında yetkisiz giriş yapılmıştır. 

**Akademik Kıyaslama:** Modern SSO mimarisi bu "domino taşı" etkisini ortadan kaldırırken, geleneksel sistemde kullanıcıların aynı şifreyi kullanma eğilimi tüm ekosistemi riske atmaktadır. (Vulnerability Confirmed)

---

## T3 — Service Isolation / Fault Tolerance (Geleneksel Sistem)
**Makale Analizi:** Zineddine et al. (CMC 2025)

**Sonuç:** Service A kasıtlı olarak çökertildiğinde (`docker stop trad-service-a`), geriye kalan 3 servise başarıyla login olunmaya devam edilmiştir. (%75 erişilebilirlik).

**Akademik Kıyaslama:** Merkezi bir doğrulama noktası (IdP) olmayan geleneksel mimari, kısmi çöküntülere (partial outages) karşı SSO'dan çok daha dayanıklıdır. (Advantage Confirmed)

---

## T4 — JWT Replay & alg:none Attacks (SSO)
**Makale Analizi:** Philippaerts et al. (RAID 2022)

**Güvensiz Mod:** 
- JTI (Replay) kontrolü eksikken: Çalınan JWT defalarca kullanıldı (Başarılı)
- JWT signature check eksikken: Token algoritması `alg:none` olarak değiştirilip sisteme sızıldı (Başarılı)

**Güvenli Mod:**
- Replay: `usedJtis.has()` ile 401 Unauthorized
- alg:none: `jwt.verify(..., {algorithms: ['RS256']})` ile 401 Unauthorized

**Akademik Kıyaslama:** Araştırma verilerinde belirtilen "OAuth 2.0 / JWT uygulamalarındaki konfigurasyon eksikliklerinin %97'ye varan güvenlik ihlallerine yol açtığı" teorisi, Insecure PoC'de %100 sömürüye dönüştürülmüş ve doğru RS256/JTI validasyonuyla mitigate edilmiştir.

---

## T5 — Redirect URI Manipulation (SSO)
**Makale Analizi:** Innocenti et al. (ACSAC 2023)

**Güvensiz Mod (Prefix-based validation `startsWith`):**
- Path Confusion (`/callback/../evil`): Başarılı
- OAuth Parameter Pollution (`/callback?redirect_uri=evil.com`): Başarılı
- Wildcard/Suffix (`/callback.evil.com`): Başarılı

**Güvenli Mod (Exact-match validation `includes`):** Tüm vektörler engellendi.

**Akademik Kıyaslama:** Yüzde 37 ila 62 aralığında tehlike doğuran zayıf URI validasyonları, Exact-Match algoritmayla bütünüyle bertaraf edilmiştir.

---

## T6 — CSRF / Session Fixation (SSO)
**Makale Analizi:** Fett et al. (CCS 2016)

**Güvensiz Mod:** Saldırgan kendi authorization code'unu, `state` kontrolünden habersiz kurbanın oturum fiksasyonuna (Session Fixation) yamadı. Kurbanın giriş bilgileri saldırganın hesabına tahsis edildi. (Başarılı)

**Güvenli Mod:** State ve PKCE (`code_verifier`) kontrolleri, kurbanın foreign authorization code'u işletmesini 400 Bad Request hatasıyla engelledi. (Mitigate edildi)

---

## T7 — Identity-Account Mismatch (SSO)
**Makale Analizi:** Liu et al. (WWW 2021)

**Metodoloji:** Saldırgan kendi oluşturduğu, kurbanın (`victim@test.com`) emailini taşıyan fakat tamamen farklı bir yabancı RSA Private Key ile imzalanmış (`iss: evil-idp.com`) bir JWT üretti.

**Güvensiz Mod:** Service A token içerisindeki `email` adresine güvenerek Account Takeover'a izin verdi.
**Güvenli Mod:** Yabancı imza, `token_verification_failed` hatası verip isteği anında düşürdü.

---

## T8 — Single Point of Failure Nüansı (SSO)
**Makale Analizi:** Zineddine et al. (CMC 2025)

**Test Senaryosu:** SSO Identity Provider sunucusu öldürülmüştür.

- **Yeni Oturum Denemesi:** 4 servise de giriş başarısız (**0/4 New Login**)
- **Mevcut JWT ile Deneme:** Servis sağlayıcılar kendi belleklerindeki Public Key ile JWT imzasını doğrulayabildiği için 4 serviste de oturumlar açık kaldı (**4/4 Existing Token Survives**).

**Akademik Kıyaslama:** SPOF'un SSO ekosistemini anında karartmadığı, önceden elde edilen JWT tokenların ömrü (exp) dolana dek sistemlerin işlevsellik göstermeye devam ettiği (Stateless) saptanmıştır.

---

## T9 — Token Expiration Enforcement (SSO)
**Makale Analizi:** Philippaerts et al. (RAID 2022)

- **Test A (Gerçek Süresi Dolmuş Token):** Her iki modda da RBAC tarafından engellendi.
- **Test B (İmzası Değiştirilmiş Exp_2030 Token):** Güvensiz modda (Sadece decodes) saldırganın kendi foreign key'iyle exp süresini sonsuza uzattığı token **kabul görmüştür.**

**Akademik Kıyaslama:** JWT token iptal mekanizmasındaki sorunlar ve süresiz yaşama zafiyetleri (Expiration Manipulation), imza mekanizması atlatıldığında kaçınılmazdır.

---

## T10 — DoS Bottleneck: Centralization Stress (SSO vs Trad)
**Makale Analizi:** Zineddine et al. (CMC 2025)

**Senaryo:** Eşzamanlı 100 concurrent Login isteği

| Metrik (ms) | Geleneksel (Dağıtık) | SSO (Merkezileşmiş | Fark |
|------------|----------|----------|--------|
| Ort. Yanıt (Mean) | 376ms | 643ms | **1.71x Yavaş** |
| p50 (Median) | 387ms | 643ms | 1.66x |
| p95 (Kuyruk) | 636ms | 1,145ms | **1.80x Yavaş** |
| p99 (Kuyruk) | 677ms | 1,191ms | 1.76x |

**Akademik Kıyaslama:** Tüm trafiğin IdP üzerinde merkezileşmesi, yoğun yük altında Geleneksel sisteme kıyasla 1.80 kat (p95) darboğaz yaratmıştır. Centralization riski (Bottleneck) ampirik olarak kanıtlanmıştır.

---

## T11 — RBAC Role Escalation (SSO)
**Bağımsız Test (Privilege Escalation)**

- User rolüyle `/admin` endpointine gidiş: `403 Forbidden` (RBAC engelledi)
- Saldırganın sahte "admin" rolü set ederek token istemesi (`iss: localhost:4000`, `role: admin`): **Her iki modda da Güvenlik İhlali (200 OK — Admin Access Granted)**

**Nihai Yorum:** Token üretim anında Role claim'lerinin "Self-asserted" (kullanıcının kendi beyanına bırakılmış) olması, JWT tabanlı sistemlerdeki en tehlikeli mantık hatalarından biridir ve sistem imzaları kontrol etse de yetki yükselmesini doğrudan engelleyemez.
