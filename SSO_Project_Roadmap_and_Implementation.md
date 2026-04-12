# SSO vs. Geleneksel Login — Proje Uygulama Rehberi
### Network Security HW2 | Samet Bulut | Dokuz Eylül Üniversitesi

---

## İÇİNDEKİLER

1. [Makale Bulguları ve Test Karşılaştırma Planı](#1-makale-bulgulari)
2. [Mimari Kurulum — Faz 1 (Prompt ve Detaylar)](#2-mimari-kurulum)
3. [Geleneksel Sistem Testleri — Faz 2](#3-geleneksel-sistem-testleri)
4. [SSO Sistem Testleri — Faz 3](#4-sso-sistem-testleri)
5. [Tablo ve Grafik Planı — Son Aşama](#5-tablo-ve-grafik-plani)
6. [Rapor Bölümü Yazım Rehberi](#6-rapor-bolumu)

---

## 1. MAKALE BULGULARI VE TEST KARŞILAŞTIRMA PLANI

Her testin hangi makaleyle eşleştiğini ve senin bulgularınla nasıl karşılaştırılacağını burada tanımlıyoruz.

---

### BULGU 1 — IdP Mix-Up & CSRF Saldırısı
**Makale:** Fett, Küsters & Schmitz — *A Comprehensive Formal Security Analysis of OAuth 2.0* [1], CCS 2016

**Makale Bulgusu:**
OAuth 2.0'ın Authorization Code ve Implicit grant tiplerinde formal analiz sırasında 4 adet kritik güvenlik açığı keşfedilmiştir. Bunların en önemlisi **IdP Mix-Up Attack**'tır: kullanıcı birden fazla IdP destekleyen bir RP üzerinde oturum açmaya çalıştığında, saldırgan kullanıcıyı kötü niyetli bir IdP'ye yönlendirerek authorization code'u çalabilmektedir. Ayrıca `state` parametresinin yeniden kullanılması durumunda CSRF saldırısı mümkün olmaktadır. Bu açıkların protokol standardının kendisinde var olduğu, sadece implementasyon hatası olmadığı kanıtlanmıştır.

**Senin Testin (T6):**
- SSO sisteminde `state` parametresi olmadan authorization isteği gönder.
- Aynı `state` değeriyle ikinci bir istek başlat ve session integrity'nin kırılıp kırılmadığını gözlemle.
- Node.js IdP implementasyonunda `state` doğrulamasını devre dışı bırak → saldırı başarılı olmalı.
- Ardından `state` doğrulamasını etkinleştir → saldırı engellenmiş olmalı.

**Karşılaştırma Sorusu:**
> Fett et al., bu açığın protokol standardının kendisinde olduğunu iddia ediyor. Senin implementasyonunda bu açık yalnızca kodlama hatası mıydı yoksa standart mı eksik? `state` parametresi eklenince saldırı tam olarak engellendi mi?

---

### BULGU 2 — Redirect URI Validasyon Yetersizliği
**Makale:** Innocenti et al. — *OAuth 2.0 Redirect URI Validation Falls Short, Literally* [9], ACSAC 2023

**Makale Bulgusu:**
16 popüler IdP (Atlassian, Facebook, GitHub, Microsoft, NAVER vb.) üzerinde yapılan deneysel çalışmada:
- **6/16 IdP** (%37.5) path confusion saldırısına karşı savunmasız bulunmuştur.
- **10/16 IdP** (%62.5) OAuth Parameter Pollution (OPP) saldırısına karşı savunmasız bulunmuştur.
- **GitHub ve NAVER**, redirect URI'ı doğrulama aşamasında da hatalı davranmıştır (*Incorrect Redeem Validation*).
- İncelenen ölçümlerin %10'unda (464 ölçümden 46'sında) authorization code'un 3. parti reklam ağlarına sızdığı tespit edilmiştir.

**Senin Testin (T5):**
- IdP'ye kayıtlı URI: `http://localhost:3001/callback`
- Saldırı denemesi 1 — Path Confusion: `http://localhost:3001/callback/../evil`
- Saldırı denemesi 2 — OPP: `http://localhost:3001/callback?redirect_uri=http://evil.com`
- Saldırı denemesi 3 — Wildcard: `http://localhost:3001/callback*`
- Her denemede authorization code'un nereye gittiğini Postman ile kaydet.
- Tam eşleşme (exact match) validasyonu uygula → tekrar test et.

**Karşılaştırma Sorusu:**
> Innocenti et al. gerçek dünya IdP'lerinin %37.5–62.5'inin savunmasız olduğunu gösterdi. Senin implementasyonunda bu oran neydi? Tam URI eşleşmesi uygulandıktan sonra açık kapandı mı?

---

### BULGU 3 — OAuth CSRF Saldırısı Yaygınlığı
**Makale:** Benolli et al. — *The Full Gamut of an Attack: An Empirical Analysis of OAuth CSRF in the Wild* [7], DIMVA 2021

**Makale Bulgusu:**
Gerçek dünyada OAuth CSRF saldırıları analiz edildiğinde, `state` parametresinin kullanılmaması veya yanlış kullanılmasının CSRF saldırısına doğrudan yol açtığı gösterilmiştir. Saldırgan, bir kurbanın OAuth flow'unu kendi hesabına bağlayabilir ve kurban fark etmeden saldırganın oturumunu açar hale gelebilir (*session fixation via CSRF*).

**Senin Testin (T6 ile birleşik):**
- Postman'da iki farklı kullanıcı oturumu aç (kurban ve saldırgan).
- Saldırganın başlattığı OAuth flow'una ait `code` değerini kopyala.
- Bu `code` değerini kurban tarafından gönderilmiş gibi callback endpoint'ine yolla.
- SSO sisteminin bu isteği kabul edip etmediğini gözlemle.
- `state` + PKCE aktifken aynı saldırıyı tekrarla.

**Karşılaştırma Sorusu:**
> Benolli et al. bu saldırının gerçek platformlarda gözlemlendiğini kanıtladı. Senin prototip ortamında `state` olmadan bu saldırı kaç denemede başarılı oldu? `state` eklenince başarı oranı sıfıra düştü mü?

---

### BULGU 4 — Identity–Account Eşleşmezliği
**Makale:** Liu, Gao & Wang — *An Investigation of Identity-Account Inconsistency in Single Sign-On* [6], WWW 2021

**Makale Bulgusu:**
SSO sistemlerinde identity (IdP'den gelen kimlik bilgisi) ile account (RP'deki hesap) arasındaki bağlama (linking) sürecindeki tutarsızlıklar ciddi güvenlik açıklarına yol açmaktadır. Farklı IdP'lerin aynı e-posta adresiyle farklı user ID'leri döndürmesi ya da e-posta doğrulamasının yapılmaması durumunda hesap ele geçirme mümkün hale gelmektedir.

**Senin Testin (T7):**
- Sistem A'ya `attacker@evil.com` ile kayıt ol.
- Aynı e-posta adresini kullanarak farklı bir IdP token'ı (sahte JWT) oluştur.
- Bu token'ı Service B'ye sun ve sistemin bu kimliği doğrulayıp doğrulamadığını gözlemle.
- Ardından `iss` (issuer) + `sub` (subject) + `email` triple doğrulamasını ekle → tekrar test et.

**Karşılaştırma Sorusu:**
> Liu et al. bu açığın SSO sistemlerinde hesap ele geçirilmesine yol açtığını gösterdi. Senin sistemin sadece e-posta bazlı doğrulama yaptığında bu açık mevcut muydu? `iss` + `sub` kombinasyonu eklenince kapandı mı?

---

### BULGU 5 — Tek Nokta Başarısızlığı (Single Point of Failure)
**Makale:** Zineddine et al. — *Single Sign-On Security and Privacy: A Systematic Literature Review* [11], CMC 2025

**Makale Bulgusu:**
2315 makale arasından seçilen 88 yayının sistematik derlemesinde, SSO'nun en kritik yapısal dezavantajı olarak **tek nokta başarısızlığı** öne çıkmaktadır. IdP'nin çökmesi veya ele geçirilmesi durumunda bağlı tüm servislerin erişim kaybettiği vurgulanmaktadır. Token kötüye kullanımı (token abuse/leakage), DangerNeighbor saldırısı ve misconfigured SDK'ler de literatürün sıklıkla işaret ettiği tehditler arasındadır.

**Senin Testin (T8):**
- 4 servis (Service A, B, Admin Panel, API) çalışırken IdP container'ını durdur (`docker stop idp`).
- Her serviste oturum açmayı dene → tüm servisler için yanıt süresini ve hata mesajını kaydet.
- Geleneksel sistemde Service A'yı durdur → diğer 3 servise erişimin devam ettiğini göster.
- İki sistemin "blast radius" (etki alanı genişliği) metriğini karşılaştır.

**Karşılaştırma Sorusu:**
> Zineddine et al. literatürün bu riski sürekli vurguladığını ama pratik çözümlerin yetersiz kaldığını belirtiyor. Senin testinde IdP çöküşünde kaç servis etkilendi? Geleneksel sistemde tek servis çöküşünde kaç servis etkilendi? Fark ne kadar büyük?

---

### BULGU 6 — Güvenlik Uyum Yetersizliği
**Makale:** Philippaerts et al. — *Exploring Security Compliance in the OAuth 2.0 Ecosystem* [8], RAID 2022

**Makale Bulgusu:**
OAuth 2.0 ekosisteminde güvenlik uyumluluğu incelendiğinde, RFC spesifikasyonunu tam olarak uygulayan sistemlerin bile pratikte ciddi güvenlik açıkları barındırdığı görülmüştür. Sistemlerin RFC'yi takip etmesi, güvenli olduklarını garanti etmemektedir.

**Senin Testin (T4 + T5 ile bağlantılı):**
- JWT token'ını expiry kontrolü olmadan tekrar kullan (replay attack).
- `alg: none` başlıklı JWT gönder → sistem kabul ediyor mu?
- İmza doğrulamasını devre dışı bırak → token kabul ediliyor mu?
- Tüm bu testleri RFC 6749 uyumlu yazdığını düşündüğün kodla yap.

**Karşılaştırma Sorusu:**
> Philippaerts et al. RFC uyumunun yeterli olmadığını gösterdi. Senin "doğru" yazdığını düşündüğün JWT implementasyonunda `alg: none` saldırısı çalıştı mı? Bu, RFC'nin değil implementasyonun eksikliği miydi?

---

## 2. MİMARİ KURULUM — FAZ 1

### ÇOK UZUN DETAYLI UYGULAMA PROMPTU

Aşağıdaki prompt'u bir AI kod asistanına (Claude, ChatGPT vb.) veya doğrudan kendi geliştirme sürecine rehber olarak kullan:

---

```
GÖREV: İki ayrı Node.js + Express.js prototip ortamı oluştur.
Birinci ortam geleneksel çok-girişli (multi-login) kimlik doğrulama 
sistemi, ikinci ortam merkezi SSO (Single Sign-On) sistemidir.
Her iki sistem de Docker container'larıyla izole edilecektir.

=======================================================
ORTAM 1: GELENEKSEL MULTİ-LOGIN SİSTEMİ
=======================================================

Dizin yapısı şöyle olmalı:
traditional-auth/
├── docker-compose.yml
├── service-a/          (Port 3001)
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js
│   └── db.json         (kullanıcı veritabanı — sadece bu servisin kullanıcıları)
├── service-b/          (Port 3002)
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js
│   └── db.json
├── admin-panel/        (Port 3003)
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js
│   └── db.json
└── api-service/        (Port 3004)
    ├── Dockerfile
    ├── package.json
    ├── server.js
    └── db.json

Her servisin kendi bağımsız kullanıcı tablosu var:
- Her servis kendi db.json dosyasına sahip
- Kullanıcılar farklı şifreler kullanmak zorunda (veya aynı şifreyi tekrar
  kaydetmeleri gerekiyor — bu password reuse'u test etmek için kritik)
- Hiçbir servis diğerinin user tablosunu bilmiyor

Her servis için server.js şunları içermeli:
  POST /register   → kullanıcı kaydı (email + password hash bcrypt ile)
  POST /login      → email + password doğrulama, başarılı ise session cookie
  GET  /dashboard  → giriş yapmış kullanıcıya özel içerik (session kontrolü)
  POST /logout     → session silme
  GET  /health     → servis durumu (IdP çöküş testleri için)

ÖNEMLI DETAYLAR:
- Şifreleri bcrypt ile hashle (saltRounds: 10)
- Session yönetimi için express-session kullan
- Rate limiting YOKTUR (brute-force testleri için kasıtlı olarak)
- Hiçbir MFA mekanizması yok (kasıtlı olarak)
- Her serviste farklı bir SECRET_KEY kullan (kasıtlı güvenlik açığı)
- db.json'da test kullanıcıları: 
  { "users": [ 
    { "email": "user@test.com", "password": "$2b$10$...", "role": "user" },
    { "email": "admin@test.com", "password": "$2b$10$...", "role": "admin" }
  ]}

DOCKER YAPILANDIRMASI (docker-compose.yml):
version: '3.8'
services:
  service-a:
    build: ./service-a
    ports: ["3001:3001"]
    networks: [traditional-net]
  service-b:
    build: ./service-b
    ports: ["3002:3002"]
    networks: [traditional-net]
  admin-panel:
    build: ./admin-panel
    ports: ["3003:3003"]
    networks: [traditional-net]
  api-service:
    build: ./api-service
    ports: ["3004:3004"]
    networks: [traditional-net]
networks:
  traditional-net:
    driver: bridge

=======================================================
ORTAM 2: SSO MERKEZİ KİMLİK DOĞRULAMA SİSTEMİ
=======================================================

Dizin yapısı:
sso-system/
├── docker-compose.yml
├── identity-provider/   (Port 4000) ← KRİTİK BİLEŞEN
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js
│   └── users.json       (tek merkezi kullanıcı veritabanı)
├── jwt-service/         (Port 4001) ← Token üretme/doğrulama
│   ├── Dockerfile
│   ├── package.json
│   └── server.js
├── service-a/           (Port 4002)
│   ├── Dockerfile
│   ├── package.json
│   └── server.js
├── service-b/           (Port 4003)
│   ├── Dockerfile
│   ├── package.json
│   └── server.js
├── admin-panel/         (Port 4004)
│   ├── Dockerfile
│   ├── package.json
│   └── server.js
├── api-service/         (Port 4005)
│   ├── Dockerfile
│   ├── package.json
│   └── server.js
└── rbac-middleware/     (paylaşımlı npm modülü)
    └── index.js

IDENTITY PROVIDER (identity-provider/server.js) şunları içermeli:
  POST /auth/login          → email+password doğrula, authorization_code üret
  GET  /auth/authorize      → OAuth 2.0 benzeri authorization endpoint
                              Query params: client_id, redirect_uri, state, response_type
                              STATE PARAMETRESİNİ DOĞRULA
                              REDIRECT URI'yi EXACT MATCH ile doğrula
  POST /auth/token          → authorization_code'u JWT'ye çevir
                              Döndür: { access_token, token_type, expires_in, id_token }
  GET  /auth/userinfo       → Bearer token ile kullanıcı bilgisi sorgula
  POST /auth/revoke         → Token iptal endpoint'i
  GET  /.well-known/openid-configuration → OIDC discovery endpoint
  GET  /health              → IdP sağlık kontrolü (çöküş testi için)

JWT YAPISI (id_token payload):
{
  "iss": "http://localhost:4000",     ← issuer — MUTLAKA DOĞRULA
  "sub": "user_unique_id_123",        ← subject — MUTLAKA DOĞRULA
  "aud": "service-a-client-id",       ← audience — MUTLAKA DOĞRULA
  "exp": 1714000000,                  ← expiry — MUTLAKA DOĞRULA
  "iat": 1713996400,                  ← issued at
  "email": "user@test.com",
  "role": "user",
  "jti": "unique-jwt-id"              ← replay saldırısını önlemek için
}

JWT İMZALAMA:
- RS256 algoritması kullan (RSA asimetrik imza) — HS256 değil
- Private key IdP'de, public key service provider'larda
- Hiçbir zaman alg:none kabul etme
- jti (JWT ID) değerini kullanılan token'lar listesinde tut → replay attack önleme

RBAC MIDDLEWARE (rbac-middleware/index.js):
Her servis bu middleware'i kullanarak JWT doğrulamalı:
  1. Authorization header'dan Bearer token al
  2. RS256 public key ile imzayı doğrula
  3. exp, iss, aud alanlarını doğrula
  4. jti'nin daha önce kullanılıp kullanılmadığını kontrol et
  5. role bazlı erişim kontrolü uygula

HER SERVICE PROVIDER (service-a, service-b vb.) şunları içermeli:
  GET  /dashboard   → JWT doğrulama middleware'i arkasında korumalı endpoint
  GET  /health      → Sağlık kontrolü
  POST /logout      → Token revocation endpoint'ini çağır

KAYITLI CLIENT'LAR (IdP'de hard-coded, production'da DB'de olur):
clients = [
  { client_id: "service-a", client_secret: "secret-a", 
    redirect_uris: ["http://localhost:4002/callback"] },
  { client_id: "service-b", client_secret: "secret-b",
    redirect_uris: ["http://localhost:4003/callback"] },
  { client_id: "admin-panel", client_secret: "secret-admin",
    redirect_uris: ["http://localhost:4004/callback"] },
  { client_id: "api-service", client_secret: "secret-api",
    redirect_uris: ["http://localhost:4005/callback"] }
]

DOCKER YAPILANDIRMASI:
version: '3.8'
services:
  identity-provider:
    build: ./identity-provider
    ports: ["4000:4000"]
    networks: [sso-net]
  jwt-service:
    build: ./jwt-service
    ports: ["4001:4001"]
    networks: [sso-net]
  service-a:
    build: ./service-a
    ports: ["4002:4002"]
    networks: [sso-net]
    depends_on: [identity-provider]
  service-b:
    build: ./service-b
    ports: ["4003:4003"]
    networks: [sso-net]
    depends_on: [identity-provider]
  admin-panel:
    build: ./admin-panel
    ports: ["4004:4004"]
    networks: [sso-net]
    depends_on: [identity-provider]
  api-service:
    build: ./api-service
    ports: ["4005:4005"]
    networks: [sso-net]
    depends_on: [identity-provider]
networks:
  sso-net:
    driver: bridge

=======================================================
ORTAK GEREKSINIMLER (İKİ SİSTEM İÇİN DE)
=======================================================

package.json bağımlılıkları:
{
  "dependencies": {
    "express": "^4.18.2",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2",
    "express-session": "^1.17.3",
    "cors": "^2.8.5",
    "uuid": "^9.0.0",
    "morgan": "^1.10.0"
  }
}

Her servis için Dockerfile:
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE [PORT]
CMD ["node", "server.js"]

=======================================================
TEST KULLANICILARI (Her iki sistem için)
=======================================================

Geleneksel sistemde AYNI kullanıcılar 4 servise de ayrı ayrı kayıtlı:
  user@test.com    → Şifre: "password123"  (zayıf, brute-force testi için)
  admin@test.com   → Şifre: "adminpass"    (password reuse testi için)
  victim@test.com  → Şifre: "victim123"

SSO sisteminde AYNI kullanıcılar SADECE IdP'de kayıtlı:
  user@test.com    → Şifre: "password123", role: "user"
  admin@test.com   → Şifre: "adminpass",   role: "admin"
  victim@test.com  → Şifre: "victim123",   role: "user"

=======================================================
POSTMAN KOLEKSIYONU YAPISI
=======================================================

Aşağıdaki klasörler ve istekler oluşturulmalı:

Klasör 1: "Traditional Auth — Normal Flow"
  - Service A Login (POST localhost:3001/login)
  - Service B Login (POST localhost:3002/login)
  - Admin Login (POST localhost:3003/login)
  - API Login (POST localhost:3004/login)

Klasör 2: "Traditional Auth — Attack Tests"
  - T1: Brute Force — Service A (for loop, 50 deneme)
  - T2: Password Reuse — Aynı şifreyi tüm servislerde dene
  - T3: Service Down Test — service-a durdur, diğerleri test et

Klasör 3: "SSO — Normal Flow"
  - Step 1: Get Authorization Code (GET IdP/auth/authorize)
  - Step 2: Exchange Code for Token (POST IdP/auth/token)
  - Step 3: Access Service A with Token
  - Step 4: Access Service B with SAME Token (SSO özelliği)

Klasör 4: "SSO — Attack Tests"
  - T4: JWT Replay Attack (aynı token'ı 2 kez gönder)
  - T4b: alg:none Attack (imzasız JWT gönder)
  - T5: Redirect URI Path Confusion
  - T5b: OAuth Parameter Pollution
  - T6: CSRF — state parametresi olmadan flow başlat
  - T7: Identity Mismatch — farklı issuer'dan JWT
  - T8: IdP Down Test — IdP durdur, tüm servisleri test et

Klasör 5: "Measurement & Logging"
  - Response time measurement (Pre-request Script ile)
  - Success/Failure rate logging (Test Scripts ile)

=======================================================
ÖLÇÜLMESİ GEREKEN METRİKLER
=======================================================

Her test için şu değerleri kaydet ve tabloya işle:

1. BRUTE FORCE METRİKLERİ:
   - Kaç denemede başarılı? (attempt count)
   - Ne kadar sürdü? (ms cinsinden)
   - Rate limiting olmadan vs varsa

2. PASSWORD REUSE METRİKLERİ:
   - Geleneksel: Aynı şifre kaç serviste çalıştı?
   - SSO: Tek şifre ele geçince kaç servise erişim?

3. TOKEN GÜVENLİK METRİKLERİ:
   - Replay attack: Token expire'dan önce 2. kullanımda ne döndü?
   - alg:none: Kabul edildi mi? (Evet/Hayır)
   - Manipüle JWT: İmza hatası alındı mı?

4. REDIRECT URI METRİKLERİ:
   - Path confusion: Yetkisiz URI'ya yönlendirme oldu mu?
   - OPP: Kirletilmiş parametre kabul edildi mi?

5. SİSTEM DİRENÇ METRİKLERİ:
   - SSO'da IdP çöküşünde etkilenen servis sayısı: N/N
   - Geleneksel'de 1 servis çöküşünde etkilenen: 1/N
   - İyileşme süresi (recovery time)

=======================================================
GÜVENLİ vs GÜVENSİZ SÜRÜM STRATEJİSİ
=======================================================

Her test için iki versiyon çalıştır:

AŞAMA A — GÜVENSİZ (açık bırakılmış):
  → Saldırı başarılı olmalı
  → Bu makale bulgusunu DOĞRULAR

AŞAMA B — GÜVENLİ (önlem uygulanmış):
  → Saldırı engellenmiş olmalı
  → Bu önlemin etkinliğini ÖLÇER

Örnek: T5 Redirect URI Testi
  Aşama A: Yalnızca host kontrolü → path confusion başarılı
  Aşama B: Exact string match → path confusion engellendi
  Sonuç: Innocenti et al. [9]'un bulgusu kendi sisteminde doğrulandı.
```

---

## 3. GELENEKSEL SİSTEM TESTLERİ — FAZ 2

### T1 — Kaba Kuvvet (Brute Force) Saldırısı

**Ne test ediyoruz:** Geleneksel sistemde her servisin ayrı login endpoint'i olduğu için saldırgan her birine ayrı ayrı brute-force uygulayabilir mi?

**Adımlar:**
1. `victim@test.com` için 50 farklı şifre denemesi içeren bir liste oluştur.
2. Postman Runner veya küçük bir Node.js scripti ile Service A'ya ardışık POST isteği gönder.
3. Başarılı denemelerin kaç ms sürdüğünü kaydet.
4. Aynı saldırıyı Service B, Admin Panel ve API Service'e tekrarla.
5. Rate limiting YOKSA bu saldırı ne kadar sürede tamamlanıyor?

**Ölçülecek değerler:**
- Her servis için başarılı deneme sayısı ve süresi
- Toplam saldırı yüzeyi: 4 ayrı endpoint = 4 kat saldırı fırsatı

**Sonuç tablosunda gösterilecek:**
| Servis | Deneme Sayısı | Başarı | Süre (ms) |
|---|---|---|---|
| Service A | 23 | ✓ | 4.2s |
| Service B | 41 | ✓ | 7.1s |
| ... | ... | ... | ... |

---

### T2 — Şifre Tekrarı (Password Reuse)

**Ne test ediyoruz:** Geleneksel sistemde kullanıcılar şifrelerini tekrar kullandığında tek bir servisin ihlali diğerlerine nasıl yansır?

**Adımlar:**
1. `user@test.com`'un Service A şifresini "password123" olarak belirle.
2. Aynı şifreyle Service B, Admin ve API'ye login dene.
3. Kaç servis aynı şifreyle erişilebilir durumda?

**Not:** Makale bağlantısı — bu, Zineddine et al. [11]'in vurguladığı çok kimlik bilgisi yönetim riskiyle doğrudan ilgilidir.

---

### T3 — Servis İzolasyon Testi

**Ne test ediyoruz:** Geleneksel sistemde bir servis çöktüğünde diğerleri bağımsız çalışmaya devam edebiliyor mu?

**Adımlar:**
1. Tüm 4 servis çalışırken erişimi doğrula.
2. Service A container'ını durdur: `docker stop traditional-auth_service-a_1`
3. Service B, Admin, API'ye erişimi test et → Hepsi çalışmalı.
4. Her servis için `/health` endpoint'ini sorgula ve yanıt süresini kaydet.

**Beklenen sonuç:** Service A çöktüğünde yalnızca o 1 servis etkilenir. Diğer 3 servis bağımsız çalışmaya devam eder.

---

## 4. SSO SİSTEM TESTLERİ — FAZ 3

### T4 — JWT Replay Attack & alg:none

**Adımlar:**
1. Normal flow ile geçerli bir JWT token al.
2. Aynı token'ı 30 saniye içinde Service A'ya iki kez gönder → İkinci kullanımda ne döndü?
3. Token'ı base64 decode et, payload'u değiştir (role: "user" → role: "admin"), tekrar encode et.
4. Manipüle token'ı gönder → İmza hatası alınmalı.
5. Header'da `"alg": "none"` olan imzasız token üret ve gönder → Reddedilmeli.

**Ölçülecek değerler:**
- Replay attack: İkinci kullanımda 401 mi döndü? (jti kontrolü çalıştı mı?)
- alg:none: 401 mi döndü yoksa kabul mi edildi?
- Payload değişikliği: İmza uyumsuzluğu 401 döndürdü mü?

---

### T5 — Redirect URI Saldırısı [Innocenti et al. 2023]

**Adımlar:**
1. Kayıtlı URI: `http://localhost:4002/callback`
2. Saldırı 1 — Path Confusion: `http://localhost:4002/callback/../evil-endpoint`
3. Saldırı 2 — OPP: `http://localhost:4002/callback?next=http://evil.com`
4. Saldırı 3 — Relative path: `http://localhost:4002/callback%2F..%2Fevil`
5. Her denemede authorization code'un gelip gelmediğini Postman ile kaydet.

---

### T6 — CSRF & State Parameter [Fett et al. 2016, Benolli et al. 2021]

**Adımlar:**
1. `state` parametresi olmadan authorization isteği gönder → Kabul edildi mi?
2. Aynı `state` değerini iki farklı istek için kullan → İkinci istek reddedildi mi?
3. Başka bir kullanıcının authorization `code`'unu kendin kullanmaya çalış → Reddedilmeli.

---

### T7 — Identity–Account Mismatch [Liu et al. 2021]

**Adımlar:**
1. `victim@test.com` için sahte bir JWT üret (farklı `iss` değeriyle).
2. Bu token'ı Service A'ya gönder → `iss` doğrulaması yapılıyorsa reddedilmeli.
3. Doğrulama sadece `email` bazlıysa → Sahte token kabul edilebilir (açık var).
4. `iss` + `sub` + `aud` triple doğrulaması ekleyince → Reddedilmeli.

---

### T8 — IdP Çöküş Testi [Zineddine et al. 2025]

**Adımlar:**
1. Tüm SSO servisleri çalışırken 4 service provider'a giriş yap → Başarılı.
2. IdP container'ını durdur: `docker stop sso-system_identity-provider_1`
3. Yeni login denemesi yap → Tüm servisler için hata alınmalı.
4. Mevcut (zaten alınmış) token ile servislere erişmeye çalış → Çalışabilir mi?
5. Her servis için response time ve hata tipini kaydet.
6. Geleneksel sistemde Service A durdurulduğunda yalnızca 1 servis etkilendiğini göster.

---

## 5. TABLO VE GRAFİK PLANI — SON AŞAMA

### Tablo 1 — Saldırı Başarı Oranı Özeti

```
| Test | Saldırı Tipi | Geleneksel | SSO (Güvensiz) | SSO (Güvenli) | Makale |
|------|-------------|-----------|----------------|---------------|--------|
| T1   | Brute Force | %100 (4 endpoint) | N/A | N/A | [2],[11] |
| T2   | Password Reuse | 4/4 servis | N/A | N/A | [11] |
| T4   | JWT Replay | N/A | Başarılı | Engellendi | [1] |
| T4b  | alg:none | N/A | Başarılı | Engellendi | [1],[8] |
| T5   | Redirect URI | N/A | Başarılı | Engellendi | [9] |
| T6   | CSRF/state | N/A | Başarılı | Engellendi | [1],[7] |
| T7   | Identity Mismatch | N/A | Başarılı | Engellendi | [6] |
| T8   | IdP SPOF | 1/4 servis etkilendi | 4/4 etkilendi | 4/4 etkilendi | [11] |
```

### Tablo 2 — Makale Bulgusu vs Kendi Bulgun

```
| Makale | Makale Bulgusu | Kendi Test Sonucun | Uyum |
|--------|---------------|-------------------|------|
| Fett [1] | 4 kritik açık; state eksikliği CSRF'e yol açar | T6: state olmadan CSRF başarılı | ✓ |
| Innocenti [9] | 10/16 IdP OPP'ye açık (%62.5) | T5: OPP denemesi başarılı/başarısız | ? |
| Benolli [7] | State eksikliği CSRF'i mümkün kılar | T6: state bypass başarılı | ✓ |
| Liu [6] | e-posta bazlı linking hesap ele geçirmeye yol açar | T7: sadece email doğrulaması açık verdi | ✓ |
| Zineddine [11] | SPOF en kritik yapısal risk | T8: IdP çöküşünde 4/4 etkilendi | ✓ |
| Philippaerts [8] | RFC uyumu güvenlik garantisi değil | T4b: alg:none kabul edildi mi? | ? |
```

*Not: "?" satırları kendi test sonucunla doldurulacak.*

### Grafik 1 — Radar Chart: Güvenlik Boyutları Karşılaştırması

6 eksen (0-10 puan):
- Brute-force direnci
- Şifre yönetim riski
- Token güvenliği
- Redirect saldırısı direnci
- Sistem sürekliliği (SPOF)
- Merkezi risk yoğunlaşması

### Grafik 2 — Bar Chart: Etkilenen Servis Sayısı

Tek bir bileşen başarısız olduğunda kaç servis etkileniyor?
- Geleneksel: 1 servis çöküşü → 1 servis etkilenir
- SSO: IdP çöküşü → 4 servis etkilenir

### Grafik 3 — Saldırı Başarı Oranları (Güvenli vs Güvensiz)

Her saldırı tipi için iki çubuk: güvensiz versiyon vs güvenli versiyon.

---

## 6. RAPOR BÖLÜMÜ YAZIM REHBERİ

IEEE template'e eklenecek yeni section şu yapıda olmalı:

```
IV. TEST RESULTS AND COMPARATIVE ANALYSIS

A. Test Environment Setup
   → Docker ortamı, kullanılan teknolojiler, port yapısı

B. Traditional Authentication Test Results
   → T1, T2, T3 sonuçları — tablo ve grafik

C. SSO Architecture Test Results
   → T4, T5, T6, T7, T8 sonuçları — tablo ve grafik

D. Literature Comparison
   → Her makale için: Makale bulgusu | Kendi bulgun | Uyum/Farklılık analizi
   → Bu bölüm hocaya özellikle hitap edecek kısım

E. Discussion
   → Sonuçların yorumu: SSO riski azaltıyor mu, yoksa odaklaştırıyor mu?
   → Kendi sonuçlarının literatürle ne kadar örtüştüğü
```

**Her grafik/tablo için yorum paragrafı şablonu:**

```
[Tablo/Grafik X], [saldırı/bulgu türü]'nü karşılaştırmaktadır.
Geleneksel sistemde [A gözlemlendi], SSO sisteminde ise [B gözlemlendi].
Bu bulgu, [Makale] tarafından öngörülen [C] ile [uyumludur / farklılık göstermektedir].
[Farklılık varsa: Fark, [nedeni] ile açıklanabilir.]
```

---

## ÖZET KONTROL LİSTESİ

- [ ] `traditional-auth/` dizini oluşturuldu ve 4 servis çalışıyor
- [ ] `sso-system/` dizini oluşturuldu, IdP + 4 SP çalışıyor
- [ ] Docker Compose ile her iki sistem `docker-compose up` ile ayağa kalkıyor
- [ ] Postman koleksiyonu oluşturuldu, tüm test klasörleri hazır
- [ ] T1–T3 geleneksel sistem testleri tamamlandı ve sonuçlar kaydedildi
- [ ] T4–T8 SSO testleri tamamlandı ve sonuçlar kaydedildi
- [ ] Güvensiz → Güvenli geçiş testleri her saldırı için yapıldı
- [ ] Tablo 1 ve Tablo 2 dolduruldu
- [ ] Grafik 1 (Radar), Grafik 2 (SPOF bar), Grafik 3 (başarı oranları) hazırlandı
- [ ] Her grafik/tablo için IEEE formatında yorum paragrafı yazıldı
- [ ] Section IV rapor şablonuna eklendi
- [ ] Turnitin kontrolü yapıldı

---

*Hazırlayan: Samet Bulut | 2021510016 | Network Security HW2*
*Referanslar için raporun orijinal kaynakça bölümüne bakınız.*
