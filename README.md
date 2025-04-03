## Hakkımda
Bilgisayar Programcılığı ön lisans mezunuyum ve ASP.NET Core, .NET Framework, Entity Framework, SQL Server, SignalR gibi teknolojilerle gerçek dünya uygulamaları geliştiriyorum. Şu anda tam anlamıyla production seviyesinde, güvenli, modüler yapılı bir kimlik doğrulama ve yönetim sistemi geliştirdim. Aşağıda detayları paylaştığım bu proje, hem teknik hem sistem tasarımı hem de güvenlik anlamında derinlemesine bilgi ve beceri sunmaktadır.

---

## Proje 1: Admin Panel ve Kimlik Doğrulama Sistemi (Production Ready)

### Teknolojiler
- ASP.NET Core Web API
- Entity Framework Core
- Identity, JWT & Refresh Token
- SignalR
- SQL Server
- HTML, CSS, JS
- Docker & open-wa/wa-automate (WhatsApp Service)

### Mimari
- Katmanlı mimari: API, Service, Repository, DTO yapısı
- Swagger ile API dokümantasyonu
- IoC container ile dependency injection

### Güvenlik Bileşenleri
- JWT + HttpOnly Cookie ile oturum yönetimi
- Refresh Token veritabanında tutulur ve cihaz bazlı kontrol edilebilir
- E-posta doğrulama sistemi (tek kullanımlık link + expire)
- 2FA (Two-Factor Authentication) - Session tabanlı, e-posta ile
- Rate Limiting (AspNetCoreRateLimit)
- Cooldown sistemi (brute force koruması)
- Şifre sıfırlama ve resend kod işlemlerinde IP ve cihaz bazlı loglama

### Yetkilendirme ve Yetki Dağıtımı
- Guest / User / Admin rolleri otomatik sistem rolu olarak atanır daha sonradan roller eklenebilir
- Sayfa ve API endpoint'leri dinamik olarak PageDiscoveryService ile tespit edilir
- RolePermissionSeeder ile bu yollar ilgili rollere otomatik olarak atanır
- SignalR ile yetki ve rol değişiklikleri anlık olarak istemciye yansıtılır
- Middleware katmanı ile sayfa erişimleri kontrol edilir; statik dosyalar regex ile hariç tutulur

### Loglama ve Denetim
- Tüm kritik işlemler (giriş, çıkış, doğrulama vb.) Audit Trail olarak veritabanına yazılır
- GeoIP & UAParser ile IP, tarayıcı, cihaz ve lokasyon bilgileri analiz edilir

### Admin Panel Yetkileri
- Rol yönetimi (kullanıcılara rol atama)
- Sayfa bazlı erişim izinlerini checkbox ile belirleme
- Site ayarları: Whatsapp, SMTP, E-posta, genel güvenlik ayarları
- Kullanıcı yönetimi silme, ekleme (CRUD)

### Ek Entegrasyonlar
- WhatsApp servisi entegre edildi (open-wa/wa-automate)
- Docker Compose ile izole olarak yönetiliyor
- Her proje için özel session klasörü oluşturuluyor

---

## Son Söz
Bu projede tüm sistem benim tarafımdan planlandı, geliştirildi ve yayına hazır hale getirildi. Gerek frontend gerek backend gerekse sistem mimarisi ve güvenlik tarafında baştan sona sorumluluk aldım. Tüm detayları düşünülmüş bu sistem, bugün herhangi bir kuruma rahatıyla entegre edilebilir ve ölçeklenebilir yapıdadır.
