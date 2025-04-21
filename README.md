## Proje 1: Admin Panel ve Kimlik Doğrulama Sistemi

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



.env config

DEFAULT_CONNECTION_STRING=Server=sqlserver,1433;Database=<DATABASE NAME>;User Id=sa;Password=<SA PASSWORD>;TrustServerCertificate=True
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=http://+:80
API_URL=<DOMAIN>
WHATSAPP_API=http://whatsapp:8002
JWT_SECRET=<*>
JWT_VALID_ISSUER=<DOMAIN>
JWT_VALID_AUDIENCE=<DOMAIN>


![dashboard](https://github.com/user-attachments/assets/3ffbf009-e34f-4c00-9429-968d2094a6cc)
![userma](https://github.com/user-attachments/assets/35dc848f-b85d-4dbf-bb3c-450ceb2812d2)
![userrole](https://github.com/user-attachments/assets/f3c224d0-cdd5-49d4-ba04-658e750027ae)
![sitesettings](https://github.com/user-attachments/assets/1eb95fb8-2086-4c4b-b449-221c43b28613)
![rolepermiss](https://github.com/user-attachments/assets/1dc15add-adaa-4ae4-87d4-6935e08adfbe)
![report](https://github.com/user-attachments/assets/22b851b3-78ea-496b-98cd-b92577e0a047)








