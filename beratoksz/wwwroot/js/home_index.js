document.addEventListener("DOMContentLoaded", function () {
    console.log("🚀 DOM Yüklendi!");

    // ✅ Tüm giriş/çıkış butonlarını seç
    let loginBtns = document.querySelectorAll("#login-btn"); // Tüm giriş butonları
    let logoutBtns = document.querySelectorAll("#logout-btn"); // Tüm çıkış butonları

    // ✅ Giriş Butonlarına Event Listener Ekle
    if (loginBtns.length > 0) {
        console.log(`✅ ${loginBtns.length} adet giriş butonu bulundu!`);
        loginBtns.forEach(btn => {
            btn.addEventListener("click", function () {
                console.log("🔵 Giriş butonuna basıldı. Yönlendirme başlıyor...");
                window.location.href = "/Account/Login"; // Login sayfasına yönlendir
            });
        });
    } else {
        console.error("❌ Giriş butonu bulunamadı!");
    }

    // ✅ Kullanıcı bilgilerini çek ve butonları düzenle
    fetch("/api/ApiAccount/check-auth")
        .then(response => response.json())
        .then(data => {
            console.log("🟢 Auth kontrol sonucu:", data);

            if (data.isAuthenticated) {
                console.log("✅ Kullanıcı giriş yapmış.");
                document.getElementById("userActions").style.display = "block";
                document.getElementById("guestActions").style.display = "none";
                document.getElementById("userName").innerText = data.userName;
            } else {
                console.log("🔴 Kullanıcı giriş yapmamış.");
                document.getElementById("guestActions").style.display = "block";
                document.getElementById("userActions").style.display = "none";
            }
        })
        .catch(err => console.error("❌ Auth kontrolü başarısız:", err));

    // ✅ Çıkış Butonlarına Event Listener Ekle
    if (logoutBtns.length > 0) {
        logoutBtns.forEach(btn => {
            btn.addEventListener("click", function () {
                console.log("🔴 Çıkış butonuna basıldı...");
                fetch("/api/ApiAccount/logout", {
                    method: "POST",
                    credentials: "include"
                })
                    .then(() => {
                        document.cookie = "AuthToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
                        document.cookie = "RefreshToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";

                        console.log("✅ Çıkış başarılı! Anasayfaya yönlendiriliyor...");
                        window.location.href = "/";
                    })
                    .catch(err => console.error("❌ Logout failed:", err));
            });
        });
    } else {
        console.error("❌ Çıkış butonu bulunamadı!");
    }
});
