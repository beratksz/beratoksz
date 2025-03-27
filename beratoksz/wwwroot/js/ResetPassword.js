document.addEventListener("DOMContentLoaded", function () {
    // Lottie animasyonunu başlat
    lottie.loadAnimation({
        container: document.getElementById('resetAnimation'),
        renderer: 'svg',
        loop: true,
        autoplay: true,
        path: '/lottie/reset-password.json'
    });

    // Şifre doğrulama fonksiyonu
    function validatePassword(password) {
        const errors = [];
        if (password.length < 6) {
            errors.push("Şifre en az 6 karakter olmalıdır.");
        }
        if (!/[A-Z]/.test(password)) {
            errors.push("Şifre en az bir büyük harf içermelidir.");
        }
        if (!/[a-z]/.test(password)) {
            errors.push("Şifre en az bir küçük harf içermelidir.");
        }
        if (!/\d/.test(password)) {
            errors.push("Şifre en az bir rakam içermelidir.");
        }
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            errors.push("Şifre en az bir özel karakter içermelidir.");
        }
        return errors;
    }

    document.getElementById("resetForm").addEventListener("submit", function (event) {
        event.preventDefault();

        let newPassword = document.getElementById("NewPassword").value;
        let confirmPassword = document.getElementById("ConfirmNewPassword").value;

        const passwordErrors = validatePassword(newPassword);
        if (passwordErrors.length > 0) {
            Swal.fire({ icon: 'error', title: 'Hata!', html: passwordErrors.join('<br>') });
            return;
        }

        if (newPassword !== confirmPassword) {
            Swal.fire('Hata!', 'Şifreler eşleşmiyor!', 'error');
            return;
        }

        const submitButton = document.getElementById("submitButton");
        submitButton.disabled = true;
        submitButton.textContent = "Kaydediliyor...";

        fetch("/api/Account/reset-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                UserId: document.getElementById("UserId").value,
                Token: document.getElementById("Token").value,
                NewPassword: newPassword,
                ConfirmPassword: confirmPassword
            })
        })
            .then(res => res.json())
            .then(data => {
                Swal.fire('Başarılı!', data.message, 'success');
                setTimeout(() => window.location.href = "/VAccount/Login", 3000);
            })
            .catch(err => {
                Swal.fire('Hata!', err.message, 'error');
            })
            .finally(() => {
                submitButton.disabled = false;
                submitButton.textContent = "Kaydet";
            });
    });

});
