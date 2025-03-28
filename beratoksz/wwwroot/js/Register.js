document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("registerForm");
    const registerBtn = document.getElementById("registerBtn");
    const spinner = document.getElementById("registerSpinner");
    const btnText = document.getElementById("registerBtnText");
    const passwordInput = document.getElementById("Password");
    const passwordStrengthBar = document.getElementById("passwordStrengthBar");
    const passwordFeedback = document.getElementById("passwordFeedback");
    const userNameInput = document.getElementById("UserName");
    const emailInput = document.getElementById("Email");
    const confirmPasswordInput = document.getElementById("ConfirmPassword");

    // Kullanıcı adı doğrulama fonksiyonu
    function validateUserName(userName) {
        const errors = [];
        if (userName.length < 3) {
            errors.push("Kullanıcı adı en az 3 karakter olmalıdır.");
        }
        if (/\s/.test(userName)) {
            errors.push("Kullanıcı adı boşluk içeremez.");
        }
        if (/[çÇğĞıİöÖşŞüÜ]/.test(userName)) {
            errors.push("Kullanıcı adı Türkçe karakter içeremez.");
        }
        return errors;
    }

    // Şifre doğrulama fonksiyonu
    function validatePassword(password) {
        const errors = [];
        if (password.length < 6) {
            errors.push("Şifre en az 8 karakter olmalıdır.");
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

    // E-posta doğrulama fonksiyonu
    function validateEmail(email) {
        const errors = [];
        // Razor'da @ karakterinin karışmaması için RegExp constructor kullanıldı.
        const emailPattern = new RegExp("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
        if (!emailPattern.test(email)) {
            errors.push("Geçerli bir email adresi girin.");
        }
        return errors;
    }

    // Şifre Güç Puanı Hesaplama
    function calculatePasswordStrength(pwd) {
        let strength = 0;
        if (pwd.length >= 8) strength += 1;
        if (/\d/.test(pwd)) strength += 1;
        if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) {
            strength += 1;
        } else if (/[a-zA-Z]/.test(pwd)) {
            strength += 0.5;
        }
        if (/[!@#$%^&*(),.?":{}|<>]/.test(pwd)) strength += 1;
        return strength;
    }

    // Şifre girişine bağlı olarak progress bar güncellemesi
    passwordInput.addEventListener("input", () => {
        const pwd = passwordInput.value;
        const strength = calculatePasswordStrength(pwd);
        const percentage = Math.min((strength / 4.5) * 100, 100);
        passwordStrengthBar.style.width = percentage + "%";

        let feedback = "";
        let barClass = "bg-danger";
        if (percentage < 40) {
            feedback = "Zayıf şifre";
            barClass = "bg-danger";
        } else if (percentage < 70) {
            feedback = "Orta seviye şifre";
            barClass = "bg-warning";
        } else {
            feedback = "Güçlü şifre";
            barClass = "bg-success";
        }
        passwordStrengthBar.className = "progress-bar " + barClass;
        passwordFeedback.innerHTML = feedback;
    });

    // Kullanıcı adı girişine bağlı olarak anında geri bildirim
    userNameInput.addEventListener("input", () => {
        const userName = userNameInput.value.trim();
        const userNameErrors = validateUserName(userName);
        const userNameFeedback = document.getElementById("userNameFeedback");
        if (userNameErrors.length > 0) {
            userNameFeedback.innerHTML = userNameErrors.join('<br>');
        } else {
            userNameFeedback.innerHTML = "";
        }
    });

    // E-posta girişine bağlı olarak anında geri bildirim
    emailInput.addEventListener("input", () => {
        const email = emailInput.value.trim();
        const emailErrors = validateEmail(email);
        const emailFeedback = document.getElementById("emailFeedback");
        if (emailErrors.length > 0) {
            emailFeedback.innerHTML = emailErrors.join('<br>');
        } else {
            emailFeedback.innerHTML = "";
        }
    });

    // Şifre onayı girişine bağlı olarak anında geri bildirim
    confirmPasswordInput.addEventListener("input", () => {
        const password = passwordInput.value.trim();
        const confirmPassword = confirmPasswordInput.value.trim();
        const confirmPasswordFeedback = document.getElementById("confirmPasswordFeedback");
        if (password !== confirmPassword) {
            confirmPasswordFeedback.innerHTML = "Şifreler eşleşmiyor!";
        } else {
            confirmPasswordFeedback.innerHTML = "";
        }
    });

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        const userName = userNameInput.value.trim();
        const email = emailInput.value.trim();
        const password = passwordInput.value.trim();
        const confirmPassword = confirmPasswordInput.value.trim();

        const userNameErrors = validateUserName(userName);
        const emailErrors = validateEmail(email);
        const passwordErrors = validatePassword(password);

        if (userNameErrors.length > 0) {
            Swal.fire({ icon: 'error', title: 'Hata!', html: userNameErrors.join('<br>') });
            return;
        }

        if (emailErrors.length > 0) {
            Swal.fire({ icon: 'error', title: 'Hata!', html: emailErrors.join('<br>') });
            return;
        }

        if (passwordErrors.length > 0) {
            Swal.fire({ icon: 'error', title: 'Hata!', html: passwordErrors.join('<br>') });
            return;
        }

        if (password !== confirmPassword) {
            Swal.fire({ icon: 'error', title: 'Oops...', text: 'Şifreler eşleşmiyor!' });
            return;
        }

        spinner.style.display = "inline-block";
        btnText.textContent = "Kayıt Olunuyor...";

        const registerData = {
            UserName: userName,
            Email: email,
            PhoneNumber: document.getElementById("PhoneNumber").value.trim(),
            Password: password,
            ConfirmPassword: confirmPassword
        };

        fetch("/api/Account/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(registerData)
        })
            .then(response => response.json().then(data => {
                if (!response.ok) {
                    if (data.code === "DuplicateUserName") {
                        throw new Error("Kullanıcı adı zaten kayıtlı.");
                    }
                    throw new Error(data.description || "Kayıt başarısız.");
                }
                return data;
            }))
            .then(data => {
                Swal.fire({
                    icon: 'success',
                    title: 'Başarılı!',
                    text: data.message || 'Kayıt başarılı! E-postanızı kontrol edin.',
                    timer: 3000,
                    showConfirmButton: false
                });
                setTimeout(() => {
                    window.location.href = "/VAccount/Login";
                }, 3000);
            })
            .catch(error => {
                Swal.fire({ icon: 'error', title: 'Hata!', text: error.message });
            })
            .finally(() => {
                spinner.style.display = "none";
                btnText.textContent = "Hesap Oluştur";
            });
    });
});
