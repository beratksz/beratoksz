// ✅ Yetkilendirme listesi getir ve tabloya ekle
async function fetchPermissions() {
    let response = await fetch("/api/role-permissions");
    let data = await response.json();
    let tableBody = document.getElementById("rolePermissionTable");
    tableBody.innerHTML = "";

    data.forEach(permission => {
        let row = `<tr>
            <td>${permission.roleName}</td>
            <td>${permission.pagePath}</td>
            <td>
                <input type="checkbox" class="toggle-permission" data-id="${permission.id}" ${permission.canAccess ? "checked" : ""} />
            </td>
            <td>
                <button class="btn btn-danger btn-sm delete-permission" data-id="${permission.id}">Sil</button>
            </td>
        </tr>`;
        tableBody.innerHTML += row;
    });

    // ✅ Yetki değiştirme işlemi
    document.querySelectorAll('.toggle-permission').forEach(el => {
        el.addEventListener('change', async function () {
            let id = this.getAttribute("data-id");
            let canAccess = this.checked;

            let row = this.closest("tr");
            let roleName = row.cells[0].innerText;
            let pagePath = row.cells[1].innerText;

            let payload = { roleName, pagePath, canAccess };

            try {
                await fetch(`/api/role-permissions/${id}`, {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
            } catch (error) {
                console.error("Yetki değiştirme hatası:", error);
            }
        });
    });

    // ✅ Yetki silme işlemi
    document.querySelectorAll('.delete-permission').forEach(el => {
        el.addEventListener('click', async function () {
            let id = this.getAttribute("data-id");

            if (confirm("Bu yetkiyi silmek istediğinize emin misiniz?")) {
                await fetch(`/api/role-permissions/${id}`, { method: "DELETE" });
                fetchPermissions();
            }
        });
    });
}

// ✅ Yeni yetki ekleme modalını aç
function showAddPermissionModal() {
    let modal = new bootstrap.Modal(document.getElementById('addPermissionModal'));
    modal.show();
    fetchRolesAndPages();
}

// ✅ Roller ve sayfa listesini doldur
async function fetchRolesAndPages() {
    let roleSelect = document.getElementById("roleNameSelect");
    let pageSelect = document.getElementById("pagePathSelect");

    // Rolleri getir
    let roleRes = await fetch("/api/roles");
    let roles = await roleRes.json();
    roleSelect.innerHTML = roles.map(role => `<option value="${role.name}">${role.name}</option>`).join("");

    // Sayfaları getir
    let pageRes = await fetch("/api/pages");
    let pages = await pageRes.json();
    pageSelect.innerHTML = pages.map(page => `<option value="${page}">${page}</option>`).join("");
}

// ✅ Yeni yetki ekle
async function addPermission() {
    let roleName = document.getElementById("roleNameSelect").value;
    let pagePath = document.getElementById("pagePathSelect").value;
    let canAccess = document.getElementById("canAccessSelect").value === "true";

    if (!roleName || !pagePath) {
        alert("Lütfen tüm alanları doldurun!");
        return;
    }

    let payload = { roleName, pagePath, canAccess };

    try {
        let response = await fetch("/api/role-permissions", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            alert("Yetki başarıyla eklendi!");
            fetchPermissions();
            bootstrap.Modal.getInstance(document.getElementById('addPermissionModal')).hide();
        } else {
            let errorData = await response.json();
            console.error("Hata Detayı:", errorData);
            alert(`Yetki eklenirken hata oluştu: ${JSON.stringify(errorData.errors)}`);
        }
    } catch (error) {
        console.error("Yetki ekleme hatası:", error);
        alert("Yetki eklenirken bir hata oluştu.");
    }
}

// Sayfa yüklendiğinde yetkilendirmeleri getir
document.addEventListener("DOMContentLoaded", fetchPermissions);
