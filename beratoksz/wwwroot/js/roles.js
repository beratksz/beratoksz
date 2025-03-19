// ✅ Roller listesini API'den çek ve tabloya yerleştir
async function fetchRoles() {
    let tableBody = document.getElementById("roleTableBody");
    tableBody.innerHTML = "<tr><td colspan='3' class='text-center'>Yükleniyor...</td></tr>";

    try {
        let response = await fetch("/api/roles");
        let roles = await response.json();
        tableBody.innerHTML = "";

        roles.forEach(role => {
            let row = `<tr>
                <td>${role.id}</td>
                <td>${role.name}</td>
                <td>
                    <button class="btn btn-warning btn-sm" onclick="showEditRoleModal('${role.id}', '${role.name}')">Düzenle</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteRole('${role.id}')">Sil</button>
                </td>
            </tr>`;
            tableBody.innerHTML += row;
        });
    } catch (error) {
        console.error("Roller yüklenirken hata oluştu:", error);
    }
}

// ✅ Yeni rol ekleme modalını aç
function showAddRoleModal() {
    document.getElementById("roleId").value = "";
    document.getElementById("roleName").value = "";
    let modal = new bootstrap.Modal(document.getElementById("roleModal"));
    modal.show();
}

// ✅ Düzenleme modalını aç
function showEditRoleModal(id, name) {
    document.getElementById("roleId").value = id;
    document.getElementById("roleName").value = name;
    let modal = new bootstrap.Modal(document.getElementById("roleModal"));
    modal.show();
}

// ✅ Yeni rol ekle veya var olanı güncelle
async function saveRole() {
    let roleId = document.getElementById("roleId").value;
    let roleName = document.getElementById("roleName").value;

    let payload = { name: roleName };
    let method = roleId ? "PUT" : "POST";
    let url = roleId ? `/api/roles/${roleId}` : "/api/roles";

    try {
        let response = await fetch(url, {
            method: method,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            alert("Rol başarıyla kaydedildi!");
            fetchRoles();
            bootstrap.Modal.getInstance(document.getElementById("roleModal")).hide();
        } else {
            alert("Hata oluştu!");
        }
    } catch (error) {
        console.error("Rol kaydetme hatası:", error);
    }
}

// ✅ Rolü silme fonksiyonu
async function deleteRole(id) {
    if (!confirm("Bu rolü silmek istediğinize emin misiniz?")) return;

    try {
        let response = await fetch(`/api/roles/${id}`, { method: "DELETE" });

        if (response.ok) {
            alert("Rol başarıyla silindi!");
            fetchRoles();
        }
    } catch (error) {
        console.error("Silme hatası:", error);
    }
}

// Sayfa yüklendiğinde roller listesini getir
document.addEventListener("DOMContentLoaded", fetchRoles);
