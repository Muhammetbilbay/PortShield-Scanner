// Tema Değiştirici Kodları
const themeBtn = document.getElementById("themeToggleBtn");
if (themeBtn) {
    themeBtn.addEventListener("click", () => {
        document.body.classList.toggle("light-theme");
        if (document.body.classList.contains("light-theme")) {
            localStorage.setItem("theme", "light");
        } else {
            localStorage.setItem("theme", "dark");
        }
    });
}

// Sayfa yüklendiğinde temayı hatırla
if (localStorage.getItem("theme") === "light") {
    document.body.classList.add("light-theme");
}

// Yükleniyor (Spinner) Durum Kodları
const scanForm = document.getElementById("scanForm");
if (scanForm) {
    scanForm.addEventListener("submit", () => {
        const submitBtn = document.getElementById("submitBtn");
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner"></span> Tarama Yapılıyor...';
    });
}

// Bulguları Filtreleme ve Canlı Arama Kodları
const searchInput = document.getElementById("resultsSearch");
const filterAllBtn = document.getElementById("filterAllBtn");
const filterVulnBtn = document.getElementById("filterVulnBtn");

let filterMode = "all"; // "all" veya "vuln"

function filterTable() {
    if (!searchInput) return;
    const query = searchInput.value.toLowerCase().trim();
    const rows = document.querySelectorAll("#scanResultsTable tbody tr");
    
    rows.forEach(row => {
        const ip = row.cells[0].textContent.toLowerCase();
        const port = row.cells[1].textContent.toLowerCase();
        const analysisText = row.cells[3].textContent.toLowerCase();
        const hasWarnings = row.querySelector(".warning-list") !== null;
        
        // Arama eşleşmesi kontrolü
        const matchesQuery = ip.includes(query) || port.includes(query) || analysisText.includes(query);
        
        // Filtre modu kontrolü
        let matchesFilter = true;
        if (filterMode === "vuln") {
            matchesFilter = hasWarnings;
        }
        
        if (matchesQuery && matchesFilter) {
            row.style.display = "";
        } else {
            row.style.display = "none";
        }
    });
}

if (searchInput) {
    searchInput.addEventListener("input", filterTable);
}
if (filterAllBtn) {
    filterAllBtn.addEventListener("click", () => {
        filterMode = "all";
        filterAllBtn.style.borderColor = "var(--accent-blue)";
        filterVulnBtn.style.borderColor = "var(--border-color)";
        filterTable();
    });
}
if (filterVulnBtn) {
    filterVulnBtn.addEventListener("click", () => {
        filterMode = "vuln";
        filterVulnBtn.style.borderColor = "var(--accent-red)";
        filterAllBtn.style.borderColor = "var(--border-color)";
        filterTable();
    });
}
