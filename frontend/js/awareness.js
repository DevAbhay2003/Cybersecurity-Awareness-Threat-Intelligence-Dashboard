/**
 * Cybersecurity Awareness Center Controller
 * File: frontend/js/awareness.js
 */

let allModules = [];

document.addEventListener("DOMContentLoaded", () => {
    loadAwarenessModules();
    setupAwarenessEvents();
});

function setupAwarenessEvents() {
    // Category tabs
    document.querySelectorAll(".cat-tab").forEach(tab => {
        tab.addEventListener("click", () => {
            document.querySelectorAll(".cat-tab").forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            const cat = tab.getAttribute("data-category");
            filterModules(cat);
        });
    });

    // Search bar
    const searchInput = document.getElementById("module-search-input");
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            const query = e.target.value.toLowerCase().trim();
            const filtered = allModules.filter(m =>
                m.title.toLowerCase().includes(query) ||
                m.category.toLowerCase().includes(query) ||
                m.description.toLowerCase().includes(query)
            );
            renderModules(filtered);
        });
    }

    // Modal close
    document.getElementById("btn-close-module-modal")?.addEventListener("click", () => {
        document.getElementById("module-modal").classList.remove("open");
    });
}

async function loadAwarenessModules() {
    try {
        const res = await apiFetch("/api/awareness/modules");
        allModules = res.data.modules || [];
        renderModules(allModules);
    } catch (err) {
        console.error("Failed to load awareness modules:", err);
    }
}

function filterModules(category) {
    if (!category || category === "ALL") {
        renderModules(allModules);
    } else {
        const filtered = allModules.filter(m => m.category.toUpperCase().includes(category.toUpperCase()));
        renderModules(filtered);
    }
}

function renderModules(modules) {
    const grid = document.getElementById("modules-grid");
    if (!grid) return;

    if (modules.length === 0) {
        grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:3rem;color:var(--text-dim);">No awareness modules match the selected filter.</div>`;
        return;
    }

    grid.innerHTML = modules.map(m => `
        <div class="module-card" onclick="openModuleDetail('${m.id}')">
            <div>
                <div class="module-cat">${m.category}</div>
                <div class="module-title">${m.title}</div>
                <div class="module-desc">${m.description}</div>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:1rem;border-top:1px solid var(--border-subtle);padding-top:0.75rem;">
                <span style="font-size:0.75rem;color:var(--text-dim);font-family:var(--font-mono);">${m.id}</span>
                <span style="font-size:0.8rem;color:var(--cyan-accent);font-weight:600;">Explore Module &rarr;</span>
            </div>
        </div>
    `).join("");
}

function openModuleDetail(moduleId) {
    const m = allModules.find(item => item.id === moduleId);
    if (!m) return;

    const modal = document.getElementById("module-modal");
    const titleEl = document.getElementById("modal-module-title");
    const catEl = document.getElementById("modal-module-cat");
    const bodyEl = document.getElementById("modal-module-body");

    titleEl.textContent = m.title;
    catEl.textContent = `${m.id} • ${m.category}`;

    bodyEl.innerHTML = `
        <div style="margin-bottom:1.25rem;">
            <h4 style="color:var(--cyan-accent);font-size:0.85rem;text-transform:uppercase;margin-bottom:0.4rem;">What is it?</h4>
            <p style="font-size:0.9rem;color:var(--text-muted);line-height:1.5;">${m.what_is_it}</p>
        </div>

        <div style="margin-bottom:1.25rem;">
            <h4 style="color:var(--cyan-accent);font-size:0.85rem;text-transform:uppercase;margin-bottom:0.4rem;">Why does it matter?</h4>
            <p style="font-size:0.9rem;color:var(--text-muted);line-height:1.5;">${m.why_it_matters}</p>
        </div>

        <div style="margin-bottom:1.25rem;">
            <h4 style="color:var(--sev-high);font-size:0.85rem;text-transform:uppercase;margin-bottom:0.4rem;">Key Warning Signs</h4>
            <ul style="padding-left:1.2rem;font-size:0.85rem;color:var(--text-muted);line-height:1.6;">
                ${(m.warning_signs || []).map(w => `<li style="margin-bottom:0.25rem;">${w}</li>`).join("")}
            </ul>
        </div>

        <div style="margin-bottom:1.25rem;">
            <h4 style="color:var(--sev-success);font-size:0.85rem;text-transform:uppercase;margin-bottom:0.4rem;">Safe Defensive Practices</h4>
            <ul style="padding-left:1.2rem;font-size:0.85rem;color:var(--text-muted);line-height:1.6;">
                ${(m.safe_practices || []).map(p => `<li style="margin-bottom:0.25rem;">${p}</li>`).join("")}
            </ul>
        </div>

        <div style="background:var(--bg-input);padding:1rem;border-radius:8px;border:1px solid var(--border-color);">
            <h4 style="color:var(--text-main);font-size:0.85rem;margin-bottom:0.3rem;">What To Do If An Incident Occurs:</h4>
            <p style="font-size:0.85rem;color:var(--text-muted);line-height:1.5;">${m.what_to_do}</p>
        </div>
    `;

    modal.classList.add("open");
}
