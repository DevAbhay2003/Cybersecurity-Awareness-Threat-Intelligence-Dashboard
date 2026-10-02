/**
 * Threat Investigation View Controller
 * File: frontend/js/details.js
 */

let currentThreatId = "THR-2026-0001";

document.addEventListener("DOMContentLoaded", () => {
    const urlParams = new URLSearchParams(window.location.search);
    currentThreatId = urlParams.get("id") || "THR-2026-0001";
    loadThreatDetails(currentThreatId);
    loadThreatTimeline(currentThreatId);
    setupDetailsEvents();
});

function setupDetailsEvents() {
    // Add note form
    document.getElementById("form-add-note")?.addEventListener("submit", handleAddNote);

    // Status action buttons
    document.querySelectorAll(".btn-status-action").forEach(btn => {
        btn.addEventListener("click", () => {
            const status = btn.getAttribute("data-status");
            handleUpdateStatus(status);
        });
    });
}

async function loadThreatDetails(threatId) {
    try {
        const res = await apiFetch(`/api/threats/${threatId}`);
        const t = res.data;
        renderThreatDetails(t);
    } catch (err) {
        console.error("Failed to load details:", err);
        document.getElementById("threat-details-container").innerHTML = `
            <div class="card" style="text-align:center;padding:3rem;">
                <h3 style="color:var(--sev-critical);margin-bottom:0.5rem;">Threat Record Not Found</h3>
                <p style="color:var(--text-muted);margin-bottom:1.5rem;">The specified threat identifier '${threatId}' does not exist in local dataset.</p>
                <a href="/threat-dashboard" class="btn btn-primary">Return to SOC Dashboard</a>
            </div>
        `;
    }
}

function renderThreatDetails(t) {
    document.getElementById("threat-id-heading").textContent = t.threat_id;
    document.getElementById("threat-name-heading").textContent = t.threat_name;
    document.getElementById("threat-desc").textContent = t.description;

    // Badges
    document.getElementById("badge-category").textContent = t.category;
    document.getElementById("badge-severity").innerHTML = getSeverityBadge(t.severity);
    document.getElementById("badge-status").innerHTML = getStatusBadge(t.status);

    // TLP Badge
    if (t.tlp) {
        document.getElementById("badge-tlp").innerHTML = `
            <span class="badge-tlp" style="background:${t.tlp.color};color:#000;">${t.tlp.tlp}</span>
        `;
    }

    // Score dials
    document.getElementById("detail-risk-score").textContent = `${t.risk_score}/100`;
    document.getElementById("detail-confidence").textContent = `${t.confidence_score}%`;
    document.getElementById("detail-sightings").textContent = t.observation_count.toLocaleString();
    document.getElementById("detail-source").textContent = `${t.source_name} (${t.source_reliability})`;

    // First/Last Seen
    document.getElementById("detail-first-seen").textContent = formatDate(t.first_seen);
    document.getElementById("detail-last-seen").textContent = formatDate(t.last_seen);
    document.getElementById("detail-campaign").textContent = t.campaign_id || "NONE";

    // Primary & Related Indicators
    const indTbody = document.getElementById("indicators-tbody");
    if (indTbody) {
        indTbody.innerHTML = (t.indicators || []).map(i => `
            <tr>
                <td><span class="badge badge-info">${i.indicator_type}</span></td>
                <td class="code-cell">${i.indicator_value}</td>
                <td>${formatDate(i.first_seen)}</td>
                <td>${formatDate(i.last_seen)}</td>
            </tr>
        `).join("");
    }

    // ATT&CK Mapping
    const attackWrap = document.getElementById("attack-mapping-wrap");
    if (attackWrap) {
        if (!t.attack_mappings || t.attack_mappings.length === 0) {
            attackWrap.innerHTML = `<p style="color:var(--text-dim);font-size:0.85rem;">No MITRE ATT&CK technique mapping established for this indicator telemetry.</p>`;
        } else {
            attackWrap.innerHTML = t.attack_mappings.map(m => `
                <div style="background:var(--bg-input);padding:0.75rem 1rem;border-radius:6px;border:1px solid var(--border-color);margin-bottom:0.5rem;display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <span class="badge badge-low" style="margin-right:0.5rem;">${m.tactic}</span>
                        <strong>${m.technique}</strong>
                    </div>
                    <code class="code-cell">${m.technique_id || 'TTP'}</code>
                </div>
            `).join("");
        }
    }

    // Analyst Notes
    renderNotes(t.notes || []);
}

async function loadThreatTimeline(threatId) {
    try {
        const res = await apiFetch(`/api/threats/${threatId}/timeline`);
        const timeline = res.data;
        const timelineWrap = document.getElementById("timeline-container");
        if (!timelineWrap) return;

        timelineWrap.innerHTML = timeline.map(item => `
            <div class="timeline-item">
                <div class="timeline-dot" style="background:var(--${item.badge_color === 'danger' ? 'sev-critical' : 'cyan-accent'})"></div>
                <div class="timeline-header">
                    <span class="timeline-title">${item.title}</span>
                    <span class="timeline-time">${formatDate(item.timestamp)}</span>
                </div>
                <div class="timeline-body">${item.description}</div>
            </div>
        `).join("");
    } catch (err) {
        console.error("Failed to load timeline:", err);
    }
}

function renderNotes(notes) {
    const notesWrap = document.getElementById("notes-container");
    if (!notesWrap) return;

    if (notes.length === 0) {
        notesWrap.innerHTML = `<p style="color:var(--text-dim);font-size:0.85rem;">No analyst triage notes recorded yet.</p>`;
        return;
    }

    notesWrap.innerHTML = notes.map(n => `
        <div style="background:var(--bg-input);padding:0.75rem 1rem;border-radius:6px;border:1px solid var(--border-color);margin-bottom:0.5rem;">
            <div style="display:flex;justify-content:space-between;font-size:0.75rem;color:var(--text-dim);margin-bottom:0.3rem;">
                <strong>${n.author}</strong>
                <span>${formatDate(n.created_at)}</span>
            </div>
            <p style="font-size:0.85rem;color:var(--text-muted);">${n.note}</p>
        </div>
    `).join("");
}

async function handleAddNote(e) {
    e.preventDefault();
    const form = e.target;
    const author = form["author"].value;
    const noteText = form["note"].value;

    try {
        const res = await apiFetch(`/api/threats/${currentThreatId}/notes`, {
            method: "POST",
            body: JSON.stringify({ author, note: noteText })
        });
        showToast("Analyst note added successfully", "success");
        form.reset();
        // Refresh details
        loadThreatDetails(currentThreatId);
    } catch (err) {
        showToast(err.message, "error");
    }
}

async function handleUpdateStatus(newStatus) {
    try {
        const res = await apiFetch(`/api/threats/${currentThreatId}`, {
            method: "PUT",
            body: JSON.stringify({ status: newStatus })
        });
        showToast(`Threat status updated to ${newStatus}`, "success");
        loadThreatDetails(currentThreatId);
        loadThreatTimeline(currentThreatId);
    } catch (err) {
        showToast(err.message, "error");
    }
}
