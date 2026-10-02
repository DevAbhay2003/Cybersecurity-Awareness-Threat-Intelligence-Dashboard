/**
 * Global Frontend Utilities & API Client
 * File: frontend/js/app.js
 */

const API_BASE = "";

async function apiFetch(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            headers: {
                "Content-Type": "application/json",
                ...options.headers
            },
            ...options
        });
        const json = await response.json();
        if (!response.ok) {
            throw new Error(json.message || json.error || `HTTP ${response.status}`);
        }
        return json;
    } catch (err) {
        console.error(`API Error [${endpoint}]:`, err);
        showToast(err.message || "Network error occurred", "error");
        throw err;
    }
}

function showToast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.style.cssText = "position:fixed;bottom:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    const bgColors = {
        error: "#ef4444",
        success: "#10b981",
        warning: "#f59e0b",
        info: "#0284c7"
    };
    toast.style.cssText = `background:${bgColors[type] || '#1f2937'};color:#fff;padding:12px 18px;border-radius:8px;font-size:0.85rem;box-shadow:0 4px 15px rgba(0,0,0,0.5);font-family:sans-serif;max-width:350px;animation:fadeIn 0.3s ease;`;
    toast.textContent = message;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.4s ease";
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

function getSeverityBadge(severity) {
    const s = (severity || "INFORMATIONAL").toUpperCase();
    const map = {
        CRITICAL: "badge-critical",
        HIGH: "badge-high",
        MEDIUM: "badge-medium",
        LOW: "badge-low",
        INFORMATIONAL: "badge-info"
    };
    return `<span class="badge ${map[s] || 'badge-info'}">${s}</span>`;
}

function getStatusBadge(status) {
    const st = (status || "NEW").toUpperCase();
    let cls = "badge-info";
    if (st === "MONITORING") cls = "badge-low";
    if (st === "INVESTIGATING") cls = "badge-high";
    if (st === "CLOSED" || st === "RESOLVED") cls = "badge-success";
    if (st === "FALSE_POSITIVE") cls = "badge-info";
    return `<span class="badge ${cls}">${st.replace('_', ' ')}</span>`;
}

function formatDate(isoStr) {
    if (!isoStr || isoStr === "N/A") return "N/A";
    try {
        const d = new Date(isoStr);
        return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
        return isoStr;
    }
}
