/**
 * SOC Threat Intelligence Dashboard Controller
 * File: frontend/js/dashboard.js
 */

let currentPage = 1;
let chartInstances = {};

document.addEventListener("DOMContentLoaded", () => {
    loadDashboardMetrics();
    loadCorrelatedClusters();
    loadThreatFeed();
    setupEventListeners();
});

function setupEventListeners() {
    // Search IOC form
    const searchBtn = document.getElementById("btn-search-ioc");
    const searchInput = document.getElementById("ioc-search-input");
    if (searchBtn && searchInput) {
        searchBtn.addEventListener("click", () => handleIocSearch(searchInput.value));
        searchInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") handleIocSearch(searchInput.value);
        });
    }

    // Filter changes
    ["filter-severity", "filter-category", "filter-type", "filter-status", "filter-sort"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("change", () => { currentPage = 1; loadThreatFeed(); });
    });

    const tableSearch = document.getElementById("table-search-input");
    if (tableSearch) {
        tableSearch.addEventListener("input", debounce(() => { currentPage = 1; loadThreatFeed(); }, 400));
    }

    // Pagination
    document.getElementById("btn-prev-page")?.addEventListener("click", () => {
        if (currentPage > 1) { currentPage--; loadThreatFeed(); }
    });
    document.getElementById("btn-next-page")?.addEventListener("click", () => {
        currentPage++; loadThreatFeed();
    });

    // New threat modal
    document.getElementById("btn-open-create")?.addEventListener("click", () => openModal("create-threat-modal"));
    document.getElementById("form-create-threat")?.addEventListener("submit", handleCreateThreat);
}

function debounce(func, wait) {
    let timeout;
    return (...args) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

async function loadDashboardMetrics() {
    try {
        const res = await apiFetch("/api/dashboard/stats");
        const { cards, charts } = res.data;

        // Render KPI Cards
        document.getElementById("kpi-total-threats").textContent = cards.total_threats.toLocaleString();
        document.getElementById("kpi-critical-threats").textContent = cards.critical_threats.toLocaleString();
        document.getElementById("kpi-high-threats").textContent = cards.high_threats.toLocaleString();
        document.getElementById("kpi-active-iocs").textContent = cards.active_indicators.toLocaleString();
        document.getElementById("kpi-open-investigations").textContent = cards.open_investigations.toLocaleString();
        document.getElementById("kpi-avg-confidence").textContent = `${cards.average_confidence}%`;
        document.getElementById("kpi-vulns-tracked").textContent = cards.vulnerabilities_tracked.toLocaleString();

        // Render All 10 Charts
        renderCharts(charts);
    } catch (err) {
        console.error("Failed to load metrics:", err);
    }
}

function renderCharts(charts) {
    // Theme Colors
    const colors = {
        cyan: "#06b6d4",
        blue: "#3b82f6",
        purple: "#8b5cf6",
        red: "#ef4444",
        orange: "#f97316",
        yellow: "#f59e0b",
        green: "#10b981",
        gray: "#64748b"
    };

    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: "#94a3b8", font: { family: 'Inter', size: 11 } } },
            tooltip: { backgroundColor: "#1e293b", titleColor: "#f8fafc", bodyColor: "#cbd5e1" }
        },
        scales: {
            x: { ticks: { color: "#64748b" }, grid: { color: "rgba(255,255,255,0.05)" } },
            y: { ticks: { color: "#64748b" }, grid: { color: "rgba(255,255,255,0.05)" } }
        }
    };

    // Chart 1: Threats Over Time
    initOrUpdateChart("chart-timeline", "line", {
        labels: charts.threats_over_time.map(d => d.date.slice(5)),
        datasets: [{
            label: "Threat Sightings",
            data: charts.threats_over_time.map(d => d.count),
            borderColor: colors.cyan,
            backgroundColor: "rgba(6, 182, 212, 0.15)",
            fill: true,
            tension: 0.35
        }]
    }, chartDefaults);

    // Chart 2: Threats by Severity
    initOrUpdateChart("chart-severity", "doughnut", {
        labels: charts.threats_by_severity.map(s => s.severity),
        datasets: [{
            data: charts.threats_by_severity.map(s => s.count),
            backgroundColor: [colors.red, colors.orange, colors.yellow, colors.blue, colors.gray]
        }]
    }, { responsive: true, maintainAspectRatio: false, plugins: chartDefaults.plugins });

    // Chart 3: Threats by Category
    initOrUpdateChart("chart-category", "bar", {
        labels: charts.threats_by_category.map(c => c.category),
        datasets: [{
            label: "Threat Count",
            data: charts.threats_by_category.map(c => c.count),
            backgroundColor: colors.blue,
            borderRadius: 4
        }]
    }, chartDefaults);

    // Chart 4: IOC Type Distribution
    initOrUpdateChart("chart-iocs", "doughnut", {
        labels: charts.ioc_distribution.map(i => i.type),
        datasets: [{
            data: charts.ioc_distribution.map(i => i.count),
            backgroundColor: [colors.cyan, colors.blue, colors.purple, colors.orange, colors.green, colors.yellow]
        }]
    }, { responsive: true, maintainAspectRatio: false, plugins: chartDefaults.plugins });

    // Chart 5: Top ATT&CK Tactics
    initOrUpdateChart("chart-attack", "bar", {
        labels: charts.top_tactics.map(t => t.tactic),
        datasets: [{
            label: "Mapped Detections",
            data: charts.top_tactics.map(t => t.count),
            backgroundColor: colors.purple,
            borderRadius: 4
        }]
    }, { ...chartDefaults, indexAxis: 'y' });

    // Chart 6: Risk Score Distribution
    initOrUpdateChart("chart-risk", "bar", {
        labels: charts.risk_distribution.map(r => r.tier),
        datasets: [{
            label: "Threats in Risk Tier",
            data: charts.risk_distribution.map(r => r.count),
            backgroundColor: [colors.gray, colors.blue, colors.yellow, colors.orange, colors.red],
            borderRadius: 4
        }]
    }, chartDefaults);

    // Chart 7: Confidence Distribution
    initOrUpdateChart("chart-confidence", "bar", {
        labels: charts.confidence_distribution.map(c => c.band),
        datasets: [{
            label: "Intelligence Records",
            data: charts.confidence_distribution.map(c => c.count),
            backgroundColor: colors.green,
            borderRadius: 4
        }]
    }, chartDefaults);

    // Chart 8: Vulnerabilities by Severity
    initOrUpdateChart("chart-vulns", "doughnut", {
        labels: charts.vulns_by_severity.map(v => v.severity),
        datasets: [{
            data: charts.vulns_by_severity.map(v => v.count),
            backgroundColor: [colors.red, colors.orange, colors.yellow, colors.blue]
        }]
    }, { responsive: true, maintainAspectRatio: false, plugins: chartDefaults.plugins });

    // Chart 9: Top Threat Categories
    initOrUpdateChart("chart-top-categories", "bar", {
        labels: charts.top_categories.map(c => c.category),
        datasets: [{
            label: "Prevalence",
            data: charts.top_categories.map(c => c.count),
            backgroundColor: colors.yellow,
            borderRadius: 4
        }]
    }, chartDefaults);

    // Chart 10: Threat Status Distribution
    initOrUpdateChart("chart-status", "pie", {
        labels: charts.threat_statuses.map(s => s.status),
        datasets: [{
            data: charts.threat_statuses.map(s => s.count),
            backgroundColor: [colors.blue, colors.orange, colors.yellow, colors.green, colors.gray]
        }]
    }, { responsive: true, maintainAspectRatio: false, plugins: chartDefaults.plugins });
}

function initOrUpdateChart(canvasId, type, data, options) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    if (chartInstances[canvasId]) {
        chartInstances[canvasId].destroy();
    }
    chartInstances[canvasId] = new Chart(ctx, { type, data, options });
}

async function loadCorrelatedClusters() {
    try {
        const res = await apiFetch("/api/dashboard/trends");
        const tbody = document.getElementById("clusters-tbody");
        if (!tbody) return;

        const clusters = res.data.clusters || [];
        if (clusters.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">No correlated clusters identified.</td></tr>`;
            return;
        }

        tbody.innerHTML = clusters.slice(0, 6).map(c => `
            <tr>
                <td class="code-cell">${c.campaign_id}</td>
                <td><strong>${c.cluster_name}</strong></td>
                <td><span class="badge badge-info">${c.category}</span></td>
                <td><span class="badge ${c.average_risk >= 70 ? 'badge-critical' : 'badge-high'}">${c.average_risk}/100</span></td>
                <td><strong>${c.threat_count}</strong> records</td>
                <td>${formatDate(c.last_seen)}</td>
            </tr>
        `).join("");
    } catch (err) {
        console.error("Failed to load clusters:", err);
    }
}

async function loadThreatFeed() {
    const sev = document.getElementById("filter-severity")?.value || "ALL";
    const cat = document.getElementById("filter-category")?.value || "ALL";
    const type = document.getElementById("filter-type")?.value || "ALL";
    const status = document.getElementById("filter-status")?.value || "ALL";
    const sort = document.getElementById("filter-sort")?.value || "newest";
    const search = document.getElementById("table-search-input")?.value || "";

    const query = new URLSearchParams({
        severity: sev,
        category: cat,
        indicator_type: type,
        status: status,
        sort_by: sort,
        search: search,
        page: currentPage,
        page_size: 15
    });

    try {
        const res = await apiFetch(`/api/threats?${query.toString()}`);
        const { records, total, page, total_pages } = res.data;

        const tbody = document.getElementById("threats-tbody");
        if (!tbody) return;

        if (records.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:2rem;">No threat records match filter criteria.</td></tr>`;
            document.getElementById("page-info").textContent = "Page 0 of 0";
            return;
        }

        tbody.innerHTML = records.map(t => `
            <tr>
                <td class="code-cell"><a href="/threat-details?id=${t.threat_id}" style="color:var(--cyan-accent);text-decoration:none;font-weight:700;">${t.threat_id}</a></td>
                <td><strong>${t.threat_name}</strong></td>
                <td><span class="badge badge-info">${t.category}</span></td>
                <td><code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px;font-size:0.75rem;">${t.indicator_value}</code></td>
                <td>${getSeverityBadge(t.severity)}</td>
                <td><strong style="color:${t.risk_score >= 70 ? 'var(--sev-critical)' : 'var(--sev-high)'}">${t.risk_score}</strong>/100</td>
                <td>${t.confidence_score}%</td>
                <td>${getStatusBadge(t.status)}</td>
                <td><a href="/threat-details?id=${t.threat_id}" class="btn btn-sm btn-primary">Investigate</a></td>
            </tr>
        `).join("");

        document.getElementById("page-info").textContent = `Page ${page} of ${total_pages} (${total.toLocaleString()} total)`;
        document.getElementById("btn-prev-page").disabled = page <= 1;
        document.getElementById("btn-next-page").disabled = page >= total_pages;
    } catch (err) {
        console.error("Failed to load feed:", err);
    }
}

async function handleIocSearch(indicator) {
    if (!indicator || !indicator.trim()) {
        showToast("Please enter an indicator (IP, domain, hash, URL, or CVE).", "warning");
        return;
    }

    try {
        const res = await apiFetch(`/api/indicators/search?q=${encodeURIComponent(indicator.trim())}`);
        const data = res.data;
        renderIocSearchResult(data);
        openModal("search-result-modal");
    } catch (err) {
        console.error("IOC search failed:", err);
    }
}

function renderIocSearchResult(data) {
    const wrap = document.getElementById("search-result-body");
    if (!wrap) return;

    wrap.innerHTML = `
        <div style="background:var(--bg-input);padding:1rem;border-radius:8px;border:1px solid var(--border-color);margin-bottom:1rem;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <span style="font-size:0.75rem;color:var(--text-dim);text-transform:uppercase;">Queried Indicator</span>
                    <h3 class="code-cell" style="font-size:1.15rem;margin-top:0.2rem;">${data.normalized_value}</h3>
                </div>
                <div>
                    ${data.known_in_dataset ? '<span class="badge badge-critical">KNOWN IN DEMO DATASET</span>' : '<span class="badge badge-info">NOT IN DATASET (NEW)</span>'}
                </div>
            </div>
            <div style="margin-top:0.5rem;font-size:0.8rem;color:var(--text-muted);">
                <strong>Type:</strong> ${data.indicator_type} &nbsp;|&nbsp; <strong>Syntax Valid:</strong> ${data.valid ? 'YES' : 'NO'} &nbsp;|&nbsp; <em>${data.validation_notes}</em>
            </div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0.75rem;margin-bottom:1rem;">
            <div class="card" style="padding:0.75rem;text-align:center;">
                <div style="font-size:0.7rem;color:var(--text-dim);">RISK SCORE</div>
                <div style="font-size:1.4rem;font-weight:800;color:var(--sev-high);">${data.risk_score}/100</div>
            </div>
            <div class="card" style="padding:0.75rem;text-align:center;">
                <div style="font-size:0.7rem;color:var(--text-dim);">SEVERITY</div>
                <div style="margin-top:0.3rem;">${getSeverityBadge(data.severity)}</div>
            </div>
            <div class="card" style="padding:0.75rem;text-align:center;">
                <div style="font-size:0.7rem;color:var(--text-dim);">CONFIDENCE</div>
                <div style="font-size:1.4rem;font-weight:800;color:var(--cyan-accent);">${data.confidence_score}%</div>
            </div>
            <div class="card" style="padding:0.75rem;text-align:center;">
                <div style="font-size:0.7rem;color:var(--text-dim);">STATUS</div>
                <div style="margin-top:0.3rem;">${getStatusBadge(data.status)}</div>
            </div>
        </div>

        <div style="margin-bottom:1rem;">
            <h4 style="font-size:0.85rem;color:var(--cyan-accent);margin-bottom:0.4rem;">DEFENSIVE ENRICHMENT CONTEXT</h4>
            <p style="font-size:0.85rem;color:var(--text-muted);">${data.description}</p>
        </div>

        ${data.known_in_dataset ? `
        <div style="margin-bottom:1rem;">
            <h4 style="font-size:0.85rem;color:var(--cyan-accent);margin-bottom:0.4rem;">RECOMMENDED DEFENSIVE ACTIONS</h4>
            <ul style="padding-left:1.2rem;font-size:0.82rem;color:var(--text-muted);">
                ${data.recommended_actions.map(a => `<li style="margin-bottom:0.25rem;">${a}</li>`).join("")}
            </ul>
        </div>
        ` : ''}

        <div style="text-align:right;margin-top:1.5rem;">
            ${data.threat_id !== 'UNKNOWN' ? `<a href="/threat-details?id=${data.threat_id}" class="btn btn-primary">Open Full Investigation View</a>` : ''}
        </div>
    `;
}

async function handleCreateThreat(e) {
    e.preventDefault();
    const form = e.target;
    const payload = {
        threat_name: form["threat_name"].value,
        category: form["category"].value,
        indicator_value: form["indicator_value"].value,
        severity: form["severity"].value,
        confidence_score: parseInt(form["confidence_score"].value),
        source_name: form["source_name"].value,
        source_reliability: form["source_reliability"].value,
        description: form["description"].value
    };

    try {
        const res = await apiFetch("/api/threats", {
            method: "POST",
            body: JSON.stringify(payload)
        });
        showToast(`Threat ${res.data.threat_id} created successfully!`, "success");
        closeModal("create-threat-modal");
        form.reset();
        loadThreatFeed();
        loadDashboardMetrics();
    } catch (err) {
        showToast(err.message, "error");
    }
}

function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add("open");
}

function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove("open");
}
