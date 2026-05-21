const sampleLogs = `Jan 10 10:12:44 firewall sshd[2188]: Failed password for admin from 192.168.1.44 port 51422 ssh2
Jan 10 10:13:01 web01 nginx: 203.0.113.10 GET /login.php 500 SQL injection attempt detected
Jan 10 10:14:27 endpoint01 kernel: USB storage mounted by user analyst
Jan 10 10:15:52 vpn01 auth: Accepted password for manager from 10.0.0.15 port 443
Jan 10 10:16:34 db01 audit: critical privilege escalation attempt from 198.51.100.23`;

const state = {
    summary: {},
    events: [],
    charts: {},
};

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
    })[char]);
}

function setMessage(text, type = "info") {
    const box = $("messageBox");
    box.textContent = text;
    box.dataset.type = type;
}

function setBusy(isBusy, text = "Working") {
    $("modelStatus").textContent = isBusy ? text : "Ready";
    $("analyzeBtn").disabled = isBusy;
}

function filtersAsParams() {
    const params = new URLSearchParams();
    const pairs = {
        search: $("searchFilter").value.trim(),
        verdict: $("verdictFilter").value,
        severity: $("severityFilter").value,
        source_ip: $("sourceIpFilter").value.trim(),
        event_type: $("eventTypeFilter").value.trim(),
        limit: "250",
    };

    Object.entries(pairs).forEach(([key, value]) => {
        if (value) params.set(key, value);
    });

    return params;
}

async function requestJson(url, options = {}) {
    const response = await fetch(url, options);
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(payload.error || `Request failed with ${response.status}`);
    }

    return payload;
}

function updateStats(summary = {}) {
    $("totalLogs").textContent = summary.total_logs || 0;
    $("alerts").textContent = summary.alerts || 0;
    $("attacks").textContent = summary.attacks || 0;
    $("averageRisk").textContent = summary.average_risk || 0;
    drawVerticalBarChart("verdictChart", summary.verdict_counts || {}, ["#b94a5a", "#c58a35", "#3a8f7b"]);
    drawVerticalBarChart("ipChart", summary.top_ips || {}, ["#3a8f7b", "#6e7f94", "#a7834a", "#8b6478", "#4f786c"]);
}

function verdictClass(verdict = "") {
    return verdict.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function renderEvents(events = []) {
    const tbody = $("eventsBody");

    if (!events.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No matching events found.</td></tr>';
        return;
    }

    tbody.innerHTML = events.map((event) => `
        <tr>
            <td>${escapeHtml(event.line_no)}</td>
            <td>${escapeHtml(event.timestamp || "unknown")}</td>
            <td>${escapeHtml(event.source_ip || "unknown")}</td>
            <td><span class="severity">${escapeHtml(event.severity || "low")}</span></td>
            <td>${escapeHtml(event.event_type || "unknown")}</td>
            <td>${escapeHtml(event.risk_score ?? 0)}</td>
            <td><span class="verdict ${verdictClass(event.verdict)}">${escapeHtml(event.verdict || "NORMAL")}</span></td>
            <td>${escapeHtml(event.explanation || "")}</td>
        </tr>
    `).join("");
}

function drawVerticalBarChart(canvasId, values, palette) {
    const canvas = $(canvasId);
    const context = canvas.getContext("2d");
    const entries = Object.entries(values).slice(0, 8);
    const width = canvas.width;
    const height = canvas.height;
    const padding = { top: 28, right: 22, bottom: 66, left: 42 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;

    context.clearRect(0, 0, width, height);
    state.charts[canvasId] = [];

    if (!entries.length) {
        context.fillStyle = "#768293";
        context.font = "14px Arial";
        context.fillText("No data yet", 24, 42);
        return;
    }

    const max = Math.max(...entries.map(([, value]) => Number(value)), 1);
    const slotWidth = plotWidth / entries.length;
    const barWidth = Math.min(58, slotWidth * 0.58);

    context.strokeStyle = "#354253";
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(padding.left, padding.top);
    context.lineTo(padding.left, padding.top + plotHeight);
    context.lineTo(width - padding.right, padding.top + plotHeight);
    context.stroke();

    entries.forEach(([label, value], index) => {
        const numericValue = Number(value);
        const barHeight = Math.max(4, (plotHeight * numericValue) / max);
        const x = padding.left + index * slotWidth + (slotWidth - barWidth) / 2;
        const y = padding.top + plotHeight - barHeight;
        const color = palette[index % palette.length];

        const gradient = context.createLinearGradient(0, y, 0, y + barHeight);
        gradient.addColorStop(0, color);
        gradient.addColorStop(1, `${color}b8`);

        context.fillStyle = gradient;
        context.beginPath();
        context.roundRect(x, y, barWidth, barHeight, 8);
        context.fill();

        context.fillStyle = "#dbe4ef";
        context.font = "bold 13px Arial";
        context.textAlign = "center";
        context.fillText(numericValue, x + barWidth / 2, y - 8);

        context.save();
        context.translate(x + barWidth / 2, height - 12);
        context.rotate(-Math.PI / 7);
        context.font = "12px Arial";
        context.fillStyle = "#92a0b2";
        context.fillText(String(label).slice(0, 14), 0, 0);
        context.restore();

        state.charts[canvasId].push({
            x,
            y,
            width: barWidth,
            height: barHeight,
            label,
            value: numericValue,
        });
    });

    context.textAlign = "left";
}

async function refreshResults() {
    const params = filtersAsParams();
    const data = await requestJson(`/get_results?${params.toString()}`);
    state.summary = data.summary || {};
    state.events = data.events || [];
    updateStats(state.summary);
    renderEvents(state.events);
}

async function analyzeLogs() {
    const logs = $("logInput").value.trim();

    if (!logs) {
        setMessage("Paste logs or upload a file before analysis.", "warning");
        return;
    }

    setBusy(true, "Analyzing");
    setMessage("Analyzing evidence and storing results...");

    try {
        const data = await requestJson("/upload_logs", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                logs,
                case_name: $("caseName").value.trim() || "Default Investigation",
            }),
        });

        updateStats(data.summary);
        renderEvents(data.events || []);
        setMessage(`Processed ${data.summary.total_logs || 0} log entries.`, "success");
    } catch (error) {
        setMessage(error.message, "error");
    } finally {
        setBusy(false);
    }
}

async function uploadFile(file) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("case_name", $("caseName").value.trim() || file.name);

    setBusy(true, "Uploading");
    setMessage(`Uploading ${file.name}...`);

    try {
        const data = await requestJson("/upload_file", {
            method: "POST",
            body: formData,
        });

        updateStats(data.summary);
        renderEvents(data.events || []);
        setMessage(`Uploaded and processed ${file.name}.`, "success");
    } catch (error) {
        setMessage(error.message, "error");
    } finally {
        setBusy(false);
        $("fileInput").value = "";
    }
}

async function clearLogs() {
    const confirmed = window.confirm("Clear all stored investigation logs?");
    if (!confirmed) return;

    setBusy(true, "Clearing");

    try {
        await requestJson("/clear_logs", { method: "DELETE" });
        state.summary = {};
        state.events = [];
        updateStats(state.summary);
        renderEvents(state.events);
        setMessage("Stored logs cleared.", "success");
    } catch (error) {
        setMessage(error.message, "error");
    } finally {
        setBusy(false);
    }
}

function exportReport(type) {
    const params = filtersAsParams();
    window.location.href = `/export/${type}?${params.toString()}`;
}

function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

function bindEvents() {
    $("analyzeBtn").addEventListener("click", analyzeLogs);
    $("loadSampleBtn").addEventListener("click", () => {
        $("logInput").value = sampleLogs;
        setMessage("Sample logs loaded.", "success");
    });
    $("fileInput").addEventListener("change", (event) => {
        const [file] = event.target.files;
        if (file) uploadFile(file);
    });
    $("clearBtn").addEventListener("click", clearLogs);
    $("refreshBtn").addEventListener("click", () => refreshResults().catch((error) => setMessage(error.message, "error")));

    document.querySelectorAll("[data-export]").forEach((button) => {
        button.addEventListener("click", () => exportReport(button.dataset.export));
    });

    const autoRefresh = debounce(() => refreshResults().catch((error) => setMessage(error.message, "error")));
    ["searchFilter", "verdictFilter", "severityFilter", "sourceIpFilter", "eventTypeFilter"].forEach((id) => {
        $(id).addEventListener("input", autoRefresh);
        $(id).addEventListener("change", autoRefresh);
    });

    ["verdictChart", "ipChart"].forEach(bindChartTooltip);
}

document.addEventListener("DOMContentLoaded", () => {
    bindEvents();
    updateStats({});
    renderEvents([]);
    setMessage("Paste logs or upload a file to start a new analysis.", "info");
});

function bindChartTooltip(canvasId) {
    const canvas = $(canvasId);
    const tooltip = $(`${canvasId}Tooltip`);

    canvas.addEventListener("mousemove", (event) => {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;
        const x = (event.clientX - rect.left) * scaleX;
        const y = (event.clientY - rect.top) * scaleY;
        const hit = (state.charts[canvasId] || []).find((bar) => (
            x >= bar.x &&
            x <= bar.x + bar.width &&
            y >= bar.y &&
            y <= bar.y + bar.height
        ));

        if (!hit) {
            tooltip.classList.remove("visible");
            return;
        }

        tooltip.innerHTML = `<strong>${escapeHtml(hit.label)}</strong><span>Count: ${escapeHtml(hit.value)}</span>`;
        tooltip.style.left = `${event.clientX - rect.left + 14}px`;
        tooltip.style.top = `${event.clientY - rect.top - 12}px`;
        tooltip.classList.add("visible");
    });

    canvas.addEventListener("mouseleave", () => {
        tooltip.classList.remove("visible");
    });
}
