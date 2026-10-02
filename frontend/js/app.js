/**
 * CyberGuard Frontend Application Logic
 * Implements real-time debounced password analysis, credential generation,
 * interactive hashing benchmarks, and Chart.js telemetry dashboard.
 * 
 * STRICT PRIVACY DIRECTIVE:
 * - Plaintext passwords are NEVER printed to console.log
 * - Plaintext passwords are NEVER saved in localStorage or sessionStorage
 * - All analytics transmission uses exclusively aggregated non-reversible metadata
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements - Password Input & Controls
    const passwordInput = document.getElementById("password-input");
    const togglePasswordBtn = document.getElementById("toggle-password-btn");
    const eyeIcon = document.getElementById("eye-icon");
    const clearBtn = document.getElementById("clear-btn");
    const charCounter = document.getElementById("char-counter");

    // Context Drawer Elements
    const toggleContextBtn = document.getElementById("toggle-context-btn");
    const contextDrawer = document.getElementById("context-drawer");
    const ctxName = document.getElementById("ctx-name");
    const ctxYear = document.getElementById("ctx-year");
    const ctxOrg = document.getElementById("ctx-org");

    // Meter Elements
    const classificationBadge = document.getElementById("classification-badge");
    const scoreText = document.getElementById("score-text");
    const progressBar = document.getElementById("progress-bar");
    const classificationDesc = document.getElementById("classification-desc");

    // Metrics Elements
    const metricLength = document.getElementById("metric-length");
    const metricBand = document.getElementById("metric-band");
    const metricUnique = document.getElementById("metric-unique");
    const metricTypes = document.getElementById("metric-types");
    const tagLower = document.getElementById("tag-lower");
    const tagUpper = document.getElementById("tag-upper");
    const tagDigits = document.getElementById("tag-digits");
    const tagSymbols = document.getElementById("tag-symbols");

    // Entropy Elements
    const metricTheoEntropy = document.getElementById("metric-theo-entropy");
    const metricEffEntropy = document.getElementById("metric-eff-entropy");
    const metricKeyspace = document.getElementById("metric-keyspace");
    const metricResistance = document.getElementById("metric-resistance");

    // Findings & Suggestions
    const findingsContainer = document.getElementById("findings-container");
    const suggestionsList = document.getElementById("suggestions-list");

    // Policy Elements
    const policyStatusBadge = document.getElementById("policy-status-badge");
    const policyViolationsBox = document.getElementById("policy-violations");
    const policyChkCommon = document.getElementById("policy-chk-common");
    const policyChkPersonal = document.getElementById("policy-chk-personal");
    const policyMinLength = document.getElementById("policy-min-length");

    // Generator Elements
    const tabGenPwd = document.getElementById("tab-gen-pwd");
    const tabGenPassphrase = document.getElementById("tab-gen-passphrase");
    const genPwdControls = document.getElementById("gen-pwd-controls");
    const genPassphraseControls = document.getElementById("gen-passphrase-controls");
    const genLength = document.getElementById("gen-length");
    const genLengthVal = document.getElementById("gen-length-val");
    const genWords = document.getElementById("gen-words");
    const genWordsVal = document.getElementById("gen-words-val");
    const genSeparator = document.getElementById("gen-separator");
    const genUpper = document.getElementById("gen-upper");
    const genLower = document.getElementById("gen-lower");
    const genDigits = document.getElementById("gen-digits");
    const genSymbols = document.getElementById("gen-symbols");
    const generateBtn = document.getElementById("generate-btn");
    const genOutputDisplay = document.getElementById("gen-output-display");
    const copyGenBtn = document.getElementById("copy-gen-btn");
    const testGenBtn = document.getElementById("test-gen-btn");

    // Hashing Lab Elements
    const runHashBenchmarkBtn = document.getElementById("run-hash-benchmark-btn");
    const hashingResultsContainer = document.getElementById("hashing-results-container");

    // Dashboard Telemetry Elements
    const statTotal = document.getElementById("stat-total");
    const statAvgScore = document.getElementById("stat-avg-score");
    const statAvgLen = document.getElementById("stat-avg-len");
    const statDominant = document.getElementById("stat-dominant");
    const statPostureBadge = document.getElementById("stat-posture-badge");
    const statPostureScore = document.getElementById("stat-posture-score");
    const statPostureBar = document.getElementById("stat-posture-bar");
    const statScoreTier = document.getElementById("stat-score-tier");
    const statAtRisk = document.getElementById("stat-at-risk");
    const statAtRiskCount = document.getElementById("stat-at-risk-count");
    const statNistRate = document.getElementById("stat-nist-rate");
    const statNistCount = document.getElementById("stat-nist-count");
    const dashboardLastSync = document.getElementById("dashboard-last-sync");
    const dashboardSessionCounter = document.getElementById("dashboard-session-counter");
    const telemetryInsightsContainer = document.getElementById("telemetry-insights-container");
    const telemetryTableBody = document.getElementById("telemetry-table-body");
    const telemetrySearchInput = document.getElementById("telemetry-search-input");
    const telemetryFilterTier = document.getElementById("telemetry-filter-tier");
    const btnRefreshDashboard = document.getElementById("btn-refresh-dashboard");
    const btnSimulateIngestion = document.getElementById("btn-simulate-ingestion");
    const btnExportTelemetry = document.getElementById("btn-export-telemetry");
    const btnResetTelemetry = document.getElementById("btn-reset-telemetry");
    const simChips = document.querySelectorAll(".sim-chip");

    // Global Chart Instances
    let chartClassifications = null;
    let chartScores = null;
    let chartLengths = null;
    let chartWeaknesses = null;
    let chartSeverities = null;
    let chartUniqueness = null;

    // Local cached telemetry events for table filtering
    let currentTelemetryEvents = [];

    // Debounce timer for smooth typing experience
    let debounceTimer = null;

    /* ========================================================
       1. SHOW / HIDE PASSWORD TOGGLE
       ======================================================== */
    togglePasswordBtn.addEventListener("click", () => {
        if (passwordInput.type === "password") {
            passwordInput.type = "text";
            eyeIcon.textContent = "🔒";
            togglePasswordBtn.title = "Hide Password";
        } else {
            passwordInput.type = "password";
            eyeIcon.textContent = "👁️";
            togglePasswordBtn.title = "Show Password";
        }
    });

    /* ========================================================
       2. CLEAR INPUT
       ======================================================== */
    clearBtn.addEventListener("click", () => {
        passwordInput.value = "";
        charCounter.textContent = "0 characters";
        resetAnalysisUI();
    });

    /* ========================================================
       3. VOLUNTARY CONTEXT DRAWER TOGGLE
       ======================================================== */
    toggleContextBtn.addEventListener("click", () => {
        contextDrawer.classList.toggle("hidden");
        const isHidden = contextDrawer.classList.contains("hidden");
        toggleContextBtn.textContent = isHidden 
            ? "+ Optional Personal Context Check" 
            : "- Hide Personal Context Check";
    });

    [ctxName, ctxYear, ctxOrg].forEach(el => {
        el.addEventListener("input", triggerDebouncedAnalysis);
    });

    /* ========================================================
       4. POLICY OPTION CHANGED
       ======================================================== */
    [policyChkCommon, policyChkPersonal, policyMinLength].forEach(el => {
        el.addEventListener("change", triggerDebouncedAnalysis);
    });

    /* ========================================================
       5. REAL-TIME INPUT EVENT LISTENER
       ======================================================== */
    passwordInput.addEventListener("input", () => {
        const len = passwordInput.value.length;
        charCounter.textContent = `${len} character${len === 1 ? "" : "s"}`;
        triggerDebouncedAnalysis();
    });

    function triggerDebouncedAnalysis() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            const pwd = passwordInput.value;
            if (!pwd) {
                resetAnalysisUI();
                return;
            }
            performAnalysis(pwd);
        }, 220); // 220ms debounce
    }

    /* ========================================================
       6. CORE ANALYSIS ENGINE DISPATCHER
       ======================================================== */
    async function performAnalysis(password) {
        // Collect voluntary context locally
        const context = {};
        if (ctxName.value.trim()) context.first_name = ctxName.value.trim();
        if (ctxYear.value.trim()) context.birth_year = ctxYear.value.trim();
        if (ctxOrg.value.trim()) context.org_name = ctxOrg.value.trim();

        // Collect policy settings
        const policyConfig = {
            min_length: parseInt(policyMinLength.value, 10),
            reject_common: policyChkCommon.checked,
            reject_personal: policyChkPersonal.checked
        };

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    password: password,
                    context: context,
                    policy: policyConfig,
                    record_analytics: true
                })
            });

            if (!response.ok) {
                throw new Error("Analysis failed");
            }

            const data = await response.json();
            if (data.status === "success") {
                renderAnalysisResults(data.data);
                // Refresh dashboard stats asynchronously
                loadDashboardStats();
            }
        } catch (err) {
            // Defensive error handling without password leaking
            classificationDesc.textContent = "Defensive analysis engine encountered a communication issue.";
        }
    }

    /* ========================================================
       7. RENDER RESULTS IN UI
       ======================================================== */
    function renderAnalysisResults(res) {
        const score = res.score;
        const cls = res.classification;
        const metrics = res.metrics;
        const entropy = res.entropy;
        const policy = res.policy;

        // Score & Progress Bar
        scoreText.textContent = score;
        progressBar.style.width = `${score}%`;

        // Classification badge and colors
        classificationBadge.textContent = cls;
        classificationBadge.className = `badge badge-${cls.toLowerCase().replace(" ", "-")}`;

        const colorMap = {
            "VERY WEAK": "var(--color-very-weak)",
            "WEAK": "var(--color-weak)",
            "MODERATE": "var(--color-moderate)",
            "STRONG": "var(--color-strong)",
            "VERY STRONG": "var(--color-very-strong)"
        };
        progressBar.style.backgroundColor = colorMap[cls] || "var(--color-primary)";
        classificationDesc.textContent = res.classification_description;

        // Composition metrics
        metricLength.innerHTML = `${metrics.length} chars (<span id="metric-band">${metrics.length_band}</span>)`;
        metricUnique.textContent = `${metrics.unique_character_count} (Ratio: ${metrics.unique_character_ratio})`;
        metricTypes.textContent = `${metrics.character_type_count} of 4 types`;

        // Diversity tags
        tagLower.className = `tag ${metrics.has_lowercase ? 'tag-active' : 'tag-inactive'}`;
        tagUpper.className = `tag ${metrics.has_uppercase ? 'tag-active' : 'tag-inactive'}`;
        tagDigits.className = `tag ${metrics.has_digits ? 'tag-active' : 'tag-inactive'}`;
        tagSymbols.className = `tag ${metrics.has_symbols ? 'tag-active' : 'tag-inactive'}`;

        // Entropy
        metricTheoEntropy.textContent = `${entropy.theoretical_bits} bits`;
        metricEffEntropy.textContent = `${entropy.effective_bits} bits`;
        metricKeyspace.textContent = entropy.search_space_notation;
        metricResistance.textContent = entropy.strength_tier;

        // Findings Rendering
        findingsContainer.innerHTML = "";
        if (res.findings && res.findings.length > 0) {
            res.findings.forEach(f => {
                const item = document.createElement("div");
                const sevClass = `finding-${(f.severity || 'medium').toLowerCase()}`;
                item.className = `finding-item ${sevClass}`;
                item.innerHTML = `
                    <div class="finding-badge">[${f.severity}]</div>
                    <div class="finding-text">${f.description}</div>
                `;
                findingsContainer.appendChild(item);
            });
        } else {
            findingsContainer.innerHTML = `
                <div class="finding-item finding-low">
                    <div class="finding-badge">[CLEAN]</div>
                    <div class="finding-text">No common patterns, sequences, keyboard walks, or repetitions identified!</div>
                </div>
            `;
        }

        // Suggestions Rendering
        suggestionsList.innerHTML = "";
        if (res.suggestions && res.suggestions.length > 0) {
            res.suggestions.forEach(sug => {
                const li = document.createElement("li");
                li.className = "suggestion-item";
                li.textContent = sug;
                suggestionsList.appendChild(li);
            });
        }

        // Policy Evaluation Rendering
        if (policy) {
            policyStatusBadge.textContent = policy.status;
            policyStatusBadge.className = `badge ${policy.status === 'PASS' ? 'badge-success' : 'badge-danger'}`;

            if (policy.violations.length === 0) {
                policyViolationsBox.innerHTML = `<strong style="color:#6ee7b7;">✓ Compliant with current authentication policy criteria.</strong>`;
            } else {
                policyViolationsBox.innerHTML = `
                    <strong style="color:#fca5a5;">Policy Violations Detected (${policy.violations.length}):</strong>
                    <ul style="margin-top:0.4rem; padding-left:1.2rem;">
                        ${policy.violations.map(v => `<li>${v}</li>`).join("")}
                    </ul>
                `;
            }
        }
    }

    function resetAnalysisUI() {
        scoreText.textContent = "0";
        progressBar.style.width = "0%";
        classificationBadge.textContent = "PENDING INPUT";
        classificationBadge.className = "badge badge-neutral";
        classificationDesc.textContent = "Enter a password above to begin defensive evaluation.";

        metricLength.innerHTML = `0 chars (<span id="metric-band">Empty</span>)`;
        metricUnique.textContent = "0 (Ratio: 0.0)";
        metricTypes.textContent = "0 of 4 types";

        [tagLower, tagUpper, tagDigits, tagSymbols].forEach(tag => {
            tag.className = "tag tag-inactive";
        });

        metricTheoEntropy.textContent = "0.0 bits";
        metricEffEntropy.textContent = "0.0 bits";
        metricKeyspace.textContent = "0 combinations";
        metricResistance.textContent = "Uncertain";

        findingsContainer.innerHTML = `<div class="empty-state">No vulnerabilities detected yet. Enter input above.</div>`;
        suggestionsList.innerHTML = `<li class="suggestion-item info-item">Security recommendations will adapt dynamically as you test passwords.</li>`;

        policyStatusBadge.textContent = "PENDING";
        policyStatusBadge.className = "badge badge-neutral";
        policyViolationsBox.innerHTML = `<em>Policy results will synchronize with the active password entered above.</em>`;
    }

    /* ========================================================
       8. SECURE CREDENTIAL GENERATOR
       ======================================================== */
    let generatorMode = "password";

    tabGenPwd.addEventListener("click", () => {
        generatorMode = "password";
        tabGenPwd.classList.add("active");
        tabGenPassphrase.classList.remove("active");
        genPwdControls.classList.remove("hidden");
        genPassphraseControls.classList.add("hidden");
    });

    tabGenPassphrase.addEventListener("click", () => {
        generatorMode = "passphrase";
        tabGenPassphrase.classList.add("active");
        tabGenPwd.classList.remove("active");
        genPassphraseControls.classList.remove("hidden");
        genPwdControls.classList.add("hidden");
    });

    genLength.addEventListener("input", () => {
        genLengthVal.textContent = genLength.value;
    });

    genWords.addEventListener("input", () => {
        genWordsVal.textContent = genWords.value;
    });

    generateBtn.addEventListener("click", async () => {
        try {
            const payload = { mode: generatorMode };
            if (generatorMode === "password") {
                payload.length = parseInt(genLength.value, 10);
                payload.include_upper = genUpper.checked;
                payload.include_lower = genLower.checked;
                payload.include_digits = genDigits.checked;
                payload.include_symbols = genSymbols.checked;
            } else {
                payload.word_count = parseInt(genWords.value, 10);
                payload.separator = genSeparator.value;
            }

            const response = await fetch("/api/generate-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const data = await response.json();
            if (data.status === "success") {
                const cred = data.data.password || data.data.passphrase;
                genOutputDisplay.value = cred;
            }
        } catch (e) {
            genOutputDisplay.value = "Error generating credential.";
        }
    });

    copyGenBtn.addEventListener("click", () => {
        if (genOutputDisplay.value && !genOutputDisplay.value.startsWith("Error")) {
            navigator.clipboard.writeText(genOutputDisplay.value);
            const orig = copyGenBtn.textContent;
            copyGenBtn.textContent = "Copied!";
            setTimeout(() => { copyGenBtn.textContent = orig; }, 1500);
        }
    });

    testGenBtn.addEventListener("click", () => {
        if (genOutputDisplay.value && !genOutputDisplay.value.startsWith("Error")) {
            passwordInput.value = genOutputDisplay.value;
            passwordInput.type = "text";
            eyeIcon.textContent = "🔒";
            charCounter.textContent = `${passwordInput.value.length} characters`;
            triggerDebouncedAnalysis();
            // Smooth scroll to analyzer
            document.getElementById("analyzer-section").scrollIntoView({ behavior: "smooth" });
        }
    });

    /* ========================================================
       9. EDUCATIONAL HASHING BENCHMARK LAB
       ======================================================== */
    runHashBenchmarkBtn.addEventListener("click", async () => {
        hashingResultsContainer.innerHTML = `<div class="empty-state">Running cryptographic calculations with 600,000 PBKDF2 iterations and scrypt...</div>`;
        try {
            const response = await fetch("/api/hashing-demo", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ sample: "DemoSyntheticPassphrase2026!" })
            });

            const data = await response.json();
            if (data.status === "success") {
                renderHashingBenchmarks(data.data);
            }
        } catch (e) {
            hashingResultsContainer.innerHTML = `<div class="empty-state">Benchmark error occurred.</div>`;
        }
    });

    function renderHashingBenchmarks(demoData) {
        hashingResultsContainer.innerHTML = "";
        demoData.benchmarks.forEach(b => {
            const card = document.createElement("div");
            card.className = "hash-benchmark-card";
            card.innerHTML = `
                <div class="hash-card-header">
                    <span class="hash-algo-name">${b.algorithm}</span>
                    <span class="hash-time-badge">${b.execution_time_ms} ms</span>
                </div>
                <p class="hash-advantage"><strong>Attacker Impact:</strong> ${b.attacker_advantage}</p>
                <p class="micro-note" style="margin-top:0.3rem;">Sample Hash: <code>${b.hash_sample}</code></p>
            `;
            hashingResultsContainer.appendChild(card);
        });
    }

    /* ========================================================
       10. DASHBOARD CHARTS & TELEMETRY SUITE
       ======================================================== */
    function escapeHTML(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    async function loadDashboardStats(isManualRefresh = false) {
        const refreshIcon = btnRefreshDashboard ? btnRefreshDashboard.querySelector(".btn-icon") : null;
        if (isManualRefresh && refreshIcon) {
            refreshIcon.style.transition = "transform 0.5s ease";
            refreshIcon.style.transform = "rotate(360deg)";
            setTimeout(() => {
                refreshIcon.style.transform = "rotate(0deg)";
            }, 600);
        }

        try {
            const response = await fetch("/api/dashboard/stats");
            if (!response.ok) return;
            const res = await response.json();
            if (res.status === "success") {
                renderDashboard(res.data);
            }
        } catch (e) {
            // Dashboard load failure should remain non-blocking
        }
    }

    function renderDashboard(stats) {
        // 1. Executive Stat Cards
        statTotal.textContent = stats.total_analyses;
        statAvgScore.textContent = `${stats.average_score} / 100`;
        statAvgLen.textContent = `${stats.average_length} chars`;

        // Dominant classification
        let maxCount = -1;
        let dominantTier = "N/A";
        for (const [tier, count] of Object.entries(stats.classifications)) {
            if (count > maxCount) {
                maxCount = count;
                dominantTier = tier;
            }
        }
        statDominant.textContent = dominantTier;

        if (statScoreTier) {
            statScoreTier.textContent = stats.average_score >= 75
                ? "Grade: Enterprise Resilience"
                : (stats.average_score >= 50 ? "Grade: Moderate Resistance" : "Grade: High Vulnerability Rate");
        }

        if (statAtRisk) statAtRisk.textContent = `${stats.at_risk_percentage || 0}%`;
        if (statAtRiskCount) statAtRiskCount.textContent = `${stats.at_risk_count || 0} in VERY WEAK / WEAK`;

        if (statNistRate) statNistRate.textContent = `${stats.nist_compliance_rate || 0}%`;
        if (statNistCount) statNistCount.textContent = `${stats.nist_compliant_count || 0} zero-weakness compliant`;

        // 2. Posture Rating Banner
        if (statPostureBadge && statPostureScore && statPostureBar) {
            const pScore = stats.risk_posture_score || 0;
            statPostureScore.textContent = pScore;
            statPostureBar.style.width = `${pScore}%`;

            let postureBadgeClass = "badge badge-neutral";
            let postureColor = "#3b82f6";

            if (pScore >= 75) {
                postureBadgeClass = "badge badge-success";
                postureColor = "#10b981";
            } else if (pScore >= 55) {
                postureBadgeClass = "badge badge-info";
                postureColor = "#06b6d4";
            } else if (pScore >= 40) {
                postureBadgeClass = "badge badge-warning";
                postureColor = "#eab308";
            } else {
                postureBadgeClass = "badge badge-danger";
                postureColor = "#ef4444";
            }

            statPostureBadge.className = postureBadgeClass;
            statPostureBadge.textContent = stats.risk_posture || "ASSESSING";
            statPostureBar.style.backgroundColor = postureColor;
        }

        if (dashboardSessionCounter) {
            dashboardSessionCounter.textContent = `${stats.total_analyses} Sessions Logged`;
        }

        if (dashboardLastSync) {
            const now = new Date();
            dashboardLastSync.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }

        // 3. Render 6 Charts
        renderClassificationChart(stats.classifications);
        renderScoreChart(stats.score_distribution);
        renderLengthChart(stats.length_distribution);
        renderWeaknessChart(stats.common_weaknesses || []);
        renderSeverityChart(stats.severity_distribution || {});
        renderUniquenessChart(stats.uniqueness_distribution || {});

        // 4. Render Dynamic Automated Security Insights
        renderSecurityInsights(stats.security_insights || []);

        // 5. Render Recent Telemetry Activity Feed
        currentTelemetryEvents = stats.recent_telemetry || [];
        renderTelemetryTable(currentTelemetryEvents);
    }

    /* --- CHART 1: Classification Doughnut --- */
    function renderClassificationChart(dataObj) {
        const canvas = document.getElementById("chart-classifications");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const labels = Object.keys(dataObj);
        const values = Object.values(dataObj);

        if (chartClassifications) chartClassifications.destroy();
        chartClassifications = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: [
                        "#ef4444", "#f97316", "#eab308", "#06b6d4", "#10b981"
                    ],
                    borderColor: "#111827",
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#9ca3af", font: { size: 10, weight: "bold" }, boxWidth: 12, padding: 10 }
                    },
                    tooltip: {
                        backgroundColor: "#111827",
                        borderColor: "#374151",
                        borderWidth: 1,
                        titleColor: "#f9fafb",
                        bodyColor: "#9ca3af"
                    }
                },
                cutout: "68%"
            }
        });
    }

    /* --- CHART 2: Defense Score Histogram --- */
    function renderScoreChart(dataObj) {
        const canvas = document.getElementById("chart-scores");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const labels = Object.keys(dataObj);
        const values = Object.values(dataObj);

        if (chartScores) chartScores.destroy();
        chartScores = new Chart(ctx, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Evaluations",
                    data: values,
                    backgroundColor: [
                        "#ef4444", "#f97316", "#eab308", "#3b82f6", "#10b981"
                    ],
                    borderRadius: 5,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "#111827",
                        borderColor: "#374151",
                        borderWidth: 1
                    }
                },
                scales: {
                    x: { ticks: { color: "#9ca3af", font: { size: 10 } }, grid: { color: "rgba(255, 255, 255, 0.05)" } },
                    y: {
                        ticks: { color: "#9ca3af", font: { size: 10 }, precision: 0 },
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    /* --- CHART 3: Length Bands --- */
    function renderLengthChart(dataObj) {
        const canvas = document.getElementById("chart-lengths");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const labels = Object.keys(dataObj);
        const values = Object.values(dataObj);

        if (chartLengths) chartLengths.destroy();
        chartLengths = new Chart(ctx, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Credentials",
                    data: values,
                    backgroundColor: [
                        "#ef4444", "#f59e0b", "#3b82f6", "#10b981"
                    ],
                    borderRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "#111827",
                        borderColor: "#374151",
                        borderWidth: 1
                    }
                },
                scales: {
                    x: { ticks: { color: "#9ca3af", font: { size: 10 } }, grid: { color: "rgba(255, 255, 255, 0.05)" } },
                    y: {
                        ticks: { color: "#9ca3af", font: { size: 10 }, precision: 0 },
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    /* --- CHART 4: Top Weaknesses --- */
    function renderWeaknessChart(weaknessList) {
        const canvas = document.getElementById("chart-weaknesses");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const labels = weaknessList.map(w => w.type.replace(/_/g, " ").slice(0, 18));
        const values = weaknessList.map(w => w.count);

        if (chartWeaknesses) chartWeaknesses.destroy();
        chartWeaknesses = new Chart(ctx, {
            type: "bar",
            indexAxis: "y",
            data: {
                labels: labels.length ? labels : ["No Weaknesses"],
                datasets: [{
                    label: "Occurrences",
                    data: values.length ? values : [0],
                    backgroundColor: "#f59e0b",
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "#111827",
                        borderColor: "#374151",
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        ticks: { color: "#9ca3af", font: { size: 10 }, precision: 0 },
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        beginAtZero: true
                    },
                    y: { ticks: { color: "#9ca3af", font: { size: 9 } }, grid: { display: false } }
                }
            }
        });
    }

    /* --- CHART 5: Weakness Severity Breakdown --- */
    function renderSeverityChart(dataObj) {
        const canvas = document.getElementById("chart-severities");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const labels = ["Critical", "High", "Medium", "Low"];
        const values = [
            dataObj["CRITICAL"] || 0,
            dataObj["HIGH"] || 0,
            dataObj["MEDIUM"] || 0,
            dataObj["LOW"] || 0
        ];

        if (chartSeverities) chartSeverities.destroy();
        chartSeverities = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6"],
                    borderColor: "#111827",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#9ca3af", font: { size: 10, weight: "bold" }, boxWidth: 12, padding: 8 }
                    },
                    tooltip: {
                        backgroundColor: "#111827",
                        borderColor: "#374151",
                        borderWidth: 1
                    }
                },
                cutout: "60%"
            }
        });
    }

    /* --- CHART 6: Character Pool Uniqueness --- */
    function renderUniquenessChart(dataObj) {
        const canvas = document.getElementById("chart-uniqueness");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const labels = Object.keys(dataObj);
        const values = Object.values(dataObj);

        if (chartUniqueness) chartUniqueness.destroy();
        chartUniqueness = new Chart(ctx, {
            type: "bar",
            data: {
                labels: labels.length ? labels : ["Empty"],
                datasets: [{
                    label: "Credentials",
                    data: values.length ? values : [0],
                    backgroundColor: [
                        "#ef4444", "#f59e0b", "#3b82f6", "#10b981"
                    ],
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "#111827",
                        borderColor: "#374151",
                        borderWidth: 1
                    }
                },
                scales: {
                    x: { ticks: { color: "#9ca3af", font: { size: 9 } }, grid: { color: "rgba(255, 255, 255, 0.05)" } },
                    y: {
                        ticks: { color: "#9ca3af", font: { size: 10 }, precision: 0 },
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    /* --- Dynamic Fleet Security Insights --- */
    function renderSecurityInsights(insights) {
        if (!telemetryInsightsContainer) return;
        if (!insights || insights.length === 0) {
            telemetryInsightsContainer.innerHTML = `<div class="insight-card-skeleton">Insufficient telemetry to synthesize fleet findings. Evaluate additional credentials above.</div>`;
            return;
        }

        telemetryInsightsContainer.innerHTML = "";
        insights.forEach(item => {
            const card = document.createElement("div");
            card.className = `insight-card insight-${item.type || "threat"}`;
            card.innerHTML = `
                <div class="insight-top">
                    <span class="insight-icon">${escapeHTML(item.icon || "📌")}</span>
                    <span class="insight-title">${escapeHTML(item.title)}</span>
                </div>
                <p class="insight-detail">${escapeHTML(item.detail)}</p>
            `;
            telemetryInsightsContainer.appendChild(card);
        });
    }

    /* --- Telemetry Audit Log Table --- */
    function renderTelemetryTable(events) {
        if (!telemetryTableBody) return;

        const filterTier = telemetryFilterTier ? telemetryFilterTier.value : "ALL";
        const searchTerm = telemetrySearchInput ? telemetrySearchInput.value.trim().toLowerCase() : "";

        const filtered = events.filter(e => {
            if (filterTier !== "ALL" && e.classification !== filterTier) return false;
            if (searchTerm) {
                const combined = `${e.analysis_id} ${e.classification} ${e.primary_weakness} ${e.top_severity}`.toLowerCase();
                if (!combined.includes(searchTerm)) return false;
            }
            return true;
        });

        if (filtered.length === 0) {
            telemetryTableBody.innerHTML = `
                <tr>
                    <td colspan="9" class="table-empty">No telemetry sessions match the selected filter.</td>
                </tr>
            `;
            return;
        }

        telemetryTableBody.innerHTML = "";
        filtered.forEach(e => {
            const tr = document.createElement("tr");

            // Tier badge class
            let tierClass = "badge-neutral";
            if (e.classification === "VERY WEAK") tierClass = "badge-danger";
            else if (e.classification === "WEAK") tierClass = "badge-warning";
            else if (e.classification === "MODERATE") tierClass = "badge-neutral";
            else if (e.classification === "STRONG") tierClass = "badge-info";
            else if (e.classification === "VERY STRONG") tierClass = "badge-success";

            // Score styling
            let scoreBg = "rgba(59, 130, 246, 0.15)";
            let scoreColor = "#60a5fa";
            if (e.score < 30) { scoreBg = "rgba(239, 68, 68, 0.2)"; scoreColor = "#f87171"; }
            else if (e.score < 60) { scoreBg = "rgba(234, 179, 8, 0.2)"; scoreColor = "#facc15"; }
            else if (e.score >= 80) { scoreBg = "rgba(16, 185, 129, 0.2)"; scoreColor = "#34d399"; }

            // Max severity badge
            const sev = (e.top_severity || "CLEAN").toLowerCase();
            const sevBadgeClass = `tbl-badge tbl-badge-${sev}`;

            // NIST flag
            const nistClass = e.nist_status === "PASS" ? "tbl-pass" : "tbl-fail";
            const nistText = e.nist_status === "PASS" ? "✓ PASS" : "✕ FAIL";

            tr.innerHTML = `
                <td><span class="table-session-id">#${escapeHTML(e.analysis_id)}</span></td>
                <td><span class="table-timestamp">${escapeHTML(e.created_at)}</span></td>
                <td>${e.password_length} chars</td>
                <td>${e.unique_ratio_pct}%</td>
                <td><span class="table-score-badge" style="background:${scoreBg}; color:${scoreColor}">${e.score}</span></td>
                <td><span class="badge ${tierClass}" style="font-size:0.7rem;">${escapeHTML(e.classification)}</span></td>
                <td>${escapeHTML(e.primary_weakness || "None (Clean)")}</td>
                <td><span class="${sevBadgeClass}">${escapeHTML(e.top_severity)}</span></td>
                <td><span class="${nistClass}">${nistText}</span></td>
            `;
            telemetryTableBody.appendChild(tr);
        });
    }

    /* --- Interactive Toolbar & Simulation Event Listeners --- */
    if (btnRefreshDashboard) {
        btnRefreshDashboard.addEventListener("click", () => {
            loadDashboardStats(true);
        });
    }

    if (btnSimulateIngestion) {
        btnSimulateIngestion.addEventListener("click", async () => {
            btnSimulateIngestion.disabled = true;
            const origText = btnSimulateIngestion.innerHTML;
            btnSimulateIngestion.innerHTML = `<span class="btn-icon">⏳</span> Ingesting...`;

            try {
                const resp = await fetch("/api/dashboard/simulate", { method: "POST" });
                const res = await resp.json();
                if (res.status === "success") {
                    renderDashboard(res.data);
                }
            } catch (err) {
                // Silently handle
            } finally {
                btnSimulateIngestion.innerHTML = origText;
                btnSimulateIngestion.disabled = false;
            }
        });
    }

    if (btnExportTelemetry) {
        btnExportTelemetry.addEventListener("click", () => {
            window.location.href = "/api/dashboard/export?format=csv";
        });
    }

    if (btnResetTelemetry) {
        btnResetTelemetry.addEventListener("click", async () => {
            if (confirm("Reset telemetry database to baseline educational demo dataset?")) {
                try {
                    const resp = await fetch("/api/dashboard/reset", { method: "POST" });
                    const res = await resp.json();
                    if (res.status === "success") {
                        renderDashboard(res.data);
                    }
                } catch (err) {
                    // Silently handle
                }
            }
        });
    }

    if (telemetrySearchInput) {
        telemetrySearchInput.addEventListener("input", () => {
            renderTelemetryTable(currentTelemetryEvents);
        });
    }

    if (telemetryFilterTier) {
        telemetryFilterTier.addEventListener("change", () => {
            renderTelemetryTable(currentTelemetryEvents);
        });
    }

    // Quick Simulation Injector Chips
    simChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const pwd = chip.getAttribute("data-pwd");
            if (pwd && passwordInput) {
                passwordInput.value = pwd;
                passwordInput.type = "text";
                if (eyeIcon) eyeIcon.textContent = "🔒";
                if (charCounter) charCounter.textContent = `${pwd.length} characters`;
                triggerDebouncedAnalysis();
                document.getElementById("analyzer-section").scrollIntoView({ behavior: "smooth" });
            }
        });
    });

    // Initial load of telemetry stats
    loadDashboardStats();
});

