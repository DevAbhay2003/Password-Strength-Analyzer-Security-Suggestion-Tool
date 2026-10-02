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

    // Global Chart Instances
    let chartClassifications = null;
    let chartScores = null;
    let chartLengths = null;
    let chartWeaknesses = null;

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
       10. DASHBOARD CHARTS & TELEMETRY
       ======================================================== */
    async function loadDashboardStats() {
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
        statTotal.textContent = stats.total_analyses;
        statAvgScore.textContent = `${stats.average_score} / 100`;
        statAvgLen.textContent = `${stats.average_length} chars`;

        // Determine dominant tier
        let maxCount = -1;
        let dominantTier = "N/A";
        for (const [tier, count] of Object.entries(stats.classifications)) {
            if (count > maxCount) {
                maxCount = count;
                dominantTier = tier;
            }
        }
        statDominant.textContent = dominantTier;

        // Render Charts using Chart.js
        renderClassificationChart(stats.classifications);
        renderScoreChart(stats.score_distribution);
        renderLengthChart(stats.length_distribution);
        renderWeaknessChart(stats.common_weaknesses);
    }

    function renderClassificationChart(dataObj) {
        const ctx = document.getElementById("chart-classifications").getContext("2d");
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
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom", labels: { color: "#9ca3af", font: { size: 11 } } }
                }
            }
        });
    }

    function renderScoreChart(dataObj) {
        const ctx = document.getElementById("chart-scores").getContext("2d");
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
                    backgroundColor: "#3b82f6",
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: "#9ca3af" }, grid: { color: "#374151" } },
                    y: { ticks: { color: "#9ca3af" }, grid: { color: "#374151" } }
                }
            }
        });
    }

    function renderLengthChart(dataObj) {
        const ctx = document.getElementById("chart-lengths").getContext("2d");
        const labels = Object.keys(dataObj);
        const values = Object.values(dataObj);

        if (chartLengths) chartLengths.destroy();
        chartLengths = new Chart(ctx, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Analyses",
                    data: values,
                    backgroundColor: "#8b5cf6",
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: "#9ca3af" }, grid: { color: "#374151" } },
                    y: { ticks: { color: "#9ca3af" }, grid: { color: "#374151" } }
                }
            }
        });
    }

    function renderWeaknessChart(weaknessList) {
        const ctx = document.getElementById("chart-weaknesses").getContext("2d");
        const labels = weaknessList.map(w => w.type.replace(/_/g, " "));
        const values = weaknessList.map(w => w.count);

        if (chartWeaknesses) chartWeaknesses.destroy();
        chartWeaknesses = new Chart(ctx, {
            type: "bar",
            indexAxis: "y",
            data: {
                labels: labels,
                datasets: [{
                    label: "Frequency",
                    data: values,
                    backgroundColor: "#f59e0b",
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: "#9ca3af" }, grid: { color: "#374151" } },
                    y: { ticks: { color: "#9ca3af" }, grid: { color: "#374151" } }
                }
            }
        });
    }

    // Initial load of telemetry stats
    loadDashboardStats();
});
