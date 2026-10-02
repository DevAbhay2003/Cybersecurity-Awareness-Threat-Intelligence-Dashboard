/**
 * Cybersecurity Awareness Quiz Controller
 * File: frontend/js/quiz.js
 */

let quizQuestions = [];
let userAnswers = {};
let categoryChartInstance = null;

document.addEventListener("DOMContentLoaded", () => {
    loadQuiz();
    setupQuizEvents();
});

function setupQuizEvents() {
    document.getElementById("btn-submit-quiz")?.addEventListener("click", submitQuiz);
    document.getElementById("btn-retake-quiz")?.addEventListener("click", () => {
        userAnswers = {};
        document.getElementById("quiz-results-container").style.display = "none";
        document.getElementById("quiz-form-container").style.display = "block";
        window.scrollTo({ top: 0, behavior: 'smooth' });
        loadQuiz();
    });
}

async function loadQuiz() {
    try {
        const res = await apiFetch("/api/awareness/quiz");
        quizQuestions = res.data.questions || [];
        renderQuizQuestions(quizQuestions);
        updateProgress();
    } catch (err) {
        console.error("Failed to load quiz:", err);
    }
}

function renderQuizQuestions(questions) {
    const container = document.getElementById("questions-list");
    if (!container) return;

    container.innerHTML = questions.map((q, idx) => `
        <div class="quiz-card" id="card-${q.id}">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
                <span class="badge badge-info">${q.category}</span>
                <span style="font-size:0.75rem;color:var(--text-dim);font-family:var(--font-mono);">Question ${idx + 1} of ${questions.length}</span>
            </div>
            <div class="question-text">${q.question}</div>
            <div class="options-group">
                ${q.options.map((opt, optIdx) => `
                    <div class="option-item" onclick="selectOption('${q.id}', ${optIdx}, this)">
                        <input type="radio" name="opt-${q.id}" class="option-radio" value="${optIdx}" ${userAnswers[q.id] === optIdx ? 'checked' : ''}>
                        <span style="font-size:0.875rem;color:var(--text-main);">${opt}</span>
                    </div>
                `).join("")}
            </div>
        </div>
    `).join("");
}

function selectOption(questionId, optionIndex, element) {
    userAnswers[questionId] = optionIndex;

    // Update styling in DOM
    const card = document.getElementById(`card-${questionId}`);
    if (card) {
        card.querySelectorAll(".option-item").forEach(item => item.classList.remove("selected"));
        element.classList.add("selected");
        const radio = element.querySelector("input[type='radio']");
        if (radio) radio.checked = true;
    }

    updateProgress();
}

function updateProgress() {
    const answeredCount = Object.keys(userAnswers).length;
    const total = quizQuestions.length;
    const progressEl = document.getElementById("quiz-progress-text");
    const barEl = document.getElementById("quiz-progress-bar");

    if (progressEl) progressEl.textContent = `${answeredCount} of ${total} Questions Answered`;
    if (barEl) {
        const pct = total > 0 ? (answeredCount / total) * 100 : 0;
        barEl.style.width = `${pct}%`;
    }
}

async function submitQuiz() {
    const answeredCount = Object.keys(userAnswers).length;
    const total = quizQuestions.length;

    if (answeredCount < total) {
        const confirmSubmit = confirm(`You have answered ${answeredCount} of ${total} questions. Are you sure you want to submit? Unanswered questions will be scored as incorrect.`);
        if (!confirmSubmit) return;
    }

    try {
        const res = await apiFetch("/api/awareness/quiz/submit", {
            method: "POST",
            body: JSON.stringify({ answers: userAnswers })
        });
        const result = res.data;
        renderQuizResult(result);
    } catch (err) {
        console.error("Failed to submit quiz:", err);
    }
}

function renderQuizResult(result) {
    document.getElementById("quiz-form-container").style.display = "none";
    const resultContainer = document.getElementById("quiz-results-container");
    resultContainer.style.display = "block";
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // Score Dial
    document.getElementById("res-overall-score").textContent = `${result.overall_score}%`;
    document.getElementById("res-grade-label").textContent = result.grade_label;
    document.getElementById("res-correct-count").textContent = `${result.correct_count} of ${result.total_questions} questions correct`;

    // Tier badge color
    const gradeBadge = document.getElementById("res-grade-label");
    if (result.overall_score >= 81) {
        gradeBadge.className = "badge badge-success";
    } else if (result.overall_score >= 61) {
        gradeBadge.className = "badge badge-low";
    } else if (result.overall_score >= 41) {
        gradeBadge.className = "badge badge-medium";
    } else {
        gradeBadge.className = "badge badge-critical";
    }

    // Render Category Breakdown Chart
    renderCategoryChart(result.category_scores);

    // Render Recommendations
    const recsWrap = document.getElementById("recommendations-list");
    if (recsWrap) {
        recsWrap.innerHTML = result.recommendations.map(r => `
            <div style="background:var(--bg-input);padding:1rem;border-radius:8px;border:1px solid var(--border-color);margin-bottom:0.75rem;display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem;">
                        <span class="badge ${r.score < 50 ? 'badge-critical' : (r.score < 70 ? 'badge-medium' : 'badge-success')}">${r.category}: ${r.score}%</span>
                        <strong>${r.module_title}</strong>
                    </div>
                    <p style="font-size:0.85rem;color:var(--text-muted);">${r.recommendation}</p>
                </div>
                <div>
                    <a href="/awareness" class="btn btn-sm btn-cyan">Start Module</a>
                </div>
            </div>
        `).join("");
    }

    // Render Detailed Question Review
    const reviewWrap = document.getElementById("questions-review-list");
    if (reviewWrap) {
        reviewWrap.innerHTML = result.detailed_results.map((q, idx) => `
            <div class="card" style="margin-bottom:1rem;border-left:4px solid ${q.is_correct ? 'var(--sev-success)' : 'var(--sev-critical)'};">
                <div style="display:flex;justify-content:space-between;margin-bottom:0.5rem;">
                    <span class="badge badge-info">${q.category}</span>
                    <span style="font-size:0.75rem;font-weight:700;color:${q.is_correct ? 'var(--sev-success)' : 'var(--sev-critical)'}">
                        ${q.is_correct ? '✓ CORRECT' : '✗ INCORRECT'}
                    </span>
                </div>
                <div style="font-weight:600;font-size:0.95rem;color:var(--text-main);margin-bottom:0.75rem;">
                    ${idx + 1}. ${q.question}
                </div>
                <div style="font-size:0.85rem;margin-bottom:0.5rem;">
                    <div style="color:${q.is_correct ? 'var(--sev-success)' : 'var(--sev-critical)'};margin-bottom:0.25rem;">
                        <strong>Your Answer:</strong> ${q.user_choice !== null ? q.options[q.user_choice] : 'Not answered'}
                    </div>
                    ${!q.is_correct ? `
                    <div style="color:var(--sev-success);">
                        <strong>Correct Answer:</strong> ${q.options[q.correct_choice]}
                    </div>
                    ` : ''}
                </div>
                <div style="background:var(--bg-input);padding:0.75rem;border-radius:6px;font-size:0.8rem;color:var(--text-muted);margin-top:0.5rem;">
                    <strong style="color:var(--cyan-accent);">Analyst Explanation:</strong> ${q.explanation}
                </div>
            </div>
        `).join("");
    }
}

function renderCategoryChart(categoryScores) {
    const ctx = document.getElementById("chart-quiz-categories");
    if (!ctx) return;

    if (categoryChartInstance) categoryChartInstance.destroy();

    const labels = Object.keys(categoryScores);
    const scores = Object.values(categoryScores);

    categoryChartInstance = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Awareness Proficiency (%)',
                data: scores,
                backgroundColor: 'rgba(6, 182, 212, 0.2)',
                borderColor: '#06b6d4',
                pointBackgroundColor: '#06b6d4',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: '#06b6d4'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: { color: 'rgba(255,255,255,0.1)' },
                    grid: { color: 'rgba(255,255,255,0.1)' },
                    pointLabels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } },
                    suggestedMin: 0,
                    suggestedMax: 100,
                    ticks: { color: '#64748b', backdropColor: 'transparent', stepSize: 20 }
                }
            },
            plugins: {
                legend: { labels: { color: '#cbd5e1' } }
            }
        }
    });
}
