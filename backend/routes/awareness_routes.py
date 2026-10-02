"""
Cybersecurity Awareness Center & Quiz Routes
Module: backend.routes.awareness_routes

Provides educational awareness content, multi-topic quizzes, and scoring engines.
"""

import os
import sys
import json
from flask import Blueprint, request

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.models.database import get_db_connection
from backend.services.threat_service import grade_quiz_submission
from backend.utils.helpers import sanitize_input, format_api_response

awareness_bp = Blueprint("awareness", __name__, url_prefix="/api/awareness")

@awareness_bp.route("/modules", methods=["GET"])
def list_modules():
    """
    GET /api/awareness/modules
    Retrieves all 15 cybersecurity learning modules.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT module_id, title, category, description, content_json FROM awareness_modules ORDER BY module_id ASC")
    rows = cursor.fetchall()
    conn.close()

    modules = []
    for r in rows:
        item = json.loads(r["content_json"])
        modules.append(item)

    return format_api_response(data={"modules": modules, "total": len(modules)}, message="Awareness modules retrieved successfully")

@awareness_bp.route("/modules/<module_id>", methods=["GET"])
def get_single_module(module_id):
    """
    GET /api/awareness/modules/{id}
    """
    clean_id = sanitize_input(module_id).upper()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT content_json FROM awareness_modules WHERE UPPER(module_id) = ?", (clean_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return format_api_response(error=f"Module '{clean_id}' not found.", status_code=404)

    return format_api_response(data=json.loads(row["content_json"]), message="Module details retrieved")

@awareness_bp.route("/quiz", methods=["GET"])
def get_quiz():
    """
    GET /api/awareness/quiz
    Retrieves the 30+ question bank (without answers for test fairness).
    """
    questions_file = os.path.join(BASE_DIR, "awareness", "quiz_questions.json")
    if not os.path.exists(questions_file):
        return format_api_response(error="Quiz question repository missing.", status_code=500)

    with open(questions_file, mode="r", encoding="utf-8") as qf:
        questions = json.load(qf)

    # Sanitize by omitting correct_index and explanation before client test submission
    sanitized_questions = []
    for q in questions:
        sanitized_questions.append({
            "id": q["id"],
            "category": q["category"],
            "question": q["question"],
            "options": q["options"]
        })

    return format_api_response(
        data={"questions": sanitized_questions, "total": len(sanitized_questions)},
        message="Quiz questions loaded successfully"
    )

@awareness_bp.route("/quiz/submit", methods=["POST"])
def submit_quiz():
    """
    POST /api/awareness/quiz/submit
    Body:
    {
        "answers": {
            "Q-01": 2,
            "Q-02": 1,
            ...
        }
    }
    """
    body = request.get_json() or {}
    answers = body.get("answers", {})

    if not isinstance(answers, dict):
        return format_api_response(error="Invalid answers format. Dictionary of question IDs to selected option index expected.", status_code=400)

    score_result = grade_quiz_submission(answers)
    return format_api_response(
        data=score_result,
        message=f"Quiz graded: {score_result['overall_score']}% ({score_result['grade_label']})"
    )

@awareness_bp.route("/quiz/history", methods=["GET"])
def get_quiz_history():
    """
    GET /api/awareness/quiz/history
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT result_id, overall_score, category_scores_json, weak_areas_json, recommendations_json, created_at
    FROM quiz_results
    ORDER BY created_at DESC
    LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()

    history = []
    for r in rows:
        history.append({
            "result_id": r["result_id"],
            "overall_score": r["overall_score"],
            "category_scores": json.loads(r["category_scores_json"]),
            "weak_areas": json.loads(r["weak_areas_json"]),
            "recommendations": json.loads(r["recommendations_json"]),
            "created_at": r["created_at"]
        })

    return format_api_response(data={"history": history, "total": len(history)}, message="Quiz history retrieved")
