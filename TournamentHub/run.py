"""Простой локальный запуск TournamentHub из VS Code."""
import os
from app import app, init_db

if __name__ == "__main__":
    init_db()
    # Для локальной разработки. Перед публикацией отключите debug.
    app.run(host="127.0.0.1", port=5000, debug=True)

from flask import jsonify

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})