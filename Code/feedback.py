"""
feedback.py

Feedback capture for Agentic Maliciousness Query Agent.
Stores analyst feedback (correct/incorrect) and optional comments per query in SQLite.
Provides:
- init_feedback_db()
- submit_feedback(query_id: int, verdict: str, correct: bool, comments: str = None)
- get_feedback(query_id: int)
"""
import sqlite3
from datetime import datetime
from typing import Optional, Dict

DB_PATH = 'feedback.db'

# Initialize feedback database
def init_feedback_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_id INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            correct INTEGER NOT NULL,
            comments TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Ensure database is initialized
init_feedback_db()


def submit_feedback(query_id: int, verdict: str, correct: bool, comments: Optional[str] = None) -> None:
    """
    Record feedback for a given query.
    correct: True if the agent's verdict was correct, False otherwise.
    comments: Optional free-text feedback from the analyst.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    ts = datetime.utcnow().isoformat()
    cursor.execute(
        'INSERT INTO feedback (query_id, verdict, correct, comments, timestamp) VALUES (?, ?, ?, ?, ?)',
        (query_id, verdict, int(correct), comments, ts)
    )
    conn.commit()
    conn.close()


def get_feedback(query_id: int) -> Optional[Dict]:
    """
    Retrieve the most recent feedback entry for a given query.
    Returns a dict with keys: id, verdict, correct, comments, timestamp or None if none exists.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, verdict, correct, comments, timestamp FROM feedback WHERE query_id = ? ORDER BY id DESC LIMIT 1',
        (query_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            'id': row[0],
            'verdict': row[1],
            'correct': bool(row[2]),
            'comments': row[3],
            'timestamp': row[4]
        }
    return None

if __name__ == '__main__':
    # Simple test harness
    submit_feedback(1, 'malicious', False, comments='Analyst notes: IP belongs to internal network')
    print(get_feedback(1))
