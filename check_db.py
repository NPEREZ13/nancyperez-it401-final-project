from app import create_app
from database import get_db

app = create_app()

with app.app_context():
    with get_db().cursor() as cursor:
        cursor.execute("SELECT 1 AS connected")
        print(cursor.fetchone())