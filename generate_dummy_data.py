# generate_dummy_data.py
import os
import random
from datetime import datetime, timedelta
from app import db, User, CheckIn, CHECKIN_SLOTS, app  # import your Flask app and models

# -------------------- Configuration --------------------
NUM_DAYS = 30  # number of days to generate data for
COMMENTS = [
    "On time", "Late arrival", "Working remotely", "Meeting", "Training", "Task completed", ""
]

def generate_dummy_checkins():
    with app.app_context():
        # Fetch all registered students
        students = User.query.filter_by(role="Student").all()
        if not students:
            print("❌ No students found in the database.")
            return

        today = datetime.now().date()
        start_date = today - timedelta(days=NUM_DAYS)

        for student in students:
            for i in range(NUM_DAYS):
                checkin_date = start_date + timedelta(days=i)

                # Randomly decide if the student checked in for each slot
                for slot in CHECKIN_SLOTS:
                    if random.random() < 0.8:  # 80% chance the student checked in
                        timestamp = datetime.combine(checkin_date, datetime.strptime(slot, "%H:%M").time())
                        comment = random.choice(COMMENTS)
                        # Avoid duplicates
                        existing = CheckIn.query.filter_by(user_id=student.id, slot=slot, date=checkin_date).first()
                        if not existing:
                            ci = CheckIn(
                                user_id=student.id,
                                slot=slot,
                                timestamp=timestamp,
                                date=checkin_date,
                                comment=comment
                            )
                            db.session.add(ci)
        db.session.commit()
        print(f"✅ Dummy check-ins generated for {len(students)} students for the last {NUM_DAYS} days.")

if __name__ == "__main__":
    generate_dummy_checkins()
