from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
from datetime import datetime, timedelta
from flask import session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
import pyotp
import qrcode
import io
import base64
from sqlalchemy import func
from flask import send_from_directory, abort
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_this_with_a_strong_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'moepi.sql')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload settings
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads', 'timesheets')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'codnellsmall@gmail.com'
app.config['MAIL_PASSWORD'] = 'mrmxmmomvhvfqoee'
app.config['MAIL_DEFAULT_SENDER'] = 'codnellsmall@gmail.com'
mail = Mail(app)

# Token serializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Database
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------- Models --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(50), nullable=False)
    organization = db.Column(db.String(100), nullable=False)

    # ---------------- Student-specific fields ----------------
    student_number = db.Column(db.String(50), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    institution_type = db.Column(db.String(100), nullable=True)

    # ---------------- Mentor-student mapping ----------------
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    students = db.relationship(
        'User',
        backref=db.backref('mentor', remote_side=[id]),
        lazy='dynamic'
    )

    # ---------------- 2FA for TOTP ----------------
    two_factor_secret = db.Column(db.String(16), nullable=True)

    # ---------------- Relationships ----------------
    checkins = db.relationship('CheckIn', backref='user', lazy=True)
    timesheets = db.relationship('Timesheet', backref='user', lazy=True)

    # ---------------- Password Helpers ----------------
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # ---------------- 2FA Helpers ----------------
    def get_totp_uri(self):
        """Generate TOTP URI for Google Authenticator QR code."""
        import pyotp
        if not self.two_factor_secret:
            self.two_factor_secret = pyotp.random_base32()
        return pyotp.totp.TOTP(self.two_factor_secret).provisioning_uri(
            name=self.email,
            issuer_name="Moepi Check-In System"
        )

    def verify_totp(self, token):
        """Verify a 6-digit TOTP token."""
        import pyotp
        if not self.two_factor_secret:
            return False
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(token)


class CheckIn(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    slot = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date = db.Column(db.Date, nullable=False)
    comment = db.Column(db.String(255), nullable=True)


class Timesheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(400), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    
class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(200))
    upload_date = db.Column(db.DateTime)
    wb1_submitted = db.Column(db.Boolean, default=False)
    wbl2_submitted = db.Column(db.Boolean, default=False)
    wbl3_submitted = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='assignments')



# -------------------- Initialize DB & Default Admin --------------------
with app.app_context():
    db.create_all()
    admin_email = "support@tekete.co.za"
    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        admin = User(
            fullname="System Administrator",
            email=admin_email,
            password_hash=generate_password_hash("Admin@123"),
            is_admin=True,
            role="Administrator",
            organization="Moepi Publishing"
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin created successfully.")
    else:
        print("ℹ️ Admin already exists.")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------- Constants --------------------
CHECKIN_SLOTS = ["11:00", "13:00", "16:00"]
ALLOWED_EXTENSIONS = {'pdf', 'xlsx', 'csv', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# -------------------- Routes --------------------
@app.route('/')
def home():
    return render_template('home.html')



# -------------------- Registration --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # ------------------- Common Fields -------------------
        fullname = request.form.get('fullname', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not fullname or not email or not password or not confirm:
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for('register'))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register'))

        # Only allow certain domains
        allowed_domains = ('@tekete.co.za', '@vut.ac.za', '@micseta.org.za','@edu.vut.ac.za','@tut.ac.za','@tut.ac.za')
        if not email.endswith(allowed_domains):
            flash('Only organization emails allowed.', 'danger')
            return redirect(url_for('register'))

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Account with this email already exists.', 'danger')
            return redirect(url_for('register'))

        # ------------------- Student Registration -------------------
        student_number = request.form.get('student_number', '').strip()
        if student_number:  # Treat as student
            institution_type = request.form.get('institution_type', '').strip()
            institution_name = request.form.get('institution_name', '').strip()
            department = request.form.get('department', '').strip()
            mentor_id = request.form.get('mentor_id', None)

            # Validate all required student fields
            if not institution_type or not institution_name or not department:
                flash("Please fill in all student fields.", "danger")
                return redirect(url_for('register'))

            user = User(
                fullname=fullname,
                email=email,
                role="Student",
                organization=institution_name,      # Store institution name
                student_number=student_number,
                department=department,
                institution_type=institution_type,
                mentor_id=int(mentor_id) if mentor_id else None,
                is_admin=False
            )

        # ------------------- Admin Registration -------------------
        else:
            user_type_form = request.form.get('user_type', '').strip()  # Admin type
            organization = request.form.get('organization', '').strip()

            if not user_type_form or not organization:
                flash("Please fill in all admin fields.", "danger")
                return redirect(url_for('register'))

            user = User(
                fullname=fullname,
                email=email,
                role=user_type_form,
                organization=organization,
                is_admin=user_type_form in ['Mentor', 'WIL Co-ordinator', 'Administrator']
            )

        # ------------------- Set Password & Save -------------------
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for('login'))

    # ------------------- GET Request -------------------
    # Provide list of mentors for student dropdown
    mentors = User.query.filter(User.role.in_(['Mentor', 'MICSETA Mentor']), User.is_admin == True).order_by(User.fullname.asc()).all()
    return render_template('register.html', mentors=mentors)





# -------------------- Login with 2FA --------------------
import pyotp
import qrcode
import io
import base64

from flask import session

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'otp' not in request.form:
        # Step 1: Verify password
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        allowed_domains = ('@tekete.co.za', '@vut.ac.za', '@micseta.org.za', '@edu.vut.ac.za', '@tut.ac.za')
        if not email.endswith(allowed_domains):
            flash('Only organization emails are allowed.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        # If user does not have 2FA set, generate secret
        if not user.two_factor_secret:
            user.two_factor_secret = pyotp.random_base32()
            db.session.commit()

        # Generate QR code for first-time setup
        totp_uri = user.get_totp_uri()
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        # Store user ID in session to verify OTP
        session['pre_2fa_user_id'] = user.id

        return render_template('verify_otp.html', email=email, qr_b64=qr_b64)

    # Step 2: Verify OTP
    if request.method == 'POST' and 'otp' in request.form:
        otp = request.form.get('otp', '').strip()
        user_id = session.get('pre_2fa_user_id')

        if not user_id:
            flash('Session expired. Please log in again.', 'danger')
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        if not user or not user.two_factor_secret:
            flash('User not found or 2FA not set.', 'danger')
            return redirect(url_for('login'))

        if user.verify_totp(otp):
            session.pop('pre_2fa_user_id', None)
            login_user(user)
            flash('Logged in successfully ✅', 'success')

            # Redirect based on role
            if user.role == "Mentor" or user.role == "Administrator":
                return redirect(url_for('admin_dashboard'))
            elif user.role == "MICSETA Mentor":
                return redirect(url_for('micseta_dashboard'))
            elif user.role == "WIL Co-ordinator":
                return redirect(url_for('wil_coordinator_dashboard'))
            else:
                return redirect(url_for('dashboard'))

        else:
            flash('Invalid or expired verification code.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email') or request.form.get('email')
    if not email:
        flash("Email is required to verify OTP.", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    # Generate QR code if user doesn't have 2FA secret
    qr_b64 = None
    if not user.two_factor_secret:
        user.two_factor_secret = pyotp.random_base32()
        db.session.commit()

        totp = pyotp.TOTP(user.two_factor_secret)
        uri = totp.provisioning_uri(name=user.email, issuer_name="Moepi Publishing")

        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    # Handle OTP submission
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if not otp_input:
            flash("Please enter the 6-digit code.", "danger")
            return redirect(url_for('verify_otp', email=email))

        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(otp_input, valid_window=1):
            login_user(user)
            flash("Two-factor authentication successful!", "success")

            # Redirect based on role
            if user.role == "Mentor" or user.role == "Administrator":
                return redirect(url_for('admin_dashboard'))
            elif user.role == "MICSETA Mentor":
                return redirect(url_for('micseta_dashboard'))
            elif user.role == "WIL Co-ordinator":
                return redirect(url_for('wil_coordinator_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for('verify_otp', email=email))

    return render_template("verify_otp.html", email=email, qr_b64=qr_b64)





# -------------------- Logout --------------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))


# -------------------- Forgot / Reset Password --------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[user.email])
            msg.body = f"Hi {user.fullname},\n\nClick the link to reset your password:\n{reset_link}"
            mail.send(msg)
        flash('If this email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('Invalid or expired link.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(password)
            db.session.commit()
            flash('Password reset successful.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# -------------------- Employee Dashboard --------------------
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    now = datetime.now()
    slot_states = {}
    for slot in CHECKIN_SLOTS:
        already = CheckIn.query.filter_by(user_id=current_user.id, slot=slot, date=now.date()).first()
        slot_states[slot] = {'already': bool(already), 'comment': already.comment if already else None}

    recent = CheckIn.query.filter_by(user_id=current_user.id).order_by(CheckIn.timestamp.desc()).limit(20).all()
    last_timesheet = Timesheet.query.filter_by(user_id=current_user.id).order_by(Timesheet.upload_date.desc()).first()
    return render_template('dashboard.html', slot_states=slot_states, now=now, recent=recent, last_timesheet=last_timesheet)


# -------------------- Check-in --------------------
@app.route('/checkin/<slot>', methods=['POST'])
@login_required
def checkin(slot):
    if slot not in CHECKIN_SLOTS:
        flash('Invalid check-in slot.', 'danger')
        return redirect(url_for('dashboard'))

    comment = request.form.get('comment', '').strip()
    now = datetime.now()
    slot_time = datetime.strptime(slot, "%H:%M").time()
    slot_datetime = datetime.combine(now.date(), slot_time)
    start_time = slot_datetime
    end_time = slot_datetime + timedelta(minutes=10)

    if not (start_time <= now <= end_time):
        flash(f"⏰ Check-in for {slot} is only allowed until {end_time.strftime('%H:%M')}.", "danger")
        return redirect(url_for('dashboard'))

    existing = CheckIn.query.filter_by(user_id=current_user.id, slot=slot, date=now.date()).first()
    if existing:
        flash(f"You already checked in for {slot} today.", 'warning')
        return redirect(url_for('dashboard'))

    ci = CheckIn(user_id=current_user.id, slot=slot, timestamp=now, date=now.date(), comment=comment)
    db.session.add(ci)
    db.session.commit()
    flash(f"✅ Check-in for {slot} recorded successfully.", 'success')
    return redirect(url_for('dashboard'))


@app.route('/upload_timesheet', methods=['GET', 'POST'])
@login_required
def upload_timesheet_page():
    now = datetime.now()
    current_day = now.day
    current_month = now.month
    current_year = now.year

    if request.method == 'POST':
        if current_day != 28:
            flash("❌ Timesheets can only be uploaded on the 28th of each month.", "danger")
            return redirect(url_for('upload_timesheet_page'))

        file = request.files.get('timesheet')
        if not file:
            flash('⚠️ No file selected. Please choose a file.', 'warning')
            return redirect(url_for('upload_timesheet_page'))

        existing_timesheet = Timesheet.query.filter_by(user_id=current_user.id).filter(
            db.extract('month', Timesheet.upload_date) == current_month,
            db.extract('year', Timesheet.upload_date) == current_year
        ).first()

        if existing_timesheet:
            flash('❌ You have already uploaded a timesheet for this month.', 'danger')
            return redirect(url_for('upload_timesheet_page'))

        filename = secure_filename(file.filename)
        upload_folder = os.path.join(app.root_path, 'uploads', 'timesheets')
        os.makedirs(upload_folder, exist_ok=True)

        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        new_timesheet = Timesheet(
            user_id=current_user.id,
            filename=filename,
            filepath=file_path,
            upload_date=now
        )
        db.session.add(new_timesheet)
        db.session.commit()

        flash('✅ Timesheet uploaded successfully for this month!', 'success')
        return redirect(url_for('upload_timesheet_page'))

    last_timesheet = (
        Timesheet.query.filter_by(user_id=current_user.id)
        .order_by(Timesheet.upload_date.desc())
        .first()
    )

    return render_template('timsheet.html', last_timesheet=last_timesheet)



# ----------------- Serve Uploaded Timesheets -----------------
@app.route('/uploads/timesheets/<path:filename>')
@login_required
def uploaded_timesheet(filename):
    ts = Timesheet.query.filter(Timesheet.filepath.like(f"%{filename}")).first()
    if not ts or (ts.user_id != current_user.id and not getattr(current_user, 'is_admin', False)):
        flash("Access denied or file not found.", "danger")
        return redirect(url_for('dashboard'))

    folder = os.path.join(app.root_path, 'uploads', 'timesheets')
    return send_from_directory(folder, filename, as_attachment=True)


# -------------------- Admin Dashboard --------------------
@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    # ------------------- Role-based access -------------------
    if current_user.role not in ["Administrator", "Mentor"]:
        flash("Access denied.", "danger")
        if current_user.role == "MICSETA Mentor":
            return redirect(url_for('micseta_dashboard'))
        elif current_user.role == "WIL Co-ordinator":
            return redirect(url_for('wil_coordinator_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    # ------------------- Filters -------------------
    name_filter = request.args.get('name', '').strip()
    month_filter = request.args.get('month', '')
    year_filter = request.args.get('year', '')
    day_filter = request.args.get('day', '')

    now = datetime.now()

    # ------------------- Employees / Students -------------------
    # Admin sees all students
    employees_query = User.query.filter(User.role == "Student").order_by(User.fullname.asc())

    # Mentor sees only their assigned students
    if current_user.role == "Mentor":
        employees_query = employees_query.filter(User.mentor_id == current_user.id)

    employees = employees_query.all()

    # ------------------- Base CheckIn Query -------------------
    query = CheckIn.query.join(User).filter(User.role == "Student")

    # Mentor restriction: only their students
    if current_user.role == "Mentor":
        query = query.filter(User.mentor_id == current_user.id)

    # Apply filters
    if name_filter:
        try:
            query = query.filter(User.id == int(name_filter))
        except ValueError:
            flash("Invalid student selected.", "warning")

    if month_filter:
        try:
            query = query.filter(db.extract('month', CheckIn.date) == int(month_filter))
        except:
            pass

    if year_filter:
        try:
            query = query.filter(db.extract('year', CheckIn.date) == int(year_filter))
        except:
            pass

    if day_filter:
        try:
            day_date = datetime.strptime(day_filter, "%Y-%m-%d").date()
            query = query.filter(CheckIn.date == day_date)
        except ValueError:
            flash("Invalid day filter.", "warning")

    # ------------------- Pagination -------------------
    page = request.args.get('page', 1, type=int)
    pagination = query.order_by(CheckIn.date.desc(), CheckIn.timestamp.desc()).paginate(page=page, per_page=20)
    checkins = pagination.items

    # ------------------- Stats -------------------
    total_checkins = query.count()
    overall_check = CheckIn.query.count()
    highest_checkin_employee = (
        db.session.query(User.fullname, db.func.count(CheckIn.id).label('total'))
        .join(CheckIn)
        .group_by(User.id)
        .order_by(db.desc('total'))
        .first()
    )
    earliest_checkin = db.session.query(CheckIn).order_by(CheckIn.timestamp.asc()).first()

    # ------------------- Chart Data -------------------
    from sqlalchemy import func

    month_data = (
        db.session.query(func.strftime('%m', CheckIn.date).label('month'), func.count(CheckIn.id))
        .join(User)
        .filter(User.role == "Student")
        .group_by('month')
        .order_by('month')
        .all()
    )
    month_labels = [datetime.strptime(m, '%m').strftime('%B') for m, _ in month_data]
    month_counts = [c for _, c in month_data]

    employee_data = (
        db.session.query(User.fullname, func.count(CheckIn.id))
        .join(CheckIn)
        .filter(User.role == "Student")
        .group_by(User.fullname)
        .order_by(User.fullname)
        .all()
    )
    employee_names = [e for e, _ in employee_data]
    employee_counts = [c for _, c in employee_data]

    # Attendance
    all_days = 22
    unique_days = len(set([c.date for c in query.all()]))
    absent_days = max(0, all_days - unique_days)
    attendance_labels = ['Present Days', 'Absent Days']
    attendance_data = [unique_days, absent_days]

    # ------------------- Render Template -------------------
    return render_template(
        'admin_dashboard.html',
        checkins=checkins,
        pagination=pagination,
        total_checkins=total_checkins,
        overall_check=overall_check,
        highest_checkin_employee=highest_checkin_employee,
        earliest_checkin=earliest_checkin,
        employees=employees,
        name_filter=name_filter,
        month_filter=month_filter,
        year_filter=year_filter,
        day_filter=day_filter,
        now=now,
        month_labels=month_labels,
        month_counts=month_counts,
        employee_names=employee_names,
        employee_counts=employee_counts,
        attendance_labels=attendance_labels,
        attendance_data=attendance_data
    )

    
@app.route('/wil_coordinator_dashboard')
@login_required
def wil_coordinator_dashboard():
    if current_user.role != "WIL Co-ordinator":
        flash("You are not authorized to access this page.", "danger")
        # Redirect to their correct dashboard
        if current_user.role in ["Administrator", "Mentor"]:
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == "MICSETA Mentor":
            return redirect(url_for('micseta_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return render_template('wil_coordinator_dashboard.html')




@app.route('/admin/data', methods=['GET'])
@login_required
def admin_dashboard_data():
    # ------------------- Filters -------------------
    name_filter = request.args.get('name', '').strip()
    month_filter = request.args.get('month', '')
    year_filter = request.args.get('year', '')
    day_filter = request.args.get('day', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    # ------------------- Base Query -------------------
    query = CheckIn.query.join(User).filter(User.role == "Student")

    # Restrict Mentor to only assigned students
    if current_user.role == "Mentor":
        query = query.filter(User.mentor_id == current_user.id)

    # ------------------- Apply Filters -------------------
    if name_filter:
        try:
            query = query.filter(User.id == int(name_filter))
        except ValueError:
            return jsonify({"error": "Invalid student selected."})

    if month_filter:
        try:
            query = query.filter(db.extract('month', CheckIn.date) == int(month_filter))
        except:
            pass

    if year_filter:
        try:
            query = query.filter(db.extract('year', CheckIn.date) == int(year_filter))
        except:
            pass

    if day_filter:
        try:
            day_date = datetime.strptime(day_filter, "%Y-%m-%d").date()
            query = query.filter(CheckIn.date == day_date)
        except ValueError:
            return jsonify({"error": "Invalid day filter."})

    # ------------------- Pagination -------------------
    pagination = query.order_by(CheckIn.date.desc(), CheckIn.timestamp.desc()).paginate(page=page, per_page=per_page)
    checkins = pagination.items

    # ------------------- Stats -------------------
    total_checkins = query.count()
    unique_days = len(set([c.date for c in query.all()]))
    absent_count = max(0, 22 - unique_days)

    # Employee statistics
    employee_data = (
        db.session.query(User.fullname, func.count(CheckIn.id))
        .join(CheckIn)
        .filter(User.role == "Student")
        .group_by(User.fullname)
        .order_by(User.fullname)
        .all()
    )

    # Monthly check-ins
    month_data = (
        db.session.query(func.strftime('%m', CheckIn.date).label('month'), func.count(CheckIn.id))
        .join(User)
        .filter(User.role == "Student")
        .group_by('month')
        .order_by('month')
        .all()
    )

    return jsonify({
        "page": page,
        "total_pages": pagination.pages,
        "checkins": [
            {
                "id": c.id,
                "user_id": c.user_id,
                "employee": c.user.fullname,
                "date": c.date.strftime("%Y-%m-%d"),
                "time": c.timestamp.strftime("%H:%M:%S"),
                "comment": c.comment
            } for c in checkins
        ],
        "total_checkins": total_checkins,
        "present_count": total_checkins,
        "absent_count": absent_count,
        "employee_names": [e for e, _ in employee_data],
        "employee_counts": [c for _, c in employee_data],
        "month_labels": [datetime.strptime(m, '%m').strftime('%B') for m, _ in month_data],
        "month_counts": [c for _, c in month_data],
        "most_active_employee": employee_data[0][0] if employee_data else '-',
        "least_active_employee": employee_data[-1][0] if employee_data else '-'
    })

@app.route('/mentor/add_student', methods=['POST'])
@login_required
def add_student():
    if current_user.role != "Mentor":
        return jsonify({"error": "Access denied."}), 403

    data = request.get_json()
    if not data or 'student_id' not in data:
        return jsonify({"error": "Missing student_id"}), 400

    student_id = data['student_id']
    student = User.query.filter_by(id=student_id, role='Student').first()
    
    if not student:
        return jsonify({"error": "Student not found"}), 404

    if student.mentor_id:
        return jsonify({"error": f"Student is already assigned to another mentor."}), 400

    student.mentor_id = current_user.id
    db.session.commit()
    return jsonify({"success": True, "message": f"{student.fullname} assigned to you successfully."})


@app.route('/mentor/remove_student', methods=['POST'])
@login_required
def remove_student():
    if current_user.role != "Mentor":
        return jsonify({"error": "Access denied."}), 403

    data = request.get_json()
    if not data or 'student_id' not in data:
        return jsonify({"error": "Missing student_id"}), 400

    student_id = data['student_id']
    student = User.query.filter_by(id=student_id, role='Student', mentor_id=current_user.id).first()

    if not student:
        return jsonify({"error": "Student not found or not assigned to you."}), 404

    student.mentor_id = None
    db.session.commit()
    return jsonify({"success": True, "message": f"{student.fullname} removed from your list successfully."})
@app.route('/upload_assignment_page', methods=['GET', 'POST'])
@login_required
def upload_assignment_page():
    flash_msg = None

    if request.method == 'POST':
        logbook_field = None
        logbook_type = None

        if 'wb1' in request.files:
            logbook_field = request.files['wb1']
            logbook_type = 'wb1'
        elif 'wbl2' in request.files:
            logbook_field = request.files['wbl2']
            logbook_type = 'wbl2'
        elif 'wbl3' in request.files:
            logbook_field = request.files['wbl3']
            logbook_type = 'wbl3'

        if not logbook_field or logbook_field.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_assignment_page'))

        if not allowed_file(logbook_field.filename):
            flash('Invalid file type. Only PDF, DOCX, XLSX, PNG, JPG allowed.', 'danger')
            return redirect(url_for('upload_assignment_page'))

        # Save file
        filename = secure_filename(logbook_field.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{current_user.id}_{logbook_type}_{timestamp}_{filename}"

        upload_folder = os.path.join(BASE_DIR, 'static', 'uploads', 'assignments')
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, unique_filename)
        logbook_field.save(filepath)

        # Store in DB
        relative_path = os.path.relpath(filepath, BASE_DIR)
        new_assignment = Assignment(
            user_id=current_user.id,
            filename=filename,
            filepath=relative_path
        )

        # Mark the corresponding logbook as submitted
        if logbook_type == 'wb1':
            new_assignment.wb1_submitted = True
            flash_msg = "✅ WB1 submitted successfully!"
        elif logbook_type == 'wbl2':
            new_assignment.wbl2_submitted = True
            flash_msg = "✅ WBL2 submitted successfully!"
        elif logbook_type == 'wbl3':
            new_assignment.wbl3_submitted = True
            flash_msg = "✅ WBL3 submitted successfully!"

        db.session.add(new_assignment)
        db.session.commit()

        # Email mentor if assigned
        if current_user.mentor:
            try:
                msg = Message(
                    subject=f"New {logbook_type.upper()} Uploaded by {current_user.fullname}",
                    recipients=[current_user.mentor.email]
                )
                msg.body = (
                    f"Hello {current_user.mentor.fullname},\n\n"
                    f"{current_user.fullname} has uploaded their {logbook_type.upper()}.\n"
                    "Please check the system for review.\n\n"
                    "Regards,\nMoepi Attendance System"
                )
                mail.send(msg)
            except Exception as e:
                print("❌ Failed to send email to mentor:", e)

        if flash_msg:
            flash(flash_msg, 'success')

        return redirect(url_for('upload_assignment_page'))

    return render_template('projects.html')


UPLOAD_FOLDER = 'static/uploads/assignments'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Helper function to save file
def save_file(file, prefix):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{current_user.id}_{prefix}_{timestamp}_{secure_filename(file.filename)}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return filename


# ✅ WB1 upload
@app.route('/upload/wb1', methods=['POST'])
@login_required
def upload_wb1():
    file = request.files.get('wb1_file')
    if not file or file.filename == '':
        flash("No file selected for WB1", "danger")
        return redirect(url_for('upload_assignment_page'))

    # Check if already submitted
    assignment = Assignment.query.filter_by(user_id=current_user.id).first()
    if assignment and assignment.wb1_submitted:
        flash("WB1 has already been submitted.", "info")
        return redirect(url_for('upload_assignment_page'))

    filename = save_file(file, 'wb1')

    if not assignment:
        assignment = Assignment(user_id=current_user.id)

    assignment.filename = filename
    assignment.upload_date = datetime.now()
    assignment.wb1_submitted = True

    db.session.add(assignment)
    db.session.commit()

    flash("WB1 uploaded successfully ✅", "success")
    return redirect(url_for('upload_assignment_page'))


# ✅ WB2 upload
@app.route('/upload/wb2', methods=['POST'])
@login_required
def upload_wb2():
    file = request.files.get('wb2_file')
    if not file or file.filename == '':
        flash("No file selected for WB2", "danger")
        return redirect(url_for('upload_assignment_page'))

    assignment = Assignment.query.filter_by(user_id=current_user.id).first()
    if assignment and assignment.wbl2_submitted:
        flash("WB2 has already been submitted.", "info")
        return redirect(url_for('upload_assignment_page'))

    filename = save_file(file, 'wb2')

    if not assignment:
        assignment = Assignment(user_id=current_user.id)

    assignment.filename = filename
    assignment.upload_date = datetime.now()
    assignment.wbl2_submitted = True

    db.session.add(assignment)
    db.session.commit()

    flash("WB2 uploaded successfully ✅", "success")
    return redirect(url_for('upload_assignment_page'))


# ✅ WB3 upload
@app.route('/upload/wb3', methods=['POST'])
@login_required
def upload_wb3():
    file = request.files.get('wb3_file')
    if not file or file.filename == '':
        flash("No file selected for WB3", "danger")
        return redirect(url_for('upload_assignment_page'))

    assignment = Assignment.query.filter_by(user_id=current_user.id).first()
    if assignment and assignment.wbl3_submitted:
        flash("WB3 has already been submitted.", "info")
        return redirect(url_for('upload_assignment_page'))

    filename = save_file(file, 'wb3')

    if not assignment:
        assignment = Assignment(user_id=current_user.id)

    assignment.filename = filename
    assignment.upload_date = datetime.now()
    assignment.wbl3_submitted = True

    db.session.add(assignment)
    db.session.commit()

    flash("WB3 uploaded successfully ✅", "success")
    return redirect(url_for('upload_assignment_page'))


@app.route('/mentor/assignments')
@login_required
def mentor_assignments():
    if current_user.role != "Mentor":
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    # Fetch students assigned to this mentor
    students = User.query.filter_by(mentor_id=current_user.id, role='Student').all()
    student_ids = [s.id for s in students]

    # Fetch assignments for those students
    assignments = Assignment.query.filter(Assignment.user_id.in_(student_ids)).order_by(Assignment.upload_date.desc()).all()
    return render_template('mentor_assignments.html', assignments=assignments, students=students)

@app.route('/mentor/download/<int:assignment_id>')
@login_required
def mentor_download(assignment_id):
    if current_user.role != "Mentor":
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    assignment = Assignment.query.get_or_404(assignment_id)

    # Ensure mentor is allowed to access this student's file
    if not assignment.user.mentor_id == current_user.id:
        flash("You do not have permission to download this file.", "danger")
        return redirect(url_for('mentor_assignments'))

    return send_from_directory(
        directory=os.path.join(BASE_DIR, os.path.dirname(assignment.filepath)),
        path=os.path.basename(assignment.filepath),
        as_attachment=True
    )

app.route('/mentor/download/<int:assignment_id>')
def mentor_download(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    logbook_dir = os.path.join(app.root_path, 'uploads/logbooks')  # adjust path
    file_path = os.path.join(logbook_dir, assignment.filename)
    if os.path.exists(file_path):
        return send_from_directory(logbook_dir, assignment.filename, as_attachment=True)
    else:
        abort(404)
        
@app.route('/micseta-dashboard', methods=['GET'])
@login_required
def micseta_dashboard():
    if current_user.role not in ["Administrator", "MICSETA Mentor"]:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    # ------------------- Filters -------------------
    name_filter = request.args.get('name', '').strip()
    month_filter = request.args.get('month', '')
    year_filter = request.args.get('year', '')
    day_filter = request.args.get('day', '')
    now = datetime.now()

    # ------------------- MICSETA Students -------------------
    employees_query = User.query.filter(
        User.role == "Student",
        User.organization.ilike("%MICSETA%")  # Only MICSETA students
    ).order_by(User.fullname.asc())

    # Mentor restriction: only their assigned students
    if current_user.role == "MICSETA Mentor":
        employees_query = employees_query.filter(User.mentor_id == current_user.id)

    employees = employees_query.all()

    # ------------------- Base CheckIn Query -------------------
    query = CheckIn.query.join(User).filter(User.role == "Student", User.organization.ilike("%MICSETA%"))

    # Mentor restriction
    if current_user.role == "MICSETA Mentor":
        query = query.filter(User.mentor_id == current_user.id)

    # ------------------- Apply Filters -------------------
    if name_filter:
        try:
            query = query.filter(User.id == int(name_filter))
        except ValueError:
            flash("Invalid student selected.", "warning")

    if month_filter:
        try:
            query = query.filter(db.extract('month', CheckIn.date) == int(month_filter))
        except:
            pass

    if year_filter:
        try:
            query = query.filter(db.extract('year', CheckIn.date) == int(year_filter))
        except:
            pass

    if day_filter:
        try:
            day_date = datetime.strptime(day_filter, "%Y-%m-%d").date()
            query = query.filter(CheckIn.date == day_date)
        except ValueError:
            flash("Invalid day filter.", "warning")

    # ------------------- Pagination -------------------
    page = request.args.get('page', 1, type=int)
    pagination = query.order_by(CheckIn.date.desc(), CheckIn.timestamp.desc()).paginate(page=page, per_page=20)
    checkins = pagination.items

    # ------------------- Stats -------------------
    total_checkins = query.count()
    highest_checkin_employee = (
        db.session.query(User.fullname, db.func.count(CheckIn.id).label('total'))
        .join(CheckIn)
        .filter(User.organization.ilike("%MICSETA%"))
        .group_by(User.id)
        .order_by(db.desc('total'))
        .first()
    )
    earliest_checkin = db.session.query(CheckIn).filter(CheckIn.user.has(organization=func.like("%MICSETA%"))).order_by(CheckIn.timestamp.asc()).first()

    # ------------------- Chart Data -------------------
    month_data = (
        db.session.query(func.strftime('%m', CheckIn.date).label('month'), func.count(CheckIn.id))
        .join(User)
        .filter(User.organization.ilike("%MICSETA%"))
        .group_by('month')
        .order_by('month')
        .all()
    )
    month_labels = [datetime.strptime(m, '%m').strftime('%B') for m, _ in month_data]
    month_counts = [c for _, c in month_data]

    employee_data = (
        db.session.query(User.fullname, func.count(CheckIn.id))
        .join(CheckIn)
        .filter(User.organization.ilike("%MICSETA%"))
        .group_by(User.fullname)
        .order_by(User.fullname)
        .all()
    )
    employee_names = [e for e, _ in employee_data]
    employee_counts = [c for _, c in employee_data]

    # Attendance
    all_days = 22
    unique_days = len(set([c.date for c in query.all()]))
    absent_days = max(0, all_days - unique_days)
    attendance_labels = ['Present Days', 'Absent Days']
    attendance_data = [unique_days, absent_days]

    return render_template(
        'micseta_mentor_dashboard.html',
        checkins=checkins,
        pagination=pagination,
        total_checkins=total_checkins,
        highest_checkin_employee=highest_checkin_employee[0] if highest_checkin_employee else '-',
        earliest_checkin=earliest_checkin,
        employees=employees,
        name_filter=name_filter,
        month_filter=month_filter,
        year_filter=year_filter,
        day_filter=day_filter,
        now=now,
        month_labels=month_labels,
        month_counts=month_counts,
        employee_names=employee_names,
        employee_counts=employee_counts,
        attendance_labels=attendance_labels,
        attendance_data=attendance_data
    )


# -------------------- Run --------------------
if __name__ == '__main__':
    app.run(debug=True)
