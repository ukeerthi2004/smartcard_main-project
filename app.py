from flask import Flask, render_template, request, redirect, session, flash, jsonify, url_for
from flask_mail import Mail, Message
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
import mysql.connector
from mysql.connector import Error as MySQLError
import bcrypt
import random
import os
import re
from werkzeug.utils import secure_filename
import config


app = Flask(__name__)
app.secret_key = config.SECRET_KEY
assert app.secret_key is not None, "SECRET_KEY must be set in config"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_USERNAME
app.config['MAIL_USE_SSL'] = False

# ---------------- IMAGE UPLOAD CONFIGURATION ----------------
BASE_UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_UPLOAD_FOLDER, 'product_images')
app.config['USER_UPLOAD_FOLDER'] = os.path.join(BASE_UPLOAD_FOLDER, 'user_profiles')
app.config['ADMIN_UPLOAD_FOLDER'] = os.path.join(BASE_UPLOAD_FOLDER, 'admin_profiles')

mail = Mail(app)
password_reset_serializer = URLSafeTimedSerializer(str(app.secret_key))  # type: ignore
PASSWORD_RESET_MAX_AGE = 3600


def create_folder(path: str):
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except OSError as exc:
        print(f"[ERROR] Cannot create upload folder {path}: {exc}")
        return False


def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def validate_password(password: str) -> bool:
    return len(password or "") >= 6


for folder in [app.config['UPLOAD_FOLDER'], app.config['USER_UPLOAD_FOLDER'], app.config['ADMIN_UPLOAD_FOLDER']]:
    create_folder(folder)


# ---------------- DB CONNECTION FUNCTION --------------

def get_db_connection():
    try:
        return mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME
        )
    except MySQLError as ex:
        print(f"[DB ERROR] Failed to connect: {ex}")
        raise





def init_user_tables():
    """Create users and cart tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            profile_image VARCHAR(255) DEFAULT NULL
        )
    """)
    # Add profile_image column if table already exists without it
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_image VARCHAR(255) DEFAULT NULL")
    except Exception:
        pass  # Column already exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cart (
            cart_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            product_id INT NOT NULL,
            quantity INT DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (product_id) REFERENCES products(product_id)
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


init_user_tables()


def create_password_reset_token(admin):
    return password_reset_serializer.dumps(
        {"admin_id": admin["admin_id"], "email": admin["email"]},
        salt="admin-password-reset"
    )

def verify_password_reset_token(token):
    return password_reset_serializer.loads(
        token,
        salt="admin-password-reset",
        max_age=PASSWORD_RESET_MAX_AGE
    )

# ---------------------------------------------------------
# ROUTE 0: ROOT -> REDIRECT TO LOGIN
# ---------------------------------------------------------
@app.route('/')
def index():
    return redirect('/admin-login')

# ---------------------------------------------------------
# ABOUT PAGE
# ---------------------------------------------------------
@app.route('/about')
def about_page():
    base_template = "admin/base.html"
    if 'user_id' in session or request.referrer and 'user' in request.referrer:
        base_template = "user/user_base.html"
    return render_template("admin/about.html", base_template=base_template)

# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()

    if not name or not email:
        flash("Name and email are required to sign up.", "danger")
        return redirect('/admin-signup')

    if not validate_email(email):
        flash("Please enter a valid email address.", "danger")
        return redirect('/admin-signup')

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
        existing_admin = cursor.fetchone()
    except Exception as ex:
        print(f"[DB ERROR] Admin signup check failed: {ex}")
        flash("Unable to verify email right now. Please try again later.", "danger")
        return redirect('/admin-signup')
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    session['signup_name'] = name
    session['signup_email'] = email

    otp = str(random.randint(100000, 999999))
    session['otp'] = otp

    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"

    try:
        mail.send(message)
        flash("OTP sent to your email!", "success")
    except Exception as ex:
        print(f"[MAIL ERROR] Admin OTP mail failed: {ex}")
        flash("Unable to send OTP email. Check your Gmail App Password and try again.", "danger")
        return redirect('/admin-signup')

    return redirect('/verify-otp')

# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")


# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    user_otp = request.form.get('otp', '').strip()
    password = request.form.get('password', '')
    signup_name = session.get('signup_name')
    signup_email = session.get('signup_email')

    if not signup_name or not signup_email or not user_otp or not password:
        flash("Please complete all fields and request OTP again.", "danger")
        return redirect('/admin-signup')

    if session.get('otp') != user_otp:
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    if not validate_password(password):
        flash("Password must be at least 6 characters.", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO admin (name, email, password) VALUES (%s, %s, %s)",
            (signup_name, signup_email, hashed_password)
        )
        conn.commit()
    except Exception as ex:
        print(f"[DB ERROR] Saving admin after OTP failed: {ex}")
        flash("Unable to create admin account right now. Please try again.", "danger")
        return redirect('/admin-signup')
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass

    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully! Please login.", "success")
    return redirect('/admin-login')

# ---------------------------------------------------------
# ROUTE 4: ADMIN LOGIN
# ---------------------------------------------------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    if not email or not password:
        flash("Both email and password are required.", "danger")
        return redirect('/admin-login')

    if not validate_email(email):
        flash("Enter a valid email address.", "danger")
        return redirect('/admin-login')

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
        admin = cursor.fetchone()
    except Exception as ex:
        print(f"[DB ERROR] Admin login failed: {ex}")
        flash("Unable to log in right now. Please try again later.", "danger")
        return redirect('/admin-login')
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    hashed_password: str = admin['password']  # type: ignore
    if not bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']  # type: ignore
    session['admin_name'] = admin['name']  # type: ignore
    session['admin_email'] = admin['email']  # type: ignore
    session.modified = True

    flash(f"Welcome, {admin['name']}", "success")  # type: ignore
    return redirect('/admin-dashboard')

# ---------------------------------------------------------
# ROUTE 4A: REQUEST ADMIN PASSWORD RESET LINK
# ---------------------------------------------------------
@app.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'GET':
        return render_template("admin/forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id, name, email FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if admin:
        token = create_password_reset_token(admin)
        reset_link = url_for('admin_reset_password', token=token, _external=True)

        admin_email: str = admin['email']  # type: ignore
        admin_name: str = admin['name']  # type: ignore
        message = Message(
            subject="SmartCart Admin Password Reset",
            sender=config.MAIL_USERNAME,
            recipients=[admin_email]
        )
        message.body = (
            f"Hello {admin_name},\n\n"
            "Click the link below to reset your SmartCart admin password:\n"
            f"{reset_link}\n\n"
            "This link will expire in 1 hour. If you did not request this, please ignore this email."
        )

        try:
            mail.send(message)
            flash("Password reset link sent to your email.", "success")
        except Exception:
            flash("Unable to send reset email right now. Please try again later.", "danger")
            return redirect('/admin/forgot-password')
    else:
        flash("Email not found. Please check your email or register first.", "danger")
        return redirect('/admin/forgot-password')

    return redirect('/admin-login')

# ---------------------------------------------------------
# ROUTE 4B: RESET ADMIN PASSWORD FROM EMAIL LINK
# ---------------------------------------------------------
@app.route('/admin/reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):

    try:
        reset_data = verify_password_reset_token(token)
    except SignatureExpired:
        flash("Reset link expired. Please request a new password reset link.", "danger")
        return redirect('/admin/forgot-password')
    except BadSignature:
        flash("Invalid reset link. Please request a new password reset link.", "danger")
        return redirect('/admin/forgot-password')

    if request.method == 'GET':
        return render_template("admin/reset_password.html", token=token)

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match. Please try again.", "danger")
        return redirect(f'/admin/reset-password/{token}')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE admin SET password=%s WHERE admin_id=%s AND email=%s",
        (hashed_password, reset_data['admin_id'], reset_data['email'])
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Password changed successfully. Please login with your new password.", "success")
    return redirect('/admin-login')

# ---------------------------------------------------------
# ROUTE 5: ADMIN DASHBOARD (PROTECTED)
# ---------------------------------------------------------
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login to access the dashboard!", "danger")
        return redirect('/admin-login')

    return render_template("admin/dashboard.html", admin_name=session['admin_name'])


@app.route('/admin/admin_dashboard')
def old_admin_dashboard():
    return redirect('/admin-dashboard')

# ---------------------------------------------------------
# ROUTE 5A: ADMIN CONTACT FORM
# ---------------------------------------------------------
@app.route('/contact', methods=['GET', 'POST'])
def contact_page():
    base_template = "admin/base.html"
    if 'user_id' in session or request.referrer and 'user' in request.referrer:
        base_template = "user/user_base.html"

    if request.method == 'GET':
        return render_template("admin/contact.html", base_template=base_template)

    name = request.form['name']
    email = request.form['email']
    phone = request.form.get('phone', '')
    subject = request.form['subject']
    message_text = request.form['message']

    message = Message(
        subject=f"SmartCart Contact: {subject}",
        sender=config.MAIL_USERNAME,
        recipients=[config.MAIL_USERNAME]
    )
    message.body = (
        "New contact message from SmartCart:\n\n"
        f"Name: {name}\n"
        f"Email: {email}\n"
        f"Phone: {phone}\n"
        f"Subject: {subject}\n\n"
        f"Message:\n{message_text}"
    )

    try:
        mail.send(message)
        flash("Your message was sent successfully.", "success")
    except Exception:
        flash("Unable to send your message right now. Please try again later.", "danger")

    return redirect('/contact')

# ---------------------------------------------------------
# ROUTE 6: ADMIN LOGOUT
# ---------------------------------------------------------
@app.route('/admin-logout')
def admin_logout():

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')

# ---------------------------------------------------------
# ROUTE 7: SHOW ADD PRODUCT PAGE (PROTECTED)
# ---------------------------------------------------------
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")

# ---------------------------------------------------------
# ROUTE 8: ADD PRODUCT INTO DATABASE
# ---------------------------------------------------------
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    name        = request.form['name']
    description = request.form['description']
    category    = request.form['category']
    price       = request.form['price']
    image_file  = request.files['image']

    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)  # type: ignore
    if not filename:
        flash("Invalid filename!", "danger")
        return redirect('/admin/add-item')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, description, category, price, image) VALUES (%s, %s, %s, %s, %s)",
        (name, description, category, price, filename)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')

# ---------------------------------------------------------
# ROUTE 9: DISPLAY ALL PRODUCTS
# ---------------------------------------------------------
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    page = request.args.get('page', 1, type=int)
    per_page = 12

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch category list for dropdown
    cursor.execute("SELECT DISTINCT category FROM products ORDER BY category")
    categories = cursor.fetchall()

    # Build dynamic query based on filters
    base_where = " WHERE 1=1"
    params = []

    if search:
        base_where += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        base_where += " AND category = %s"
        params.append(category_filter)

    # Get total count for pagination
    cursor.execute("SELECT COUNT(*) AS total FROM products" + base_where, params[:])
    result = cursor.fetchone()
    total: int = int(result['total']) if result else 0  # type: ignore
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    # Fetch paginated results
    query = "SELECT * FROM products" + base_where + " ORDER BY product_id ASC LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])
    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories,
        page=page,
        total_pages=total_pages,
        total=total,
        search=search,
        category_filter=category_filter
    )

# ---------------------------------------------------------
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# ---------------------------------------------------------
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)

# ---------------------------------------------------------
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# ---------------------------------------------------------
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)

# ---------------------------------------------------------
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# ---------------------------------------------------------
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    name        = request.form['name']
    description = request.form['description']
    category    = request.form['category']
    price       = request.form['price']
    new_image   = request.files['image']

    # Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    # Close connection before redirecting
    if not product:
        cursor.close()
        conn.close()
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name: str = product['image']  # type: ignore

    # If new image uploaded, replace old image
    if new_image and new_image.filename != "":

        new_filename = secure_filename(new_image.filename)  # type: ignore
        if not new_filename:
            flash("Invalid filename!", "danger")
            cursor.close()
            conn.close()
            return redirect('/admin/update-item/' + str(item_id))

        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        new_image.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))

        # Delete old image file from folder
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image, keep existing image
        final_image_name = old_image_name

    # Update product in database
    final_image: str = final_image_name
    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s
    """, (name, description, category, price, final_image, item_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')

# ---------------------------------------------------------
# ROUTE 13: DELETE PRODUCT
# ---------------------------------------------------------
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch image name before deleting
    cursor.execute("SELECT image FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    if product:
        # Delete image file from folder
        product_image: str = product['image']  # type: ignore
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product_image)
        if os.path.exists(image_path):
            os.remove(image_path)

        # Delete product from database
        cursor.execute("DELETE FROM products WHERE product_id = %s", (item_id,))
        conn.commit()
        flash("Product deleted successfully!", "success")
    else:
        flash("Product not found!", "danger")

    cursor.close()
    conn.close()

    return redirect('/admin/item-list')

ADMIN_UPLOAD_FOLDER = app.config['ADMIN_UPLOAD_FOLDER']

# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()
    if not admin:
        cursor.close()
        conn.close()
        flash("Admin not found!", "danger")
        return redirect('/admin/profile')

    old_image_name = admin['profile_image']  # type: ignore

    # Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        admin_password: str = admin['password']  # type: ignore
        hashed_password = admin_password  # keep old password

    # Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)  # type: ignore
        if not new_filename:
            flash("Invalid filename!", "danger")
            cursor.close()
            conn.close()
            return redirect('/admin/profile')

        # Save new image
        os.makedirs(app.config['ADMIN_UPLOAD_FOLDER'], exist_ok=True)
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], str(old_image_name))  # type: ignore
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # Update database
    cursor.execute("""
        UPDATE admin
        SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_password, str(final_image_name) if final_image_name else None, admin_id))  # type: ignore

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')

# ---------------------------------------------------------
# USER ROUTE 1: USER REGISTRATION (SEND OTP)
# ---------------------------------------------------------
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    if not name or not email or not password:
        flash("Name, email, and password are required.", "danger")
        return redirect('/user-register')

    if not validate_email(email):
        flash("Please enter a valid email address.", "danger")
        return redirect('/user-register')

    if not validate_password(password):
        flash("Password must be at least 6 characters.", "danger")
        return redirect('/user-register')

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        existing = cursor.fetchone()
    except Exception as ex:
        print(f"[DB ERROR] User signup check failed: {ex}")
        flash("Unable to verify email right now. Please try again later.", "danger")
        return redirect('/user-register')
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass

    if existing:
        flash("This email is already registered. Please login.", "danger")
        return redirect('/user-register')

    session['user_signup_name'] = name
    session['user_signup_email'] = email
    session['user_signup_password'] = password

    otp = str(random.randint(100000, 999999))
    session['user_otp'] = otp

    message = Message(
        subject="SmartCart User OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Registration is: {otp}"

    try:
        mail.send(message)
        flash("OTP sent to your email!", "success")
    except Exception as ex:
        print(f"[MAIL ERROR] User OTP mail failed: {ex}")
        flash("Unable to send OTP email. Check your Gmail App Password and try again.", "danger")
        return redirect('/user-register')

    return redirect('/user-verify-otp')

# ---------------------------------------------------------
# USER ROUTE 2: VERIFY OTP & COMPLETE REGISTRATION
# ---------------------------------------------------------
@app.route('/user-verify-otp', methods=['GET', 'POST'])
def user_verify_otp():
    if request.method == 'GET':
        return render_template("user/user_verify_otp.html")

    user_otp = request.form.get('otp', '').strip()
    password = request.form.get('password', '')
    signup_name = session.get('user_signup_name')
    signup_email = session.get('user_signup_email')

    if not signup_name or not signup_email or not user_otp or not password:
        flash("Please fill all fields and request a new OTP if needed.", "danger")
        return redirect('/user-register')

    if session.get('user_otp') != user_otp:
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/user-verify-otp')

    if not validate_password(password):
        flash("Password must be at least 6 characters.", "danger")
        return redirect('/user-verify-otp')

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (signup_name, signup_email, hashed)
        )
        conn.commit()
    except Exception as ex:
        print(f"[DB ERROR] Saving user after OTP failed: {ex}")
        flash("Unable to complete registration right now. Please try again.", "danger")
        return redirect('/user-register')
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass

    session.pop('user_otp', None)
    session.pop('user_signup_name', None)
    session.pop('user_signup_email', None)
    session.pop('user_signup_password', None)

    flash("Registered successfully! Please login.", "success")
    return redirect('/user-login')

    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
        (session['user_signup_name'], session['user_signup_email'], hashed)
    )
    conn.commit()
    cursor.close()
    conn.close()

    session.pop('user_otp', None)
    session.pop('user_signup_name', None)
    session.pop('user_signup_email', None)
    session.pop('user_signup_password', None)

    flash("Registered successfully! Please login.", "success")
    return redirect('/user-login')

# ---------------------------------------------------------
# USER ROUTE 3: USER LOGIN
# ---------------------------------------------------------
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    if not email or not password:
        flash("Email and password are required.", "danger")
        return redirect('/user-login')

    if not validate_email(email):
        flash("Enter a valid email address.", "danger")
        return redirect('/user-login')

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
    except Exception as ex:
        print(f"[DB ERROR] User login failed: {ex}")
        flash("Unable to log in right now. Please try again later.", "danger")
        return redirect('/user-login')
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass

    if user is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/user-login')

    user_password: str = user['password']  # type: ignore
    if not bcrypt.checkpw(password.encode('utf-8'), user_password.encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    session['user_id'] = user['user_id']  # type: ignore
    session['user_name'] = user['name']  # type: ignore
    session['user_email'] = user['email']  # type: ignore
    session.modified = True

    flash(f"Welcome, {user['name']}!", "success")  # type: ignore
    return redirect('/user-home')

# ---------------------------------------------------------
# USER ROUTE 4: USER HOME / DASHBOARD
# ---------------------------------------------------------
@app.route('/user-home')
def user_home():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')
    return render_template("user/user_home.html", user_name=session['user_name'])


@app.route('/user-dashboard')
def user_dashboard_redirect():
    return redirect('/user-home')

# ---------------------------------------------------------
# USER ROUTE 4A: EXPLORE PRODUCTS
# ---------------------------------------------------------
@app.route('/user/products')
def user_products():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )


# ---------------------------------------------------------
# USER ROUTE 5: PRODUCT DETAILS
# ---------------------------------------------------------
@app.route('/user/product/<int:product_id>')
def user_product_detail(product_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user-home')

    return render_template("user/product_details.html", product=product)



# ---------------------------------------------------------
# USER ROUTE 9: USER PROFILE
# ---------------------------------------------------------
@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return render_template("user/user_profile.html", user=user)

    # POST - update profile
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files.get('profile_image')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        flash("User not found!", "danger")
        return redirect('/user/profile')

    if new_password:
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        user_password: str = user['password']  # type: ignore
        hashed = user_password

    old_image_name = user['profile_image'] if 'profile_image' in user else None  # type: ignore

    # Handle profile image upload
    if new_image and new_image.filename != '':
        new_filename = secure_filename(new_image.filename)  # type: ignore
        if not new_filename:
            flash("Invalid filename!", "danger")
            cursor.close()
            conn.close()
            return redirect('/user/profile')
        
        os.makedirs(app.config['USER_UPLOAD_FOLDER'], exist_ok=True)
        new_image.save(os.path.join(app.config['USER_UPLOAD_FOLDER'], new_filename))

        # Delete old image
        if old_image_name:
            old_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], str(old_image_name))  # type: ignore
            if os.path.exists(old_path):
                os.remove(old_path)

        final_image = new_filename
    else:
        final_image = old_image_name

    cursor.execute(
        "UPDATE users SET name=%s, email=%s, password=%s, profile_image=%s WHERE user_id=%s",
        (name, email, hashed, str(final_image) if final_image else None, user_id)  # type: ignore
    )
    conn.commit()
    cursor.close()
    conn.close()

    session['user_name'] = name
    session['user_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/user/profile')

# ---------------------------------------------------------
# USER ROUTE 10: FORGOT PASSWORD (SEND RESET LINK)
# ---------------------------------------------------------
@app.route('/user/forgot-password', methods=['GET', 'POST'])
def user_forgot_password():
    if request.method == 'GET':
        return render_template("user/user_forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id, name, email FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        user_id_val: int = user["user_id"]  # type: ignore
        user_email: str = user["email"]  # type: ignore
        user_name: str = user['name']  # type: ignore
        
        token = password_reset_serializer.dumps(
            {"user_id": user_id_val, "email": user_email},
            salt="user-password-reset"
        )
        reset_link = url_for('user_reset_password', token=token, _external=True)

        message = Message(
            subject="SmartCart Password Reset",
            sender=config.MAIL_USERNAME,
            recipients=[user_email]
        )
        message.body = (
            f"Hello {user_name},\n\n"
            "Click the link below to reset your SmartCart password:\n"
            f"{reset_link}\n\n"
            "This link will expire in 1 hour. If you did not request this, please ignore this email."
        )

        try:
            mail.send(message)
            flash("Password reset link sent to your email.", "success")
        except Exception:
            flash("Unable to send reset email right now. Please try again later.", "danger")
            return redirect('/user/forgot-password')
    else:
        flash("Email not found. Please check your email or register first.", "danger")
        return redirect('/user/forgot-password')

    return redirect('/user-login')

# ---------------------------------------------------------
# USER ROUTE 11: RESET PASSWORD FROM EMAIL LINK
# ---------------------------------------------------------
@app.route('/user/reset-password/<token>', methods=['GET', 'POST'])
def user_reset_password(token):
    try:
        reset_data = password_reset_serializer.loads(
            token, salt="user-password-reset", max_age=PASSWORD_RESET_MAX_AGE
        )
    except SignatureExpired:
        flash("Reset link expired. Please request a new one.", "danger")
        return redirect('/user/forgot-password')
    except BadSignature:
        flash("Invalid reset link. Please request a new one.", "danger")
        return redirect('/user/forgot-password')

    if request.method == 'GET':
        return render_template("user/user_reset_password.html", token=token)

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match. Please try again.", "danger")
        return redirect(f'/user/reset-password/{token}')

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password=%s WHERE user_id=%s AND email=%s",
        (hashed, reset_data['user_id'], reset_data['email'])
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Password changed successfully. Please login with your new password.", "success")
    return redirect('/user-login')


# =================================================================
# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],  # type: ignore
            'price': float(product['price']),  # type: ignore
            'image': product['image'],  # type: ignore
            'quantity': 1
        }

    session['cart'] = cart
    session.modified = True

    flash("Item added to cart!", "success")
    return redirect(request.referrer)   # ⭐ Return to same page


# =================================================================
# ADD ITEM TO CART AJAX
# =================================================================
@app.route('/user/add-to-cart-ajax/<int:product_id>')
def add_to_cart_ajax(product_id):

    if 'user_id' not in session:
        return {"error": "not_logged_in"}, 401

    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Fetch product from DB
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        return {"error": "Product not found"}, 404

    pid = str(product_id)

    # Increase quantity if exists
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],  # type: ignore
            'price': float(product['price']),  # type: ignore
            'image': product['image'],  # type: ignore
            'quantity': 1
        }

    session['cart'] = cart
    session.modified = True

    # Return JSON response
    return {
        "message": "Item added to cart!",
        "cart_count": len(cart)
    }


# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)

# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    session.modified = True
    return redirect('/user/cart')

# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    session.modified = True
    return redirect('/user/cart')

# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart
    session.modified = True

    flash("Item removed!", "success")
    return redirect('/user/cart')


# ---------------------------------------------------------
# USER ROUTE 12: USER LOGOUT
# ---------------------------------------------------------
@app.route('/user-logout')
def user_logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/user-login')

# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)