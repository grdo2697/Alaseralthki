from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json 
from functools import wraps

# تهيئة التطبيق وقاعدة البيانات
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex() 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# إضافة فلتر Jinja2 مخصص لتحويل JSON string إلى Python object
@app.template_filter('from_json')
def from_json_filter(value):
    if value is None:
        return [] # Return an empty list if value is None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return [] # Return empty list on decode error


# تعريف موديل المستخدم (User Model)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='viewer', nullable=False) 
    permissions = db.Column(db.Text, nullable=True) 

    def __repr__(self):
        return f'<User {self.username}>'

# قائمة شاملة لجميع الصلاحيات الممكنة (أسماء دوال الـ routes في Flask)
ALL_POSSIBLE_PERMISSIONS = [
    "dashboard", 
    "show_main_index", 
    "admin_panel", 
    "register", 
    "delete_user",
    "edit_user_permissions", 
    "show_bikes", 
    "show_compliance", 
    "show_employment_requests", 
    "show_penalties", 
    "show_ratings", 
    "show_manage_users", 
    "generate_insight",
]

# دالة مساعدة (Decorator) للتحقق من صلاحيات المستخدم
def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('الرجاء تسجيل الدخول أولاً.', 'info')
                return redirect(url_for('login'))
            
            user = User.query.get(session['user_id'])
            if not user:
                flash('المستخدم غير موجود أو تم حذفه. الرجاء تسجيل الدخول مرة أخرى.', 'danger')
                session.pop('user_id', None) 
                return redirect(url_for('login'))
            
            user_permissions_list = []
            if user.permissions:
                try:
                    user_permissions_list = json.loads(user.permissions)
                except json.JSONDecodeError:
                    print(f"Warning: User {user.username} has malformed permissions JSON: {user.permissions}")
                    user_permissions_list = []

            if permission_name not in user_permissions_list:
                flash('ليس لديك الصلاحية للوصول إلى هذه الصفحة.', 'danger')
                return redirect(url_for('dashboard')) 

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# إنشاء جداول قاعدة البيانات وإضافة مستخدم admin افتراضي
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_password = generate_password_hash('admin_password', method='pbkdf2:sha256')
        admin_permissions_json = json.dumps(ALL_POSSIBLE_PERMISSIONS)
        admin_user = User(username='admin', password_hash=hashed_password, role='admin', permissions=admin_permissions_json)
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created with all permissions.")


# المسار الرئيسي (صفحة البداية)
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return redirect(url_for('show_main_index')) 
    return redirect(url_for('login'))

# صفحة تسجيل الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            user_permissions_list = json.loads(user.permissions) if user.permissions else []
            if not user_permissions_list: 
                flash('ليس لديك صلاحية للدخول، الرجاء التواصل مع المسؤول.', 'danger')
                return render_template('login.html')

            session['user_id'] = user.id
            flash('تم تسجيل الدخول بنجاح!', 'success')
            return redirect(url_for('dashboard')) 
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'danger')
            return render_template('login.html', error="اسم المستخدم أو كلمة المرور غير صحيحة.")
    return render_template('login.html')

# صفحة تسجيل مستخدم جديد
@app.route('/register', methods=['GET', 'POST'])
@permission_required('register') 
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'viewer') 
        selected_permissions = request.form.getlist('permissions') 

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('اسم المستخدم هذا موجود بالفعل. الرجاء اختيار اسم آخر.', 'danger')
            return render_template('register.html', 
                                   all_permissions=ALL_POSSIBLE_PERMISSIONS, 
                                   selected_permissions=selected_permissions,
                                   current_user_role=User.query.get(session['user_id']).role if 'user_id' in session else 'viewer',
                                   roles=["admin", "editor", "hr", "viewer"])
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        permissions_json = json.dumps(selected_permissions)

        new_user = User(username=username, password_hash=hashed_password, role=role, permissions=permissions_json)
        db.session.add(new_user)
        db.session.commit()
        flash('تم إنشاء المستخدم بنجاح!', 'success')
        return redirect(url_for('admin_panel')) 
    
    current_user_role = User.query.get(session['user_id']).role if 'user_id' in session else 'viewer'
    return render_template('register.html', 
                           all_permissions=ALL_POSSIBLE_PERMISSIONS, 
                           selected_permissions=[], 
                           current_user_role=current_user_role,
                           roles=["admin", "editor", "hr", "viewer"])

# لوحة التحكم/الصفحة الرئيسية للمستخدمين المسجلين
@app.route('/dashboard')
@permission_required('dashboard') 
def dashboard():
    user = User.query.get(session['user_id'])
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('dashboard.html', 
                           username=user.username, 
                           role=user.role, 
                           user_permissions=user_permissions)

# لوحة إدارة المسؤولين
@app.route('/admin_panel')
@permission_required('admin_panel') 
def admin_panel():
    users = User.query.all() 
    current_user_role = User.query.get(session['user_id']).role if 'user_id' in session else 'viewer'
    return render_template('admin_panel.html', users=users, current_user_role=current_user_role, all_permissions=ALL_POSSIBLE_PERMISSIONS)

# مسار تعديل صلاحيات المستخدم
@app.route('/edit_user_permissions/<int:user_id>', methods=['POST'])
@permission_required('edit_user_permissions') 
def edit_user_permissions(user_id):
    user_to_edit = User.query.get(user_id)
    if not user_to_edit:
        return jsonify({'success': False, 'message': 'المستخدم غير موجود.'}), 404
    
    if user_to_edit.username == 'admin':
        return jsonify({'success': False, 'message': 'لا يمكن تعديل صلاحيات حساب المدير الرئيسي لأسباب أمنية.'}), 403

    selected_permissions = request.json.get('permissions', []) 

    try:
        user_to_edit.permissions = json.dumps(selected_permissions)
        db.session.commit()
        flash('تم تعديل صلاحيات المستخدم بنجاح!', 'success')
        return jsonify({'success': True, 'message': 'تم تعديل صلاحيات المستخدم بنجاح.'})
    except Exception as e:
        db.session.rollback()
        print(f"Error editing user permissions: {e}")
        return jsonify({'success': False, 'message': 'فشل تعديل صلاحيات المستخدم.'}), 500


# مسار حذف المستخدم
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@permission_required('delete_user') 
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({'success': False, 'message': 'المستخدم غير موجود.'}), 404
    
    if user_to_delete.username == 'admin':
        return jsonify({'success': False, 'message': 'لا يمكن حذف حساب المدير الرئيسي لأسباب أمنية.'}), 403

    try:
        db.session.delete(user_to_delete)
        db.session.commit()

        if 'user_id' in session and session['user_id'] == user_id:
            session.pop('user_id', None)
            flash('تم حذف حسابك وتم تسجيل الخروج.', 'success')
            return jsonify({'success': True, 'redirect': url_for('login')})
            
        flash('تم حذف المستخدم بنجاح!', 'success')
        return jsonify({'success': True, 'message': 'تم حذف المستخدم بنجاح.'})

    except Exception as e:
        db.session.rollback() 
        print(f"Error deleting user: {e}")
        return jsonify({'success': False, 'message': 'فشل حذف المستخدم.'}), 500


# تسجيل الخروج
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('تم تسجيل الخروج.', 'info')
    return redirect(url_for('login'))

# --- مسارات لصفحاتك الأصلية (محمية بتسجيل الدخول والصلاحيات) ---

@app.route('/index_main') 
@permission_required('show_main_index') 
def show_main_index():
    user = User.query.get(session['user_id'])
    user_role = user.role if user else 'viewer'
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('index.html', user_role=user_role, user_permissions=user_permissions)

@app.route('/bikes')
@permission_required('show_bikes')
def show_bikes():
    user = User.query.get(session['user_id'])
    user_role = user.role if user else 'viewer'
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('bikes.html', user_role=user_role, user_permissions=user_permissions)

@app.route('/compliance')
@permission_required('show_compliance')
def show_compliance():
    user = User.query.get(session['user_id'])
    user_role = user.role if user else 'viewer'
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('compliance.html', user_role=user_role, user_permissions=user_permissions)

@app.route('/employment-requests')
@permission_required('show_employment_requests')
def show_employment_requests():
    user = User.query.get(session['user_id'])
    user_role = user.role if user else 'viewer'
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('employment-requests.html', user_role=user_role, user_permissions=user_permissions)

@app.route('/manage-users')
@permission_required('show_manage_users')
def show_manage_users():
    user = User.query.get(session['user_id'])
    user_role = user.role if user else 'viewer'
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('manage-users.html', user_role=user_role, user_permissions=user_permissions)

@app.route('/penalties')
@permission_required('show_penalties')
def show_penalties():
    user = User.query.get(session['user_id'])
    user_role = user.role if user else 'viewer'
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('penalties.html', user_role=user_role, user_permissions=user_permissions)

@app.route('/ratings')
@permission_required('show_ratings')
def show_ratings():
    user = User.query.get(session['user_id'])
    user_role = user.role if user else 'viewer'
    user_permissions = json.loads(user.permissions) if user.permissions else []
    return render_template('ratings.html', user_role=user_role, user_permissions=user_permissions)

# هذا هو المسار الذي سيتصل بـ Gemini API
@app.route('/generate_insight', methods=['POST'])
@permission_required('generate_insight')
def generate_insight():
    user = User.query.get(session['user_id'])
    user_role = user.role if user else 'guest'

    prompt = f"أعطني نصيحة سريعة ومفيدة في مجال تكنولوجيا المعلومات لمستخدم ذو دور {user_role} في سطر واحد."

    try:
        llm_response_text = ""
        if user_role == 'admin':
            llm_response_text = "كنت دائماً على اطلاع بآخر التحديثات الأمنية وأنظمة النسخ الاحتياطي للمسؤولين."
        elif user_role == 'editor':
            llm_response_text = "عند كتابة المحتوى، ركز على الوضوح والدقة لجذب القراء."
        elif user_role == 'hr':
            llm_response_text = "استثمر في تطوير مهارات الموظفين لتعزيز الإنتاجية والرضا الوظيفي."
        else: 
            llm_response_text = "نصيحة تقنية: تأكد من تحديث برامجك بانتظام لسد الثغرات الأمنية."

        return jsonify({'insight': llm_response_text}), 200

    except Exception as e:
        print(f"Error calling LLM API: {e}")
        return jsonify({'error': 'فشل في توليد النصيحة.'}), 500

if __name__ == '__main__':
    app.run(debug=True)
