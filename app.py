from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complaints.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)


# МОДЕЛИ
class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    color = db.Column(db.String(20), default='#95a5a6')
    icon = db.Column(db.String(50), default='fas fa-circle')
    order = db.Column(db.Integer, default=0)

    complaints = db.relationship('Complaint', backref='status_ref', lazy=True)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    icon = db.Column(db.String(50), default='fas fa-folder')
    color = db.Column(db.String(20), default='#3498db')
    description = db.Column(db.String(200))

    complaints = db.relationship('Complaint', backref='category_ref', lazy=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    complaints = db.relationship('Complaint', backref='author_ref', lazy=True)
    comments = db.relationship('Comment', backref='user_ref', lazy=True)

    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    address = db.Column(db.String(300))
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), default=1)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), default=1)
    photo = db.Column(db.String(200))
    votes = db.Column(db.Integer, default=0)
    views = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    comments = db.relationship('Comment', backref='complaint_ref', lazy=True, cascade='all, delete-orphan')

    # Для удобного доступа
    @property
    def author(self):
        return self.author_ref

    @property
    def status(self):
        return self.status_ref

    @property
    def category(self):
        return self.category_ref


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'))


# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def create_initial_data():
    """Создание начальных данных"""
    # Статусы
    statuses = [
        Status(name='Новая', description='Жалоба только что создана',
               color='#e74c3c', icon='fas fa-clock', order=1),
        Status(name='Подтверждена', description='Жалоба проверена',
               color='#f39c12', icon='fas fa-check-circle', order=2),
        Status(name='В работе', description='Над проблемой работают',
               color='#3498db', icon='fas fa-tools', order=3),
        Status(name='Исправлено', description='Проблема решена',
               color='#27ae60', icon='fas fa-check', order=4),
        Status(name='Отклонена', description='Жалоба отклонена',
               color='#95a5a6', icon='fas fa-times-circle', order=5),
    ]
    for status in statuses:
        if not Status.query.filter_by(name=status.name).first():
            db.session.add(status)

    # Категории
    categories = [
        Category(name='Дороги', icon='fas fa-road', color='#e74c3c',
                 description='Проблемы с дорогами и тротуарами'),
        Category(name='Мусор', icon='fas fa-trash', color='#2ecc71',
                 description='Мусор и уборка'),
        Category(name='Освещение', icon='fas fa-lightbulb', color='#f39c12',
                 description='Уличное освещение'),
        Category(name='Вода', icon='fas fa-tint', color='#3498db',
                 description='Водоснабжение и канализация'),
        Category(name='Транспорт', icon='fas fa-bus', color='#9b59b6',
                 description='Общественный транспорт'),
        Category(name='ЖКХ', icon='fas fa-building', color='#1abc9c',
                 description='Жилищно-коммунальные услуги'),
        Category(name='Озеленение', icon='fas fa-tree', color='#27ae60',
                 description='Парки, скверы, газоны'),
        Category(name='Другое', icon='fas fa-question-circle', color='#7f8c8d',
                 description='Другие проблемы'),
    ]
    for category in categories:
        if not Category.query.filter_by(name=category.name).first():
            db.session.add(category)

    # Администратор
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)

    # Тестовый пользователь
    if not User.query.filter_by(username='test').first():
        test_user = User(username='test', email='test@example.com')
        test_user.set_password('test123')
        db.session.add(test_user)

    db.session.commit()


# Создаём таблицы и начальные данные
with app.app_context():
    db.create_all()
    create_initial_data()


# ДЕКОРАТОРЫ ДЛЯ ПРОВЕРКИ ПРАВ
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Для доступа к этой странице необходимо войти в систему', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Необходима авторизация', 'error')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Доступ запрещён. Требуются права администратора', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)

    return decorated_function


# ВСЕ МАРШРУТЫ

# ==================== ГЛАВНЫЕ СТРАНИЦЫ ====================
@app.route('/')
def index():
    """Главная страница со списком жалоб"""
    page = request.args.get('page', 1, type=int)
    category_id = request.args.get('category', '')
    status_id = request.args.get('status', '')
    sort = request.args.get('sort', 'newest')
    search = request.args.get('search', '')

    query = Complaint.query

    # Поиск
    if search:
        query = query.filter(
            Complaint.title.contains(search) |
            Complaint.description.contains(search) |
            Complaint.address.contains(search)
        )

    # Фильтры
    if category_id and category_id.isdigit():
        query = query.filter_by(category_id=int(category_id))

    if status_id and status_id.isdigit():
        query = query.filter_by(status_id=int(status_id))

    # Сортировка
    if sort == 'popular':
        query = query.order_by(Complaint.votes.desc())
    elif sort == 'oldest':
        query = query.order_by(Complaint.created_at.asc())
    elif sort == 'updated':
        query = query.order_by(Complaint.updated_at.desc())
    else:  # newest
        query = query.order_by(Complaint.created_at.desc())

    # Пагинация
    complaints_paginated = query.paginate(page=page, per_page=10, error_out=False)

    # Получаем общее количество для отображения
    total_complaints = complaints_paginated.total
    complaints_items = complaints_paginated.items

    # Статистика для фильтров
    categories = Category.query.all()
    statuses = Status.query.order_by(Status.order).all()

    return render_template('index.html',
                           complaints=complaints_paginated,
                           complaints_items=complaints_items,
                           total_complaints=total_complaints,
                           categories=categories,
                           statuses=statuses,
                           current_category=category_id,
                           current_status=status_id,
                           current_sort=sort,
                           search_query=search)


@app.route('/about')
def about():
    """Страница о проекте"""
    return render_template('about.html')


@app.route('/rules')
def rules():
    """Правила пользования"""
    return render_template('rules.html')


@app.route('/contact')
def contact():
    """Контактная информация"""
    return render_template('contact.html')


# ==================== ЖАЛОБЫ ====================
@app.route('/complaint/<int:id>')
def complaint_detail(id):
    """Детальная страница жалобы"""
    complaint = Complaint.query.get_or_404(id)

    # Увеличиваем счётчик просмотров
    complaint.views += 1
    db.session.commit()

    # Комментарии
    comments = Comment.query.filter_by(complaint_id=id).order_by(Comment.created_at.desc()).all()

    return render_template('complaint_detail.html',
                           complaint=complaint,
                           comments=comments)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_complaint():
    """Добавление новой жалобы"""
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        address = request.form.get('address', '').strip()
        category_id = request.form.get('category_id', 1, type=int)

        # Валидация
        if not title or len(title) < 5:
            flash('Заголовок должен содержать не менее 5 символов', 'error')
            return render_template('add_complaint.html',
                                   categories=Category.query.all())

        if not description or len(description) < 20:
            flash('Описание должно содержать не менее 20 символов', 'error')
            return render_template('add_complaint.html',
                                   categories=Category.query.all())

        # Обработка фото
        photo_filename = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{timestamp}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    photo_filename = filename
                else:
                    flash('Недопустимый формат файла. Используйте JPG, PNG или GIF', 'error')
                    return render_template('add_complaint.html',
                                           categories=Category.query.all())

        # Получаем статус "Новая"
        new_status = Status.query.filter_by(name='Новая').first()

        # Создаём жалобу
        complaint = Complaint(
            title=title,
            description=description,
            address=address,
            category_id=category_id,
            status_id=new_status.id if new_status else 1,
            photo=photo_filename,
            user_id=session['user_id']
        )

        db.session.add(complaint)
        db.session.commit()

        flash('Жалоба успешно добавлена!', 'success')
        return redirect(url_for('complaint_detail', id=complaint.id))

    return render_template('add_complaint.html',
                           categories=Category.query.all())


@app.route('/complaint/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_complaint(id):
    """Редактирование жалобы"""
    complaint = Complaint.query.get_or_404(id)

    # Проверяем права
    user = User.query.get(session['user_id'])
    if complaint.user_id != user.id and not user.is_admin:
        flash('У вас нет прав редактировать эту жалобу', 'error')
        return redirect(url_for('complaint_detail', id=id))

    if request.method == 'POST':
        complaint.title = request.form.get('title', '').strip()
        complaint.description = request.form.get('description', '').strip()
        complaint.address = request.form.get('address', '').strip()
        complaint.category_id = request.form.get('category_id', 1, type=int)

        # Только администратор может менять статус
        if user.is_admin:
            complaint.status_id = request.form.get('status_id', complaint.status_id, type=int)

        # Удаление фото
        if request.form.get('delete_photo') == '1':
            if complaint.photo:
                old_file = os.path.join(app.config['UPLOAD_FOLDER'], complaint.photo)
                if os.path.exists(old_file):
                    os.remove(old_file)
                complaint.photo = None

        # Обновление фото
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '':
                if allowed_file(file.filename):
                    # Удаляем старое фото
                    if complaint.photo:
                        old_file = os.path.join(app.config['UPLOAD_FOLDER'], complaint.photo)
                        if os.path.exists(old_file):
                            os.remove(old_file)

                    # Сохраняем новое
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{timestamp}_{filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    complaint.photo = filename
                else:
                    flash('Недопустимый формат файла. Используйте JPG, PNG или GIF', 'error')
                    return render_template('edit_complaint.html',
                                           complaint=complaint,
                                           categories=Category.query.all(),
                                           statuses=Status.query.all(),
                                           is_admin=user.is_admin)

        complaint.updated_at = datetime.utcnow()
        db.session.commit()

        flash('Жалоба успешно обновлена!', 'success')
        return redirect(url_for('complaint_detail', id=id))

    return render_template('edit_complaint.html',
                           complaint=complaint,
                           categories=Category.query.all(),
                           statuses=Status.query.all(),
                           is_admin=user.is_admin)


@app.route('/complaint/<int:id>/delete', methods=['POST'])
@login_required
def delete_complaint(id):
    """Удаление жалобы"""
    complaint = Complaint.query.get_or_404(id)

    # Проверяем права
    user = User.query.get(session['user_id'])
    if complaint.user_id != user.id and not user.is_admin:
        return jsonify({'success': False, 'error': 'Нет прав на удаление'}), 403

    # Удаляем фото
    if complaint.photo:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], complaint.photo)
        if os.path.exists(photo_path):
            os.remove(photo_path)

    db.session.delete(complaint)
    db.session.commit()

    flash('Жалоба успешно удалена', 'success')
    return jsonify({'success': True, 'redirect': url_for('index')})


# ==================== ГОЛОСОВАНИЕ ====================
@app.route('/complaint/<int:id>/vote', methods=['POST'])
@login_required
def vote_complaint(id):
    """Голосование за жалобу"""
    complaint = Complaint.query.get_or_404(id)

    # Проверяем, не голосовал ли уже пользователь
    # В реальном приложении нужно хранить историю голосований

    complaint.votes += 1
    complaint.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'success': True,
        'new_count': complaint.votes
    })


# ==================== КОММЕНТАРИИ ====================
@app.route('/complaint/<int:id>/comment', methods=['POST'])
@login_required
def add_comment(id):
    """Добавление комментария"""
    complaint = Complaint.query.get_or_404(id)
    text = request.form.get('text', '').strip()

    if not text:
        flash('Комментарий не может быть пустым', 'error')
        return redirect(url_for('complaint_detail', id=id))

    comment = Comment(
        text=text,
        user_id=session['user_id'],
        complaint_id=id
    )

    complaint.updated_at = datetime.utcnow()
    db.session.add(comment)
    db.session.commit()

    flash('Комментарий добавлен', 'success')
    return redirect(url_for('complaint_detail', id=id))


@app.route('/comment/<int:id>/delete', methods=['POST'])
@login_required
def delete_comment(id):
    """Удаление комментария"""
    comment = Comment.query.get_or_404(id)

    # Проверяем права
    user = User.query.get(session['user_id'])
    if comment.user_id != user.id and not user.is_admin:
        return jsonify({'success': False, 'error': 'Нет прав на удаление'}), 403

    complaint_id = comment.complaint_id
    db.session.delete(comment)
    db.session.commit()

    return jsonify({'success': True})


# ==================== АУТЕНТИФИКАЦИЯ ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Валидация
        errors = []

        if len(username) < 3:
            errors.append('Имя пользователя должно быть не менее 3 символов')

        if User.query.filter_by(username=username).first():
            errors.append('Это имя пользователя уже занято')

        if email and User.query.filter_by(email=email).first():
            errors.append('Этот email уже используется')

        if len(password) < 6:
            errors.append('Пароль должен быть не менее 6 символов')

        if password != confirm_password:
            errors.append('Пароли не совпадают')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html',
                                   username=username,
                                   email=email)

        # Создаём пользователя
        user = User(username=username, email=email if email else None)
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            session['username'] = user.username
            flash('Регистрация успешна! Добро пожаловать!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при регистрации: {str(e)}', 'error')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Вход в систему"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username

            # Запоминаем пользователя
            if remember:
                session.permanent = True

            flash(f'Добро пожаловать, {user.username}!', 'success')

            # Редирект на запрошенную страницу
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    # Добавьте это для передачи статистики в шаблон
    # Получаем общую статистику для отображения в навигации
    from collections import defaultdict
    stats_dict = defaultdict(int)

    try:
        # Получаем статистику по статусам
        status_stats = db.session.query(
            Status.name,
            db.func.count(Complaint.id)
        ).join(Complaint).group_by(Status.name).all()

        for status_name, count in status_stats:
            stats_dict[status_name] = count
    except:
        pass

    return render_template('login.html', stats=stats_dict)


@app.route('/logout')
def logout():
    """Выход из системы"""
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    """Профиль пользователя"""
    user = User.query.get(session['user_id'])
    user_complaints = Complaint.query.filter_by(user_id=user.id).order_by(Complaint.created_at.desc()).limit(10).all()

    # Статистика
    stats = {
        'total_complaints': Complaint.query.filter_by(user_id=user.id).count(),
        'solved_complaints': Complaint.query.filter_by(user_id=user.id)
        .join(Status).filter(Status.name == 'Исправлено').count(),
        'total_votes': sum(c.votes for c in user_complaints),
        'total_comments': Comment.query.filter_by(user_id=user.id).count()
    }

    return render_template('profile.html',
                           user=user,
                           complaints=user_complaints,
                           stats=stats)


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Редактирование профиля"""
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        # Обновление email
        if email != user.email:
            if email and User.query.filter_by(email=email).first():
                flash('Этот email уже используется другим пользователем', 'error')
            else:
                user.email = email if email else None

        # Смена пароля
        if current_password and new_password:
            if user.check_password(current_password):
                if len(new_password) >= 6:
                    user.set_password(new_password)
                    flash('Пароль успешно изменён', 'success')
                else:
                    flash('Новый пароль должен быть не менее 6 символов', 'error')
            else:
                flash('Текущий пароль неверен', 'error')

        db.session.commit()
        flash('Профиль успешно обновлён', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)


# ==================== АДМИНИСТРАТИВНЫЕ МАРШРУТЫ ====================
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Административная панель"""
    stats = {
        'total_complaints': Complaint.query.count(),
        'total_users': User.query.count(),
        'total_comments': Comment.query.count(),
        'new_complaints_today': Complaint.query.filter(
            Complaint.created_at >= datetime.now().date()
        ).count(),
        'popular_category': db.session.query(
            Category.name,
            db.func.count(Complaint.id)
        ).join(Complaint).group_by(Category.id).order_by(db.func.count(Complaint.id).desc()).first()
    }

    recent_complaints = Complaint.query.order_by(Complaint.created_at.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    return render_template('admin/dashboard.html',
                           stats=stats,
                           recent_complaints=recent_complaints,
                           recent_users=recent_users)


@app.route('/admin/complaints')
@admin_required
def admin_complaints():
    """Управление жалобами"""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    category_filter = request.args.get('category', '')

    query = Complaint.query

    if status_filter and status_filter.isdigit():
        query = query.filter_by(status_id=int(status_filter))

    if category_filter and category_filter.isdigit():
        query = query.filter_by(category_id=int(category_filter))

    complaints = query.order_by(Complaint.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template('admin/complaints.html',
                           complaints=complaints,
                           categories=Category.query.all(),
                           statuses=Status.query.all(),
                           current_status=status_filter,
                           current_category=category_filter)


@app.route('/admin/complaint/<int:id>/change_status', methods=['POST'])
@admin_required
def change_complaint_status(id):
    """Изменение статуса жалобы (админ)"""
    complaint = Complaint.query.get_or_404(id)
    new_status_id = request.form.get('status_id', type=int)

    if new_status_id:
        complaint.status_id = new_status_id
        complaint.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Статус жалобы обновлён', 'success')

    return redirect(request.referrer or url_for('admin_complaints'))


@app.route('/admin/users')
@admin_required
def admin_users():
    """Управление пользователями"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = User.query

    if search:
        query = query.filter(
            User.username.contains(search) |
            User.email.contains(search)
        )

    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template('admin/users.html',
                           users=users,
                           search_query=search)


@app.route('/admin/user/<int:id>/toggle_admin', methods=['POST'])
@admin_required
def toggle_admin(id):
    """Назначение/снятие прав администратора"""
    if id == session['user_id']:
        flash('Нельзя изменить свои собственные права администратора', 'error')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(id)
    user.is_admin = not user.is_admin
    db.session.commit()

    action = 'назначены' if user.is_admin else 'сняты'
    flash(f'Права администратора {action} для пользователя {user.username}', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/categories')
@admin_required
def admin_categories():
    """Управление категориями"""
    categories = Category.query.all()
    return render_template('admin/categories.html', categories=categories)


@app.route('/admin/category/add', methods=['POST'])
@admin_required
def add_category():
    """Добавление категории"""
    name = request.form.get('name', '').strip()
    color = request.form.get('color', '#3498db')
    icon = request.form.get('icon', 'fas fa-folder')
    description = request.form.get('description', '')

    if not name:
        flash('Название категории обязательно', 'error')
        return redirect(url_for('admin_categories'))

    if Category.query.filter_by(name=name).first():
        flash('Категория с таким названием уже существует', 'error')
        return redirect(url_for('admin_categories'))

    category = Category(
        name=name,
        color=color,
        icon=icon,
        description=description
    )

    db.session.add(category)
    db.session.commit()
    flash('Категория успешно добавлена', 'success')
    return redirect(url_for('admin_categories'))


@app.route('/admin/statuses')
@admin_required
def admin_statuses():
    """Управление статусами"""
    statuses = Status.query.order_by(Status.order).all()
    return render_template('admin/statuses.html', statuses=statuses)


# ==================== API ====================
@app.route('/api/categories')
def api_categories():
    """API для получения категорий"""
    categories = Category.query.all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'color': c.color,
        'icon': c.icon,
        'description': c.description
    } for c in categories])


@app.route('/api/statuses')
def api_statuses():
    """API для получения статусов"""
    statuses = Status.query.order_by(Status.order).all()
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'color': s.color,
        'icon': s.icon,
        'description': s.description
    } for s in statuses])


@app.route('/api/check_username/<username>')
def check_username(username):
    """Проверка доступности имени пользователя"""
    user = User.query.filter_by(username=username).first()
    return jsonify({'available': user is None})


@app.route('/api/stats')
def api_stats():
    """Статистика для главной страницы"""
    stats = {
        'total_complaints': Complaint.query.count(),
        'solved_complaints': Complaint.query.join(Status)
        .filter(Status.name == 'Исправлено').count(),
        'total_users': User.query.count(),
        'total_votes': db.session.query(db.func.sum(Complaint.votes)).scalar() or 0,
        'categories': [{
            'name': c.name,
            'count': len(c.complaints),
            'color': c.color
        } for c in Category.query.all()]
    }
    return jsonify(stats)


# ==================== ОБРАБОТЧИКИ ОШИБОК ====================
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    return render_template('errors/500.html'), 500


# ==================== ЗАПУСК ====================
if __name__ == '__main__':
    app.run(debug=True)