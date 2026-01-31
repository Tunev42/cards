from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ваш-секретный-ключ-тут'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complaints.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)


# Модели (оставляем как было)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    complaints = db.relationship('Complaint', backref='author', lazy=True)

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
    category = db.Column(db.String(50), default='Дороги')
    photo = db.Column(db.String(200))
    votes = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='Новая')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# Создаём таблицы
with app.app_context():
    db.create_all()

    # Тестовый пользователь
    if not User.query.first():
        test_user = User(username='test', email='test@example.com')
        test_user.set_password('test123')
        db.session.add(test_user)
        db.session.commit()


# Главная страница
@app.route('/')
def index():
    category = request.args.get('category', '')
    status = request.args.get('status', '')
    sort_by = request.args.get('sort', 'newest')

    query = Complaint.query

    if category and category != 'all':
        query = query.filter_by(category=category)

    if status and status != 'all':
        query = query.filter_by(status=status)

    if sort_by == 'popular':
        query = query.order_by(Complaint.votes.desc())
    elif sort_by == 'oldest':
        query = query.order_by(Complaint.created_at.asc())
    else:
        query = query.order_by(Complaint.created_at.desc())

    complaints = query.all()

    categories = ['Дороги', 'Мусор', 'Освещение', 'Вода', 'Транспорт', 'Другое']
    statuses = ['Новая', 'В работе', 'Исправлено']

    # Статистика
    stats = {}
    for cat in categories:
        stats[cat] = Complaint.query.filter_by(category=cat).count()

    for st in statuses:
        stats[st] = Complaint.query.filter_by(status=st).count()

    return render_template('index.html',
                           complaints=complaints,
                           categories=categories,
                           statuses=statuses,
                           current_category=category,
                           current_status=status,
                           current_sort=sort_by,
                           stats=stats)


# Маршрут добавления жалобы - ВАЖНО: он должен быть!
@app.route('/add', methods=['GET', 'POST'])
def add_complaint():  # Имя функции должно быть add_complaint
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        address = request.form.get('address', '')
        category = request.form.get('category', 'Дороги')

        # Обработка фото
        photo_filename = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                photo_filename = filename

        # Создаём жалобу
        new_complaint = Complaint(
            title=title,
            description=description,
            address=address,
            category=category,
            photo=photo_filename
        )

        # Привязываем к пользователю
        if 'user_id' in session:
            new_complaint.user_id = session['user_id']
        else:
            test_user = User.query.first()
            if test_user:
                new_complaint.user_id = test_user.id

        db.session.add(new_complaint)
        db.session.commit()

        flash('Жалоба успешно добавлена!', 'success')
        return redirect(url_for('index'))

    return render_template('add_complaint.html')


# Маршрут голосования
@app.route('/vote/<int:id>', methods=['POST'])
def vote_complaint(id):
    complaint = Complaint.query.get_or_404(id)
    complaint.votes += 1
    db.session.commit()

    return jsonify({
        'success': True,
        'new_count': complaint.votes
    })


# Маршруты регистрации и входа
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form.get('email', '')
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято', 'error')
            return redirect(url_for('register'))

        user = User(username=username, email=email if email else None)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        session['username'] = user.username
        flash('Регистрация успешна!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Вход выполнен!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'error')

    return render_template('login.html')


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


# Проверка доступности имени пользователя
@app.route('/api/check_username/<username>')
def check_username(username):
    user = User.query.filter_by(username=username).first()
    return jsonify({'available': user is None})


if __name__ == '__main__':
    app.run(debug=True)