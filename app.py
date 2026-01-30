from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ВАЖНО: Установите секретный ключ для сессий!
app.config['SECRET_KEY'] = 'ваш-секретный-ключ-тут'  # Измените на случайную строку!

# Конфигурация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complaints.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Конфигурация загрузки файлов
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Создаём папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)


# Модели
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    complaints = db.relationship('Complaint', backref='author', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    address = db.Column(db.String(300))
    category = db.Column(db.String(50), default='Дороги')
    photo = db.Column(db.String(200))  # Путь к фото
    votes = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='Новая')  # Новая, В работе, Исправлено
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'<Complaint {self.title}>'


# Создаём таблицы
with app.app_context():
    db.create_all()
    # Создаём тестового пользователя, если нет
    if not User.query.first():
        test_user = User(username='test', email='test@example.com', password_hash='test')
        db.session.add(test_user)
        db.session.commit()


# Вспомогательные функции
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Маршруты
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    category = request.args.get('category', '')

    # Запрос с фильтрами
    query = Complaint.query

    if search:
        query = query.filter(
            (Complaint.title.contains(search)) |
            (Complaint.description.contains(search))
        )

    if category:
        query = query.filter_by(category=category)

    # Пагинация
    complaints = query.order_by(Complaint.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )

    return render_template('index.html',
                           complaints=complaints.items,
                           page=page,
                           total_pages=complaints.pages,
                           category=category)


@app.route('/add', methods=['GET', 'POST'])
def add_complaint():
    if request.method == 'POST':
        # Получаем данные из формы
        title = request.form['title']
        description = request.form['description']
        address = request.form.get('address', '')
        category = request.form.get('category', 'Дороги')

        # Обработка загруженного файла
        photo_filename = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Добавляем timestamp для уникальности
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                photo_filename = filename

        # Создаём новую жалобу
        new_complaint = Complaint(
            title=title,
            description=description,
            address=address,
            category=category,
            photo=photo_filename,
            votes=0,
            status='Новая'
        )

        # Если есть пользователь в сессии, добавляем его ID
        if 'user_id' in session:
            new_complaint.user_id = session['user_id']
        else:
            # Или используем тестового пользователя
            test_user = User.query.filter_by(username='test').first()
            if test_user:
                new_complaint.user_id = test_user.id

        db.session.add(new_complaint)
        db.session.commit()

        flash('Жалоба успешно отправлена!', 'success')
        return redirect(url_for('index'))

    return render_template('add_complaint.html')


@app.route('/complaint/<int:id>')
def complaint_detail(id):
    complaint = Complaint.query.get_or_404(id)
    return render_template('complaint_detail.html', complaint=complaint)


@app.route('/vote/<int:id>', methods=['POST'])
def vote_complaint(id):
    complaint = Complaint.query.get_or_404(id)
    complaint.votes += 1
    db.session.commit()

    return jsonify({
        'success': True,
        'new_count': complaint.votes
    })


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Проверка на существование
        if User.query.filter_by(username=username).first():
            flash('Это имя пользователя уже занято', 'error')
            return redirect(url_for('register'))

        # В реальном приложении хэшируйте пароль с помощью bcrypt!
        user = User(username=username, email=email, password_hash=password)
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

        # В реальном приложении проверяйте хэш пароля!
        user = User.query.filter_by(username=username, password_hash=password).first()

        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Вход выполнен!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


# Запуск приложения
if __name__ == '__main__':
    app.run(debug=True)