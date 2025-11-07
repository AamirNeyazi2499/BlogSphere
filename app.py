# app.py - Enhanced Flask Blog System with User Authentication
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    bio = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def __repr__(self):
        return f'<User {self.username}>'

# Post Model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_published = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Post {self.title}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

def validate_password(password):
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

# Routes
@app.route('/')
def index():
    posts = Post.query.filter_by(is_published=True).order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        
        # Validation
        if not all([username, email, password, confirm_password, first_name, last_name]):
            flash('All fields are required!', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if not validate_username(username):
            flash('Username must be 3-20 characters and contain only letters, numbers, and underscores!', 'error')
            return render_template('register.html')
        
        if not validate_email(email):
            flash('Please enter a valid email address!', 'error')
            return render_template('register.html')
        
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            flash(password_message, 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        remember_me = 'remember_me' in request.form
        
        if not username or not password:
            flash('Please enter both username and password!', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember_me)
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.first_name}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    user_posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.created_at.desc()).all()
    return render_template('profile.html', user_posts=user_posts)

@app.route('/profile/edit', methods=['POST'])
@login_required
def edit_profile():
    first_name = request.form['first_name'].strip()
    last_name = request.form['last_name'].strip()
    email = request.form['email'].strip().lower()
    bio = request.form['bio'].strip()
    
    if not all([first_name, last_name, email]):
        flash('First name, last name, and email are required!', 'error')
        return redirect(url_for('profile'))
    
    if not validate_email(email):
        flash('Please enter a valid email address!', 'error')
        return redirect(url_for('profile'))
    
    # Check if email is taken by another user
    existing_user = User.query.filter_by(email=email).first()
    if existing_user and existing_user.id != current_user.id:
        flash('Email already registered by another user!', 'error')
        return redirect(url_for('profile'))
    
    current_user.first_name = first_name
    current_user.last_name = last_name
    current_user.email = email
    current_user.bio = bio if bio else None
    
    try:
        db.session.commit()
        flash('Profile updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while updating profile.', 'error')
    
    return redirect(url_for('profile'))

@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not post.is_published and (not current_user.is_authenticated or current_user.id != post.user_id):
        flash('Post not found!', 'error')
        return redirect(url_for('index'))
    return render_template('view_post.html', post=post)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        is_published = 'is_published' in request.form
        
        if not title or not content:
            flash('Title and content are required!', 'error')
            return render_template('create_post.html')
        
        if len(title) < 3:
            flash('Title must be at least 3 characters long!', 'error')
            return render_template('create_post.html')
        
        if len(content) < 10:
            flash('Content must be at least 10 characters long!', 'error')
            return render_template('create_post.html')
        
        post = Post(
            title=title,
            content=content,
            user_id=current_user.id,
            is_published=is_published
        )
        
        try:
            db.session.add(post)
            db.session.commit()
            status = "published" if is_published else "saved as draft"
            flash(f'Post {status} successfully!', 'success')
            return redirect(url_for('view_post', post_id=post.id))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating the post.', 'error')
    
    return render_template('create_post.html')

@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    if post.user_id != current_user.id:
        flash('You can only edit your own posts!', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        is_published = 'is_published' in request.form
        
        if not title or not content:
            flash('Title and content are required!', 'error')
            return render_template('edit_post.html', post=post)
        
        if len(title) < 3:
            flash('Title must be at least 3 characters long!', 'error')
            return render_template('edit_post.html', post=post)
        
        if len(content) < 10:
            flash('Content must be at least 10 characters long!', 'error')
            return render_template('edit_post.html', post=post)
        
        post.title = title
        post.content = content
        post.is_published = is_published
        post.updated_at = datetime.utcnow()
        
        try:
            db.session.commit()
            flash('Post updated successfully!', 'success')
            return redirect(url_for('view_post', post_id=post.id))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the post.', 'error')
    
    return render_template('edit_post.html', post=post)

@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    if post.user_id != current_user.id:
        flash('You can only delete your own posts!', 'error')
        return redirect(url_for('index'))
    
    try:
        db.session.delete(post)
        db.session.commit()
        flash('Post deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the post.', 'error')
    
    return redirect(url_for('profile'))

@app.route('/api/posts')
def api_posts():
    posts = Post.query.filter_by(is_published=True).order_by(Post.created_at.desc()).all()
    posts_data = []
    for post in posts:
        posts_data.append({
            'id': post.id,
            'title': post.title,
            'content': post.content[:200] + '...' if len(post.content) > 200 else post.content,
            'author': post.author.get_full_name(),
            'username': post.author.username,
            'created_at': post.created_at.isoformat(),
            'updated_at': post.updated_at.isoformat(),
            'is_published': post.is_published
        })
    return jsonify(posts_data)

@app.route('/api/users/<username>')
def api_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return jsonify({
        'username': user.username,
        'full_name': user.get_full_name(),
        'bio': user.bio,
        'posts_count': len([p for p in user.posts if p.is_published]),
        'total_posts': len(user.posts),
        'joined': user.created_at.isoformat()
    })

# Note the new function name: 'admin_delete_post'
@app.route('/post/<int:post_id>/admin_delete', methods=['POST'])
@login_required  # Ensures user must be logged in
def admin_delete_post(post_id):
    
    # 1. Check if the logged-in user is an admin
    if not current_user.is_admin:
        abort(403)  # This will now work!
        
    # 2. Find the post or show a 404 "Not Found" error
    post = Post.query.get_or_404(post_id)
    
    # 3. Delete the post from the database
    try:
        db.session.delete(post)
        db.session.commit()
        flash('Post has been deleted successfully by admin.', 'success')
    except:
        db.session.rollback()
        flash('Error: Could not delete post.', 'danger')
        
    # 4. Redirect back to the homepage
    return redirect(url_for('index'))
# Initialize database and create sample data
def init_database():
    with app.app_context():
        db.create_all()
        
        # Check if we need to create sample data
        if User.query.count() == 0:
            # Create sample users
            admin_user = User(
                username='admin',
                email='admin@blog.com',
                first_name='Admin',
                last_name='User',
                bio='Blog administrator and content manager'
            )
            admin_user.set_password('admin123')
            
            john_user = User(
                username='john_doe',
                email='john@example.com',
                first_name='John',
                last_name='Doe',
                bio='Tech enthusiast and blogger who loves sharing knowledge about web development'
            )
            john_user.set_password('john123')
            
            jane_user = User(
                username='jane_smith',
                email='jane@example.com',
                first_name='Jane',
                last_name='Smith',
                bio='Web developer and UI/UX designer passionate about creating beautiful user experiences'
            )
            jane_user.set_password('jane123')
            
            db.session.add_all([admin_user, john_user, jane_user])
            db.session.commit()
            
            # Create sample posts
            sample_posts = [
                Post(
                    title="Welcome to Our Enhanced Blog System",
                    content="This is our new and improved blog system! Now with user authentication, you can create your own account, write posts, save drafts, and manage your content. We've added many exciting features including user profiles, secure login, and much more. Feel free to explore and start writing your own posts!",
                    user_id=admin_user.id,
                    is_published=True
                ),
                Post(
                    title="Learning Flask with Authentication",
                    content="Flask is an amazing micro web framework for Python. It's lightweight, flexible, and perfect for building web applications quickly. Adding user authentication with Flask-Login makes it even better for multi-user applications.\n\nIn this post, I'll share some tips about building Flask applications with proper user management and security considerations.",
                    user_id=john_user.id,
                    is_published=True
                ),
                Post(
                    title="Web Development Best Practices",
                    content="Here are some essential tips for modern web development:\n\n1. Always validate user input on both client and server side\n2. Use responsive design principles for mobile compatibility\n3. Optimize for performance with proper caching\n4. Test your applications thoroughly\n5. Implement proper user authentication and authorization\n6. Keep your dependencies updated\n7. Use version control effectively\n\nThese practices will help you build robust and secure web applications.",
                    user_id=jane_user.id,
                    is_published=True
                ),
                Post(
                    title="Draft: Upcoming Features",
                    content="I'm working on some exciting new features for our blog system including:\n\n- Comment system for posts\n- Categories and tags\n- Email notifications\n- Rich text editor\n- Image uploads\n\nStay tuned for updates!",
                    user_id=admin_user.id,
                    is_published=False
                )
            ]
            
            db.session.add_all(sample_posts)
            db.session.commit()
            
            print("Sample data created successfully!")

if __name__ == '__main__':
    # Create directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Initialize database
    init_database()
    
    print("=" * 60)
    print("🚀 Enhanced Flask Blog System with Authentication")
    print("=" * 60)
    print("📊 Sample users created:")
    print("  👤 Username: admin     | Password: admin123")
    print("  👤 Username: john_doe  | Password: john123")
    print("  👤 Username: jane_smith| Password: jane123")
    print("=" * 60)
    print("🌐 Visit: http://127.0.0.1:5000")
    print("📝 Features: Registration, Login, Profile, CRUD Posts")
    print("=" * 60)
    
    app.run(debug=True)