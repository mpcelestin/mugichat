from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from datetime import datetime
import os
import secrets
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from PIL import Image
from flask_moment import Moment
from flask import Blueprint
from flask_wtf.csrf import CSRFProtect
from flask import send_file
# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] =  'd29c234ca310aa6990092d4b6cd4c4854585c51e1f73bf4de510adca03f5bc4e'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mugichat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
csrf = CSRFProtect(app)
# Configure upload folders
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['POST_PICS_FOLDER'] = 'static/post_pics'
app.config['PROFILE_PICS_FOLDER'] = 'static/profile_pics'
app.config['GROUP_PICS_FOLDER'] = 'static/group_pics'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
moment = Moment(app)

# Create upload folders if they don't exist
def create_upload_folders():
    folders = [
        app.config['UPLOAD_FOLDER'],
        app.config['POST_PICS_FOLDER'],
        app.config['PROFILE_PICS_FOLDER'],
        app.config['GROUP_PICS_FOLDER']
    ]
    for folder in folders:
        os.makedirs(folder, exist_ok=True)

create_upload_folders()

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*")

# Create the main Blueprint
main = Blueprint('main', __name__)

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_picture(form_picture, folder='profile_pics'):
    if folder == 'profile_pics':
        upload_folder = app.config['PROFILE_PICS_FOLDER']
    elif folder == 'post_pics':
        upload_folder = app.config['POST_PICS_FOLDER']
    elif folder == 'group_pics':
        upload_folder = app.config['GROUP_PICS_FOLDER']
    else:
        upload_folder = app.config['UPLOAD_FOLDER']
    
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, upload_folder, picture_fn)
    
    # Resize image before saving
    output_size = (125, 125) if folder == 'profile_pics' else (800, 800)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return picture_fn

def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ''
    return value.strftime(format)

app.jinja_env.filters['datetimeformat'] = datetimeformat



# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    profile_pic = db.Column(db.String(20), nullable=False, default='default.jpg')
    bio = db.Column(db.String(200))
    location = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Changed backref name from 'likes' to 'liked_by' to avoid conflict
    liked_posts = db.relationship(
        'Post',
        secondary='like',
        backref=db.backref('liked_by', lazy='dynamic'),
        lazy='dynamic'
    )
    
    def current_user_like(self):
        if current_user.is_authenticated:
            return Like.query.filter_by(post_id=self.id, user_id=current_user.id).first()
        return None
    def get_unread_notifications_count(self):
        return Notification.query.filter_by(user_id=self.id, is_read=False).count()
    
    def is_streaming(self):
        return LiveStream.query.filter_by(user_id=self.id, is_live=True).first() is not None
    
    def get_active_stream(self):
        return LiveStream.query.filter_by(user_id=self.id, is_live=True).first()

    # Relationships
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)
    sent_friend_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', backref='sender', lazy=True)
    received_friend_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.recipient_id', backref='recipient', lazy=True)
    friends = db.relationship('Friend', foreign_keys='Friend.user_id', backref='user', lazy=True)
    group_memberships = db.relationship('GroupMember', backref='member', lazy=True)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy=True)
    # Changed this from 'likes' to 'like_instances' to avoid conflict
    like_instances = db.relationship('Like', backref='post', lazy=True)
    
    # Property to get like count
    @property
    def likes_count(self):
        return Like.query.filter_by(post_id=self.id).count()
    
    def current_user_like(self):
        if current_user.is_authenticated:
            return Like.query.filter_by(post_id=self.id, user_id=current_user.id).first()
        return None

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    reaction = db.Column(db.String(10), default='like')  # like, love, haha, wow, sad, angry
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)



class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    
    def __repr__(self):
        return f"Comment('{self.content[:20]}...', '{self.timestamp}')"



class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f"Message('{self.content[:20]}...', '{self.timestamp}')"

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f"FriendRequest('{self.sender_id}', '{self.recipient_id}')"

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    __table_args__ = (
        db.Index('idx_friends_user_friend', 'user_id', 'friend_id', unique=True),
    )

    def __repr__(self):
        return f"Friend('{self.user_id}', '{self.friend_id}')"

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_public = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    group_pic = db.Column(db.String(20), nullable=False, default='group_default.jpg')

    # Relationships
    creator = db.relationship('User', backref='created_groups')  # ✅ correct
    members = db.relationship('GroupMember', backref='group', lazy=True)
    posts = db.relationship('GroupPost', backref='group', lazy=True)

    def __repr__(self):
        return f"Group('{self.name}', '{self.creator_id}')"


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f"GroupMember('{self.user_id}', '{self.group_id}')"

class GroupPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.relationship('GroupPostLike', backref='post', lazy='joined')

    # ✅ Relationship to User (author of the post)
    author = db.relationship('User', backref='group_posts')

    def __repr__(self):
        return f"GroupPost('{self.content[:20]}', '{self.timestamp}')"


class GroupPostComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('group_post.id'), nullable=False)
    
    def __repr__(self):
        return f"GroupPostComment('{self.content[:20]}...', '{self.timestamp}')"

class GroupPostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('group_post.id'), nullable=False)
    reaction = db.Column(db.String(10))  # like, love, haha, etc.
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f"GroupPostLike('{self.user_id}', '{self.post_id}')"


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    link = db.Column(db.String(200))  # URL to the relevant page
    
    def __repr__(self):
        return f"Notification('{self.content[:20]}...', '{self.timestamp}')"

class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


# Add to your models section
class LiveStream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    stream_key = db.Column(db.String(50), unique=True)
    is_live = db.Column(db.Boolean, default=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    viewers_count = db.Column(db.Integer, default=0)
    
    user = db.relationship('User', backref=db.backref('streams', lazy=True))

class LiveViewer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stream_id = db.Column(db.Integer, db.ForeignKey('live_stream.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    stream = db.relationship('LiveStream', backref=db.backref('viewers', lazy=True))
    user = db.relationship('User', backref=db.backref('viewed_streams', lazy=True))


# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = SelectField('Remember Me', choices=[('no', 'No'), ('yes', 'Yes')])
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    bio = TextAreaField('Bio')
    location = StringField('Location')
    profile_pic = FileField('Update Profile Picture')
    submit = SubmitField('Update')
    
    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')
    
    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

class PostForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    image = FileField('Add Image')
    submit = SubmitField('Post')

class CommentForm(FlaskForm):
    content = TextAreaField('Add a comment', validators=[DataRequired()])
    submit = SubmitField('Comment')

class MessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class AcceptRejectForm(FlaskForm):
    submit = SubmitField('Submit')



class GroupForm(FlaskForm):
    name = StringField('Group Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description')
    is_public = SelectField('Privacy', choices=[('public', 'Public'), ('private', 'Private')])
    group_pic = FileField('Group Picture')
    submit = SubmitField('Create Group')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


# Add to your forms section
class LiveStreamForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    submit = SubmitField('Go Live')



# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_picture(form_picture, folder='profile_pics'):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static', folder, picture_fn)
    
    # Resize image before saving
    output_size = (125, 125) if folder == 'profile_pics' else (800, 800)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return picture_fn

# Routes
@app.route("/", methods=['GET', 'POST'])
@app.route("/home", methods=['GET', 'POST'])
@login_required
def home():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(content=form.content.data, author=current_user)
        if form.image.data:
            if allowed_file(form.image.data.filename):
                picture_file = save_picture(form.image.data, 'post_pics')
                post.image = picture_file
            else:
                flash('Invalid file type. Only PNG, JPG, JPEG, GIF allowed.', 'danger')
                return redirect(url_for('home'))
        
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    
    # Modified this part to get all posts instead of just friends' posts
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('main/home.html', posts=posts, form=form)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('auth/login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated! You can now log in', 'success')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address', 'danger')
    return render_template('auth/reset_password.html', title='Reset Password', form=form)

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.profile_pic.data:
            picture_file = save_picture(form.profile_pic.data)
            current_user.profile_pic = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.bio = form.bio.data
        current_user.location = form.location.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.bio.data = current_user.bio
        form.location.data = current_user.location
    image_file = url_for('static', filename='profile_pics/' + current_user.profile_pic)
    return render_template('main/account.html', title='Account', image_file=image_file, form=form)

@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(content=form.content.data, author=current_user)
        if form.image.data:
            picture_file = save_picture(form.image.data, 'post_pics')
            post.image = picture_file
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('main/create_post.html', title='New Post', form=form, legend='New Post')

@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()  # Create a form instance for comments
    return render_template('main/post.html', title=post.content[:20], post=post, form=form)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.content = form.content.data
        if form.image.data:
            picture_file = save_picture(form.image.data, 'post_pics')
            post.image = picture_file
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.content.data = post.content
    return render_template('main/create_post.html', title='Update Post', form=form, legend='Update Post')

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route("/post/<int:post_id>/comment", methods=['GET', 'POST'])
@login_required
def comment_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    
    if form.validate_on_submit():
        comment = Comment(content=form.content.data, author=current_user, post=post)
        db.session.add(comment)
        db.session.commit()
        
        # Check if it's an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'comment': {
                    'content': comment.content,
                    'author': comment.author.username,
                    'profile_pic': url_for('static', filename='profile_pics/' + comment.author.profile_pic),
                    'timestamp': comment.timestamp.strftime('%Y-%m-%d %H:%M')
                }
            })
        
        flash('Your comment has been added!', 'success')
        return redirect(url_for('post', post_id=post.id))
    
    # Handle AJAX validation errors
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': False, 'errors': form.errors}), 400
    
    return render_template('main/comment.html', title='Comment', form=form, post=post)




@app.route("/friend_requests")
@login_required
def view_friend_requests():
    pending_requests = db.session.query(FriendRequest, User).join(
        User, FriendRequest.sender_id == User.id
    ).filter(
        FriendRequest.recipient_id == current_user.id,
        FriendRequest.status == 'pending'
    ).all()
    
    accept_form = AcceptRejectForm()
    reject_form = AcceptRejectForm()
    
    return render_template('main/friend_requests.html', 
                         requests=pending_requests,
                         accept_form=accept_form,
                         reject_form=reject_form)



@app.route("/send_friend_request/<int:user_id>", methods=['POST'])
@login_required
def send_friend_request(user_id):
    recipient = User.query.get_or_404(user_id)
    if recipient == current_user:
        flash('You cannot send a friend request to yourself!', 'danger')
        return redirect(url_for('user_posts', username=recipient.username))
    
    # Check if request already exists
    existing_request = FriendRequest.query.filter_by(
        sender_id=current_user.id, 
        recipient_id=user_id
    ).first()
    
    if existing_request:
        flash('Friend request already sent!', 'info')
        return redirect(url_for('user_posts', username=recipient.username))
    
    # Check if they are already friends
    existing_friend = Friend.query.filter_by(
        user_id=current_user.id, 
        friend_id=user_id
    ).first()
    
    if existing_friend:
        flash('You are already friends!', 'info')
        return redirect(url_for('user_posts', username=recipient.username))
    
    # Create new friend request
    friend_request = FriendRequest(
        sender_id=current_user.id, 
        recipient_id=user_id
    )
    db.session.add(friend_request)
    db.session.commit()
    
    # Create notification
    notification = Notification(
        user_id=user_id,
        content=f"{current_user.username} sent you a friend request",
        link=url_for('friends')
    )
    db.session.add(notification)
    db.session.commit()
    
    flash('Friend request sent!', 'success')
    return redirect(url_for('user_posts', username=recipient.username))


@app.route("/accept_friend_request/<int:request_id>", methods=['POST'])
@login_required
def accept_friend_request(request_id):
    form = AcceptRejectForm()
    if form.validate_on_submit():
        friend_request = FriendRequest.query.get_or_404(request_id)
        if friend_request.recipient_id != current_user.id:
            abort(403)
        
        friend_request.status = 'accepted'
        
        # Create friendship both ways
        friendship1 = Friend(user_id=current_user.id, friend_id=friend_request.sender_id)
        friendship2 = Friend(user_id=friend_request.sender_id, friend_id=current_user.id)
        
        db.session.add(friendship1)
        db.session.add(friendship2)
        db.session.commit()
        
        # Create notification
        notification = Notification(
            user_id=friend_request.sender_id,
            content=f"{current_user.username} accepted your friend request",
            link=url_for('user_posts', username=current_user.username)
        )
        db.session.add(notification)
        db.session.commit()
        
        flash('Friend request accepted!', 'success')
    else:
        flash('Invalid request', 'danger')
    return redirect(url_for('view_friend_requests'))


@app.route("/reject_friend_request/<int:request_id>", methods=['POST'])
@login_required
def reject_friend_request(request_id):
    form = AcceptRejectForm()
    if form.validate_on_submit():
        friend_request = FriendRequest.query.get_or_404(request_id)
        if friend_request.recipient_id != current_user.id:
            abort(403)
        
        friend_request.status = 'rejected'
        db.session.commit()
        flash('Friend request rejected!', 'info')
    else:
        flash('Invalid request', 'danger')
    return redirect(url_for('view_friend_requests'))

@app.route("/remove_friend/<int:friend_id>", methods=['POST'])
@login_required
def remove_friend(friend_id):
    form = AcceptRejectForm()
    if form.validate_on_submit():
        friendship1 = Friend.query.filter_by(user_id=current_user.id, friend_id=friend_id).first()
        friendship2 = Friend.query.filter_by(user_id=friend_id, friend_id=current_user.id).first()
        
        if friendship1 and friendship2:
            db.session.delete(friendship1)
            db.session.delete(friendship2)
            db.session.commit()
            flash('Friend removed!', 'info')
        else:
            flash('Friendship not found!', 'danger')
    else:
        flash('Invalid request', 'danger')
    return redirect(url_for('friends'))


@app.route("/messages")
@login_required
def messages():
    # Get all friends
    friends = Friend.query.filter_by(user_id=current_user.id).all()
    friend_users = [User.query.get(friend.friend_id) for friend in friends]
    
    # Get conversations only with friends
    conversations = []
    for friend in friend_users:
        last_message = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.recipient_id == friend.id)) |
            ((Message.sender_id == friend.id) & (Message.recipient_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()
        
        if last_message:
            unread_count = Message.query.filter_by(
                sender_id=friend.id,
                recipient_id=current_user.id,
                is_read=False
            ).count()
            
            # Calculate online status (5 minute threshold)
            is_online = friend.last_seen and (datetime.utcnow() - friend.last_seen).total_seconds() < 300
            
            conversations.append({
                'user': friend,
                'last_message': last_message,
                'unread_count': unread_count,
                'is_online': is_online
            })
    
    # Sort conversations by last message timestamp
    conversations.sort(key=lambda x: x['last_message'].timestamp, reverse=True)
    
    # Get all friends for the new message modal
    friends_for_modal = User.query.join(
        Friend, 
        (Friend.friend_id == User.id) & (Friend.user_id == current_user.id)
    ).all()
    
    return render_template('main/messages.html', 
                        conversations=conversations,
                        friends=friends_for_modal)

@app.route("/chat/<int:user_id>", methods=['GET', 'POST'])
@login_required
def chat(user_id):
    other_user = User.query.get_or_404(user_id)
    
    # Check if users are friends
    is_friend = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == user_id)) |
        ((Friend.user_id == user_id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if not is_friend:
        flash('You need to be friends to message this user', 'danger')
        return redirect(url_for('user_posts', username=other_user.username))
    
    form = MessageForm()
    
    if form.validate_on_submit():
        message = Message(
            content=form.content.data,
            sender_id=current_user.id,
            recipient_id=user_id
        )
        db.session.add(message)
        
        # Mark previous messages as read
        Message.query.filter_by(sender_id=user_id, recipient_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        
        # Emit socketio event
        socketio.emit('message', {
            'sender_id': current_user.id,
            'recipient_id': user_id,
            'content': form.content.data,
            'timestamp': str(datetime.utcnow())
        }, room=f'user_{user_id}')
        
        return redirect(url_for('chat', user_id=user_id))
    
    # Get all messages between current user and other user
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Mark received messages as read
    Message.query.filter_by(sender_id=user_id, recipient_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    
    # Get all friends for the sidebar
    friends = User.query.join(
        Friend, 
        (Friend.friend_id == User.id) & (Friend.user_id == current_user.id)
    ).all()
    
    return render_template('chat/chat.html', 
                         form=form, 
                         messages=messages, 
                         other_user=other_user,
                         friends=friends,
                         active_conversation={'user': other_user})

@app.route('/start-conversation', methods=['POST'])
@login_required
def start_conversation():
    recipient_id = request.form.get('recipient_id')
    content = request.form.get('content')
    
    if not recipient_id or not content:
        flash('Recipient and message content are required', 'danger')
        return redirect(url_for('messages'))
    
    other_user = User.query.get_or_404(recipient_id)
    
    # Check if users are friends
    is_friend = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == other_user.id)) |
        ((Friend.user_id == other_user.id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if not is_friend:
        flash('You need to be friends to message this user', 'danger')
        return redirect(url_for('messages'))
    
    # Create new message
    message = Message(
        content=content,
        sender_id=current_user.id,
        recipient_id=other_user.id
    )
    db.session.add(message)
    db.session.commit()
    
    return redirect(url_for('chat', user_id=other_user.id))

@socketio.on('join')
def on_join(data):
    user_id = data['user_id']
    join_room(f'user_{user_id}')

@socketio.on('message')
def handle_message(data):
    recipient_id = data['recipient_id']
    emit('message', data, room=f'user_{recipient_id}')


@app.route("/groups")
@login_required
def groups():
    # Get groups the user is a member of
    user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()
    groups = [member.group for member in user_groups]
    
    # Get suggested public groups
    all_groups = Group.query.filter_by(is_public=True).all()
    suggested = [group for group in all_groups if group not in [g.group for g in user_groups]]
    
    return render_template('groups/groups.html', groups=groups, suggested=suggested)

@app.route("/group/new", methods=['GET', 'POST'])
@login_required
def create_group():
    form = GroupForm()
    if form.validate_on_submit():
        group = Group(
            name=form.name.data,
            description=form.description.data,
            is_public=(form.is_public.data == 'public'),
            creator_id=current_user.id
        )
        if form.group_pic.data:
            picture_file = save_picture(form.group_pic.data, 'group_pics')
            group.group_pic = picture_file
        
        db.session.add(group)
        db.session.flush()  # <-- This is the fix: assigns group.id
        
        # Add creator as admin member
        member = GroupMember(
            user_id=current_user.id,
            group_id=group.id,
            is_admin=True,
            joined_at=datetime.utcnow()  # if you have this field, add it
        )
        db.session.add(member)
        db.session.commit()
        
        flash('Your group has been created!', 'success')
        return redirect(url_for('group', group_id=group.id))
    return render_template('groups/create_group.html', form=form)




@app.route("/group/<int:group_id>")
@login_required
def group(group_id):
    group = Group.query.get_or_404(group_id)
    is_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()

    if not group.is_public and not is_member:
        abort(403)

    posts = GroupPost.query.filter_by(group_id=group_id).order_by(GroupPost.timestamp.desc()).all()
    members = GroupMember.query.filter_by(group_id=group_id).all()

    form = PostForm()  # ✅ Add this

    return render_template('groups/group.html', 
                           group=group, 
                           posts=posts, 
                           members=members, 
                           is_member=is_member,
                           form=form)  # ✅ Pass form



@app.route("/group/<int:group_id>/join", methods=['POST'])
@login_required
def join_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if already a member
    existing_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if existing_member:
        flash('You are already a member of this group!', 'info')
        return redirect(url_for('group', group_id=group_id))
    
    # Add as member
    member = GroupMember(
        user_id=current_user.id,
        group_id=group_id,
        is_admin=False
    )
    db.session.add(member)
    db.session.commit()
    
    flash(f'You have joined {group.name}!', 'success')
    return redirect(url_for('group', group_id=group_id))

@app.route("/group/<int:group_id>/leave", methods=['POST'])
@login_required
def leave_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if member
    member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not member:
        flash('You are not a member of this group!', 'danger')
        return redirect(url_for('group', group_id=group_id))
    
    # Check if creator (creator can't leave)
    if group.creator_id == current_user.id:
        flash('As the group creator, you cannot leave. You must delete the group instead.', 'danger')
        return redirect(url_for('group', group_id=group_id))
    
    db.session.delete(member)
    db.session.commit()
    
    flash(f'You have left {group.name}!', 'info')
    return redirect(url_for('groups'))

@app.route("/group/<int:group_id>/post/new", methods=['GET', 'POST'])
@login_required
def new_group_post(group_id):
    group = Group.query.get_or_404(group_id)
    is_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    
    if not group.is_public and not is_member:
        abort(403)
    
    form = PostForm()
    if form.validate_on_submit():
        post = GroupPost(
            content=form.content.data,
            user_id=current_user.id,
            group_id=group_id
        )
        if form.image.data:
            picture_file = save_picture(form.image.data, 'post_pics')
            post.image = picture_file
        
        db.session.add(post)
        db.session.commit()
        
        # Create notifications for group members
        members = GroupMember.query.filter(GroupMember.user_id != current_user.id, GroupMember.group_id == group_id).all()
        for member in members:
            notification = Notification(
                user_id=member.user_id,
                content=f"{current_user.username} posted in {group.name}",
                link=url_for('group', group_id=group_id)
            )
            db.session.add(notification)
        
        db.session.commit()
        
        flash('Your post has been created!', 'success')
        return redirect(url_for('group', group_id=group_id))
    return render_template('create_post.html', form=form, legend='New Group Post')










@app.route('/group_post/<int:post_id>/like', methods=['POST'])
@login_required
def like_group_post(post_id):
    post = GroupPost.query.get_or_404(post_id)
    reaction = request.json.get('reaction', 'like')
    
    like = GroupPostLike.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    
    if like:
        if like.reaction == reaction:
            # User clicked same reaction - unlike
            db.session.delete(like)
            action = 'unliked'
        else:
            # User changed reaction
            like.reaction = reaction
            action = 'changed'
    else:
        # New like
        like = GroupPostLike(user_id=current_user.id, post_id=post.id, reaction=reaction)
        db.session.add(like)
        action = 'liked'
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'action': action,
        'likes_count': post.likes.count(),
        'current_reaction': reaction if action != 'unliked' else None
    })

@app.route("/group_post/<int:post_id>/comment", methods=['POST'])
@login_required
def comment_group_post(post_id):
    post = GroupPost.query.get_or_404(post_id)
    content = request.form.get('content')
    
    if not content:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Comment cannot be empty'}), 400
        flash('Comment cannot be empty', 'danger')
        return redirect(url_for('group', group_id=post.group_id))
    
    comment = GroupPostComment(
        content=content,
        user_id=current_user.id,
        post_id=post.id
    )
    db.session.add(comment)
    db.session.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'comment': {
                'content': comment.content,
                'author': comment.author.username,
                'profile_pic': url_for('static', filename='profile_pics/' + comment.author.profile_pic),
                'timestamp': comment.timestamp.strftime('%Y-%m-%d %H:%M')
            }
        })
    
    flash('Your comment has been added!', 'success')
    return redirect(url_for('group', group_id=post.group_id))














@app.route("/notifications")
@login_required
def notifications():
    # Get all notifications for current user
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.timestamp.desc())\
        .all()
    
    # Mark all as read
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    
    return render_template('main/notifications.html', notifications=notifications)

@app.route("/search")
@login_required
def search():
    query = request.args.get('q')
    if not query:
        return redirect(url_for('home'))  # Define your home route
    
    users = User.query.filter(User.username.ilike(f'%{query}%')).all()
    posts = Post.query.filter(Post.content.ilike(f'%{query}%')).all()
    groups = Group.query.filter(Group.name.ilike(f'%{query}%')).all()

    return render_template('main/search.html',
                           users=users,
                           posts=posts,
                           groups=groups,
                           query=query)

# SocketIO events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

@socketio.on('message')
def handle_message(data):
    if not current_user.is_authenticated:
        return
    
    recipient_id = data['recipient_id']
    content = data['content']
    
    # Save message to database
    message = Message(
        content=content,
        sender_id=current_user.id,
        recipient_id=recipient_id
    )
    db.session.add(message)
    db.session.commit()
    
    # Emit to recipient
    send({
        'sender_id': current_user.id,
        'recipient_id': recipient_id,
        'content': content,
        'timestamp': str(datetime.utcnow())
    }, room=f'user_{recipient_id}')

# Error handlers

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@socketio.on('like_post')
def handle_like(data):
    post_id = data['post_id']
    likes_count = Like.query.filter_by(post_id=post_id).count()
    emit('update_likes', {
        'post_id': post_id,
        'likes_count': likes_count
    }, broadcast=True)

@main.route('/start-conversation', methods=['POST'])
@login_required
def start_conversation():
    recipient_id = request.form.get('recipient_id')
    message_content = request.form.get('message')
    
    # Check if conversation already exists
    existing_conversation = db.session.query(Message).filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == recipient_id)) |
        ((Message.sender_id == recipient_id) & (Message.recipient_id == current_user.id))
    ).first()
    
    if existing_conversation:
        # Create new message in existing conversation
        message = Message(
            content=message_content,
            sender_id=current_user.id,
            recipient_id=recipient_id
        )
        db.session.add(message)
        db.session.commit()
        
        return redirect(url_for('main.chat', user_id=recipient_id))
    else:
        # Create new conversation with first message
        message = Message(
            content=message_content,
            sender_id=current_user.id,
            recipient_id=recipient_id
        )
        db.session.add(message)
        db.session.commit()
        
        return redirect(url_for('main.chat', user_id=recipient_id))

# Error handlers
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/friends")
@login_required
def friends():
    friends = Friend.query.filter_by(user_id=current_user.id).all()
    friend_users = [User.query.get(friend.friend_id) for friend in friends]
    
    # Get pending received requests with sender info
    received_requests = db.session.query(FriendRequest, User).join(
        User, FriendRequest.sender_id == User.id
    ).filter(
        FriendRequest.recipient_id == current_user.id,
        FriendRequest.status == 'pending'
    ).all()
    
    # Get pending sent requests with recipient info
    sent_requests = db.session.query(FriendRequest, User).join(
        User, FriendRequest.recipient_id == User.id
    ).filter(
        FriendRequest.sender_id == current_user.id,
        FriendRequest.status == 'pending'
    ).all()
    
    # Get suggested friends (non-friends, no pending requests)
    all_users = User.query.filter(User.id != current_user.id).all()
    suggested = []
    
    for user in all_users:
        is_friend = Friend.query.filter_by(user_id=current_user.id, friend_id=user.id).first()
        has_received_request = FriendRequest.query.filter_by(
            sender_id=user.id, 
            recipient_id=current_user.id,
            status='pending'
        ).first()
        has_sent_request = FriendRequest.query.filter_by(
            sender_id=current_user.id, 
            recipient_id=user.id,
            status='pending'
        ).first()
        
        if not is_friend and not has_received_request and not has_sent_request:
            suggested.append(user)
    
    # Create form instances
    remove_form = AcceptRejectForm()
    request_form = AcceptRejectForm()
    
    return render_template('main/friends.html', 
                         friends=friend_users, 
                         received_requests=received_requests,
                         sent_requests=sent_requests,
                         suggested=suggested,
                         remove_form=remove_form,
                         request_form=request_form)

@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    reaction = request.json.get('reaction', 'like')
    
    like = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    
    if like:
        if like.reaction == reaction:
            # User clicked same reaction - unlike
            db.session.delete(like)
            action = 'unliked'
        else:
            # User changed reaction
            like.reaction = reaction
            action = 'changed'
    else:
        # New like
        like = Like(user_id=current_user.id, post_id=post.id, reaction=reaction)
        db.session.add(like)
        action = 'liked'
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'action': action,
        'likes_count': post.likes_count,
        'current_reaction': reaction if action != 'unliked' else None
    })

@socketio.on('like_post')
def handle_like(data):
    post_id = data['post_id']
    post = Post.query.get(post_id)
    if post:
        likes_count = post.likes_count
        emit('update_likes', {
            'post_id': post_id,
            'likes_count': likes_count
        }, broadcast=True)

@app.route("/user/<string:username>")
@login_required
def user_posts(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user).order_by(Post.timestamp.desc()).all()
    
    # Check friend status and requests
    is_friend = Friend.query.filter_by(
        user_id=current_user.id, 
        friend_id=user.id
    ).first()
    
    friend_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        recipient_id=user.id
    ).first()
    
    # Get the user's friends (mutual friends if not current user)
    friends_query = Friend.query.filter_by(user_id=user.id).all()
    friends = [User.query.get(friend.friend_id) for friend in friends_query]
    
    # Get mutual friends if viewing another user's profile
    mutual_friends = []
    if user.id != current_user.id:
        current_user_friends = {f.friend_id for f in Friend.query.filter_by(user_id=current_user.id).all()}
        viewed_user_friends = {f.friend_id for f in Friend.query.filter_by(user_id=user.id).all()}
        mutual_friend_ids = current_user_friends & viewed_user_friends
        mutual_friends = [User.query.get(fid) for fid in mutual_friend_ids]
    
    # Only create and pass the form if it's the current user's profile
    form = None
    if user.id == current_user.id:
        form = PostForm()
    
    return render_template(
        'main/user_posts.html', 
        posts=posts, 
        user=user,
        is_friend=is_friend,
        friend_request=friend_request,
        friends=friends[:9],  # Show first 9 friends
        mutual_friends=mutual_friends,
        friends_count=len(friends),
        form=form  # Pass the form to the template
    )


# Add to your routes section

@app.route('/live', methods=['GET', 'POST'])
@login_required
def live():
    # Check if user is already live
    current_stream = LiveStream.query.filter_by(user_id=current_user.id, is_live=True).first()
    
    if request.method == 'POST':
        if current_stream:
            flash('You are already live!', 'warning')
            return redirect(url_for('view_stream', stream_id=current_stream.id))
        
        # Generate stream key and create new stream
        stream_key = secrets.token_urlsafe(16)
        stream = LiveStream(
            user_id=current_user.id,
            title=f"{current_user.username}'s Stream",
            description="",
            stream_key=stream_key,
            is_live=True
        )
        
        db.session.add(stream)
        db.session.commit()
        
        return redirect(url_for('view_stream', stream_id=stream.id))
    
    # If GET request, show the form
    form = LiveStreamForm()
    return render_template('live/create_stream.html', form=form, current_stream=current_stream)

@app.route('/live/list')
@login_required
def live_list():
    live_streams = LiveStream.query.filter_by(is_live=True).order_by(LiveStream.start_time.desc()).all()
    return render_template('live/live_list.html', live_streams=live_streams)

@app.route('/live/<int:stream_id>')
@login_required
def view_stream(stream_id):
    stream = LiveStream.query.get_or_404(stream_id)
    
    # If viewer is not the streamer, increment viewer count
    if stream.user_id != current_user.id:
        existing_viewer = LiveViewer.query.filter_by(
            stream_id=stream.id,
            user_id=current_user.id
        ).first()
        
        if not existing_viewer:
            viewer = LiveViewer(
                stream_id=stream.id,
                user_id=current_user.id
            )
            db.session.add(viewer)
            stream.viewers_count += 1
            db.session.commit()
    
    return render_template('live/view_stream.html', stream=stream)

@app.route('/live/end/<int:stream_id>', methods=['POST'])
@login_required
def end_stream(stream_id):
    form = FlaskForm()  # This will validate the CSRF token
    
    if form.validate_on_submit():
        stream = LiveStream.query.get_or_404(stream_id)
        
        if stream.user_id != current_user.id:
            abort(403)
        
        stream.is_live = False
        stream.end_time = datetime.utcnow()
        db.session.commit()
        
        flash('Your live stream has ended', 'info')
        return redirect(url_for('user_posts', username=current_user.username))
    
    # If CSRF validation fails
    flash('Could not end stream. Please try again.', 'danger')
    return redirect(url_for('view_stream', stream_id=stream_id))


# Add to your SocketIO events section
@socketio.on('join_stream')
def handle_join_stream(data):
    stream_id = data['stream_id']
    join_room(f'stream_{stream_id}')
    
    # Update viewer count in real-time
    stream = LiveStream.query.get(stream_id)
    if stream:
        emit('viewer_update', {
            'stream_id': stream_id,
            'viewers_count': stream.viewers_count
        }, room=f'stream_{stream_id}')

@socketio.on('leave_stream')
def handle_leave_stream(data):
    stream_id = data['stream_id']
    leave_room(f'stream_{stream_id}')
    
    # Update viewer count in real-time
    stream = LiveStream.query.get(stream_id)
    if stream and current_user.is_authenticated:
        viewer = LiveViewer.query.filter_by(
            stream_id=stream_id,
            user_id=current_user.id
        ).first()
        
        if viewer:
            db.session.delete(viewer)
            stream.viewers_count -= 1
            db.session.commit()
            
            emit('viewer_update', {
                'stream_id': stream_id,
                'viewers_count': stream.viewers_count
            }, room=f'stream_{stream_id}')

@socketio.on('stream_chat')
def handle_stream_chat(data):
    stream_id = data['stream_id']
    message = data['message']
    
    if current_user.is_authenticated:
        emit('new_chat_message', {
            'user_id': current_user.id,
            'username': current_user.username,
            'profile_pic': current_user.profile_pic,
            'message': message,
            'timestamp': str(datetime.utcnow())
        }, room=f'stream_{stream_id}')

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    stream_id = data['stream_id']
    offer = data['offer']
    # Broadcast the offer to all viewers
    emit('webrtc_offer', {
        'offer': offer,
        'streamer_id': request.sid
    }, room=f'stream_{stream_id}', skip_sid=request.sid)

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    streamer_sid = data['streamer_sid']
    answer = data['answer']
    # Send the answer back to the streamer
    emit('webrtc_answer', {
        'answer': answer
    }, room=streamer_sid)

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    target_sid = data['target_sid']
    candidate = data['candidate']
    # Forward the ICE candidate
    emit('ice_candidate', {
        'candidate': candidate
    }, room=target_sid)


# Add these to your existing Socket.IO events in app.py

@socketio.on('join_stream_chat')
def handle_join_stream_chat(data):
    if current_user.is_authenticated:
        join_room(f'stream_chat_{data["stream_id"]}')
        print(f"User {current_user.username} joined stream chat {data['stream_id']}")

@socketio.on('leave_stream_chat')
def handle_leave_stream_chat(data):
    if current_user.is_authenticated:
        leave_room(f'stream_chat_{data["stream_id"]}')

@socketio.on('stream_chat_message')
def handle_stream_chat_message(data):
    if not current_user.is_authenticated:
        return
    
    stream_id = data['stream_id']
    message = data['message']
    
    print(f"Received chat message for stream {stream_id}: {message}")
    
    emit('new_stream_message', {
        'stream_id': stream_id,
        'user_id': current_user.id,
        'username': current_user.username,
        'profile_pic': current_user.profile_pic,
        'message': message,
        'timestamp': datetime.utcnow().isoformat()
    }, room=f'stream_chat_{stream_id}')


@app.route('/download/<folder>/<filename>')
@login_required
def download_image(filename, folder):
    # Validate folder to prevent directory traversal
    if folder not in ['post_pics', 'profile_pics', 'group_pics']:
        abort(404)
    
    # Get the absolute path to the upload folder
    upload_folder = app.config[f'{folder.upper()}_FOLDER']
    directory = os.path.join(app.root_path, upload_folder)
    file_path = os.path.join(directory, filename)
    
    # Check if file exists
    if not os.path.exists(file_path):
        abort(404)
    
    # Determine the mimetype based on file extension
    mimetype = 'application/octet-stream'
    if filename.lower().endswith('.png'):
        mimetype = 'image/png'
    elif filename.lower().endswith(('.jpg', '.jpeg')):
        mimetype = 'image/jpeg'
    elif filename.lower().endswith('.gif'):
        mimetype = 'image/gif'
    
    # Send the file for download with original filename
    return send_file(
        file_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )

@app.route('/post/<int:post_id>/delete_image', methods=['POST'])
@login_required
def delete_image(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Check if the current user is the author
    if post.author != current_user:
        abort(403)
    
    if post.image:
        try:
            # Delete the image file
            image_path = os.path.join(app.root_path, app.config['POST_PICS_FOLDER'], post.image)
            if os.path.exists(image_path):
                os.remove(image_path)
            
            # Remove the image reference from the post
            post.image = None
            db.session.commit()
            
            flash('Image deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error deleting image.', 'danger')
            app.logger.error(f"Error deleting image: {str(e)}")
    
    return redirect(url_for('post', post_id=post.id))

if __name__ == '__main__':
    socketio.run(app, debug=True)