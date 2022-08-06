import os

from flask import abort, Flask, request, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, AddComment
from functools import wraps
from flask_gravatar import Gravatar
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure login manager for authentication
login_manager = LoginManager()
login_manager.init_app(app)

# Create the gravatar profile image
gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(250), nullable=False)
    user_email = db.Column(db.String(250), unique=True, nullable=False)
    user_password = db.Column(db.String(250), nullable=False)

    # This will act like a List of BlogPost objects attached to each User.
    # The 'author' refers to the author property in the BlogPost Class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("BlogComments", back_populates="comment_author")


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Create Foreign key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    # Create a refence to the BlogComments object, the parent_post refers to the property comments in BC class.
    comments = relationship("BlogComments", back_populates="parent_post")


class BlogComments(db.Model):
    __tablename__ = 'blog_comments'
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)

    # Create Foreign key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # "comments" refers to the comments property in the User class
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    # "comments" here refers to the comments property in the Blogpost class
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()


def admin_only(func):
    @wraps(func)

    def decorator(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            print('user_not_authenticated')
            return abort(403)
        # Otherwise continue with route function
        return func(*args, **kwargs)

    return decorator


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        inputted_name = request.form.get('name')
        inputted_email = request.form.get('email')
        inputted_password = request.form.get('password')
        # Can also use (only works on WTForms):
        # inputted_name = form.name.data
        # inputted_email = form.email.data
        # inputted_password = form.password.data
        user = User.query.filter_by(user_email=inputted_email).first()
        if user:
            flash('This email already exists. Please login.')
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(
                inputted_password,
                method='pbkdf2:sha256',
                salt_length=8,
            )
            new_user = User(
                user_name=inputted_name,
                user_email=inputted_email,
                user_password=hashed_password,
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        inputted_email = request.form.get('email')
        inputted_password = request.form.get('password')
        user = User.query.filter_by(user_email=inputted_email).first()
        if not user:
            flash('This user does not exist!')
        elif not check_password_hash(user.user_password, inputted_password):
            flash('This email and password combination does not exist.')
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = AddComment()

    if form.validate_on_submit():
        new_comment = BlogComments(
            author_id=current_user.id,
            post_id=requested_post.id,
            comment=request.form.get('comment'),
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=request.form.get('title'),
            author_id=current_user.id,
            subtitle=request.form.get('subtitle'),
            body=request.form.get('body'),
            img_url=request.form.get('img_url'),
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = request.form.get('title')
        post.subtitle = request.form.get('subtitle')
        post.img_url = request.form.get('img_url')
        post.author = request.form.get('author')
        post.body = request.form.get('body')
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
