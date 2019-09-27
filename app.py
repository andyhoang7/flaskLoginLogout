from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, TextField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired


app = Flask(__name__)
login = LoginManager(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "yello"

db = SQLAlchemy(app)



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)  
    posts = db.relationship('Posts', backref='author', lazy='dynamic')

    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
      
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    body = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        
db.create_all()

class NewPost(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    body = StringField('Body', validators=[DataRequired()])
    author_id = StringField('Author', validators=[DataRequired()])
    submit = SubmitField("Post")

class NewUser(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Body', validators=[DataRequired()])
    submit = SubmitField("Post")
    
    
@login.user_loader
def load_user(id):
  return User.query.get(int(id))

@app.route('/')
def home():
   return render_template('layout.html')

@app.route('/profile')
@login_required
def profile():
   return render_template('profile.html')
 
@app.route('/logout')
def logout():
   logout_user()
   flash('please come Back.........', 'info')
   return redirect(url_for('login'))

@app.route('/login', methods=['POST', 'GET'])
def login():
  if request.method == 'POST':
      user = User.query.filter_by(email=request.form["email"]).first()
      if user is not None and user.check_password(request.form["password"]):
        login_user(user)
        flash('Welcome!', 'success')
        return redirect(url_for('profile'))
      else:
        flash('Sorry, your username or password is incorrect.', 'danger')
        return redirect(url_for('login'))
  else:
      return render_template('login.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():       
    error = None
    form = NewUser()
    if request.method == 'POST':        
        new_userx = User(email=form.email.data)
        new_userx.set_password(form.password.data)
        db.session.add(new_userx)
        db.session.commit()
        flash ("Thank you for signing up", "success")
        login_user(new_userx)
        return redirect(url_for('profile'))
    return render_template('signup.html')   


@app.route('/profile/posts')
def posts():
    posts = Posts.query.filter_by(author_id=current_user.id).all()
    return render_template('posts.html', posts = posts)

@app.route('/profile/posts/create', methods=['POST', 'GET'])
def createpost():
    error = None
    new_article = NewPost()
    if request.method == 'POST':        
        new_post = Posts(title=new_article.title.data, 
                         body=new_article.body.data) 
                         
        current_user.posts.append(new_post)
        db.session.add(new_post)
        db.session.commit()
        flash ("You have created a new post", 'success')
        return redirect(url_for('posts'))
    return render_template('newpost.html', form=new_article)

if __name__ == '__main__':
  app.run(debug=True)