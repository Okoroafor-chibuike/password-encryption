from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from cryptography.hazmat.primitives import serialization

from models import db, User
from forms import RegisterForm, LoginForm
from utils import decrypt_data_rsa, encrypt_data_rsa

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# load public and private keys
with open("./keys/public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
    )

with open("./keys/private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect('/dashboard')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Encrypt sensitive data with the public key
        encrypted_bvn = encrypt_data_rsa(public_key, form.bvn.data)
        encrypted_card_number = encrypt_data_rsa(public_key, form.card_number.data)
        encrypted_pin = encrypt_data_rsa(public_key, form.pin.data)

        user = User(name=form.name.data, address=form.address.data,
                    bvn=encrypted_bvn, card_number=encrypted_card_number, pin=encrypted_pin)
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.username.data).first()
        if user and decrypt_data_rsa(private_key, user.pin) == form.pin.data:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('admin_panel' if user.is_admin else 'dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)


# Admin panel (admin-only access)
@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Access denied: Admins only', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter_by(is_admin=False).all()
    user_data = [
        {
            'id': user.id,
            'name': user.name,
            'address': user.address,
            'bvn': decrypt_data_rsa(private_key, user.bvn),
            'card_number': decrypt_data_rsa(private_key, user.card_number),
            'pin': decrypt_data_rsa(private_key, user.pin)
        } for user in users
    ]
    return render_template('admin.html', users=user_data)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    else:
        flash('User not found', 'danger')

    return redirect('/admin')


def mask_string(value, visible_chars):
    if not value:
        return ""
    masked_length = max(len(value) - visible_chars, 0)
    return '*' * masked_length + value[-visible_chars:]

# User dashboard (normal user access)
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        flash('Access denied: User-only area', 'danger')
        return redirect(url_for('admin_panel'))

    user_data = {
        'name': current_user.name,
        'address': current_user.address,
        'bvn': decrypt_data_rsa(private_key, current_user.bvn),
        'card_number': decrypt_data_rsa(private_key, current_user.card_number),
        'pin': decrypt_data_rsa(private_key, current_user.pin)
    }
    return render_template('dashboard.html', user=user_data, mask_string=mask_string)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Initialize the database
    app.run(debug=True)
