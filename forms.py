from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    bvn = StringField('BVN', validators=[DataRequired(), Length(min=11, max=11)])
    card_number = StringField('Card Number', validators=[DataRequired(), Length(min=16, max=16)])
    pin = PasswordField('PIN', validators=[DataRequired(), Length(min=4, max=4)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    pin = PasswordField('Bank PIN', validators=[DataRequired()])
    submit = SubmitField('Login')
