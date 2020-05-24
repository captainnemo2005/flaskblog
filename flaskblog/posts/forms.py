from wtforms import StringField,TextAreaField,SubmitField
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators = [DataRequired()])
    submit = SubmitField('Post')

