from flask_wtf import Form
from wtforms import StringField, BooleanField
from wtforms.fields import SelectMultipleField, HiddenField, PasswordField, IntegerField, SelectField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import Length, Email, InputRequired, EqualTo
from wtforms import widgets


class MultiCheckboxField(SelectMultipleField):
    """
    A multiple-select, except displays a list of checkboxes.

    Iterating the field will produce subfields, allowing custom rendering of
    the enclosed checkbox fields.

    http://wtforms.readthedocs.io/en/1.0.4/specific_problems.html#specialty-field-tricks
    """
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class RegistrationForm(Form):
    name = StringField('name', validators=[InputRequired(message='Name field cannot be left blank')])
    email = EmailField('email', validators=[Email(), InputRequired(message='Email field cannot be left blank')])
    user_roles = MultiCheckboxField('Roles')


class ResourceForm(Form):
    name = StringField('name', validators=[InputRequired(message='Name field cannot be left blank')])

class RoleForm(Form):
    name = StringField('name', validators=[InputRequired(message='Name field cannot be left blank')])
    read_resources = MultiCheckboxField('ReadResources')
    write_resources = MultiCheckboxField('WriteResources')
    delete_resources = MultiCheckboxField('DeleteResources')

class AccessForm(Form):
    users = SelectField("users")
    resources = SelectField("resources")
    actions = SelectField("actions")