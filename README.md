# gamekeeper
Role Based Access Control System simulation

Gamekeeper is a Role Based Access Control System simulation built using Flask
It has provisions to:
- Manage resources
- Manage roles
- Manage users
- Assign roles to users

The three supported Actions are Read, Write and Delete

The entire RBAC logic is implemented in the models.py file

This system can be extrapolated to implement RBAC in a web application, with minimal effort

Dependencies
- flask
- flask-wtf
- flask-sqlalchemy
- sqlalchemy-migrate

You will also need flask-login or an appropriate extension to implement this RBAC in your login process
