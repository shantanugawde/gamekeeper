from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import and_

roleuser = db.Table('roleuser',
                    db.Column('user_id', db.Integer,
                              db.ForeignKey('users.id')),
                    db.Column('role_id', db.String, db.ForeignKey('roles.id'))
                    )


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True, index=True)
    roles = db.relationship('Role',
                            secondary=roleuser,
                            backref=db.backref('users', lazy='dynamic'),
                            lazy='dynamic')

    def add_role(self, role):
        if role is not None and not self.has_role(role):
            self.roles.append(role)

    def has_role(self, role):
        return self.roles.filter(roleuser.c.role_id == role.id).count() > 0

    def remove_role(self, role):
        if role is not None and self.has_role(role):
            self.roles.remove(role)

    def can(self, resource, action):
        if self.roles.count() > 0:
            for r in self.roles:
                for res in r.myresources:
                    if res.assigned_resource == resource and (res.actions & action) == action:
                        return True
        return False

    def __repr__(self):
        return '<User %r>' % (self.name)


class RoleResourceMap(db.Model):
    __tablename__ = 'roleresourcemap'
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    resource_id = db.Column(db.String, db.ForeignKey('resources.id'))
    actions = db.Column(db.Integer)
    assigned_resource = db.relationship(
        'Resource', backref=db.backref('resources'))


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    myresources = db.relationship('RoleResourceMap', backref=db.backref(
        'resources'))

    def change_resource_map(self, resource, actions):
        if not self.has_resource(resource):
            rr_item = RoleResourceMap(assigned_resource=resource, actions=actions)
            self.myresources.append(rr_item)
        else:
            rr_item = RoleResourceMap.query.filter(and_(RoleResourceMap.resource_id == resource.id,
                                                        RoleResourceMap.role_id == self.id)).first()
            rr_item.actions = actions
            db.session.commit()


    def has_resource(self, resource):
        return RoleResourceMap.query.filter(and_(RoleResourceMap.resource_id == resource.id,
                                                 RoleResourceMap.role_id == self.id)).first() is not None

    def can(self, resource, action):
        for res in self.myresources:
            if res.assigned_resource == resource and (res.actions & action) == action:
                return True
        return False

    # Not used
    @staticmethod
    def insert_roles():
        roles = ['User', 'Moderator', 'Administrator']
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % (self.name)


class ActionType:
    READ = 0x01
    WRITE = 0x02
    DELETE = 0x04


class Resource(db.Model):
    __tablename__ = 'resources'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)

    def __repr__(self):
        return '<Resource %r>' % (self.name)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
