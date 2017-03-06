from app import app, db
from flask import render_template, flash, redirect, url_for, request, g, jsonify
from flask_login import login_required, current_user, logout_user, login_user
from .forms import *
from .models import *

selected_roles = list()


@app.route('/')
@app.route('/index', methods=['GET', 'POST'])
def index():
    form = AccessForm()
    all_users = User.query.all()
    all_res = Resource.query.all()
    form.users.choices = [(str(x.id), str(x.name)) for x in all_users]
    form.resources.choices = [(str(x.id), str(x.name)) for x in all_res]
    form.actions.choices = [(str(ActionType.READ), "Read"), (str(ActionType.WRITE), "Write"),
                            (str(ActionType.DELETE), "Delete")]
    isempty = False
    if len(all_res) == 0 or len(all_users) == 0:
        isempty = True
    if form.validate_on_submit():
        u = User.query.filter_by(id=int(form.users.data)).first()
        r = Resource.query.filter_by(id=int(form.resources.data)).first()
        a = int(form.actions.data)
        if (u.can(r, a)):
            g.acc_status = "true"
        else:
            g.acc_status = "false"
    return render_template('index.html', form=form, title="Access Check", isempty=isempty)


# Users
@app.route('/users', methods=['GET', 'POST'])
def users():
    users = User.query.all()
    all_roles = Role.query.all()
    return render_template('users.html', title="Users", users=users, allroles=all_roles)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()
    all_roles = Role.query.all()
    form.user_roles.choices = [(str(x.id), x.name) for x in all_roles]
    if len(all_roles) > 0:
        noroles = False
        g.myerror = ""
        if form.validate_on_submit():
            selected_roles.clear()

            for myrole in form.user_roles:
                if myrole.checked:
                    selected_roles.append(myrole.data)

            u = User(name=form.name.data, email=form.email.data)
            checkuser = User.query.filter_by(email=form.email.data).first()
            if checkuser is None:
                db.session.add(u)

                if len(selected_roles) > 0:
                    for role in selected_roles:
                        u.add_role(Role.query.filter_by(id=role).first())
                    db.session.commit()
                    return redirect(url_for("users"))
                else:
                    g.myerror = "You must select at least one role"
            else:
                g.myerror = "This user already exists"
    else:
        noroles = True
    return render_template('registration.html', title="Add User", form=form, isedit=False, cur_roles=[], user=None, noroles=noroles)


@app.route('/edituser/<userid>', methods=['GET', 'POST'])
def edituser(userid):
    form = RegistrationForm()
    all_roles = Role.query.all()
    userid = int(userid)
    cur_user = User.query.filter_by(id=userid).first()
    if cur_user is None:
        return render_template('cust_error.html', title='User Not Found', msg="User you are looking for does not exist")
    else:
        form.user_roles.choices = [(str(x.id), x.name) for x in all_roles]
        g.myerror = ""

        # Populate fields with existing data
        cur_roles = [str(x.id) for x in cur_user.roles]
        if form.validate_on_submit():
            selected_roles.clear()

            for myrole in form.user_roles:
                if myrole.checked:
                    selected_roles.append(int(myrole.data))

            if len(selected_roles) > 0:
                for role in all_roles:
                    if role.id in selected_roles:
                        if not cur_user.has_role(role):
                            cur_user.add_role(role)
                    else:
                        if cur_user.has_role(role):
                            cur_user.remove_role(role)
                cur_user.email = form.email.data
                cur_user.name = form.name.data
                db.session.commit()
                return redirect(url_for("users"))
            else:
                g.myerror = "You must select at least one role"
        return render_template('registration.html', title="Edit User", form=form, isedit=True, cur_roles=cur_roles,
                               user=cur_user)


@app.route('/deleteuser/<userid>', methods=['GET', 'POST'])
def deleteuser(userid):
    userid = int(userid)
    cur_user = User.query.filter_by(id=userid).first()
    if cur_user is not None:
        db.session.delete(cur_user)
        db.session.commit()
    return redirect(url_for("users"))


# Resources
@app.route('/resources', methods=['GET', 'POST'])
def resources():
    all_resources = Resource.query.all()
    return render_template('resources.html', title="Resources", all_resources=all_resources)


@app.route('/addresource', methods=['GET', 'POST'])
def addresource():
    form = ResourceForm()
    g.myerror = ""
    if form.validate_on_submit():
        r = Resource(name=form.name.data)
        db.session.add(r)
        db.session.commit()
        return redirect(url_for('resources'))
    return render_template('addresource.html', title="Add Resource", form=form, isedit=False, res=None)


@app.route('/editresource/<resid>', methods=['GET', 'POST'])
def editresource(resid):
    form = ResourceForm()
    resid = int(resid)
    cur_res = Resource.query.filter_by(id=resid).first()
    if cur_res is None:
        return render_template('cust_error.html', title='Resource Not Found', msg="Resource you are looking for does not exist")
    else:
        if form.validate_on_submit():
            cur_res.name = form.name.data
            db.session.commit()
            return redirect(url_for('resources'))
        return render_template('addresource.html', title="Edit Resource", form=form, isedit=True, res=cur_res)


@app.route('/deleteresource/<resid>', methods=['GET', 'POST'])
def deleteresource(resid):
    resid = int(resid)
    cur_res = Resource.query.filter_by(id=resid).first()
    if cur_res is not None:
        db.session.delete(cur_res)
        db.session.commit()
    return redirect(url_for("resources"))


# Role
@app.route('/roles', methods=['GET', 'POST'])
def roles():
    all_roles = Role.query.all()
    all_res = Resource.query.all()

    return render_template('roles.html', title="Roles", all_roles=all_roles, all_res=all_res)


@app.route('/addrole', methods=['GET', 'POST'])
def addrole():
    form = RoleForm()
    g.myerror = ""
    all_res = Resource.query.all()
    form.read_resources.choices = [(str(x.id), str(ActionType.READ)) for x in all_res]
    form.write_resources.choices = [(str(x.id), str(ActionType.WRITE)) for x in all_res]
    form.delete_resources.choices = [(str(x.id), str(ActionType.DELETE)) for x in all_res]

    if form.validate_on_submit():
        if Role.query.filter_by(name=form.name.data).first() is None:
            r = Role(name=form.name.data)
            db.session.add(r)
            my_res_act_map = dict()
            for res in all_res:
                my_res_act_map[res] = 0

            for chk in form.read_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.READ
            for chk in form.write_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.WRITE

            for chk in form.delete_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.DELETE

            for res in my_res_act_map:
                if my_res_act_map[res] != 0:
                    r.change_resource_map(res, my_res_act_map[res])

            db.session.commit()
            return redirect(url_for('roles'))
        else:
            g.myerror = "Role with this name already exists"
    return render_template('addrole.html', title="Add Role", form=form, isedit=False, all_res=all_res, role=None)


@app.route('/editrole/<roleid>', methods=['GET', 'POST'])
def editrole(roleid):
    form = RoleForm()
    g.myerror = ""
    roleid = int(roleid)
    cur_role = Role.query.filter_by(id=roleid).first()

    if cur_role is None:
        return render_template('cust_error.html', title='Role Not Found' , msg="Role you are looking for does not exist")
    else:
        all_res = Resource.query.all()
        form.read_resources.choices = [(str(x.id), str(ActionType.READ)) for x in all_res]
        form.write_resources.choices = [(str(x.id), str(ActionType.WRITE)) for x in all_res]
        form.delete_resources.choices = [(str(x.id), str(ActionType.DELETE)) for x in all_res]

        if form.validate_on_submit():
            cur_role.name = form.name.data
            my_res_act_map = dict()
            for res in all_res:
                my_res_act_map[res] = 0

            for chk in form.read_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.READ
            for chk in form.write_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.WRITE

            for chk in form.delete_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.DELETE

            for res in my_res_act_map:
                cur_role.change_resource_map(res, my_res_act_map[res])

            db.session.commit()
            return redirect(url_for('roles'))
    return render_template('addrole.html', title="Add Role", form=form, isedit=True, all_res=all_res, role=cur_role)


@app.route('/deleterole/<roleid>', methods=['GET', 'POST'])
def deleterole(roleid):
    roleid = int(roleid)
    cur_role = Role.query.filter_by(id=roleid).first()
    if cur_role is not None:
        db.session.delete(cur_role)
        db.session.commit()
    return redirect(url_for("roles"))


@app.errorhandler(404)
def not_found_error(error):
    return render_template('cust_error.html', title='404 Not Found', msg='404 Not Found'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html', title='500 Server Error', msg='500 Server Error'), 500


@app.errorhandler(400)
def internal_error(error):
    db.session.rollback()
    return render_template('400.html', title='400 Error', msg='400 Server Error'), 400
