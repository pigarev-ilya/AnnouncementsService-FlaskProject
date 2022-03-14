import os
from datetime import datetime, timedelta

from flask.views import MethodView
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from permissions import allowed_file, token_required, is_authenticated
from validation_scheme import registration_scheme, announcement_scheme_create, announcement_scheme_update, \
    category_announcement_scheme_create_or_update
from jsonschema import validate, ValidationError

from flask import request, jsonify
from app import db, app
from models import Announcement, User, CategoryAnnouncements
import jwt
from sqlalchemy.exc import IntegrityError


class CategoryAnnouncementsView(MethodView):
    def get(self, category_id):
        data = CategoryAnnouncements.query.filter_by(id=category_id)
        return jsonify({'status': 200,
                        'data': [data.serialized for data in data]})

    def post(self):
        current_user = is_authenticated()
        if not current_user['status']:
            return jsonify({'status': 401,
                            'message': 'You are not authorized'})
        if current_user['role'] != 'Admin':
            return jsonify({'status': 401,
                            'message': 'You are not authorized to perform this action'})
        try:
            validate(instance=request.get_json(), schema=category_announcement_scheme_create_or_update)
            data = request.get_json()
            category = CategoryAnnouncements(title=data['title'])
            db.session.add(category)
            db.session.commit()
            return jsonify({'status': 201,
                            'message': 'Resource create successfully'})
        except ValidationError:
            return jsonify({'status': 400,
                            'message': 'Error validation'})

    def patch(self, category_id):
        current_user = is_authenticated()
        if not current_user['status']:
            return jsonify({'status': 401,
                            'message': 'You are not authorized'})
        if current_user['role'] != 'Admin':
            return jsonify({'status': 401,
                            'message': 'You are not authorized to perform this action'})
        client = Announcement.query.filter_by(id=category_id).first()
        try:
            validate(instance=request.get_json(), schema=category_announcement_scheme_create_or_update)
            data = request.get_json()
            client.update(data)
            db.session.commit()
            return jsonify({'status': 200,
                            'message': 'Resource updated successfully'})
        except ValidationError:
            return jsonify({'status': 400,
                            'message': 'Error validation'})

    def delete(self, category_id):
        current_user = is_authenticated()
        if not current_user['status']:
            return jsonify({'status': 401,
                            'message': 'You are not authorized'})
        if current_user['role'] != 'Admin':
            return jsonify({'status': 401,
                            'message': 'You are not authorized to perform this action'})
        category_obj_to_del = db.session.query(Announcement). \
            filter(CategoryAnnouncements.id == category_id).first()
        db.session.delete(category_obj_to_del)
        db.session.commit()
        return jsonify({'status': 200,
                        'message': 'Resource delete successfully'})


class AnnouncementView(MethodView):

    def get(self, announcement_id):
        data = Announcement.query.filter_by(id=announcement_id)
        return jsonify({'status': 200,
                        'data': [data.serialized_get_announcement for data in data]})

    def post(self):
        current_user = is_authenticated()
        if not current_user['status']:
            return jsonify({'status': 401,
                            'message': 'You are not authorized'})
        try:
            validate(instance=request.get_json(), schema=announcement_scheme_create)
            data = request.get_json()
            announcement = Announcement(title=data['title'], text=data['text'],
                                        user_id=current_user['id'],
                                        category_id=data['category_id'])
            db.session.add(announcement)
            db.session.commit()
            return jsonify({'status': 201,
                            'message': 'Resource create successfully'})
        except ValidationError:
            return jsonify({'status': 400,
                            'message': 'Error validation'})

    def patch(self, announcement_id):
        current_user = is_authenticated()
        if not current_user['status']:
            return jsonify({'status': 401,
                            'message': 'You are not authorized'})
        client = Announcement.query.filter_by(id=announcement_id).first()
        if current_user['id'] != client.user_id:
            return jsonify({'status': 401,
                            'message': 'You are not authorized to perform this action'})
        try:
            validate(instance=request.get_json(), schema=announcement_scheme_update)
            data = request.get_json()
            client.update(data)
            db.session.commit()
            return jsonify({'status': 200,
                            'message': 'Resource updated successfully'})
        except ValidationError:
            return jsonify({'status': 400,
                            'message': 'Error validation'})

    def delete(self, announcement_id):
        current_user = is_authenticated()
        if not current_user['status']:
            return jsonify({'status': 401,
                            'message': 'You are not authorized'})
        announcement_obj = Announcement.query.filter_by(id=announcement_id).first()
        if current_user['id'] == announcement_obj.user_id:
            return jsonify({'status': 401,
                            'message': 'You are not authorized to perform this action'})
        announcement_obj_to_del = db.session.query(Announcement). \
            filter(Announcement.id == announcement_id).first()
        db.session.delete(announcement_obj_to_del)
        db.session.commit()
        return jsonify({'status': 200,
                        'message': 'Resource delete successfully'})


class RegisterView(MethodView):
    # Register user account
    def post(self):
        data = request.get_json()
        try:
            validate(instance=data, schema=registration_scheme)
            user = User(username=data['username'], email=data['email'],
                        password=generate_password_hash(data['password']))
            db.session.add(user)
            db.session.commit()
            return jsonify({'status': 200,
                            'message': 'Successful registration'})
        except ValidationError:
            return jsonify({'status': 400,
                            'message': 'Error validation'})
        except IntegrityError:
            return jsonify({'status': 400,
                            'message': 'Username or email do exist'})


class LoginView(MethodView):
    def post(self):
        auth = request.get_json()

        if not auth['username'] or not auth['password']:
            # Returns 401 if any username or / and password is missing

            return jsonify({'status': 401,
                            'message': 'Username and email required.'})

        user = User.query.filter_by(username=auth['username']).first()

        if not user:
            # Returns 401 if user does not exist
            return jsonify({'status': 401,
                            'message': 'User does not exist.'})

        if check_password_hash(user.password, auth['password']):
            # Generates the JWT Token
            token = jwt.encode({
                'id': user.id,
                'role': user.role,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, app.config['SECRET_KEY'])

            return jsonify({'status': 201,
                            'token': token})
        # Returns 403 if password is wrong
        return jsonify({'status': 403,
                        'message': 'Wrong password.'})


class UserView(MethodView):
    # Show user account
    def get(self, current_user, user_id):
        user = User.query.filter_by(id=user_id)
        resp = {'status': 200, 'data': {'user': [user.serialized for user in user]}}
        return jsonify(resp)


class HomeApiView(MethodView):
    # Welcome view
    def get(self):
        current_user = is_authenticated()
        if current_user['status']:
            resp = {'status': 200,
                    'api_version': 0.1,
                    'api_documentation': '',
                    'message': 'You are logged in.',
                    'data': {'id': current_user['id'], 'username': current_user['username'],
                             'email': current_user['email']}
                    }

        else:
            resp = {'status': 200,
                    'api_version': 0.1,
                    'api_documentation': '',
                    'message': 'You are not authroized. Only viewing functions are available'}
        return jsonify(resp)


class AvatarUploadView(MethodView):
    # Upload avatar in files/avatar
    @token_required
    def post(self, current_user):
        if 'file' not in request.files:
            return jsonify({'status': 400,
                            'message': 'No file part in the request.'})
        avatar = request.files['file']
        if avatar.filename == '':
            return jsonify({'status': 400,
                            'message': 'No file selected for uploading.'})
        if avatar and allowed_file(avatar.filename):
            filename_in_secure = secure_filename(avatar.filename)
            file_name = str(current_user.username + '_avatar.' + filename_in_secure.rsplit('.', 1)[1].lower())
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
            return jsonify({'status': 201,
                            'message': 'File successfully uploaded.'})
        else:
            return jsonify({'status': 400,
                            'message': 'Allowed file types are txt, pdf, png, jpg, jpeg, gif.'})


app.add_url_rule('/api/', view_func=HomeApiView.as_view('index_api_view'), methods=['GET', ])
app.add_url_rule('/api/announcements/', view_func=AnnouncementView.as_view('announcements_add'), methods=['POST', ])
app.add_url_rule('/api/announcements/category', view_func=CategoryAnnouncementsView.as_view('category'),
                 methods=['POST', ])
app.add_url_rule('/api/announcements/category/<int:category_id>',
                 view_func=CategoryAnnouncementsView.as_view('category_view'), methods=['GET', 'PATCH', 'DELETE', ])
app.add_url_rule('/api/announcements/<int:announcement_id>', view_func=AnnouncementView.as_view('announcements_update'),
                 methods=['GET', 'PATCH', 'DELETE', ])
app.add_url_rule('/api/user/register', view_func=RegisterView.as_view('register_user'), methods=['POST', ])
app.add_url_rule('/api/user/login', view_func=LoginView.as_view('login_user'), methods=['POST', ])
app.add_url_rule('/api/user/avatar-upload', view_func=AvatarUploadView.as_view('avatar_up_user'), methods=['POST', ])
app.add_url_rule('/api/user/<int:user_id>', view_func=UserView.as_view('user_info'), methods=['GET', ])
