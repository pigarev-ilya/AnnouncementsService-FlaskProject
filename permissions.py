import jwt
from flask import jsonify, request

from app import app
from config import ALLOWED_EXTENSIONS
from models import User


def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'access-token' in request.headers:
            token = request.headers['access-token']

        # return 401 if token is not passed
        if not token:
            return jsonify({'status': 401,
                            'message': 'Token is missing.'})

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'status': 401,
                            'message': 'Token is invalid.'})
        return f(current_user=current_user, *args, **kwargs)

    return decorated


def is_authenticated():
    token = None
    # jwt is passed in the request header
    if 'access-token' in request.headers:
        token = request.headers['access-token']

        # return False if token is not passed
    if not token:
        return {"status": False}

    try:
        # decoding the payload to fetch the stored details
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query.filter_by(id=data['id']).first()
        resp = {'id': current_user.id, 'role': current_user.role,
                'username': current_user.username, 'email': current_user.email, 'status': True}
    except:
        resp = {'status': False}
    return resp


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
