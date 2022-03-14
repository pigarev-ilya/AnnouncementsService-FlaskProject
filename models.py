from sqlalchemy import func

from app import db
from flask_login import UserMixin


class Role(db.Model):
    __tablename__ = 'Role'

    name = db.Column(db.String(128), primary_key=True)
    description = db.Column(db.String(256))
    users = db.relationship('User')

    def __init__(self, name, description, users):
        self.name = name
        self.users = users
        self.description = description

    def __repr__(self):
        return f'{self.name},{self.description}'


class User(db.Model, UserMixin):
    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(128), index=True, unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String, db.ForeignKey('Role.name'),
                     nullable=False, default='User')  # 'default' value should match the user's role name
    announcements = db.relationship('Announcement')

    def __init__(self, username, password, email, id):
        self.id = id
        self.username = username
        self.password = password
        self.email = email

    def __repr__(self):
        return f'{self.id},{self.username}'


    @property
    def serialized(self):
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'announcements': None
        }
        if self.announcements:
            announcements = [announcement.serialized_get_user_announcements for announcement in self.announcements]
            data['announcements'] = announcements
            return data
        else:
            data['announcements'] = []
            return data

class CategoryAnnouncements(db.Model):
    __tablename__ = 'CategoryAnnouncements'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), index=True, unique=True, nullable=False)
    announcements = db.relationship('Announcement', cascade='all, delete')

    def __init__(self, title):
        self.title = title


    def __repr__(self):
        return f'{self.id},{self.title}'

    @property
    def serialized(self):
        data = {
            'id': self.id,
            'title': self.title,
            'announcements': None
        }
        if self.announcements:
            announcements = [announcement.serialized_get_announcement for announcement in self.announcements]
            data['announcements'] = announcements
            return data
        else:
            data['announcements'] = []
            return data


class Announcement(db.Model):
    __tablename__ = 'Announcement'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    text = db.Column(db.String(1000), nullable=False)
    date_create = db.Column(db.Date, default=func.now(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'),
                        nullable=False)

    category_id = db.Column(db.Integer, db.ForeignKey('CategoryAnnouncements.id'),
                            nullable=True)

    def __init__(self, title, text, user_id, category_id):
        self.title = title
        self.text = text
        self.user_id = user_id
        self.category_id = category_id

    def __repr__(self):
        return f'{self.id},{self.title}'

    @property
    def serialized_get_announcement(self):
        return {
            'id': self.id,
            'title': self.title,
            'text': self.text,
            'date_create': self.date_create,
            'user_id': self.user_id
        }

    @property
    def serialized_get_user_announcements(self):
        return {
            'id': self.id,
            'title': self.title,
            'text': self.text,
            'date_create': self.date_create,
            'category': self.category_id
        }
