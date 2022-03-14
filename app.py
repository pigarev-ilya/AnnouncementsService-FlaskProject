from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import config


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.POSTGRES_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.TRACK_MODIFICATIONS
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# database
db = SQLAlchemy(app)
import migrate
import models





