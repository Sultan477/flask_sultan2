import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = 'your_secret_key'
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app1.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False
