class BaseConfig(object):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///survey.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # used for encryption and session management
    SECRET_KEY = 'kakoyzheyaaxyenniy'
    UPLOAD_FOLDER = './uploads/'
    ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
    UPLOADED_FILES_DEST = './uploads'