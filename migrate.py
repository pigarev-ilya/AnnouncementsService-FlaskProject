import models
import app
from flask_migrate import Migrate


migrate = Migrate(app.app, app.db)
