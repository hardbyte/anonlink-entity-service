import logging
import pathlib
import uuid

from flask import g
import structlog

# Import the WSGI application object
# Note we explicitly do this before importing the rest of our own code
from entityservice.wsgi_app import con_app, app

from entityservice import database as db, con_app, app
from entityservice.serialization import generate_scores
from entityservice.object_store import connect_to_object_store
from entityservice.settings import Config
from entityservice.utils import fmt_bytes, iterable_to_stream
try:
    import ijson.backends.yajl2_cffi as ijson
except ImportError:
    import ijson


con_app.add_api(pathlib.Path('swagger.yaml'),
                base_path='/',
                strict_validation=Config.CONNEXION_STRICT_VALIDATION,
                validate_responses=Config.CONNEXION_RESPONSE_VALIDATION)

# Logging setup
logger = structlog.get_logger()
consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.DEBUG)
structlog.configure(
    processors=[
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer()
    ],
    context_class=structlog.threadlocal.wrap_dict(dict),
    logger_factory=structlog.stdlib.LoggerFactory(),
)

# Config could be Config, DevelopmentConfig or ProductionConfig
app.config.from_object(Config)

gunicorn_logger = logging.getLogger('gunicorn.error')
# Use the gunicorn logger handler (it owns stdout)
app.logger.handlers = gunicorn_logger.handlers
# Use the logging level passed to gunicorn on the cmd line unless DEBUG is set
if Config.DEBUG:
    app.logger.setLevel(logging.DEBUG)
else:
    app.logger.setLevel(gunicorn_logger.level)

if Config.LOGFILE is not None:
    fileHandler = logging.FileHandler(Config.LOGFILE)
    fileHandler.setLevel(logging.INFO)
    fileHandler.setFormatter(Config.fileFormat)
    app.logger.addHandler(fileHandler)


@app.cli.command('initdb')
def initdb_command():
    """Initializes the database after a short delay."""
    db.init_db(5)
    print('Initialized the database.')


@app.before_request
def before_request():
    logger.new(request=str(uuid.uuid4())[:8])
    g.db = db.connect_db()


# noinspection PyUnusedLocal
@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()


if __name__ == '__main__':
    con_app.run(debug=True, port=8851)
