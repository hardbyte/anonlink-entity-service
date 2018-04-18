import binascii
import io
import json
import logging
import os
import os.path

from flask import Flask, g, request, Response
from flask_restful import Api, abort, fields

from views.general import Status, Version
from views.project import ProjectList, Project, ProjectClks
from views.run import RunStatus

try:
    import ijson.backends.yajl2_cffi as ijson
except ImportError:
    import ijson

import anonlink
import database as db
from serialization import load_public_key, generate_scores
from object_store import connect_to_object_store
from settings import Config as config
from utils import fmt_bytes, iterable_to_stream

import urllib3


__version__ = open(os.path.join(os.path.dirname(__file__), 'VERSION')).read().strip()

INVALID_ACCESS_MSG = "Invalid access token or mapping doesn't exist"

app = Flask(__name__)

# Logging setup
if config.LOGFILE is not None:
    fileHandler = logging.FileHandler(config.LOGFILE)
    fileHandler.setLevel(logging.INFO)
    fileHandler.setFormatter(config.fileFormat)
consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.DEBUG)
consoleHandler.setFormatter(config.consoleFormat)


# Config could be Config, DevelopmentConfig or ProductionConfig
app.config.from_object('settings.Config')
# Add loggers to app
del app.logger.handlers[:]
app.logger.propagate = False
if config.LOGFILE is not None:
    app.logger.addHandler(fileHandler)
app.logger.addHandler(consoleHandler)

# Create our flask_restful api
api = Api(app)


@app.cli.command('initdb')
def initdb_command():
    """Initializes the database after a short delay."""
    db.init_db(5)
    print('Initialized the database.')


class MappingDao(object):
    """
    A python object for a newly created mapping.

    Exists before insertion into the database.
    """
    def __init__(self, resource_id, parties=2):
        app.logger.info("Creating mapping")
        self.parties = parties
        self.resource_id = resource_id
        self.result_token = generate_code()

        # Order is important here
        self.update_tokens = [generate_code() for _ in range(parties)]

        self.ready = False

        # These field will not be sent in the response
        self.status = 'not ready'
        self.data = {}

        self.result = {}


def safe_fail_request(status_code, message):
    # ensure we read the post data, even though we mightn't need it
    # without this you get occasional nginx errors failed (104:
    # Connection reset by peer) (See issue #195)
    if 'Transfer-Encoding' in request.headers and request.headers['Transfer-Encoding'] == 'chunked':
        chunk_size = 4096
        for data in request.input_stream.read(chunk_size):
            pass
    else:
        data = request.get_json()
    abort(http_status_code=status_code, message=message)


def get_stream():
    if 'Transfer-Encoding' in request.headers and request.headers['Transfer-Encoding'] == 'chunked':
        stream = request.input_stream
    else:
        stream = request.stream
    return stream


def get_json():
    # Handle chunked Transfer-Encoding...
    if 'Transfer-Encoding' in request.headers and request.headers['Transfer-Encoding'] == 'chunked':
        stream = get_stream()

        def consume_as_string(byte_stream):
            data = []
            while True:
                byte_data = byte_stream.read(4096)
                if byte_data:
                    data.append(byte_data.decode())
                else:
                    break
            return ''.join(data)

        return json.loads(consume_as_string(stream))
    else:
        return request.get_json()


def abort_if_mapping_doesnt_exist(resource_id):
    resource_exists = db.check_mapping_exists(get_db(), resource_id)
    if not resource_exists:
        app.logger.warning("Requested resource with invalid identifier token")
        safe_fail_request(403, message=INVALID_ACCESS_MSG)


def abort_if_invalid_dataprovider_token(update_token):
    app.logger.debug("checking authorization token to update data")
    resource_exists = db.check_update_auth(get_db(), update_token)
    if not resource_exists:
        safe_fail_request(403, message=INVALID_ACCESS_MSG)


def is_results_token_valid(resource_id, results_token):
    if not db.check_mapping_auth(get_db(), resource_id, results_token):
        return False
    else:
        return True


def is_receipt_token_valid(resource_id, receipt_token):
    if db.select_dataprovider_id(get_db(), resource_id, receipt_token) is None:
        return False
    else:
        return True


def abort_if_invalid_results_token(resource_id, results_token):
    app.logger.debug("checking authorization token to fetch results data")
    if not is_results_token_valid(resource_id, results_token):
        app.logger.debug("Auth invalid")
        safe_fail_request(403, message=INVALID_ACCESS_MSG)


def dataprovider_id_if_authorize(resource_id, receipt_token):
    app.logger.debug("checking authorization token to fetch mask data")
    if not is_receipt_token_valid(resource_id, receipt_token):
        safe_fail_request(403, message=INVALID_ACCESS_MSG)

    dp_id = db.select_dataprovider_id(get_db(), resource_id, receipt_token)
    return dp_id


def node_id_if_authorize(resource_id, token):
    """
    In case of a permutation with an unencrypted mask, we are using both the result token and the
    receipt tokens. The result token is used by the coordinator to get the mask. The receipts tokens
    are used by the dataproviders to get their permutations. However, we do not know before checking
    which is the type of the received token.
    """
    app.logger.debug("checking authorization token to fetch results data")
    # If the token is not a valid result token, it should be a receipt token.
    if not is_results_token_valid(resource_id, token):
        app.logger.debug("checking authorization token to fetch permutation data")
        # If the token is not a valid receipt token, we abort.
        if not is_receipt_token_valid(resource_id, token):
            safe_fail_request(403, message=INVALID_ACCESS_MSG)
        dp_id = db.select_dataprovider_id(get_db(), resource_id, token)
    else:
        dp_id = "Coordinator"
    return dp_id


def check_public_key(pk):
    """
    Check we can unmarshal the public key, and that it has sufficient length.
    """
    publickey = load_public_key(pk)
    return publickey.max_int >= 2 ** config.ENCRYPTION_MIN_KEY_LENGTH


def generate_code(length=24):
    return binascii.hexlify(os.urandom(length)).decode('utf8')



def get_similarity_scores(filename):
    """
    Read a CSV file containing the similarity scores and return the similarity scores

    :param filename: name of the CSV file, obtained from the `similarity_scores` table
    :return: the similarity scores in a streaming JSON response.
    """

    mc = connect_to_object_store()

    try:
        csv_data_stream = iterable_to_stream(mc.get_object(config.MINIO_BUCKET, filename).stream())

        # Process the CSV into JSON
        csv_text_stream = io.TextIOWrapper(csv_data_stream, encoding="utf-8")

        return Response(generate_scores(csv_text_stream), mimetype='application/json')

    except urllib3.exceptions.ResponseError:
        app.logger.warning("Attempt to read the similarity scores file failed with an error response.")
        safe_fail_request(500, "Failed to retrieve similarity scores")


def add_mapping_data(dp_id, raw_stream):
    """
    Save the untrusted user provided data and start a celery job to
    deserialize, popcount and save the hashes.

    Because this takes place in a worker, we "lock" the upload by
    setting the state to pending in the bloomingdata table.
    """
    receipt_token = generate_code()


    filename = config.RAW_FILENAME_FMT.format(receipt_token)
    app.logger.info("Storing user {} supplied clks from json".format(dp_id))

    # We will increment a counter as we process
    store = {
        'count': 0,
        'totalbytes': 0
    }

    def counting_generator():
        try:
            for clk in ijson.items(raw_stream, 'clks.item'):
                # Often the clients upload base64 strings with newlines
                # We remove those here
                raw = ''.join(clk.split('\n')).encode() + b'\n'
                store['count'] += 1
                store['totalbytes'] += len(raw)
                yield raw
        except ijson.common.IncompleteJSONError as e:
            store['count'] = 0
            app.logger.warning("Stopping as we have received incomplete json")
            return

    # Annoyingly we need the totalbytes to upload to the object store
    # so we consume the input stream here. We could change the public
    # api instead so that we know the expected size ahead of time.
    data = b''.join(counting_generator())
    num_bytes = len(data)
    buffer = io.BytesIO(data)

    if store['count'] == 0:
        abort(400, message="Missing information")

    app.logger.info("Processed {} CLKS".format(store['count']))
    app.logger.info("Uploading {} to object store".format(fmt_bytes(num_bytes)))
    mc = connect_to_object_store()
    mc.put_object(
        config.MINIO_BUCKET,
        filename,
        data=buffer,
        length=len(data)
    )

    db.insert_filter_data(get_db(), filename, dp_id, receipt_token, store['count'])

    return receipt_token, filename


api.add_resource(ProjectList, '/projects', endpoint='project-list')
api.add_resource(Project, '/projects/<project_id>', endpoint='project-description')
api.add_resource(ProjectClks, '/projects/<project_id>/clks', endpoint='project-clk-upload')

api.add_resource(RunList, '/projects/<project_id>/runs', endpoint='run-list')
api.add_resource(Run, '/projects/<project_id>/runs/<run_id>', endpoint='run-description')
api.add_resource(RunStatus, '/projects/<project_id>/runs/<run_id>/status', endpoint='run-status')
api.add_resource(RunResult, '/projects/<project_id>/runs/<run_id>/result', endpoint='run-result')

api.add_resource(Status, '/status', endpoint='status')
api.add_resource(Version, '/version', endpoint='version')


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    conn = getattr(g, '_db', None)
    if conn is None:
        conn = g._db = db.connect_db()
    return conn


@app.before_request
def before_request():
    g.db = db.connect_db()


@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()


@app.route('/danger/test')
def test():
    samples = 200
    nl = anonlink.randomnames.NameList(samples * 2)
    s1, s2 = nl.generate_subsets(samples, 0.75)
    keys = ('test1', 'test2')
    filters1 = anonlink.bloomfilter.calculate_bloom_filters(s1, nl.schema, keys)
    filters2 = anonlink.bloomfilter.calculate_bloom_filters(s2, nl.schema, keys)
    similarity = anonlink.entitymatch.calculate_filter_similarity(filters1, filters2)
    mapping = anonlink.network_flow.map_entities(similarity, threshold=0.95, method='weighted')
    return json.dumps(mapping)


@app.route('/danger/generate-names')
def generate_name_data():
    data = request.args
    samples = int(data.get("n", "200"))
    proportion = float(data.get("p", "0.75"))
    nl = anonlink.randomnames.NameList(samples * 2)
    s1, s2 = nl.generate_subsets(samples, proportion)
    return json.dumps({"A": s1, "B": s2})


if __name__ == '__main__':
    app.run(debug=True, port=8851)
