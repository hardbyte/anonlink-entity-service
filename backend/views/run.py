from flask_restful import Resource, fields, marshal

import database as db
from entityservice import app, get_db


class RunStatus(Resource):
    """
    Status of a particular run
    """

    def get(self, resource_id):
        mapping_resource_fields = {
            'ready': fields.Boolean,
            'time_added': fields.DateTime(dt_format='iso8601'),
            'time_started': fields.DateTime(dt_format='iso8601'),
            'time_completed': fields.DateTime(dt_format='iso8601'),
            'threshold': fields.Float()
        }

        app.logger.debug("Getting list of all mappings")
        query = '''
        SELECT ready, time_added, time_started, time_completed, threshold
        FROM mappings
        WHERE
        resource_id = %s
        '''

        stats = db.query_db(get_db(), query, (resource_id,), one=True)
        return marshal(stats, mapping_resource_fields)


class RunResult(Resource):
    """
    Result of a particular run
    """

    def get(self, resource_id):
        mapping_resource_fields = {
            'ready': fields.Boolean,
            'time_added': fields.DateTime(dt_format='iso8601'),
            'time_started': fields.DateTime(dt_format='iso8601'),
            'time_completed': fields.DateTime(dt_format='iso8601'),
            'threshold': fields.Float()
        }

        app.logger.debug("Getting list of all mappings")
        query = '''
        SELECT ready, time_added, time_started, time_completed, threshold
        FROM mappings
        WHERE
        resource_id = %s
        '''

        stats = db.query_db(get_db(), query, (resource_id,), one=True)
        return marshal(stats, mapping_resource_fields)

