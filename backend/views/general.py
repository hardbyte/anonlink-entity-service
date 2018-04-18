import platform

import anonlink
from flask_restful import Resource

import cache
import database as db
from entityservice import get_db, __version__


class Status(Resource):

    def get(self):
        """Displays the latest mapping statistics"""

        status = cache.get_status()

        if status is None:
            # We ensure we can connect to the database during the status check
            db1 = get_db()

            number_of_mappings = db.query_db(db1, '''
                        SELECT COUNT(*) FROM mappings
                        ''', one=True)['count']

            current_rate = db.get_latest_rate(db1)

            status = {
                'status': 'ok',
                'number_mappings': number_of_mappings,
                'rate': current_rate
            }

            cache.set_status(status)
        return status


class Version(Resource):

    def get(self):
        return {
            'anonlink': anonlink.__version__,
            'entityservice': __version__,
            'libc': "".join(platform.libc_ver()),
            'python': platform.python_version()
        }