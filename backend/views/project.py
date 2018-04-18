from flask import request
from flask_restful import Resource, fields, marshal, marshal_with

import cache
import database as db
from async_worker import handle_raw_upload
from entityservice import app, get_db, new_mapping_fields, get_json, safe_fail_request, check_public_key, generate_code, \
    MappingDao, abort_if_mapping_doesnt_exist, get_similarity_scores, abort_if_invalid_results_token, \
    dataprovider_id_if_authorize, node_id_if_authorize, get_stream, abort_if_invalid_dataprovider_token, \
    add_mapping_data
from object_store import connect_to_object_store
from settings import Config as config


class ProjectList(Resource):
    """
    Top level project endpoint.

    GET /projects       A list of all projects.
    POST /projects      Create a new project

    """

    def get(self):
        mapping_resource_fields = {
            'resource_id': fields.String,
            'ready': fields.Boolean,
            'time_added': fields.DateTime(dt_format='iso8601'),
            'time_started': fields.DateTime(dt_format='iso8601'),
            'time_completed': fields.DateTime(dt_format='iso8601')
        }

        marshaled_mappings = []

        app.logger.debug("Getting list of all mappings")
        for mapping in db.query_db(get_db(),
                                   'select resource_id, ready, time_added, time_started, time_completed from mappings'):
            marshaled_mappings.append(marshal(mapping, mapping_resource_fields))

        return {"mappings": marshaled_mappings}

    @marshal_with(new_mapping_fields)
    def post(self):
        """Create a new project

        By default the mapping will be between two organisations.

        There are three types, a "mapping", a "permutation" and a "permutation_unencrypted_mask".

        The permutation type requires a paillier public key to be
        passed in. It takes significantly longer as it has to encrypt
        a mask vector.

        The "permutation_unencrypted_mask" does a permutation but do not encrypt the mask which is
        only sends to the coordinator (owner of the results_token).
        """
        data = get_json()

        if data is None or 'schema' not in data:
            safe_fail_request(400, message="Schema information required")

        if 'result_type' not in data or data['result_type'] not in {'permutation', 'mapping',
                                                                    'permutation_unencrypted_mask',
                                                                    'similarity_scores'}:
            safe_fail_request(400, message='result_type must be either "permutation", "mapping" or '
                               '"permutation_unencrypted_mask"')

        if data['result_type'] == 'permutation' and 'public_key' not in data:
            safe_fail_request(400, message='Paillier public key required when result_type="permutation"')

        if data['result_type'] == 'permutation' and 'paillier_context' not in data:
            safe_fail_request(400, message='Paillier context required when result_type="permutation"')

        if data['result_type'] == 'permutation' and not check_public_key(data['public_key']):
            safe_fail_request(400, message='Paillier public key required when result_type="permutation"')

        mapping_resource = generate_code()
        mapping = MappingDao(mapping_resource)

        threshold = data.get('threshold', config.ENTITY_MATCH_THRESHOLD)
        if threshold <= 0.0 or threshold >= 1.0:
            safe_fail_request(400, message="Threshold parameter out of range")

        app.logger.debug("Threshold for mapping is {}".format(threshold))

        # Persist the new mapping
        app.logger.info("Adding new mapping to database")

        conn = get_db()
        with conn.cursor() as cur:
            app.logger.debug("Starting database transaction")
            app.logger.debug("Creating a new mapping")
            mapping_db_id = db.insert_mapping(cur, data['result_type'], data['schema'], threshold, mapping, mapping_resource)

            if data['result_type'] == 'permutation':
                app.logger.debug("Inserting public key and paillier context into db")
                paillier_db_id = db.insert_paillier(cur, data['public_key'], data['paillier_context'])
                db.insert_empty_encrypted_mask(cur, mapping_resource, paillier_db_id)

            app.logger.debug("New mapping created in DB: {}".format(mapping_db_id))
            app.logger.debug("Creating new data provider entries")

            for auth_token in mapping.update_tokens:
                dp_id = db.insert_dataprovider(cur, auth_token, mapping_db_id)
                app.logger.info("Added dataprovider with id = {}".format(dp_id))

            app.logger.debug("Added data providers")

            app.logger.debug("Committing transaction")
            conn.commit()

        return mapping


class Project(Resource):

    def delete(self, resource_id):
        # Check the resource exists
        abort_if_mapping_doesnt_exist(resource_id)
        app.logger.info("Deleting a mapping resource and all data")
        # First get the filenames of everything in the object store

        dbinstance = get_db()

        mc = connect_to_object_store()

        mapping = db.get_mapping(dbinstance, resource_id)

        # If result_type is similarity_scores, delete the corresponding similarity_scores file
        if mapping['result_type'] == 'similarity_scores':
            app.logger.info("Deleting the similarity scores file")
            filename = db.get_similarity_scores_filename(dbinstance, resource_id)['file']
            mc.remove_object(config.MINIO_BUCKET, filename)

        db.delete_mapping(get_db(), resource_id)

        return '', 204

    def get(self, resource_id):
        """
        This endpoint reveals the results of the calculation.
        What you're allowed to know depends on who you are.
        """

        dp_id, mapping = self.authorise_get_request(resource_id)

        app.logger.info("Checking for results")
        dbinstance = get_db()

        # Check that the mapping is ready
        if not mapping['ready']:
            progress = self.get_mapping_progress(dbinstance, resource_id)
            return progress, 503

        if mapping['result_type'] == 'mapping':
            app.logger.info("Mapping result being returned")
            result = db.get_mapping_result(dbinstance, resource_id)
            return {
                "mapping": result
            }

        elif mapping['result_type'] == 'permutation':
            app.logger.info("Encrypted permutation result being returned")
            return db.get_permutation_encrypted_result_with_mask(dbinstance, resource_id, dp_id)

        elif mapping['result_type'] == 'permutation_unencrypted_mask':
            app.logger.info("Permutation with unencrypted mask result type")

            if dp_id == "Coordinator":
                app.logger.info("Returning unencrypted mask to coordinator")
                # The mask is a json blob of an
                # array of 0/1 ints
                mask = db.get_permutation_unencrypted_mask(dbinstance, resource_id)
                return {
                    "mask": mask
                }
            else:
                perm = db.get_permutation_result(dbinstance, dp_id)
                rows = db.get_smaller_dataset_size_for_mapping(dbinstance, resource_id)

                return {
                    'permutation': perm,
                    'rows': rows
                }
            # The result in this case is either a permutation, or the encrypted mask.
            # The key 'permutation_unencrypted_mask' is kept for the Java recognition of the algorithm.

        elif mapping['result_type'] == 'similarity_scores':
            app.logger.info("Similarity scores being returned")

            try:
                filename = db.get_similarity_scores_filename(dbinstance, resource_id)['file']
                return get_similarity_scores(filename)

            except TypeError:
                app.logger.warning("`resource_id` is valid but it is not in the similarity scores table.")
                safe_fail_request(500, "Fail to retrieve similarity scores")

        else:
            app.logger.warning("Unimplemented result type")

    def get_mapping_progress(self, dbinstance, resource_id):
        # return compute time elapsed and number of comparisons here
        time_elapsed = db.get_mapping_time(dbinstance, resource_id)
        app.logger.debug("Time elapsed so far: {}".format(time_elapsed))
        comparisons = cache.get_progress(resource_id)
        total_comparisons = db.get_total_comparisons_for_mapping(dbinstance, resource_id)
        progress = {
            "message": "Mapping isn't ready.",
            "elapsed": time_elapsed.total_seconds(),
            "total": str(total_comparisons),
            "current": str(comparisons),
            "progress": (comparisons / total_comparisons) if total_comparisons is not 'NA' else 0.0
        }
        return progress

    def authorise_get_request(self, resource_id):
        if request.headers is None or 'Authorization' not in request.headers:
            safe_fail_request(401, message="Authentication token required")
        auth_header = request.headers.get('Authorization')
        dp_id = None
        # Check the resource exists
        abort_if_mapping_doesnt_exist(resource_id)
        dbinstance = get_db()
        mapping = db.get_mapping(dbinstance, resource_id)
        app.logger.info("Checking credentials")
        if mapping['result_type'] == 'mapping' or mapping['result_type'] == 'similarity_scores':
            # Check the caller has a valid results token if we are including results
            abort_if_invalid_results_token(resource_id, auth_header)
        elif mapping['result_type'] == 'permutation':
            dp_id = dataprovider_id_if_authorize(resource_id, auth_header)
        elif mapping['result_type'] == 'permutation_unencrypted_mask':
            dp_id = node_id_if_authorize(resource_id, auth_header)
        else:
            safe_fail_request(500, "Unknown error")
        return dp_id, mapping


class ProjectClks(Resource):

    def put(self, resource_id):
        """
        Update a mapping to provide data
        """

        # Pass the request.stream to add_mapping_data
        # to avoid parsing the json in one hit, this enables running the
        # web frontend with less memory.
        headers = request.headers

        # Note we don't use request.stream so we handle chunked uploads without
        # the content length set...
        stream = get_stream()

        abort_if_mapping_doesnt_exist(resource_id)
        if headers is None or 'Authorization' not in headers:
            safe_fail_request(401, message="Authentication token required")

        token = headers['Authorization']

        # Check the caller has valid token
        abort_if_invalid_dataprovider_token(token)

        dp_id = db.get_dataprovider_id(get_db(), token)

        app.logger.info("Receiving data for: dpid: {}".format(dp_id))
        receipt_token, raw_file = add_mapping_data(dp_id, stream)

        # Schedule a task to deserialize the hashes, and carry
        # out a pop count.
        handle_raw_upload.delay(resource_id, dp_id, receipt_token)
        app.logger.info("Job scheduled to handle user uploaded hashes")

        return {'message': 'Updated', 'receipt-token': receipt_token}, 201