"""

locust -f load_tester.py --host=https://testing.es.data61.xyz/api/v1

"""

import base64

from locust import HttpLocust, TaskSet, task
from bitarray import bitarray
import random


def serialize_bitarray(ba):
    return base64.encodebytes(ba.tobytes()).decode('utf8')


def generate_bitarray(length):
    return bitarray(''.join('1' if random.random() > 0.5 else '0' for _ in range(length)))


class UnencryptedMappingBehaviour(TaskSet):

    def on_start(self):
        """ on_start is called when a Locust start before any task is scheduled """
        res = self.create_mapping()
        length = 2**random.randint(8, 18)
        print("Starting mapping with {} entities".format(length))
        self.update_tokens = []
        self.rid = res['resource_id']
        self.result_token = res['result_token']

        self.upload_data(res['update_tokens'][0], length)
        self.upload_data(res['update_tokens'][1], length)

    def create_mapping(self):
        schema = [
            {"identifier": "INDEX",          "weight": 0, "notes":""},
            {"identifier": "NAME freetext",  "weight": 1, "notes": "max length set to 128"},
            {"identifier": "DOB YYYY/MM/DD", "weight": 1, "notes": ""},
            {"identifier": "GENDER M or F",  "weight": 1, "notes": ""}
        ]

        new_map_response = self.client.post('/mappings', json={
            'schema': schema,
            'result_type': 'permutation_unencrypted_mask'
        })

        return new_map_response.json()

    def upload_data(self, token, length=1000):
        response = self.client.put('/mappings/{}'.format(self.rid),
                                    name='/mappings/[id]',
                                    json={'clks': [
                                        serialize_bitarray(generate_bitarray(1024)) for _ in range(length)
                                    ]},
                                    headers={'Authorization': token})
        self.update_tokens.append(response.json()['receipt-token'])

    @task(100)
    def mapping_detail(self):
        with self.client.get(
                "/mappings/{}".format(self.rid), name='/mappings/[id]',
                headers={'Authorization': self.result_token},
                catch_response=True) as response:
            if response.status_code == 503:
                response.success()
            elif response.status_code == 200:
                response.success()

    @task(10)
    def mapping_results(self):
        client = 1 if random.random() > 0.5 else 0

        with self.client.get(
                "/mappings/{}".format(self.rid), name='/mappings/[id]',
                headers={'Authorization': self.update_tokens[client]},
                catch_response=True) as response:
            if response.status_code == 201:
                response.success()
            elif response.status_code == 503:
                response.success()
            elif response.status_code == 200:
                self.interrupt()

    @task(1)
    def stop(self):
        self.interrupt()


class UserBehavior(TaskSet):

    # Create a couple of mappings
    tasks = {UnencryptedMappingBehaviour: 10}

    @task(2)
    def status(self):
        self.client.get("/status")

    @task(2)
    def version(self):
        self.client.get("/version")

    @task(1)
    def list_mappings(self):
        self.client.get("/mappings")


class WebsiteUser(HttpLocust):
    task_set = UserBehavior
    min_wait = 2000
    max_wait = 10000
