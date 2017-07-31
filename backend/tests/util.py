import random
import time
import unittest

import anonlink
from anonlink import randomnames
from anonlink.util import generate_clks

import math

import base64

from tests.config import url, logger, rate_limit_delay


def serialize_bitarray(ba):
    """ Serialize a bitarray (bloomfilter)

    """
    return base64.encodebytes(ba.tobytes()).decode('utf8')

def generate_serialized_clks(size):
    clks = generate_clks(size)
    return [serialize_bitarray(clk) for clk,_ ,_ in clks]

def generate_overlapping_clk_data(dataset_sizes, overlap=0.9):

    datasets = []
    for size in dataset_sizes:
        datasets.append(generate_serialized_clks(size))

    # TODO enforce overlap
    overlap_to = math.floor(dataset_sizes[0]*overlap)
    for ds in datasets[1:]:
        ds[:overlap_to] = datasets[0][:overlap_to]
        random.shuffle(ds)

    return datasets


class EntityServiceTestBase(unittest.TestCase):

    def setUp(self):
        self.url = url
        self.log = logger

    def tearDown(self):
        # Small sleep to avoid hitting rate limits while testing
        time.sleep(rate_limit_delay)