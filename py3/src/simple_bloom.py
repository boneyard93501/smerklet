#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    p = (1 - [1 - 1/m]**kn)**k
    m: size bit array
    k: number of hash functions
    n: number of data capacity (expected)

    hash function candiates with god speed and uniformity:
        murmur3, https://pypi.org/project/mmh3/
        sha256
        SipHash, https://github.com/majek/pysiphash, https://idea.popcount.org/2013-01-24-siphash/
    i'm partial to blake2, so that's what we start with

    see: http://llimllib.github.io/bloomfilter-tutorial/
    don't forget: https://www.eecs.harvard.edu/~michaelm/postscripts/tr-02-05.pdf
    for capacity calculations and visualizations: https://hur.st/bloomfilter/
'''
import bitarray
import math
from collections import Iterator
from hashlib import blake2b as blake2
import mmh3
import sys


# TODO:  accomodate shannon entropy for inputs
# http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
# https://deadhacker.com/2007/05/13/finding-entropy-in-binary-files/
# look into double hashing and dynamic resizing
class BloomFilter:
    ''' can't do much simpler than that '''
    # TODO: big/little byte order
    def __init__(self, n_data, p_fp=0.0000001):
        '''
            n_data: expected  number of  data items
            p_fp: probablity of false positives
        '''
        self.n_data = n_data
        self.p_fp = p_fp
        self._setup()

    def _setup(self,):
        assert self.p_fp > 0.0 and self.p_fp < 1.0
        assert self.n_data > 0

        n_bits = math.ceil((self.n_data * math.log(self.p_fp)) / math.log(1 / math.pow(2, math.log(2))))
        n_hashers = int(round(n_bits / self.n_data) * math.log(2))
        setattr(self, 'n_bits', n_bits)
        setattr(self, 'n_hashers', n_hashers)

        array = bitarray.bitarray(n_bits)
        array.setall(0)
        setattr(self,'array', array)  # inits to 0s

    def _hash(self, payload, k, f='blake2'):
        if isinstance(payload, str):
            payload = payload.encode('utf8')
        if f=='mmh3':
            return mmh3.hash(payload,k) % len(self.array)
        if f=='blake2':
            return int(blake2(payload,salt=bytes([k])).hexdigest(), 16) % len(self.array)

    def add(self, payload):
        for k in range(self.n_hashers):
            self.array[self._hash(payload, k)] = 1

    def check(self, payload):
        for k in range(self.n_hashers):
            if not self.array[self._hash(payload, k)]:
                return False
        return True


def test_bf_setup():
    # need a few mroe tests including edge cases and AssertionErrors
    # https://hur.st/bloomfilter/?n=400000&p=0.0000001&m=&k=
    n_data = 400000
    p_fp = 0.0000001
    bF = BloomFilter(n_data, p_fp)
    assert bF.n_hashers == 23
    assert bF.n_bits == 13_419_082


def test_bf():
    # extend to pytest and add edge cases
    import random
    import string
    def string_gen(min_chars, max_chars):  # noqa E306
        char_pool = string.ascii_letters + string.digits + string.punctuation
        s = ''.join([c for c in random.sample(char_pool, random.randint(min_chars, max_chars))])
        return s

    n_set = 10000
    p_fp = 0.00001

    min_chars, max_chars = 5, 20
    s_good = set()

    while len(s_good) < n_set:
        s_good.add(string_gen(min_chars,max_chars))


    bF = BloomFilter(n_set, p_fp)

    [bF.add(s) for s in s_good]
    assert sum(bF.check(s) for s in s_good) == len(s_good)

    for i in range(1000):
        s = string_gen(min_chars,max_chars)
        if s in s_good:
            assert bF.check(s) is False


if __name__ == '__main__':
    test_bf_setup()
    test_bf()
