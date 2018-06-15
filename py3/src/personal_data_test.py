#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import datetime
import random
import string
from hashlib import blake2b as blake2
from random import sample, randint
from simple_bloom import BloomFilter
from simple_merkle import MerkleTree, validate, merkle_proof, hasher



def build_data(t_serde='json'):
    '''
        rough approximation with no consitency checks
        just a somewhat mnemonic key to random values
    '''
    d = {'firstname': ''.join([c for c in random.sample(string.ascii_letters, random.randint(3, 12))]),
         'lastname': ''.join([c for c in random.sample(string.ascii_letters, random.randint(5, 20))]),
         'Employer': ''.join([c for c in random.sample(string.ascii_letters, random.randint(10, 30))]),
         'start': '{}/{}'.format(randint(1,12), randint(1970, 2018)),
         'end': '{}/{}'.format(randint(1,12), randint(1970, 2018)),
         'utc': int(datetime.datetime.utcnow().replace(microsecond=0).timestamp())
         }

    if t_serde == 'json':
        return json.dumps(d).encode('utf8')
    raise NotImplementedError()


def tree_to_leveldb():
    raise NotImplementedError()


def tree_from_levedbl():
    raise NotImplementedError()


def test_sim():
    ''' generate user data, serialize, and look into chunking onto different merkles '''
    data = []
    for i in range(100):
        datum = build_data()
        data.append(datum)

    # merkle_trees = []
    mT = MerkleTree()
    mT.make_tree(data)
    root = mT.tree[-1]
    print("root: ", root)


    random.shuffle(data)
    for datum in data[:20]:
        v = validate(mT.tree, hasher(datum))
        if not v:
            print(f'wtf .. {datum[:15]} ... should be in our tree. check your hashing.')
        else:
            assert merkle_proof(mT.tree, v[0], v[1], v[2])

    datum = data[-1]
    assert validate(mT.tree, hasher(datum[2:])) == ()


if __name__ == '__main__':
    test_sim()
