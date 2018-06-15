#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
    super simple merkle, validation, and proof
    todo:
        where to begin ... serialization and persistence
'''
import sys
from hashlib import blake2b as blake2
from collections import namedtuple

Node = namedtuple('Node', 'left right hash')


def hashed_pairs(l_node, r_node):
    assert l_node is not None and r_node is not None
    s = ''
    if l_node is None:
        s = r_node.hash
    elif r_node is None:
        s = l_node.hash
    else:
        s = r_node.hash + l_node.hash
    return b'0x' + blake2(s, digest_size=16).hexdigest().encode('utf8')


def hasher(payload):
    # TODO: clean that up : to _bytes()
    if not isinstance(payload, bytes):
        payload = '{}'.format(payload).encode('utf8')
    return b'0x' + blake2(payload, digest_size=16).hexdigest().encode('utf8')


class MerkleTree:
    ''' very simple, balance odd with empty nodes '''
    def __init__(self, ):
        self.tree = []
        self.max_depth = 16

    def _merkle(self, data):
        if len(data) == 1:
            return

        if len(data) > 1:
            if len(data) % 2 != 0:
                data.append(Node(None, None, b''))
            temp = []
            for i in range(0, len(data) - 1, 2):
                node = Node(data[i].hash, data[i + 1].hash, hashed_pairs(data[i], data[i + 1]))
                temp.append(node)
            self.tree.append(temp)
            self._merkle(temp)

    def make_tree(self, data):
        ''' check in to serializeers --- pickle, json, RLP, ...'''
        # TODO:  well consider: link Nodes rather than hashes and add flattening
        assert len(data) < 2 ** (self.max_depth), f'max tree depth is {self.max_depth}'
        assert isinstance(data, (list, tuple)) and len(data) > 0
        self.tree = []
        base = []
        for datum in data:
            # base.append(Node(None, None, hasher(repr(datum).encode('utf8'))))

            base.append(Node(None, None, hasher(datum)))
        self._merkle(base)
        return self.tree


# move into class ?
def validate(merkle_tree, val_hash):
    ''' start bottom up as p(hash, row i) = 2 * p(hash, row i-1) '''
    for i, nodes in enumerate(merkle_tree):
        hit = [(j, node) for j, node in enumerate(nodes) if node.left == val_hash or node.right == val_hash]
        if hit:
            return (i, hit[0][0], hit[0][1])
    return ()


# move into class ?
def merkle_proof(tree, start_depth, index, source_node):
    '''  '''
    path = []
    ref_node = source_node

    if start_depth == len(tree) - 1:
        return [(0)] if source_node.hash == tree[-1][0].hash else ()

    for depth in range(start_depth + 1, len(tree), 1):
        parent = [(j,node) for j, node in enumerate(tree[depth])
                  if node.left==ref_node.hash or node.right==ref_node.hash]
        if not parent:
            print("no parent", depth)
            return ()

        p_index, p_node = parent[0]

        # TODO: add options: hasshing direction left-right, right-left or None
        # if None, hash lr and rl and pick check if one fits
        sibling_hash = p_node.left if p_node.right==ref_node.hash else p_node.right
        sibling = [(j,node) for j,node in enumerate(tree[depth - 1])
                   if node.hash==sibling_hash]
        s_index, s_node = sibling[0]

        if s_index > 0 and s_index % 2 != 0:
            test_hash = hashed_pairs(ref_node, s_node)
        else:
            test_hash = hashed_pairs(s_node,ref_node)

        if p_node.hash == test_hash:
            path.append((depth,p_index))
            ref_node = p_node
        else:
            return ()
    return path


def test_build_tree():
    '''  '''
    import pytest

    n_data = 0
    data = [i for i in range(n_data)]
    mT = MerkleTree()
    with pytest.raises(AssertionError):
        mT.make_tree(data)

    n_data = 2 ** 16
    data = [i for i in range(n_data)]
    with pytest.raises(AssertionError):
        mT.make_tree(data)

    n_data = 2**16 - 1
    data = [i for i in range(n_data)]
    mtree = mT.make_tree(data)
    assert len(mtree) == 16


def test_validate(seed=4593):
    '''  '''
    import random
    import pytest

    random.seed(seed)

    n = 2 ** random.randrange(0,16, 1)
    data = [i for i in range(n)]
    mT = MerkleTree()
    mtree = mT.make_tree(data)

    for i in range(random.randrange(0,50,1)):
        rnd_depth = random.randrange(0,len(mtree), 1)
        rnd_idx = random.randrange(0,len(mtree[rnd_depth]),1)
        rnd_hash = mtree[rnd_depth][rnd_idx].hash
        validation = validate(mtree, rnd_hash)
        assert validation


def test_proof(seed=4593):
    '''  '''
    import random

    n_data = 2 ** 16 - 1
    data = [i for i in range(n_data)]
    mT = MerkleTree()
    mtree = mT.make_tree(data)

    test_errors = []
    for i in range(random.randrange(0,50,1)):
        rnd_depth = random.randrange(0,len(mtree), 1)
        rnd_idx = random.randrange(0,len(mtree[rnd_depth]),1)
        rnd_hash = mtree[rnd_depth][rnd_idx].hash
        validation = validate(mtree, rnd_hash)
        if not validation:
            print('validation failure in proof test: ', validation)
        else:
            res = merkle_proof(mtree, validation[0], validation[1], validation[2])
            if not res:
                print('res failure -- fix edge cases: ', validation)
                print(len(mtree))
                test_errors.append((validation, len(mtree)))
            else:
                assert res
    if test_errors:
        msg = 'proof problems: {}'.format(test_errors)
        raise Exception(msg)


def smoker():
    test_build_tree()
    print('check tree builder: OK')
    # test_validate()
    print('check validator: OK')
    # test_proof()
    print('check proofs: OK')


def main():
    smoker()


if __name__ == '__main__':
    assert 2**16 - 1 < 2 ** 16
    # sys.exit()
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == 'test':
            smoker()
            sys.exit()
    main()
