#!/usr/bin/env python
# -*- coding: utf-8 -*-
from functools import partial
from hashlib import blake2b as blake2


class AgeProver:
    ''' very limited in scope -- really need to work on that to make it more general '''
    def __init__(self, hash_seed=b'123654'):
        ''' '''
        self.hash_seed = hash_seed

    def get_proof(self,actual_int, provable_int):
        '''  '''
        proof = blake2(self.hash_seed)
        start_idx = 1
        end_idx = actual_int - provable_int + 1
        for i in range(start_idx, end_idx):
            proof = blake2(proof.digest())

        return proof

    def encrypt_int(self,actual_int):
        ''' '''
        encrypted_int = blake2(self.hash_seed)
        start_idx = 1
        end_idx = actual_int + 1
        encrypted_int = [blake2(encrypted_int.digest()) for i in range(start_idx, end_idx)][-1]
        return encrypted_int

    def verify_proof(self, proof, provable_int):
        '''  '''
        verified_int = proof
        start_idx = 0
        end_idx = provable_int
        verified_int = [blake2(verified_int.digest()) for i in range(start_idx, end_idx)][-1]
        return verified_int

    def _provr(self, actual_age, provable_age):
        ''' '''
        proof = blake2(self.hash_seed)
        start_idx = 1
        end_idx = actual_age - provable_age + 1
        for i in range(start_idx, end_idx):
            proof = blake2(proof.digest())

        encrypted_age = blake2(self.hash_seed)
        start_idx = 1
        end_idx = actual_age + 1
        encrypted_age = [blake2(encrypted_age.digest()) for i in range(start_idx, end_idx)][-1]

        verified_age = proof
        start_idx = 0
        end_idx = provable_age
        verified_age = [blake2(verified_age.digest()) for i in range(start_idx, end_idx)][-1]

        return proof, encrypted_age, verified_age

    def round_trip(self, actual_int, provable_int):
        proof, encrypted_int, verified_int = self._provr(actual_int, provable_int)

        print(f'Proof: {proof.hexdigest()}')
        print(f'Encrypted INT: {encrypted_int.hexdigest()}')
        print(f'Verified INT: {verified_int.hexdigest()}')
        print('Proved claim: ', verified_int.hexdigest() == encrypted_int.hexdigest())
        return verified_int.hexdigest() == encrypted_int.hexdigest()


if __name__ == '__main__':
    assert AgeProver().round_trip(19, 21)
    assert AgeProver().round_trip(21, 19) is False
    assert AgeProver().round_trip(21, 21)


    provable_int = 21

    # use provable int and actual int to generate hashes
    proof_19 = AgeProver().get_proof(provable_int, 19)
    proof_22 = AgeProver().get_proof(provable_int, 22)

    # and encrypt the actual int
    encrypted_19 = AgeProver().encrypt_int(19)
    encrypted_22 = AgeProver().encrypt_int(22)

    # now created verification hash
    verify_19 = AgeProver().verify_proof(proof_19, provable_int)
    verify_22 = AgeProver().verify_proof(proof_22, provable_int)

    # and test against encrypted int
    assert verify_19.hexdigest() is not encrypted_19.hexdigest()
    assert verify_22.hexdigest() == encrypted_22.hexdigest()
