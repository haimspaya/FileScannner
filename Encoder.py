import hashlib

class Encoder:
    @staticmethod
    def calculate_hash_md5(binary_content):
        return hashlib.md5(binary_content).hexdigest()

    @staticmethod
    def calculate_hash_sha256(binary_content):
        return hashlib.sha256(binary_content).hexdigest()

    @staticmethod
    def calculate_hash_sha1(binary_content):
        return hashlib.sha1(binary_content).hexdigest()