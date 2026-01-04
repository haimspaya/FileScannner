import os
import virusScan
import time
from Encoder import Encoder
import ScanReport
import QuarantineManager

from UpxHelper import *
from detectors.BaseDetector import BaseDetector
from detectors.KeyloggerDetector import KeyloggerDetector

BaseDetector.detectors.append(KeyloggerDetector())


class FileScanner:
    def __init__(self, path):
        self.path = path

    @staticmethod
    def get_file_name(path):
        # returns file name from path
        return os.path.basename(path)

    @staticmethod
    def get_file_content(path):
        # return binary content of a file given a path
        with open(path, "rb") as file:
            binary_content = file.read()
        return binary_content

    @staticmethod
    def get_file_hash(path, hash_type="md5"):
        binary_content = FileScanner.get_file_content(path)
        match hash_type:
            case "sha1":
                return Encoder.calculate_hash_sha1(binary_content)
            case "sha256":
                return Encoder.calculate_hash_sha256(binary_content)
            case _:
                return Encoder.calculate_hash_md5(binary_content)

    def get_file_list(self):
        # returns a list of file tuples
        file_list = []
        if not os.path.isdir(self.path):
            print("error: received a path that is not a folder path")
            return

        for root, directories, files in os.walk(self.path):
            for file_name in files:
                file_path = os.path.abspath(os.path.join(root, file_name))
                _, ext = os.path.splitext(file_name)
                if ext.lower() in (".exe", ".dll", ".py"):
                    file_list.append((file_name, file_path))

        return file_list

    def print_files_hashes(self):
        # return a list of (file name, hash value) tuples
        name_hash_list = []
        file_list = self.get_file_list()
        for file_tuple in file_list:
            file_name, file_path = file_tuple
            file_hash = FileScanner.get_file_hash(file_path)
            name_hash_list.append((file_name, file_path, file_hash))
        return name_hash_list


def run_scan(path):
    fscan = FileScanner(path)
    name_hash_list = fscan.print_files_hashes()

    vscan = virusScan.VirusScan()
    screport = ScanReport.ScanReport()
    qm = QuarantineManager.QuarantineManager()

    vscan_results = []
    dangerous_files = []
    for file_name, file_path, file_hash in name_hash_list:
        virus_total_score = vscan.get_virusTotal_score(file_hash)
        if virus_total_score is not None:
            malicious_score = virus_total_score.get("malicious", 0)
        else:
            malicious_score = 0
        vt_flag = malicious_score >= 3

        vscan_results.append((file_name, file_path, virus_total_score))

        unpacked_path = UpxHelper.try_upx_unpack(file_path)

        scan_path = unpacked_path if unpacked_path is not None else file_path

        detectors_flag, detections = BaseDetector.run_all(file_name,scan_path)

        if unpacked_path is not None:
            detections.insert(0, f"UPX: unpacked successfully to {unpacked_path}")

        screport.write_result(file_name, file_path, virus_total_score, detections)

        if vt_flag or detectors_flag:
            dangerous_files.append((file_name, file_path, detections))

    print("All files results:")
    print('\n'.join([str(x) for x in vscan_results]))
    print("Dangerous files:")
    print('\n'.join([str(x) for x in dangerous_files]))
    qm.isolate_files(dangerous_files)


def periodic_scan(path):
    scan_interval_minutes = 60
    while True:
        print('Scanning for new files...')
        run_scan(path)
        print(f'Finished scanning, {scan_interval_minutes} minutes until next scan')
        time.sleep(scan_interval_minutes * 60)


def main():
    path = input("Enter your file path:\n")
    periodic_scan(path)


if __name__ == "__main__":
    main()
