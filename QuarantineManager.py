import os
import shutil


class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def build_quarantine_name(self, file_path):
        base_name = os.path.basename(file_path)
        name, ext = os.path.splitext(base_name)
        new_name = f"{name}{ext}.quarantine"
        return os.path.join(self.quarantine_dir, new_name)

    def isolate_files(self, files):
        for file_name, file_path, detector_reasons in files:
            new_path = self.build_quarantine_name(file_path)
            shutil.move(file_path, new_path)
