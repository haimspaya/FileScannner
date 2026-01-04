from abc import ABC, abstractmethod


class BaseDetector(ABC):
    detectors = []

    @abstractmethod
    def analyze(self, file_name, file_path):
        pass

    @abstractmethod
    def build_result(self, is_dangerous, detections):
        pass

    @classmethod
    def run_all(cls, file_name, file_path):
        flags = []
        detections = []

        for detector in cls.detectors:
            result = detector.analyze(file_name, file_path)
            flags.append(result["is_dangerous"])
            detections.append(f"{result['detector']}: {result['detections']}")

        is_dangerous = any(flags)
        return is_dangerous, detections

    @staticmethod
    def open_file_r(file_path):
        with open(file_path, "r") as f:
            content = f.read()
        return content

    @staticmethod
    def open_file_rb(file_path):
        with open(file_path, "rb") as f:
            content = f.read().decode("latin-1", errors="ignore")
        return content
