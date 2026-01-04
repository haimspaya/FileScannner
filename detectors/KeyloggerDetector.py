from detectors.BaseDetector import BaseDetector

class KeyloggerDetector(BaseDetector):
    SUSPICIOUS_PATTERNS = [
        "GetAsyncKeyState",
        "SetWindowsHookEx",
        "WH_KEYBOARD_LL",
        "pynput.keyboard",
        "Listener",
        "keylogger",
        "keyboard.record",
        "keyboard.read_event",
    ]

    def build_result(self, is_dangerous, detections):
        return {
            "detector": "KeyloggerDetector",
            "is_dangerous": is_dangerous,
            "detections": detections,
        }

    def analyze(self, file_name, file_path):
        try:
            content = BaseDetector.open_file_r(file_path)
        except Exception:
            try:
                content = BaseDetector.open_file_rb(file_path)
            except Exception:
                return self.build_result(False, "Could not read file content")

        found = []
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in content:
                found.append(pattern)

        if len(found) > 0:
            return self.build_result(True, found)
        else:
            return self.build_result(False, "No suspicious patterns found")
