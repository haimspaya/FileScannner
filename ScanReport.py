import os
import time
import win32security

class ScanReport:
    def __init__(self, output_path="scan_report.txt"):
        self.output_path = output_path
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(self.output_path, "w") as f:
            f.write(f"===== Scan Report {now_str} =====\n")

    @staticmethod
    def get_owner(file_path):
        sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        name, domain, type = win32security.LookupAccountSid(None, owner_sid)
        return f"{domain}\\{name}"

    def write_result(self, file_name, file_path, vt_status,detector_reasons):
        created_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getctime(file_path)))
        modified_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(file_path)))
        owner = self.get_owner(file_path)

        with open(self.output_path, "a") as f:
            f.write(f"\nFile Name: {file_name}\n")
            f.write(f"Path: {file_path}\n")
            f.write(f"Owner: {owner}\n")
            f.write(f"Date Created: {created_str}\n")
            f.write(f"Last Changed: {modified_str}\n")
            f.write(f"VirusTotal Status: {vt_status}\n")
            f.write(f"Detections: {detector_reasons}\n")
            f.write("-----------------------------\n")