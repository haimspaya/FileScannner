import os
import shutil
import subprocess
import tempfile

class UpxHelper:

    @staticmethod
    def try_upx_unpack(file_path):
        upx_path = shutil.which("upx")
        if not upx_path:
            return None

        tmp_dir = tempfile.mkdtemp(prefix="unpacked_")
        out_path = os.path.join(tmp_dir, os.path.basename(file_path))

        result = subprocess.run(
            [upx_path, "-d", "-o", out_path, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        if result.returncode != 0:
            return None

        if not os.path.exists(out_path):
            return None

        return out_path