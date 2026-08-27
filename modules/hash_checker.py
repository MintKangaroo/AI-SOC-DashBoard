"""
해시 검사 모듈 - hashlib 기반
파일/데이터의 MD5, SHA1, SHA256 해시를 계산하고 악성 해시 DB와 비교
"""
import hashlib
import os
from collections import deque
from datetime import datetime
from pathlib import Path

from modules.logging_setup import get_logger

_log = get_logger(__name__)


KNOWN_MALICIOUS = {
    # 데모용 알려진 악성 해시 샘플
    "md5": {
        "44d88612fea8a8f36de82e1278abb02f": "EICAR 테스트 파일",
        "d41d8cd98f00b204e9800998ecf8427e": "빈 파일 (테스트)",
    },
    "sha256": {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR 테스트 파일",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "빈 파일 (테스트)",
    },
}


class HashChecker:
    def __init__(self, malicious_db_path=None):
        self.malicious_db_path = malicious_db_path
        self.malicious_hashes = dict(KNOWN_MALICIOUS)
        self.scan_history = deque(maxlen=200)

        if malicious_db_path and os.path.exists(malicious_db_path):
            self._load_db(malicious_db_path)

    # ------------------------------------------------------------------ #

    def hash_file(self, file_path):
        """파일의 MD5 / SHA1 / SHA256 동시 계산"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        size = 0

        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    size += len(chunk)

            return {
                "file": str(file_path),
                "size": size,
                "md5": md5.hexdigest(),
                "sha1": sha1.hexdigest(),
                "sha256": sha256.hexdigest(),
                "error": None,
            }
        except Exception as e:
            return {"file": str(file_path), "size": 0, "error": str(e)}

    def hash_data(self, data: bytes):
        """바이트 데이터 해시 계산"""
        return {
            "md5":    hashlib.md5(data).hexdigest(),
            "sha1":   hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

    def check_hash(self, hash_value, algo="sha256"):
        """단일 해시 악성 여부 확인"""
        h = hash_value.lower().strip()
        db = self.malicious_hashes.get(algo, {})
        malicious = h in db
        return {
            "hash": h,
            "algorithm": algo,
            "malicious": malicious,
            "description": db.get(h, ""),
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def scan_file(self, file_path):
        """파일 스캔: 해시 계산 + 악성 여부 판단"""
        result = self.hash_file(file_path)
        if result.get("error"):
            return result

        result["checks"] = {}
        for algo in ("md5", "sha256"):
            h = result.get(algo, "")
            result["checks"][algo] = self.check_hash(h, algo)

        result["malicious"] = any(
            c["malicious"] for c in result["checks"].values()
        )
        result["scanned_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_history.append(result)
        return result

    def scan_directory(self, directory, extensions=None):
        """디렉터리 내 파일 일괄 스캔"""
        results = []
        path = Path(directory)
        if not path.exists():
            return {"error": f"경로 없음: {directory}"}

        for fp in path.rglob("*"):
            if not fp.is_file():
                continue
            if extensions and fp.suffix.lower() not in extensions:
                continue
            results.append(self.scan_file(fp))

        malicious_count = sum(1 for r in results if r.get("malicious"))
        return {
            "directory": str(directory),
            "total_files": len(results),
            "malicious_files": malicious_count,
            "results": results,
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def add_malicious_hash(self, hash_value, algo, description):
        """악성 해시 수동 추가"""
        if algo not in self.malicious_hashes:
            self.malicious_hashes[algo] = {}
        self.malicious_hashes[algo][hash_value.lower()] = description

    def get_scan_history(self, limit=50):
        return list(self.scan_history)[-limit:]

    # ------------------------------------------------------------------ #

    def _load_db(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(",")
                    if len(parts) >= 3:
                        algo, h, desc = parts[0], parts[1], ",".join(parts[2:])
                        if algo not in self.malicious_hashes:
                            self.malicious_hashes[algo] = {}
                        self.malicious_hashes[algo][h.lower()] = desc
        except Exception as e:
            _log.error(f"[HashChecker] DB 로드 오류: {e}")
