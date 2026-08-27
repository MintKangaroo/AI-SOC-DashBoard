"""구조화 로깅 설정 (docs/AUDIT.md B-9).

이전에는 전 모듈이 `print()` 119회로 상태를 알렸다. 그래서

- **시각이 없었다.** "[Syslog] 바인딩 불가"가 언제 난 건지 알 수 없다.
- **레벨이 없었다.** 정상 시작 메시지와 저장 실패가 같은 무게로 섞여, 무엇을
  봐야 하는지 화면만 보고는 구분되지 않았다.
- **파일에 남지 않았다.** nohup 으로 띄우면 stdout 이 흘러가고, 문제가 생긴
  뒤에는 원인을 되짚을 기록이 없다.
- **끌 수 없었다.** 모듈별로 시끄러움을 조절할 방법이 없다.

메시지의 `[Tag]` 접두는 그대로 둔다 — 이미 컴포넌트 표시로 동작하고 있고,
119개 문자열을 건드리면 그만큼 위험만 늘어난다. 로거 이름(모듈 경로)은
출력에는 안 나오지만 `logging.getLogger("modules.soar").setLevel(...)` 로
모듈별 조절을 가능하게 한다.
"""
import logging
import logging.handlers
import os
import sys

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def get_logger(name):
    """모듈용 로거. 각 모듈 상단에서 `_log = get_logger(__name__)`."""
    return logging.getLogger(name)


def configure_logging(level="INFO", log_dir="logs", filename="soc.log",
                      max_bytes=5 * 1024 * 1024, backups=5, force=False):
    """루트 로거에 콘솔 + 회전 파일 핸들러를 붙인다.

    앱 기동 시 한 번만 호출한다. 테스트나 스크립트가 모듈을 그냥 import 하는
    경우에는 호출되지 않으며, 그때는 파이썬 기본 동작(핸들러 없음 →
    WARNING 이상만 stderr)을 따른다. 즉 **이 함수를 부르지 않아도 모듈은
    정상 동작한다.**

    파일 핸들러 생성에 실패해도(권한·디스크) 콘솔 로깅은 살린다 — 로깅
    설정 때문에 관제 대시보드가 못 뜨는 일은 없어야 한다.
    """
    global _configured
    if _configured and not force:
        return logging.getLogger()

    root = logging.getLogger()
    if force:
        for h in list(root.handlers):
            root.removeHandler(h)
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    try:
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, filename), maxBytes=int(max_bytes),
            backupCount=int(backups), encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as e:
        root.warning("[SOC] 로그 파일 기록 불가(%s) — 콘솔로만 남깁니다.", e)

    # 서드파티 소음 억제: 요청 한 건마다 남는 werkzeug 접근 로그와
    # engineio/socketio 의 패킷 단위 디버그는 관제 화면에서 의미가 없다.
    for noisy in ("werkzeug", "engineio", "socketio", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True
    return root
