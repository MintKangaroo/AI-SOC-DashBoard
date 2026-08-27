"""구조화 로깅 (docs/AUDIT.md B-9).

전 모듈이 `print()` 119회로 상태를 알렸다. 시각도 레벨도 없고, 파일에 남지도
않고, 끌 수도 없었다. nohup 으로 띄우면 stdout 이 흘러가 버려서 사고 뒤에
원인을 되짚을 기록이 없다.

이 파일이 지키는 것은 두 가지다:
1. `print()` 가 다시 기어들어오지 않을 것.
2. 실패 경로가 INFO 로 묻히지 않을 것 — 정상 시작과 저장 실패가 같은 무게로
   섞이면 로깅을 도입한 의미가 없다.
"""
import ast
import logging
import pathlib

import pytest

from modules.logging_setup import configure_logging, get_logger

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCES = (sorted((REPO / "modules").glob("*.py"))
           + sorted((REPO / "api").glob("*.py"))
           + [REPO / "app.py", REPO / "wiring.py"])


def _print_calls(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [n.lineno for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "print"]


def test_no_print_calls_remain():
    """상태 보고는 전부 로거를 거친다."""
    offenders = {str(p.relative_to(REPO)): _print_calls(p)
                 for p in SOURCES if _print_calls(p)}
    assert offenders == {}, (
        f"print() 가 남아 있다: {offenders}\n"
        f"— `_log = get_logger(__name__)` 후 _log.info/warning/error 를 쓸 것.")


def test_every_module_that_logs_defines_its_own_logger():
    """모듈별 로거라야 `logging.getLogger('modules.soar')` 로 조절할 수 있다."""
    missing = []
    for path in SOURCES:
        src = path.read_text(encoding="utf-8")
        if "_log." in src and "_log = get_logger(__name__)" not in src:
            missing.append(str(path.relative_to(REPO)))
    assert missing == [], f"_log 를 쓰면서 정의하지 않은 파일: {missing}"


# ─────────────────── 설정 동작 ───────────────────

def test_configure_logging_writes_to_console_and_file(tmp_path):
    root = configure_logging(level="INFO", log_dir=str(tmp_path), force=True)
    try:
        kinds = {type(h).__name__ for h in root.handlers}
        assert "StreamHandler" in kinds
        assert "RotatingFileHandler" in kinds

        get_logger("modules.test_target").info("[Test] 파일에 남아야 한다")
        for h in root.handlers:
            h.flush()
        written = (tmp_path / "soc.log").read_text(encoding="utf-8")
        assert "[Test] 파일에 남아야 한다" in written
        assert "INFO" in written
        # 시각이 붙는다 — print 에는 없던 것
        assert written.startswith("20")
    finally:
        for h in list(root.handlers):
            root.removeHandler(h)


def test_logging_survives_unwritable_log_dir(tmp_path):
    """로그 파일을 못 만들어도 대시보드는 떠야 한다."""
    blocker = tmp_path / "blocked"
    blocker.write_text("이건 파일이라 디렉터리를 만들 수 없다", encoding="utf-8")
    root = configure_logging(level="INFO", log_dir=str(blocker / "logs"),
                             force=True)
    try:
        kinds = {type(h).__name__ for h in root.handlers}
        assert "StreamHandler" in kinds       # 콘솔은 살아 있다
        assert "RotatingFileHandler" not in kinds
    finally:
        for h in list(root.handlers):
            root.removeHandler(h)


def test_modules_work_without_configure_logging():
    """테스트·스크립트가 모듈만 import 해도 터지지 않는다."""
    log = get_logger("modules.standalone_check")
    log.info("핸들러가 없어도 예외가 나면 안 된다")
    log.error("에러도 마찬가지")


# ─────────────────── 레벨이 실제로 구분되는가 ───────────────────

def test_failure_path_logs_at_error(tmp_path, caplog):
    """실제 실패 경로 하나를 태워 ERROR 로 남는지 본다."""
    from modules.hash_checker import HashChecker

    db = tmp_path / "hashes.txt"
    db.write_text("md5,abc,설명\n", encoding="utf-8")
    checker = HashChecker(malicious_db_path=str(db))

    with caplog.at_level(logging.DEBUG):
        checker._load_db(str(tmp_path))       # 디렉터리를 열면 IsADirectoryError

    hits = [r for r in caplog.records if "DB 로드 오류" in r.message]
    assert hits, f"실패가 로그에 안 남았다: {[r.message for r in caplog.records]}"
    assert all(r.levelno == logging.ERROR for r in hits), (
        f"실패가 {[r.levelname for r in hits]} 로 남았다 — ERROR 여야 한다")


@pytest.mark.parametrize("module_path,expected_min", [
    ("modules/soar.py", logging.WARNING),
    ("modules/incidents.py", logging.WARNING),
    ("modules/retention.py", logging.WARNING),
])
def test_exception_handlers_do_not_log_at_info(module_path, expected_min):
    """except 블록 안의 로그는 info 면 안 된다 — 눈에 띄어야 한다."""
    tree = ast.parse((REPO / module_path).read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and isinstance(inner.func.value, ast.Name)
                    and inner.func.value.id == "_log"
                    and inner.func.attr in ("info", "debug")):
                offenders.append(inner.lineno)
    assert offenders == [], (
        f"{module_path} 의 except 블록에서 info/debug 로 남기는 곳: {offenders}")
