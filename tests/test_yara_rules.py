"""YARA 룰 CI 검증 — detection-as-code.

`hash_checker` 의 해시 대조는 '알려진 바로 그 파일'만 잡는다. YARA 는 내용
패턴으로 잡아 변종을 덮는다. 다만 **내용 패턴은 오탐이 나기 쉽다** — 문자열
하나가 넓으면 정상 파일이 CRITICAL 로 올라온다(Sigma 의 크립토마이너 룰이
`pool` 하나로 gunicorn 을 잡던 것과 같은 실패 양상).

그래서 Sigma 와 같은 장치를 건다: 각 룰이 정탐/오탐 샘플을 갖고 CI 가 매 push
마다 검증한다. 샘플은 `data/yara/rule_tests.yml` 에 있다 — YARA 의 `meta` 는
스칼라만 담을 수 있어 룰 파일 안에 넣지 못한다.

**negative 가 핵심이다.** 오탐은 조용히 쌓이다가 분석가가 알림을 무시하게
만드는 방식으로 탐지 체계를 망가뜨린다.
"""
import base64
import glob
import os
import re

import pytest
import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO, "data", "yara")
RULE_FILES = sorted(glob.glob(os.path.join(RULES_DIR, "*.yar"))
                    + glob.glob(os.path.join(RULES_DIR, "*.yara")))
TESTS_PATH = os.path.join(RULES_DIR, "rule_tests.yml")

yara = pytest.importorskip("yara", reason="yara-python 미설치")

VALID_SEVERITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@pytest.fixture(scope="module")
def scanner():
    """실제 스캐너로 평가한다 — 별도 매처를 만들면 룰이 아니라 테스트를 검증하게 된다."""
    from modules.yara_scanner import YaraScanner

    engine = YaraScanner(config={"YARA_RULES_DIR": RULES_DIR})
    engine.start()
    assert engine.stats["rules_loaded"] > 0, "룰이 하나도 로드되지 않았다"
    return engine


@pytest.fixture(scope="module")
def rule_cases():
    with open(TESTS_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _rule_names():
    names = []
    for path in RULE_FILES:
        text = open(path, encoding="utf-8").read()
        names += re.findall(r"^rule\s+([A-Za-z_][\w]*)", text, re.M)
    return sorted(names)


RULE_NAMES = _rule_names()


def _case_data(case):
    if "content_b64" in case:
        return base64.b64decode(case["content_b64"])
    return case["content"]


def _cases(kind):
    with open(TESTS_PATH, encoding="utf-8") as f:
        spec = yaml.safe_load(f) or {}
    out = []
    for rule, kinds in spec.items():
        for case in (kinds or {}).get(kind, []):
            out.append(pytest.param(rule, case, id=f"{rule}::{case.get('name', '?')}"))
    return out


# ─────────────── 룰 위생 ───────────────

def test_rules_exist_and_compile(scanner):
    assert RULE_NAMES, "YARA 룰이 하나도 없다"
    assert scanner.stats["rules_loaded"] == len(RULE_NAMES)
    assert scanner.stats["rules_error"] == 0


@pytest.mark.parametrize("name", RULE_NAMES)
def test_rule_has_required_meta(scanner, name):
    """설명·심각도·MITRE 가 없으면 탐지가 떠도 무엇인지 알 수 없다."""
    meta = next((r for r in scanner.rule_meta if r["name"] == name), None)
    assert meta, f"{name} 메타를 못 찾았다"
    assert meta["description"], f"{name}: description 이 없다"
    assert meta["severity"] in VALID_SEVERITY, f"{name}: severity={meta['severity']}"
    assert meta["mitre"], f"{name}: mitre 태그가 없다 — 커버리지 진단에서 보이지 않는다"


@pytest.mark.parametrize("name", RULE_NAMES)
def test_rule_technique_has_a_matrix_cell(scanner, name):
    """매트릭스에 칸이 없으면 탐지돼도 표시될 곳이 없다 (Sigma 와 같은 불변식)."""
    from modules.coverage import base_technique
    from modules.mitre_attack import TECHNIQUES

    known = {t["id"] for techs in TECHNIQUES.values() for t in techs}
    meta = next(r for r in scanner.rule_meta if r["name"] == name)
    tid = base_technique(meta["mitre"])
    assert tid in known, (
        f"{name}: {tid} 가 MITRE 매트릭스에 없다 — "
        f"modules/mitre_attack.py 의 TECHNIQUES 에 추가할 것")


@pytest.mark.parametrize("name", RULE_NAMES)
def test_every_rule_ships_with_tests(rule_cases, name):
    """테스트 없는 룰은 다음 수정 때 조용히 망가진다."""
    spec = rule_cases.get(name)
    assert spec, f"{name}: data/yara/rule_tests.yml 에 테스트가 없다"
    assert spec.get("positive"), f"{name}: positive 샘플이 없다"
    assert spec.get("negative"), (
        f"{name}: negative 샘플이 없다 — 오탐 회귀를 막는 건 negative 쪽이다")


def test_test_file_has_no_orphan_entries(rule_cases):
    """사라진 룰의 테스트가 남아 있으면 '검증되고 있다'는 착각을 준다."""
    orphans = sorted(set(rule_cases) - set(RULE_NAMES))
    assert orphans == [], f"대응하는 룰이 없는 테스트: {orphans}"


# ─────────────── 탐지 어서션 ───────────────

@pytest.mark.parametrize("rule,case", _cases("positive"))
def test_positive_samples_match(scanner, rule, case):
    hits = [m["rule"] for m in scanner.scan_data(_case_data(case))]
    assert rule in hits, (
        f"'{rule}' 이 자기 positive 샘플을 놓쳤다: {case['name']} → {hits}")


@pytest.mark.parametrize("rule,case", _cases("negative"))
def test_negative_samples_do_not_match(scanner, rule, case):
    hits = [m["rule"] for m in scanner.scan_data(_case_data(case))]
    assert rule not in hits, (
        f"'{rule}' 이 정상 내용을 오탐했다: {case['name']} → {hits}")


# ─────────────── 스캐너 안전 한계 ───────────────

def test_oversized_file_is_skipped_not_scanned(tmp_path):
    """스캐너가 관제 서버를 잡아먹으면 안 된다."""
    from modules.yara_scanner import YaraScanner

    engine = YaraScanner(config={"YARA_RULES_DIR": RULES_DIR, "YARA_MAX_FILE_MB": 0.001})
    engine.start()
    big = tmp_path / "big.bin"
    big.write_bytes(b"A" * 10_000)
    result = engine.scan_file(str(big))
    assert result["skipped"] is True and result["matches"] == []
    assert engine.stats["skipped_too_big"] == 1


def test_missing_file_returns_error_not_exception(scanner):
    result = scanner.scan_file("/nonexistent/definitely/not/here.bin")
    assert result["matches"] == [] and "파일 접근 불가" in result["error"]


def test_directory_scan_does_not_follow_symlinks(tmp_path):
    """심볼릭 링크를 따라가면 허용 경로 밖으로 새어나간다."""
    from modules.yara_scanner import YaraScanner

    engine = YaraScanner(config={"YARA_RULES_DIR": RULES_DIR})
    engine.start()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.php").write_text("<?php eval($_POST['c']); ?>", encoding="utf-8")
    inside = tmp_path / "inside"
    inside.mkdir()
    try:
        (inside / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):      # pragma: no cover
        pytest.skip("심볼릭 링크를 만들 수 없는 환경")
    result = engine.scan_directory(str(inside))
    assert result["matched_files"] == 0, "심볼릭 링크를 따라 허용 경로 밖을 읽었다"


def test_directory_scan_respects_file_cap(tmp_path):
    from modules.yara_scanner import YaraScanner

    engine = YaraScanner(config={"YARA_RULES_DIR": RULES_DIR, "YARA_MAX_FILES": 5})
    engine.start()
    for i in range(20):
        (tmp_path / f"f{i}.txt").write_text("normal content", encoding="utf-8")
    result = engine.scan_directory(str(tmp_path))
    assert result["files_scanned"] == 5 and result["truncated"] is True


def test_match_does_not_carry_the_payload(scanner):
    """악성 페이로드 사본을 결과에 담을 이유가 없다 — 식별자와 개수만 남긴다."""
    hits = scanner.scan_data("<?php eval($_POST['cmd']); ?>")
    assert hits and all("matched_strings" in h for h in hits)
    blob = repr(hits)
    assert "$_POST['cmd']" not in blob, "매치 결과에 원문 페이로드가 들어갔다"


# ─────────────── 파이프라인 연결 ───────────────

class _Recorder:
    def __init__(self):
        self.alerts = []

    def report_alert(self, threat_type, severity, **kw):
        self.alerts.append({"threat_type": threat_type, "severity": severity, **kw})


class _SilentSocket:
    def __init__(self):
        self.events = []

    def emit(self, name, payload=None, **kw):
        self.events.append((name, payload))


def test_match_feeds_the_detection_pipeline(tmp_path):
    """탐지가 알림으로 이어지지 않으면 스캐너는 장식이다."""
    from modules.yara_scanner import YaraScanner

    detector, socket = _Recorder(), _SilentSocket()
    engine = YaraScanner(socket, config={"YARA_RULES_DIR": RULES_DIR},
                         threat_detector=detector)
    engine.start()
    sample = tmp_path / "shell.php"
    sample.write_text("<?php system($_GET['c']); ?>", encoding="utf-8")
    result = engine.scan_file(str(sample))

    assert result["malicious"] is True and result["severity"] == "CRITICAL"
    assert detector.alerts, "매치했는데 알림이 나가지 않았다"
    alert = detector.alerts[0]
    assert alert["threat_type"] == "MALWARE_FILE"
    assert alert["details"]["source"] == "yara"
    assert alert["details"]["rule_id"] == "SOC_PHP_Webshell"
    assert ("yara_match", ) != socket.events[0][:1] or socket.events


def test_pipeline_failure_does_not_break_the_scan(tmp_path):
    """알림 전달이 실패해도 스캔 결과는 돌려줘야 한다."""
    from modules.yara_scanner import YaraScanner

    class _Broken:
        def report_alert(self, *a, **k):
            raise RuntimeError("파이프라인 고장")

    engine = YaraScanner(config={"YARA_RULES_DIR": RULES_DIR},
                         threat_detector=_Broken())
    engine.start()
    sample = tmp_path / "shell.php"
    sample.write_text("<?php eval($_POST['c']); ?>", encoding="utf-8")
    assert engine.scan_file(str(sample))["malicious"] is True


def test_yara_rules_appear_in_coverage_report(scanner):
    """YARA 룰이 커버리지 진단의 룰 소스로 잡혀야 한다."""
    from modules.coverage import build_coverage

    report = build_coverage(yara=scanner)
    covered = {t["id"]: t for tac in report["tactics"] for t in tac["techniques"]}
    # 웹셸 룰의 T1505 가 YARA 를 근거로 덮여 있어야 한다
    sources = {r["source"] for r in covered["T1505"]["rules"]}
    assert "YARA" in sources, f"YARA 가 커버리지 룰 소스에 없다: {sources}"
    assert report["untracked"] == [], "매트릭스에 칸이 없는 YARA 기법이 있다"


# ─────────────── 자동 스캔 (EDR 실행 파일 · 디렉터리 감시) ───────────────

def _auto_scanner(**cfg):
    from modules.yara_scanner import YaraScanner

    engine = YaraScanner(config={"YARA_RULES_DIR": RULES_DIR, **cfg})
    engine.start()
    return engine


def test_same_file_is_scanned_once(tmp_path):
    """자동 스캔의 전제는 같은 파일을 반복해서 읽지 않는 것이다.

    EDR 은 수 초마다 같은 프로세스 목록을 돌려준다 — 캐시가 없으면
    /usr/bin/python3 를 하루에 수만 번 읽는다.
    """
    engine = _auto_scanner()
    sample = tmp_path / "app.bin"
    sample.write_text("normal content", encoding="utf-8")
    assert engine.scan_once(str(sample)) is not None
    for _ in range(5):
        assert engine.scan_once(str(sample)) is None, "같은 파일을 또 읽었다"
    assert engine.stats["auto_scanned"] == 1
    assert engine.stats["auto_skipped_cached"] == 5


def test_modified_file_is_scanned_again(tmp_path):
    """내용이 바뀌면 다시 봐야 한다 — 캐시가 탐지를 가리면 안 된다."""
    import os
    import time

    engine = _auto_scanner()
    sample = tmp_path / "app.bin"
    sample.write_text("normal content", encoding="utf-8")
    engine.scan_once(str(sample))
    time.sleep(1.1)                     # mtime 초 단위 해상도
    sample.write_text("<?php eval($_POST['c']); ?>", encoding="utf-8")
    os.utime(str(sample), None)
    result = engine.scan_once(str(sample))
    assert result is not None and result["malicious"] is True


def test_process_images_are_scanned_and_matched(tmp_path):
    """이름을 바꿔 위장한 파일은 커맨드라인만 봐서는 안 잡힌다."""
    engine = _auto_scanner()
    disguised = tmp_path / "systemd-helper"
    disguised.write_text("<?php system($_GET['c']); ?>", encoding="utf-8")
    hits = engine.scan_process_images([
        {"pid": 1, "name": "systemd-helper", "exe_path": str(disguised)},
        {"pid": 2, "name": "python3", "exe_path": "/nonexistent/python3"},
        {"pid": 3, "name": "kthreadd", "exe_path": ""},            # 커널 스레드
        {"pid": 4, "name": "rel", "exe_path": "relative/path"},    # 절대경로 아님
    ])
    assert [h["path"] for h in hits] == [str(disguised)]


def test_process_scan_can_be_disabled():
    engine = _auto_scanner(YARA_SCAN_PROCESSES=False)
    assert engine.scan_process_images([{"exe_path": "/usr/bin/env"}]) == []


def test_seen_cache_is_bounded(tmp_path):
    """캐시가 무한히 자라면 그것도 누수다."""
    engine = _auto_scanner(YARA_SEEN_CACHE=20)
    for i in range(60):
        f = tmp_path / f"f{i}.bin"
        f.write_text(f"content {i}", encoding="utf-8")
        engine.scan_once(str(f))
    assert len(engine._seen) <= 20 + 1


def test_system_files_do_not_false_positive():
    """자동 스캔은 시스템 파일을 통째로 훑는다 — 오탐이 곧 알림 폭탄이다.

    이 테스트는 두 번 실제로 오탐을 잡았고, 그때마다 룰을 조였다:

    1. `/usr/bin` 743개 중 **ctest·tailscale** — 바이너리 안에 'curl ' 과 '| sh'
       가 서로 멀리 떨어져 있었을 뿐이다 → 근접성 조건 추가.
    2. CI 러너의 **GNU parallel** — 자기 설치 안내문에 "wget -O - pi.dk/3 | bash"
       가 있다. 문서에 적힌 명령과 실행되는 명령을 YARA 는 구분 못 한다
       → 스킴 있는 전체 URL 요구.
    3. CI 러너의 **upx-ucl**(패커 도구 자신) — UPX 룰이 걸렸다. 패킹 자체는
       악성이 아니고 패커와 패킹된 파일을 내용만으로 구분하기 어렵다
       → 그 룰을 `scope = "manual"` 로 내려 자동 스캔에서 뺐다.

    **이 테스트가 새 환경에서 실패하면 그건 진짜 오탐을 찾은 것이다.** 룰을
    조이거나, 자동 스캔에 맞지 않는 룰이면 scope 를 내리거나, 정말 탐지가 맞다면
    그 판단을 여기 적을 것. 그냥 넘기지 말 것.
    """
    import glob
    import os

    engine = _auto_scanner(YARA_MAX_FILES=20000)
    candidates = []
    for pattern in ("/usr/bin/*", "/usr/sbin/*", "/bin/*"):
        candidates += [p for p in glob.glob(pattern)
                       if os.path.isfile(p) and not os.path.islink(p)]
    if len(candidates) < 50:
        pytest.skip("시스템 파일이 충분치 않은 환경")
    matched = {}
    for path in candidates:
        # 자동 스캔과 같은 조건으로 본다 — scope="manual" 룰은 여기 해당 없다
        hits = [m["rule"] for m in engine.scan_file(path, scope="auto")["matches"]]
        if hits:
            matched[path] = hits
    assert matched == {}, f"시스템 파일 오탐: {matched}"


def test_manual_scope_rules_are_excluded_from_auto_scan(tmp_path):
    """자동 스캔에 맞지 않는 룰을 뺄 수 있어야 한다 — 없으면 룰을 지우게 된다.

    UPX 룰이 그 경우다. 패킹 자체는 악성이 아니고 패커 도구가 자기 시그니처를
    담고 있어 자동 스캔에서 소음이지만, 분석가가 의심 파일을 지목했을 때는
    의미 있는 정황이다.
    """
    import base64

    engine = _auto_scanner()
    sample = tmp_path / "packed.bin"
    sample.write_bytes(base64.b64decode("f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAVVBYIQ=="))
    manual = [m["rule"] for m in engine.scan_file(str(sample), scope="manual")["matches"]]
    auto = [m["rule"] for m in engine.scan_file(str(sample), scope="auto")["matches"]]
    assert "SOC_UPX_Packed_ELF" in manual, "수동 스캔에서도 안 잡히면 룰이 죽은 것이다"
    assert "SOC_UPX_Packed_ELF" not in auto


def test_every_rule_declares_a_valid_scope(scanner):
    for rule in scanner.rule_meta:
        assert rule["scope"] in ("auto", "manual"), \
            f"{rule['name']}: scope={rule['scope']}"


def test_permission_denied_is_a_skip_not_an_error(tmp_path):
    """자동 스캔이 /etc 를 훑으면 shadow·sudoers 에서 매번 걸린다.

    이걸 오류로 세면 로그가 잠기고 텔레메트리의 실패 카운터가 거짓말을 한다.
    실측으로 /etc 733개 중 26개가 권한 없음이었다.
    """
    import os

    engine = _auto_scanner()
    secret = tmp_path / "secret.bin"
    secret.write_text("<?php eval($_POST['c']); ?>", encoding="utf-8")
    os.chmod(secret, 0o000)
    if os.access(str(secret), os.R_OK):        # root 로 돌면 의미가 없다
        pytest.skip("root 권한 — 권한 거부를 재현할 수 없음")
    result = engine.scan_file(str(secret))
    assert result["skipped"] is True and result["matches"] == []
    assert engine.stats["errors"] == 0, "권한 없음을 오류로 셌다"
    assert engine.stats["skipped_no_permission"] == 1
