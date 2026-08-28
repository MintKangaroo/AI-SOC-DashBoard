"""탐지 커버리지 자가 진단 (docs/AUDIT.md 3단계 제안 A).

이 대시보드는 MITRE 매트릭스·Sigma 룰·퍼플팀 시나리오를 전부 갖고 있으면서도
**"우리가 무엇을 탐지하지 못하는가"** 를 답하지 못했다. 히트 0 인 기법이
'공격이 없었다'인지 '룰이 없어 못 본다'인지 구분되지 않았고, 그 둘은 정반대다.

이 테스트가 지키는 것:
1. 세 축(룰·검증·히트)이 실제로 조인된다 — 하나라도 빠지면 진단이 거짓말이 된다.
2. **소스가 없거나 고장나도 보고서가 나온다** — 진단 화면이 진단 대상 때문에
   죽으면 안 된다.
3. 서브기법이 상위 기법으로 접힌다 — 안 접으면 T1059.004 룰이 T1059 칸을
   덮지 못해 멀쩡한 커버리지가 공백으로 보고된다.
"""
import pytest

from modules.coverage import (STATE_GAP, STATE_RULE, STATE_VALIDATED,
                              base_technique, build_coverage)
from modules.mitre_attack import TACTICS, TECHNIQUES


class _Tracker:
    def __init__(self, hits=None):
        self.hits = hits or {}


class _Sigma:
    def __init__(self, rules):
        self.rules = rules


class _Purple:
    def __init__(self, scenarios, results=None):
        self.scenarios = scenarios
        self.results = results or {}


def _find(report, technique_id):
    for tactic in report["tactics"]:
        for tech in tactic["techniques"]:
            if tech["id"] == technique_id:
                return tech
    raise AssertionError(f"{technique_id} 가 매트릭스에 없다")


# ─────────────── 서브기법 접기 ───────────────

@pytest.mark.parametrize("raw,expected", [
    ("T1059.004", "T1059"),
    ("t1505.003", "T1505"),
    ("T1046", "T1046"),
    ("  T1071  ", "T1071"),
    (None, ""),
])
def test_sub_techniques_fold_to_base(raw, expected):
    assert base_technique(raw) == expected


def test_sub_technique_rule_covers_its_parent_cell():
    """T1059.004 룰이 T1059 칸을 덮지 않으면 멀쩡한 커버리지가 공백이 된다."""
    report = build_coverage(sigma=_Sigma([
        {"title": "리버스 셸", "mitre": "T1059.004", "enabled": True}]))
    tech = _find(report, "T1059")
    assert tech["state"] != STATE_GAP
    assert any(r["source"] == "Sigma" for r in tech["rules"])


# ─────────────── 세 축 조인 ───────────────

def test_rule_without_validation_is_rule_state():
    report = build_coverage(sigma=_Sigma([
        {"title": "웹셸", "mitre": "T1505.003", "enabled": True}]))
    tech = _find(report, "T1505")
    assert tech["state"] == STATE_RULE
    assert tech["validated"] is False


def test_rule_with_purple_scenario_is_validated():
    report = build_coverage(
        sigma=_Sigma([{"title": "웹셸", "mitre": "T1505.003", "enabled": True}]),
        purple=_Purple([{"id": "webshell", "name": "웹셸", "mitre": "T1505.003",
                         "expect": "Sigma/EDR"}]))
    tech = _find(report, "T1505")
    assert tech["state"] == STATE_VALIDATED
    assert tech["validations"][0]["id"] == "webshell"
    # 아직 실행 전이면 detected 는 None — '검증 계획'과 '검증 통과'는 다르다
    assert tech["validations"][0]["detected"] is None


def test_purple_result_is_carried_through():
    report = build_coverage(
        sigma=_Sigma([{"title": "웹셸", "mitre": "T1505", "enabled": True}]),
        purple=_Purple([{"id": "webshell", "name": "웹셸", "mitre": "T1505"}],
                       results={"webshell": {"detected": True}}))
    assert _find(report, "T1505")["validations"][0]["detected"] is True


def test_disabled_sigma_rule_does_not_count_as_coverage():
    """끈 룰은 탐지하지 않는다 — 커버리지로 세면 진단이 거짓말이 된다."""
    report = build_coverage(sigma=_Sigma([
        {"title": "웹셸", "mitre": "T1505.003", "enabled": False}]))
    assert _find(report, "T1505")["state"] == STATE_GAP


def test_hits_are_folded_and_reported():
    report = build_coverage(_Tracker({("TA0006", "T1110"): 3, ("TA0002", "T1059.004"): 2}))
    assert _find(report, "T1110")["hits"] == 3
    assert _find(report, "T1059")["hits"] == 2      # 서브기법 히트가 상위로 합산


# ─────────────── 공백 목록 ───────────────

def test_gaps_list_matches_gap_cells():
    report = build_coverage()
    gap_ids = {g["technique_id"] for g in report["gaps"]}
    cell_ids = {t["id"] for tac in report["tactics"] for t in tac["techniques"]
                if t["state"] == STATE_GAP}
    assert gap_ids == cell_ids
    assert report["summary"]["gaps"] == len(gap_ids)


def test_summary_counts_add_up():
    report = build_coverage()
    s = report["summary"]
    assert s["techniques"] == sum(len(TECHNIQUES.get(t["id"], [])) for t in TACTICS)
    assert s["with_rule"] + s["gaps"] == s["techniques"]
    assert s["validated"] <= s["with_rule"]


def test_hit_without_rule_is_flagged_in_the_gap_row():
    """룰이 없는데 히트가 있으면 매핑 경로가 문서화되지 않은 것이다."""
    report = build_coverage(_Tracker({("TA0001", "T1566"): 4}))
    row = next(g for g in report["gaps"] if g["technique_id"] == "T1566")
    assert row["hits"] == 4


# ─────────────── 매트릭스 밖 기법 ───────────────

def test_rules_pointing_outside_the_matrix_are_surfaced():
    """칸이 없는 기법의 룰은 탐지돼도 표시될 곳이 없다 — 조용히 넘기면 안 된다."""
    report = build_coverage(sigma=_Sigma([
        {"title": "가상 룰", "mitre": "T9999", "enabled": True}]))
    assert [u["technique_id"] for u in report["untracked"]] == ["T9999"]


def test_shipped_rules_all_have_a_matrix_cell():
    """실제 동작 구성에서는 매트릭스 밖 기법이 없어야 한다.

    T1496·T1505 가 여기 걸려서 매트릭스에 추가됐다 — 룰과 시나리오가 있는데
    표시할 칸이 없었다. 이 테스트는 그 상태로 되돌아가지 않게 한다.
    """
    import glob
    import os

    import yaml
    rules = []
    for path in sorted(glob.glob(os.path.join("data", "sigma", "*.yml"))):
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        tags = [t for t in (doc.get("tags") or []) if str(t).lower().startswith("attack.t")]
        for tag in tags:
            rules.append({"title": doc.get("title", path), "enabled": True,
                          "mitre": str(tag).split(".", 1)[1].upper()})
    from modules.purple_team import PurpleTeam
    purple = PurpleTeam.__new__(PurpleTeam)
    purple.scenarios = [{"id": "x", "name": "n", "mitre": m} for m in
                        ("T1059.004", "T1505.003", "T1496", "T1046", "T1105", "T1110", "T1071")]
    purple.results = {}
    report = build_coverage(sigma=_Sigma(rules), purple=purple)
    assert report["untracked"] == [], (
        f"매트릭스에 칸이 없는 기법: {[u['technique_id'] for u in report['untracked']]}\n"
        f"— modules/mitre_attack.py 의 TECHNIQUES 에 추가할 것.")


# ─────────────── 방어적 동작 ───────────────

def test_report_survives_missing_sources():
    report = build_coverage(None, None, None)
    assert report["summary"]["techniques"] > 0
    assert report["summary"]["with_rule"] > 0   # 내장 매핑만으로도 일부는 덮인다


class _Exploding:
    @property
    def rules(self):
        raise RuntimeError("소스 고장")

    @property
    def scenarios(self):
        raise RuntimeError("소스 고장")

    @property
    def hits(self):
        raise RuntimeError("소스 고장")


def test_report_survives_exploding_sources():
    """진단 화면이 진단 대상 때문에 죽으면 안 된다."""
    report = build_coverage(_Exploding(), _Exploding(), _Exploding())
    assert report["summary"]["techniques"] > 0
