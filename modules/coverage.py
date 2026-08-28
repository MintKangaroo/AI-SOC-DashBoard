"""탐지 커버리지 자가 진단 (docs/AUDIT.md 3단계 제안 A).

이 대시보드는 MITRE ATT&CK 매트릭스와 Sigma 룰, 퍼플팀 시나리오를 모두 갖고
있으면서도 **"우리가 무엇을 탐지하지 못하는가"** 를 답하는 화면이 없었다.
탐지 히트는 보여주지만, 히트가 0인 기법이 '공격이 없었다'는 뜻인지 '룰이 없어
못 본다'는 뜻인지 구분되지 않았다. 그 둘은 정반대의 의미다.

세 축을 겹쳐 그 구분을 만든다:

  A. 룰이 있는가      — THREAT_MAPPING · SYSMON_MAPPING · Sigma 룰의 mitre 태그
  B. 검증되었는가     — 퍼플팀 시나리오가 그 기법을 실제로 재현하는가
  C. 히트가 있었는가  — mitre_tracker 가 실제로 매핑한 횟수

룰이 없는 칸이 곧 **커버리지 공백**이고, 그 목록이 곧 다음에 써야 할 룰의
목록이다. 새 수집기는 필요 없다 — 전부 이미 있는 데이터의 조인이다.

※ 모든 조회는 방어적이다(`system_health.py` 와 같은 원칙). 소스 하나가 없거나
  예외를 던져도 나머지로 보고서를 만든다 — 진단 화면이 진단 대상 때문에
  죽으면 안 된다.
"""
from modules.mitre_attack import SYSMON_MAPPING, TACTICS, TECHNIQUES, THREAT_MAPPING

# 커버리지 상태 (나쁜 것부터)
STATE_GAP = "gap"              # 룰 없음 — 공백
STATE_RULE = "rule"            # 룰 있음, 퍼플팀 미검증
STATE_VALIDATED = "validated"  # 룰 있음 + 퍼플팀 검증

STATE_LABELS = {
    STATE_GAP: "공백 (룰 없음)",
    STATE_RULE: "룰만 있음 (미검증)",
    STATE_VALIDATED: "검증됨",
}


def base_technique(technique_id):
    """서브기법을 상위 기법으로 접는다. T1059.004 → T1059.

    Sigma 룰과 퍼플팀은 서브기법까지 지정하지만 매트릭스는 상위 기법 단위다.
    접지 않으면 T1059.004 룰이 T1059 칸을 덮지 못해 공백으로 잘못 보고된다.
    """
    return str(technique_id or "").strip().upper().split(".")[0]


def _rule_index(sigma=None):
    """기법 → 그 기법을 탐지하는 룰 목록."""
    index = {}

    def add(technique_id, source, name):
        key = base_technique(technique_id)
        if key:
            index.setdefault(key, []).append({"source": source, "name": name})

    for threat_type, pairs in THREAT_MAPPING.items():
        for _tactic, technique in pairs:
            add(technique, "탐지엔진", threat_type)

    for event_id, pairs in SYSMON_MAPPING.items():
        for _tactic, technique in pairs:
            add(technique, "Sysmon", f"EventID {event_id}")

    for rule in _sigma_rules(sigma):
        title = rule.get("title") or rule.get("id") or "(제목 없음)"
        mitre = rule.get("mitre")
        if not mitre:
            continue
        for technique in (mitre if isinstance(mitre, (list, tuple)) else [mitre]):
            add(technique, "Sigma", title)
    return index


def _sigma_rules(sigma):
    if sigma is None:
        return []
    try:
        rules = getattr(sigma, "rules", None) or []
        # 비활성 룰은 탐지하지 않으므로 커버리지로 치지 않는다
        return [r for r in rules if r.get("enabled", True)]
    except Exception:
        return []


def _validation_index(purple=None):
    """기법 → 그 기법을 재현하는 퍼플팀 시나리오."""
    index = {}
    if purple is None:
        return index
    try:
        scenarios = getattr(purple, "scenarios", None) or []
        results = getattr(purple, "results", None) or {}
    except Exception:
        return index
    for scenario in scenarios:
        key = base_technique(scenario.get("mitre"))
        if not key:
            continue
        result = results.get(scenario.get("id")) or {}
        index.setdefault(key, []).append({
            "id": scenario.get("id"),
            "name": scenario.get("name"),
            "expect": scenario.get("expect"),
            # None = 아직 실행한 적 없음 (검증 계획만 있는 상태)
            "detected": result.get("detected") if result else None,
        })
    return index


def _hit_index(mitre_tracker=None):
    """기법 → 실제 매핑된 히트 수."""
    hits = {}
    if mitre_tracker is None:
        return hits
    try:
        raw = dict(getattr(mitre_tracker, "hits", {}) or {})
    except Exception:
        return hits
    for key, count in raw.items():
        try:
            _tactic, technique = key
        except (TypeError, ValueError):
            continue
        k = base_technique(technique)
        hits[k] = hits.get(k, 0) + int(count or 0)
    return hits


def build_coverage(mitre_tracker=None, sigma=None, purple=None):
    """세 축을 조인한 커버리지 보고서."""
    rules = _rule_index(sigma)
    validations = _validation_index(purple)
    hits = _hit_index(mitre_tracker)

    tactics, gaps = [], []
    counts = {STATE_GAP: 0, STATE_RULE: 0, STATE_VALIDATED: 0}
    seen = 0
    covered_ids = set()

    for tactic in TACTICS:
        techniques = []
        for tech in TECHNIQUES.get(tactic["id"], []):
            tid = base_technique(tech["id"])
            covered_ids.add(tid)
            tech_rules = rules.get(tid, [])
            tech_validations = validations.get(tid, [])
            hit_count = hits.get(tid, 0)

            if not tech_rules:
                state = STATE_GAP
            elif tech_validations:
                state = STATE_VALIDATED
            else:
                state = STATE_RULE
            counts[state] += 1
            if hit_count:
                seen += 1
            if state == STATE_GAP:
                gaps.append({
                    "tactic_id": tactic["id"], "tactic_ko": tactic["ko"],
                    "technique_id": tech["id"], "name": tech["name"], "ko": tech["ko"],
                    # 룰이 없는데 히트가 있으면 매핑 경로가 문서화되지 않은 것이다
                    "hits": hit_count,
                })
            techniques.append({
                "id": tech["id"], "name": tech["name"], "ko": tech["ko"],
                "state": state, "state_label": STATE_LABELS[state],
                "rules": tech_rules, "rule_count": len(tech_rules),
                "validations": tech_validations,
                "validated": bool(tech_validations),
                "hits": hit_count,
            })
        tactics.append({
            **{k: tactic[k] for k in ("id", "name", "ko")},
            "techniques": techniques,
            "gap_count": sum(1 for t in techniques if t["state"] == STATE_GAP),
        })

    # 매트릭스에 없는 기법을 가리키는 룰·시나리오 — 히트가 나도 표시될 칸이 없다
    untracked = {}
    for tid, entries in rules.items():
        if tid not in covered_ids:
            untracked.setdefault(tid, {"technique_id": tid, "rules": [], "validations": []})
            untracked[tid]["rules"] = entries
    for tid, entries in validations.items():
        if tid not in covered_ids:
            untracked.setdefault(tid, {"technique_id": tid, "rules": [], "validations": []})
            untracked[tid]["validations"] = entries

    total = sum(len(t["techniques"]) for t in tactics)
    return {
        "summary": {
            "techniques": total,
            "with_rule": counts[STATE_RULE] + counts[STATE_VALIDATED],
            "validated": counts[STATE_VALIDATED],
            "gaps": counts[STATE_GAP],
            "seen": seen,
            "rule_pct": round((counts[STATE_RULE] + counts[STATE_VALIDATED]) / total * 100, 1) if total else 0.0,
            "validated_pct": round(counts[STATE_VALIDATED] / total * 100, 1) if total else 0.0,
        },
        "tactics": tactics,
        # 공백 목록이 곧 다음에 써야 할 룰의 목록이다
        "gaps": gaps,
        "untracked": sorted(untracked.values(), key=lambda u: u["technique_id"]),
        "state_labels": STATE_LABELS,
    }
