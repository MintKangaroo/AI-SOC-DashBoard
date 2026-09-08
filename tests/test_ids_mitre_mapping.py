"""IDS 분류(classtype) → MITRE 기법 매핑 — 표의 무결성과 '모르는 분류는 비운다' 원칙."""
from modules import mitre_attack as ma


def _catalog():
    return {(tac, t["id"]) for tac, techs in ma.TECHNIQUES.items() for t in techs}


def test_every_mapping_points_at_a_real_tactic_technique_pair():
    cat = _catalog()
    bad = [(k, pair) for k, pairs in ma.IDS_CATEGORY_MAPPING.items() for pair in pairs if pair not in cat]
    assert bad == [], f"매트릭스에 없는 (전술, 기법) 조합: {bad}"


def test_keys_are_normalised_lowercase():
    assert all(k == k.lower().strip() for k in ma.IDS_CATEGORY_MAPPING)


def test_lookup_is_case_and_space_insensitive():
    assert ma.ids_category_mappings("Web Application Attack") == [("TA0001", "T1190")]
    assert ma.ids_category_mappings("  web   application ATTACK ") == [("TA0001", "T1190")]
    assert ma.ids_category_mappings("attempted-recon") == [("TA0043", "T1595")]


def test_unknown_or_weak_categories_yield_nothing():
    for c in ("Misc Attack", "Potentially Bad Traffic", "Not Suspicious Traffic", "Unknown Traffic",
              "Generic Protocol Command Decode", "policy-violation", "", None, "totally new thing"):
        assert ma.ids_category_mappings(c) == [], c


def test_tracker_records_hits_only_for_mapped_categories():
    class Sock:
        def emit(self, *a, **k): pass
    tr = ma.MitreTracker(Sock()) if "socketio" in ma.MitreTracker.__init__.__code__.co_varnames else ma.MitreTracker()
    n = tr.map_ids_category("suricata", "Web Application Attack", "203.0.113.5", "10.0.0.2",
                            "[Suricata SID 1] ET WEB_SERVER x", "HIGH")
    assert n == 1
    assert tr.map_ids_category("snort", "Misc activity", "1.2.3.4", None, "x") == 0
    hits = tr.get_matrix() if hasattr(tr, "get_matrix") else None
    if isinstance(hits, dict) and "hits" in hits:
        assert any("T1190" in str(k) for k in hits["hits"])


def test_snort_parser_captures_classification():
    from modules.snort_monitor import parse_fast_alert
    line = ("07/21-17:01:02.123456  [**] [1:2100365:8] ET SCAN Test [**] "
            "[Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.50:45678 -> 192.168.1.10:22")
    ev = parse_fast_alert(line)
    assert ev["classification"] == "Attempted Information Leak"
    old = "07/21-17:01:02.123456  [**] [1:1:1] msg [**] [Priority: 1] {TCP} 1.1.1.1:1 -> 2.2.2.2:2"
    assert parse_fast_alert(old)["classification"] == ""
