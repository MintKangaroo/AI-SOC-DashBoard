#!/usr/bin/env python3
"""ML 평가 스크립트 — 재현 가능한 성능 측정.

## 설계 원칙

**데이터가 부족하면 숫자를 만들지 않는다.** 이 스크립트는 라벨이 모자랄 때
그럴듯한 지표를 출력하는 대신 "측정 불가"와 필요한 데이터량을 보고한다.
합성 데이터 기준 점수는 모델 품질이 아니라 데이터 생성기의 분리도를 재는
것이므로, 그 사실을 매번 함께 출력한다.

## 평가 항목

1. **데이터 현황** — 트래픽 피처(`data/ml_features.db`)와 라벨(`alerts.db`)의
   실제 수량. 평가 가능 여부 판정.
2. **룰 베이스라인** — ML 없이 임계값 규칙만 썼을 때의 성능. **이것이 기준선이다.**
   ML 이 이보다 못하면 그 사실을 그대로 리포트한다.
3. **Isolation Forest** — 홀드아웃 precision / recall / F1.
4. **합성 데이터 참고치** — 위 1~3 이 불가능할 때 무엇이 측정되고 있는지
   보여주기 위한 대조군. **성능 주장의 근거가 아니다.**

## 사용

    python scripts/eval_ml.py                 # 전체 리포트
    python scripts/eval_ml.py --json          # 기계 판독용
    python scripts/eval_ml.py --synthetic     # 합성 대조군만
"""
import argparse
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

from modules.ml_feature_store import MLFeatureStore

# ── 평가 가능 최소 요건 ──
MIN_FEATURES_FOR_RETRAIN = 3000   # IF 실트래픽 재학습 (3초 주기 ≈ 2.5시간)
MIN_LABELS_FOR_EVAL = 100         # precision/recall 신뢰구간이 의미를 갖는 최소치
MIN_LABELS_PER_CLASS = 30         # RF 복귀 조건 (클래스당)

ALERTS_DB = "data/alerts.db"
ARCHIVE_DB = "data/alerts_archive.db"
FEATURES_DB = "data/ml_features.db"


# ──────────────────────────────────────────────────────────
#  1. 데이터 현황
# ──────────────────────────────────────────────────────────

def _label_counts(db_path, table):
    """사람이 붙인 라벨만 센다. verdict_actor 가 SYSTEM 이면 자동 판정이다."""
    if not os.path.exists(db_path):
        return {"exists": False}
    conn = sqlite3.connect(db_path)
    try:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if "verdict" not in cols:
            return {"exists": True, "has_verdict_column": False}
        total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        rows = conn.execute(
            f"""SELECT verdict, COUNT(*) FROM {table}
                WHERE verdict IN ('TRUE_POSITIVE','FALSE_POSITIVE')
                  AND verdict_actor NOT IN ('', 'SYSTEM')
                GROUP BY verdict""").fetchall()
        auto = conn.execute(
            f"""SELECT COUNT(*) FROM {table}
                WHERE verdict IN ('TRUE_POSITIVE','FALSE_POSITIVE')
                  AND verdict_actor = 'SYSTEM'""").fetchone()[0]
        human = dict(rows)
        return {
            "exists": True, "has_verdict_column": True, "total_alerts": total,
            "human_true_positive": human.get("TRUE_POSITIVE", 0),
            "human_false_positive": human.get("FALSE_POSITIVE", 0),
            "human_total": sum(human.values()),
            "auto_labeled": auto,
        }
    finally:
        conn.close()


def survey():
    """평가에 쓸 수 있는 데이터가 실제로 얼마나 있는지 조사한다."""
    out = {"features": {"exists": os.path.exists(FEATURES_DB)}}
    if out["features"]["exists"]:
        store = MLFeatureStore(db_path=FEATURES_DB)
        try:
            out["features"].update(store.stats())
        finally:
            store.close()
    else:
        out["features"].update({"total": 0, "real": 0, "demo": 0})

    out["labels_live"] = _label_counts(ALERTS_DB, "alerts")
    out["labels_archive"] = _label_counts(ARCHIVE_DB, "alerts_archive")

    human = (out["labels_live"].get("human_total", 0)
             + out["labels_archive"].get("human_total", 0))
    real_feats = out["features"].get("real", 0)

    out["verdict"] = {
        "human_labels": human,
        "real_features": real_feats,
        "can_retrain_if": real_feats >= MIN_FEATURES_FOR_RETRAIN,
        "can_evaluate": human >= MIN_LABELS_FOR_EVAL,
        "features_needed": max(0, MIN_FEATURES_FOR_RETRAIN - real_feats),
        "labels_needed": max(0, MIN_LABELS_FOR_EVAL - human),
    }
    return out


# ──────────────────────────────────────────────────────────
#  2. 룰 베이스라인 — 기준선
# ──────────────────────────────────────────────────────────

def rule_baseline(x):
    """ML 없이 임계값 규칙만 쓴 분류. 이것이 ML 이 이겨야 할 기준선이다.

    임계값은 `modules/threat_detector.py` 의 실제 동작(avg_pps > 2000,
    unique_ports >= 40)과 데이터 구간에서 유도했다.
    """
    pps, bps, tcp, udp, icmp, usrc, udport, apkt = x
    if pps > 4000:
        return 1        # DDOS
    if udport >= 60:
        return 2        # PORT_SCAN
    if bps > 4e6 and apkt > 900:
        return 4        # DATA_EXFIL
    if pps < 35 and bps < 6e4:
        return 5        # MALWARE_C2
    if tcp > 0.88 and udport < 5 and pps > 90:
        return 3        # BRUTE_FORCE
    return 0            # NORMAL


# ──────────────────────────────────────────────────────────
#  3. 합성 대조군 — 무엇이 측정되고 있는지 보여주기 위함
# ──────────────────────────────────────────────────────────

def synthetic_control():
    """합성 데이터에서 룰과 RF 를 비교한다. **성능 주장의 근거가 아니다.**"""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import f1_score
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    from experimental.synthetic_data import generate_training_data

    X, y = generate_training_data()
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.3, random_state=0, stratify=y)
    scaler = StandardScaler().fit(Xtr)
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=12, random_state=42, n_jobs=-1,
    ).fit(scaler.transform(Xtr), ytr)

    rf_pred = rf.predict(scaler.transform(Xte))
    rule_pred = np.array([rule_baseline(x) for x in Xte])
    return {
        "samples": int(len(X)),
        "holdout": int(len(Xte)),
        "rf_f1_macro": round(float(f1_score(yte, rf_pred, average="macro")), 4),
        "rf_accuracy": round(float((rf_pred == yte).mean()), 4),
        "rule_f1_macro": round(float(f1_score(yte, rule_pred, average="macro")), 4),
        "rule_accuracy": round(float((rule_pred == yte).mean()), 4),
        "caveat": "합성 데이터는 클래스별로 겹치지 않는 uniform 구간에서 생성됐다. "
                  "손으로 쓴 규칙이 거의 만점을 받는 것이 그 증거다. "
                  "이 수치는 모델 품질이 아니라 생성기의 분리도를 측정한다.",
    }


# ──────────────────────────────────────────────────────────
#  4. 실데이터 평가 (데이터가 충분해지면 동작)
# ──────────────────────────────────────────────────────────

def real_evaluation(data):
    """실트래픽 + 사람 라벨로 IF 를 평가한다. 요건 미달이면 사유를 반환."""
    v = data["verdict"]
    if not v["can_retrain_if"]:
        return {
            "status": "insufficient_features",
            "detail": (f"실트래픽 피처 {v['real_features']:,}건 — "
                       f"IF 재학습에 최소 {MIN_FEATURES_FOR_RETRAIN:,}건 필요 "
                       f"({v['features_needed']:,}건 부족, 3초 주기로 약 "
                       f"{v['features_needed'] * 3 / 3600:.1f}시간 가동분)"),
        }
    if not v["can_evaluate"]:
        return {
            "status": "insufficient_labels",
            "detail": (f"사람 판정 라벨 {v['human_labels']}건 — "
                       f"precision/recall 산출에 최소 {MIN_LABELS_FOR_EVAL}건 필요 "
                       f"({v['labels_needed']}건 부족). 대시보드 알림 화면에서 "
                       f"'정탐/오탐 확정' 판정을 계속 쌓을 것."),
        }
    # 요건 충족 시 여기서 실제 평가를 수행한다.
    # 라벨을 알림 시각과 피처 시각으로 조인하는 약한 라벨링이 필요하며,
    # 그 설계는 데이터가 실제로 쌓인 뒤 확정한다(현재 조인 대상이 0건).
    return {
        "status": "ready_but_unimplemented",
        "detail": "데이터 요건은 충족됐다. 알림-피처 시각 조인 방식을 확정하고 "
                  "이 함수를 구현할 것 (docs/ml_models.md 참조).",
    }


# ──────────────────────────────────────────────────────────
#  출력
# ──────────────────────────────────────────────────────────

def _fmt_survey(d):
    f = d["features"]
    live, arch, v = d["labels_live"], d["labels_archive"], d["verdict"]
    lines = [
        "═══ 1. 데이터 현황 ═══",
        "",
        f"트래픽 피처 ({FEATURES_DB})",
        f"  전체 {f.get('total', 0):,}건  ·  실트래픽 {f.get('real', 0):,}건  "
        f"·  데모 {f.get('demo', 0):,}건",
        f"  수집 구간: {f.get('oldest') or '-'} ~ {f.get('newest') or '-'}",
        "",
        "라벨 (사람이 확정한 판정만 집계 — verdict_actor 가 SYSTEM 이면 자동)",
        f"  활성 alerts.db : 사람 {live.get('human_total', 0)}건 "
        f"(정탐 {live.get('human_true_positive', 0)} / "
        f"오탐 {live.get('human_false_positive', 0)})  "
        f"· 자동 {live.get('auto_labeled', 0)}건  "
        f"· 전체 알림 {live.get('total_alerts', 0):,}건",
        f"  아카이브       : 사람 {arch.get('human_total', 0)}건  "
        f"· 전체 알림 {arch.get('total_alerts', 0):,}건",
        "",
        "판정",
        f"  IF 실트래픽 재학습 : {'가능' if v['can_retrain_if'] else '불가'}"
        + ("" if v["can_retrain_if"]
           else f" — {v['features_needed']:,}건 부족 "
                f"(약 {v['features_needed'] * 3 / 3600:.1f}시간 가동분)"),
        f"  precision/recall   : {'가능' if v['can_evaluate'] else '불가'}"
        + ("" if v["can_evaluate"] else f" — 사람 라벨 {v['labels_needed']}건 부족"),
    ]
    return "\n".join(lines)


def _fmt_synthetic(s):
    better = "규칙" if s["rule_f1_macro"] >= s["rf_f1_macro"] else "RF"
    gap = abs(s["rf_f1_macro"] - s["rule_f1_macro"])
    return "\n".join([
        "═══ 3. 합성 대조군 (성능 주장의 근거 아님) ═══",
        "",
        f"  샘플 {s['samples']:,}건 · 홀드아웃 {s['holdout']:,}건 (7:3 stratified)",
        "",
        f"  {'모델':<20}{'F1(macro)':>12}{'정확도':>12}",
        f"  {'-' * 44}",
        f"  {'룰 베이스라인':<18}{s['rule_f1_macro']:>12.4f}{s['rule_accuracy']:>12.4f}",
        f"  {'Random Forest':<20}{s['rf_f1_macro']:>12.4f}{s['rf_accuracy']:>12.4f}",
        "",
        f"  → {better} 우위, 차이 {gap:.4f}",
        "",
        "  ⚠ " + s["caveat"].replace(". ", ".\n    "),
    ])


def main():
    ap = argparse.ArgumentParser(description="ML 평가 — 데이터 부족 시 숫자를 만들지 않는다")
    ap.add_argument("--json", action="store_true", help="기계 판독용 JSON 출력")
    ap.add_argument("--synthetic", action="store_true", help="합성 대조군만 실행")
    args = ap.parse_args()

    if args.synthetic:
        s = synthetic_control()
        print(json.dumps(s, ensure_ascii=False, indent=2) if args.json
              else _fmt_synthetic(s))
        return 0

    data = survey()
    data["real_evaluation"] = real_evaluation(data)
    data["synthetic_control"] = synthetic_control()

    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    print("ML 평가 리포트")
    print("=" * 60)
    print()
    print(_fmt_survey(data))
    print()
    ev = data["real_evaluation"]
    print("═══ 2. 실데이터 평가 (룰 베이스라인 대비) ═══")
    print()
    print(f"  상태: {ev['status']}")
    print(f"  {ev['detail']}")
    print()
    print(_fmt_synthetic(data["synthetic_control"]))
    print()
    print("=" * 60)
    if ev["status"].startswith("insufficient"):
        print("결론: 현재 데이터로는 정직한 성능 수치를 낼 수 없다.")
        print("      docs/ml_models.md 에 '측정 불가'로 기록하고, 데이터를 더 모을 것.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
