#!/usr/bin/env python3
"""IF 실트래픽 재학습 — 저장소(data/ml_features.db)의 origin=real 피처만 쓴다.

    python scripts/retrain_ml.py            # 3,000건 미만이면 거부하고 사유 출력
    python scripts/retrain_ml.py --force    # 표본 부족을 무릅쓰고 학습(메타데이터에 forced 기록)
    python scripts/retrain_ml.py --contamination 0.03

서버가 떠 있으면 ML 패널의 '실트래픽으로 재학습' 이나 POST /api/ml/retrain 이 낫다 —
이 스크립트는 파일만 갱신하므로 서버는 재기동해야 새 모델을 든다(기동 시 실모델 우선).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ml_analyst import MIN_REAL_SAMPLES, REAL_CONTAMINATION, MLAnalyst  # noqa: E402
from modules.ml_feature_store import MLFeatureStore  # noqa: E402


class _NoSocket:
    def emit(self, *a, **k):
        pass


def main():
    ap = argparse.ArgumentParser(description="IF 실트래픽 재학습")
    ap.add_argument("--force", action="store_true", help=f"{MIN_REAL_SAMPLES:,}건 미만이어도 학습")
    ap.add_argument("--contamination", type=float, default=REAL_CONTAMINATION)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not 0 < args.contamination <= 0.5:
        print("contamination 은 0~0.5 사이"); return 2

    store = MLFeatureStore()
    try:
        ml = MLAnalyst(_NoSocket(), feature_store=store, demo=False)
        result = ml.retrain_from_store(contamination=args.contamination, force=args.force)
    finally:
        store.close()

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2)); return 0 if result.get("ok") else 1
    if not result.get("ok"):
        print(f"재학습 안 함: {result.get('detail') or result.get('reason')}"); return 1
    print(f"재학습 완료 — 실트래픽 {result['n_samples']:,}건 ({result['span'][0]} ~ {result['span'][1]})")
    print(f"  오염률 {result['contamination']} (가정) · 홀드아웃 이상률 {result['holdout_anomaly_rate']:.1%}"
          f" · 학습 이상률 {result['train_anomaly_rate']:.1%}"
          + (" · ⚠ 분포 이동 의심(학습 구간 대표성 확인)" if result["distribution_shift_suspected"] else ""))
    if result["dropped_zero"]:
        print(f"  캡처 공백(pps·bps 0) {result['dropped_zero']}건 제외")
    print("  서버가 떠 있으면 재기동해야 새 모델을 든다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
