"""합성 학습 데이터 생성기 (실험용).

`modules/ml_analyst.py` 에서 이관. 클래스별로 **서로 겹치지 않는 uniform 구간**에서
난수를 뽑는 방식이라, 이 데이터로 학습한 분류기의 홀드아웃 성능은 모델 품질이 아니라
생성기의 분리도를 측정한다. 실제로 손으로 쓴 if문 6줄이 macro-F1 0.997 을 받는다
(`scripts/eval_ml.py` 참조).

성능 주장의 근거로 쓰지 말 것. 회귀 테스트와 형태 검증 용도로만 유지한다.
"""
import numpy as np

FEATURE_NAMES = [
    "pps",              # 패킷/초
    "bps",              # 바이트/초
    "tcp_ratio",        # TCP 비율
    "udp_ratio",        # UDP 비율
    "icmp_ratio",       # ICMP 비율
    "unique_src",       # 고유 출발지 IP 수
    "unique_dst_port",  # 고유 목적지 포트 수
    "avg_pkt_size",     # 평균 패킷 크기
]

THREAT_LABELS = {
    0: "NORMAL",
    1: "DDOS",
    2: "PORT_SCAN",
    3: "BRUTE_FORCE",
    4: "DATA_EXFIL",
    5: "MALWARE_C2",
}

SAMPLES_PER_CLASS = 200

# 클래스별 피처 구간 (min, max). 정수 피처는 randint, 나머지는 uniform.
_CLASS_RANGES = {
    0: [(10, 300), (5e3, 5e5), (0.5, 0.8), (0.1, 0.35), (0.01, 0.05), (1, 20), (1, 15), (200, 1200)],
    1: [(5e3, 5e4), (5e6, 1e8), (0.05, 0.3), (0.4, 0.8), (0.1, 0.5), (5, 30), (1, 5), (40, 100)],
    2: [(50, 500), (5e4, 3e5), (0.85, 1.0), (0, 0.05), (0, 0.02), (1, 5), (80, 1024), (40, 80)],
    3: [(100, 1000), (1e5, 1e6), (0.9, 1.0), (0, 0.05), (0, 0.01), (1, 3), (1, 3), (60, 200)],
    4: [(100, 2000), (5e6, 5e8), (0.6, 0.9), (0.05, 0.2), (0, 0.02), (1, 5), (1, 4), (1000, 1500)],
    5: [(1, 30), (500, 5e4), (0.7, 1.0), (0, 0.1), (0, 0.05), (1, 3), (1, 3), (60, 300)],
}

# 정수로 뽑아야 하는 피처 인덱스 (unique_src, unique_dst_port)
_INT_FEATURES = (5, 6)


def generate_training_data(seed=42, samples_per_class=SAMPLES_PER_CLASS):
    """공격 유형별 합성 데이터 생성. 반환: (X, y).

    원본 구현과 동일한 난수 소비 순서를 유지해 기존 캐시 모델과 재현성을 맞춘다.
    """
    rng = np.random.RandomState(seed)
    X, y = [], []
    for cls in sorted(_CLASS_RANGES):
        ranges = _CLASS_RANGES[cls]
        for _ in range(samples_per_class):
            X.append([
                rng.randint(lo, hi) if i in _INT_FEATURES else rng.uniform(lo, hi)
                for i, (lo, hi) in enumerate(ranges)
            ])
            y.append(cls)
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def generate_normal_sequences(seed=7, n_sequences=400, seq_len=30):
    """정상 트래픽 '시퀀스' 합성 — LSTM Autoencoder 학습용.

    주의: 각 타임스텝을 독립적으로 뽑으므로 시퀀스 내에 **시간 의존성이 없다**.
    추세도 주기성도 자기상관도 없는 i.i.d. 잡음이라, 시간 의존성을 학습하는
    LSTM 구조가 여기서 배울 수 있는 것은 피처별 평균뿐이다.
    이 한계는 샘플 수를 늘려도 해소되지 않는다.
    """
    rng = np.random.RandomState(seed)
    ranges = _CLASS_RANGES[0]
    seqs = [
        [
            [
                rng.randint(lo, hi) if i in _INT_FEATURES else rng.uniform(lo, hi)
                for i, (lo, hi) in enumerate(ranges)
            ]
            for _ in range(seq_len)
        ]
        for _ in range(n_sequences)
    ]
    return np.array(seqs, dtype=np.float32)
