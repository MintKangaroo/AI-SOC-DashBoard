"""API 라우트 집계 — 도메인 파일을 임포트해 api_bp 에 라우트를 등록한다.
   app.py 는 여기서 api_bp 를 가져온다."""
from api._common import api_bp  # noqa: F401 (app.py 재임포트용)
from api import (  # noqa: F401 (임포트 부수효과로 라우트 등록)
    detection_routes,
    analysis_routes,
    monitoring_routes,
    scan_routes,
    response_routes,
    console_routes,
)

from api import identity_routes  # noqa: F401
