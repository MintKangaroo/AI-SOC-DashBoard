"""
SOC 대시보드 메인 앱
"""
import secrets
import logging
from datetime import timedelta
from urllib.parse import urlparse
from flask import (Flask, render_template, request, session,
                   redirect, jsonify)
from flask_socketio import SocketIO
from flask_cors import CORS

# Werkzeug / Flask / SocketIO 요청 로그 억제
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("engineio").setLevel(logging.ERROR)
logging.getLogger("socketio").setLevel(logging.ERROR)
# 시작 배너 로그 제거
import flask.cli
flask.cli.show_server_banner = lambda *args, **kwargs: None

import config
from api.routes import api_bp
from modules.auth import AuthManager
from wiring import build_services, start_services


def create_app():
    app = Flask(__name__)
    app.config.from_object(config.Config)

    # ── SECRET_KEY 강화: 기본값이면 세션 서명용 랜덤 키 생성 ──
    if app.config.get("SECRET_KEY") in ("soc-dashboard-secret-2024",
                                        "soc-dashboard-secret-change-me", None, ""):
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        print("[SOC] 경고: 기본 SECRET_KEY — 랜덤 키 생성(재시작 시 세션 초기화). "
              ".env의 SECRET_KEY를 설정하면 유지됩니다.")

    # ── 세션 유지 시간 ──
    app.permanent_session_lifetime = timedelta(
        hours=float(app.config.get("SESSION_HOURS", 12)))

    # ── 인증 매니저 ──
    auth = AuthManager(
        username=app.config.get("DASH_USERNAME", "admin"),
        password=app.config.get("DASH_PASSWORD") or None,
        password_hash=app.config.get("DASH_PASSWORD_HASH") or None,
    )
    app.auth = auth
    auth_on = app.config.get("AUTH_ENABLED", True)
    if auth_on and not auth.configured:
        # 비밀번호 미설정 → 랜덤 발급(콘솔 1회 표시). .env에 DASH_PASSWORD 설정 권장.
        gen = secrets.token_urlsafe(9)
        auth.password_hash = AuthManager(auth.username, password=gen).password_hash
        print("=" * 56)
        print(f"[SOC] 대시보드 로그인 비밀번호 미설정 — 임시 발급")
        print(f"[SOC]   사용자명: {auth.username}")
        print(f"[SOC]   비밀번호: {gen}")
        print(f"[SOC]   (.env의 DASH_PASSWORD 로 고정 설정 권장)")
        print("=" * 56)
    elif not auth_on:
        print("[SOC] 경고: AUTH_ENABLED=False — 인증 없이 노출됩니다.")

    # ── CORS: 기본은 완전히 닫는다 ──
    # 이 대시보드는 동일 출처 앱이라 CORS 가 필요 없다. 예전 설정
    # `CORS(app, supports_credentials=True)` 는 origins 미지정 + credentials 조합이라
    # flask-cors 가 **요청 Origin 을 그대로 반사**했고, 로그인한 분석가가 방문한
    # 임의 사이트가 세션 쿠키로 API 전체를 읽을 수 있었다(docs/AUDIT.md C-1).
    cors_origins = [o.strip() for o in
                    str(app.config.get("CORS_ORIGINS", "")).split(",") if o.strip()]
    if cors_origins:
        CORS(app, origins=cors_origins, supports_credentials=True)
        print(f"[SOC] CORS 허용 출처: {cors_origins}")

    socketio = SocketIO(
        app,
        # "*" 는 임의 출처가 세션 쿠키로 실시간 이벤트를 구독하게 한다.
        # 명시된 출처가 없으면 동일 출처만 허용한다.
        cors_allowed_origins=cors_origins or [],
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )

    # 서비스 계층 생성·상호 배선·app 등록 (배선 상세는 wiring.py)
    build_services(app, socketio)

    # Blueprint 등록
    app.register_blueprint(api_bp, url_prefix="/api")

    # ------------------------------------------------------------------ #
    #  인증 가드
    # ------------------------------------------------------------------ #

    def _is_public(path):
        return (path == "/login" or path == "/logout"
                or path.startswith("/static/"))

    # ------------------------------------------------------------------ #
    #  CSRF 가드 — 상태변경 요청의 출처 검증
    # ------------------------------------------------------------------ #

    _STATE_CHANGING = ("POST", "PUT", "DELETE", "PATCH")
    csrf_on = app.config.get("CSRF_PROTECTION", True)
    _trusted_origins = {o.strip().rstrip("/") for o in
                        str(app.config.get("CSRF_TRUSTED_ORIGINS", "")).split(",")
                        if o.strip()}
    _trusted_origins |= {o.rstrip("/") for o in cors_origins}

    def _origin_allowed(origin):
        """Origin(또는 Referer 에서 뽑은 출처)이 자기 자신인지 검사."""
        if not origin:
            return False
        origin = origin.rstrip("/")
        if origin in _trusted_origins:
            return True
        # 요청이 들어온 호스트와 같은지 — 스킴 무관하게 host 로 비교한다.
        # (Tailscale HTTP 접속과 로컬 접속을 모두 수용하기 위함)
        try:
            return urlparse(origin).netloc == request.host
        except ValueError:
            return False

    def _csrf_ok():
        """상태변경 요청이 이 대시보드 자신에서 시작됐는지 확인한다.

        브라우저는 동일 출처 non-GET fetch 에도 Origin 을 붙이고, 교차 출처에서는
        위조할 수 없다. Origin 이 없으면 Referer 로 대체한다. 둘 다 없으면
        브라우저 요청이 아니므로 거부한다 — 스크립트 클라이언트가 필요하면
        CSRF_TRUSTED_ORIGINS 에 명시하거나 CSRF_PROTECTION=False 로 끈다.
        """
        origin = request.headers.get("Origin")
        if origin:
            return _origin_allowed(origin)
        referer = request.headers.get("Referer")
        if referer:
            parts = urlparse(referer)
            if parts.scheme and parts.netloc:
                return _origin_allowed(f"{parts.scheme}://{parts.netloc}")
        return False

    @app.before_request
    def _require_same_origin():
        """상태변경 요청의 출처를 검증한다 (CSRF).

        인증 가드와 분리해 둔다 — AUTH_ENABLED=False 여도 API 는 방화벽 조작·
        프로세스 종료 같은 특권 동작을 수행하므로 출처 검증은 계속 필요하다.
        """
        if not csrf_on or request.method not in _STATE_CHANGING:
            return
        if request.path.startswith("/static/"):
            return
        if _csrf_ok():
            return
        print(f"[SOC] CSRF 차단: {request.method} {request.path} "
              f"origin={request.headers.get('Origin') or '-'} "
              f"referer={request.headers.get('Referer') or '-'}")
        if request.path.startswith("/api/"):
            return jsonify({"error": "요청 출처를 확인할 수 없습니다 (CSRF 보호)",
                            "csrf": True}), 403
        return render_template("login.html",
                               error="요청 출처를 확인할 수 없습니다"), 403

    @app.before_request
    def _require_login():
        if not auth_on or _is_public(request.path):
            return
        if not session.get("user"):
            # 미인증: API는 401 JSON, 그 외는 로그인 페이지로
            if request.path.startswith("/api/"):
                return jsonify({"error": "인증이 필요합니다", "auth_required": True}), 401
            return redirect("/login")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not auth_on:
            return redirect("/")
        error = None
        if request.method == "POST":
            # 로그인 CSRF(외부 사이트가 폼을 대신 제출)는 _require_same_origin 이 막는다
            ip = request.remote_addr or "?"
            ok, reason = auth.verify(request.form.get("username", ""),
                                     request.form.get("password", ""), ip)
            if ok:
                session.permanent = True
                session["user"] = auth.username
                print(f"[SOC] 로그인 성공: {auth.username} ({ip})")
                return redirect("/")
            if reason == "locked":
                error = f"로그인 시도 과다 — {auth.lock_remaining(ip)}초 후 다시 시도하세요"
            else:
                error = "사용자명 또는 비밀번호가 올바르지 않습니다"
            print(f"[SOC] 로그인 실패({reason}): {ip}")
        elif session.get("user"):
            return redirect("/")
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    # ------------------------------------------------------------------ #
    #  라우트
    # ------------------------------------------------------------------ #

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/whoami")
    def whoami():
        return jsonify({"user": session.get("user"), "auth_enabled": auth_on,
                        "demo": app.config.get("DEMO_MODE", True)})

    # ------------------------------------------------------------------ #
    #  SocketIO 이벤트
    # ------------------------------------------------------------------ #

    @socketio.on("connect")
    def on_connect():
        # 미인증 소켓 연결 거부 (세션 쿠키로 검증)
        if auth_on and not session.get("user"):
            return False
        print(f"[SOC] 클라이언트 연결됨")

    @socketio.on("disconnect")
    def on_disconnect():
        print(f"[SOC] 클라이언트 연결 해제")

    @socketio.on("chat_message")
    def on_chat(data):
        message = data.get("message", "")
        context = data.get("context", {})
        response = app.ai_analyst.chat(message, context)
        socketio.emit("chat_response", {
            "message": message,
            "response": response,
            "timestamp": __import__("datetime").datetime.now().strftime("%H:%M:%S"),
        }, to=request.sid)

    @socketio.on("request_ai_analysis")
    def on_ai_analysis(data):
        # 이전 프런트엔드 호환용 no-op. 자동 AI 트리아지는 서버 SOAR가 1회 수행한다.
        # 브라우저별 재분석은 접속자 수만큼 중복 작업을 만들므로 실행하지 않는다.
        return {"accepted": False, "reason": "server_managed_triage"}

    # 백그라운드 서비스 시작 + ML 피드 루프 (상세는 wiring.py)
    start_services(app, socketio)

    return app, socketio


app, socketio = create_app()

if __name__ == "__main__":
    cfg = config.Config()
    print(f"[SOC] 보안관제 대시보드 v1.0 시작")
    print(f"[SOC] http://{cfg.HOST}:{cfg.PORT}")
    print(f"[SOC] 데모 모드: {cfg.DEMO_MODE}")
    socketio.run(
        app,
        host=cfg.HOST,
        port=cfg.PORT,
        debug=cfg.DEBUG,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
        log_output=False,
    )
