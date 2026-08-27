# static/vendor — 자체 호스팅 프런트엔드 라이브러리

외부 CDN 9개 참조를 여기로 옮겼다(`docs/AUDIT.md` E-1).

**왜 CDN 을 쓰지 않는가**
- 관제 대시보드가 외부 CDN 가용성에 의존하면 안 된다. CDN 이 죽으면 사고 대응
  중에 화면이 깨진다.
- 격리망·오프라인 환경에서 떠야 한다.
- SRI 없이 서드파티 스크립트를 로드하면 CDN 이 침해될 때 그대로 실행된다.
- 자체 호스팅 덕분에 CSP 의 `script-src`/`style-src`/`font-src`/`img-src` 를
  전부 `'self'` 로 좁힐 수 있다(`app.py` `_build_csp`).

## 목록

| 경로 | 버전 | 출처 |
|------|------|------|
| `bootstrap/bootstrap.min.css`, `bootstrap.bundle.min.js` | 5.3.3 | cdn.jsdelivr.net/npm/bootstrap@5.3.3 |
| `chartjs/chart.umd.min.js` | 4.4.3 | cdn.jsdelivr.net/npm/chart.js@4.4.3 |
| `jquery/jquery-3.7.1.min.js` | 3.7.1 | code.jquery.com |
| `datatables/*` | 1.13.8 | cdn.datatables.net |
| `socketio/socket.io.min.js` | 4.7.5 | cdn.socket.io |
| `fontawesome/css/all.min.css` + `webfonts/*.woff2` | 6.5.0 | cdnjs.cloudflare.com |
| `globe/three.min.js` | 0.160.0 | unpkg.com/three@0.160.0 |
| `globe/globe.gl.min.js` | 2.32.0 | unpkg.com/globe.gl@2.32.0 |

**Font Awesome 은 `.woff2` 만 받았다.** 원본 CSS 는 `.ttf` 폴백도 참조하는데,
woff2 는 2016년 이후 모든 브라우저가 지원하므로 800KB 를 아끼려고 CSS 에서
`.ttf` 참조 10곳을 제거했다. 구형 브라우저를 지원해야 하면 같은 버전의
`webfonts/*.ttf` 를 받고 CSS 의 `format("woff2")` 뒤에 폴백을 되살릴 것.

**Leaflet 은 vendoring 하지 않고 제거했다.** `L.map`/`L.tileLayer`/`L.marker`
호출이 JS 전체에 0건이었다 — 지도는 이미 globe.gl(3D 지구본, 로컬
`static/data/countries-110m.geojson`)로 옮겨간 상태였고, 남아 있던 것은
`<link>`/`<script>` 2줄과 `style.css` 의 죽은 `.leaflet-*` 오버라이드뿐이었다.

## 갱신 방법

위 표의 출처 URL 에서 같은 경로로 받아 덮어쓰고, 표의 버전을 고친다.
갱신 후 `tests/test_security_hardening.py::test_no_external_asset_references`
가 통과하는지 확인한다(외부 URL 이 다시 끼어들면 실패한다).
