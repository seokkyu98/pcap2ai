# pcap2ai

Wireshark 패킷 캡처(.pcap/.pcapng)를 ChatGPT·Gemini 등 LLM이 분석할 수 있는
구조화 텍스트로 변환하는 웹 유틸리티.

- **frontend/** — 정적 사이트 (Vercel 배포), `ads.txt`/`robots.txt`/`sitemap.xml` 포함
- **backend/** — FastAPI 스트리밍 변환 API (Render 배포)
- **render.yaml** — Render Blueprint (백엔드 자동 구성)
- 도메인: **pcap2ai.com** (Cloudflare 구입, DNS only로 Vercel에 연결 — 4번 참고)

## 아키텍처

```
브라우저 ──(pcap 업로드)──▶ Render(FastAPI + scapy)
   ▲                            │ PcapReader로 패킷 단위 스트리밍 파싱
   └──(텍스트 스트림 수신)◀─────┘ StreamingResponse로 실시간 전송
   수신 즉시 디스크 저장(File System Access API) 또는 Blob 다운로드
```

- 업로드 한도 100MB (`MAX_UPLOAD_BYTES` 환경 변수로 조정)
- 동시 변환 1건 (Render Free 512MB RAM 보호)
- 업로드 파일은 변환 종료 즉시 삭제, 결과물 서버 미보관

## 로컬 개발

```bash
# 백엔드
cd backend
python -m venv .venv && .venv\Scripts\activate   # Windows
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# 프론트엔드 (정적 서버 아무거나)
cd frontend
python -m http.server 3000
# http://localhost:3000 접속 — localhost에서는 자동으로 127.0.0.1:8000 API 사용
```

## 배포 절차

### 1) GitHub

`seokkyu98/pcap2ai` 리포지토리에 push.

### 2) Render (백엔드)

1. https://render.com — **GitHub 계정으로 로그인** (구글 계정으로 가입한 GitHub 연동 가능)
2. **New + → Blueprint** → `seokkyu98/pcap2ai` 선택 → `render.yaml` 자동 인식 → **Apply**
   - Blueprint 대신 수동으로 만들 경우: New + → Web Service →
     Root Directory `backend`, Build `pip install -r requirements.txt`,
     Start `uvicorn main:app --host 0.0.0.0 --port $PORT`, Plan `Free`
3. 배포 완료 후 발급 URL 확인 (예: `https://pcap2ai-backend.onrender.com`)
4. **frontend/assets/app.js 상단의 `PRODUCTION_API` 값을 이 URL로 교체** 후 다시 push

### 3) Vercel (프론트엔드)

1. https://vercel.com — GitHub 계정으로 로그인
2. **Add New → Project** → `seokkyu98/pcap2ai` import
3. Framework Preset: **Other**, Root Directory: **frontend** (Build 명령/Output 비워둠)
4. Deploy → `https://<project>.vercel.app` 발급

백엔드 CORS는 `*.vercel.app` 전체를 이미 허용하므로 추가 설정 불필요.

### 4) 커스텀 도메인 연결 (pcap2ai.com, Cloudflare에서 구입)

도메인 코드 반영(canonical/og:url/JSON-LD/ads.txt/robots.txt/sitemap.xml, CORS 허용 목록)은
이미 완료되어 있습니다. 실제로 연결하려면:

1. **Vercel** → 프로젝트 → Settings → Domains → `pcap2ai.com`과 `www.pcap2ai.com` 둘 다 추가
2. Vercel이 안내하는 레코드를 **Cloudflare DNS**에 등록
   - 보통 `pcap2ai.com`은 A 레코드(Vercel이 주는 IP), `www`는 CNAME(`cname.vercel-dns.com`)
   - **프록시 상태는 "DNS only"(회색 구름)로 두세요.** Cloudflare로 프록시(주황 구름)하면
     Vercel의 자동 SSL 발급/검증과 충돌할 수 있습니다. (5번의 Cloudflare Web Analytics는
     프록시 여부와 무관하게 동작하므로 이 설정으로도 트래픽 통계는 정상 수집됩니다.)
3. Vercel에서 도메인이 "Valid Configuration"으로 표시되고 HTTPS 인증서가 발급될 때까지 대기
   (보통 몇 분~1시간)
4. Render 대시보드 → 백엔드 서비스는 별도 조치 불필요 — `backend/main.py`의 CORS 허용
   목록에 `https://pcap2ai.com`과 `https://www.pcap2ai.com`이 이미 하드코딩되어 있습니다.
5. 정상 연결 확인 후 `https://pcap2ai.com`으로 접속해 변환 기능이 실제로 동작하는지 테스트

### 5) Cloudflare Web Analytics (트래픽·방문자 수 확인)

Cloudflare Analytics에는 두 종류가 있습니다.

- **Cloudflare 프록시 트래픽 분석** — DNS를 주황 구름(프록시)으로 켜야 확인 가능한데,
  위 4번에서 설명한 이유로 Vercel과 궁합이 좋지 않아 이번 배포에는 권장하지 않습니다.
- **Cloudflare Web Analytics (Beacon)** — 자바스크립트 스니펫 하나만 페이지에 넣으면
  DNS 프록시 여부와 무관하게 동작하는 무료 방문자 분석 도구입니다. 쿠키를 사용하지 않아
  개인정보처리방침에 미치는 영향도 적습니다. **이번 프로젝트는 이 방식을 이미 코드에 반영**해
  두었습니다 (4개 HTML 파일 모두).

적용 방법:

1. Cloudflare 대시보드 → **Analytics & Logs → Web Analytics** → **Add a site**
2. 사이트 호스트네임에 `pcap2ai.com` 입력 (자동 설치 여부를 묻는 화면에서 "수동으로 설치" 선택 — 이미 코드에 스니펫이 있으므로 자동 삽입은 불필요)
3. 발급되는 `token` 값을 복사
4. 이 리포지토리의 `frontend/index.html`, `about.html`, `privacy.html`, `contact.html` 4개 파일에서
   `CF_BEACON_TOKEN_PLACEHOLDER` 문자열을 모두 그 token 값으로 교체 후 push
5. Cloudflare 대시보드의 Web Analytics 화면에서 실시간 방문자/트래픽 그래프 확인 가능

### 6) Google AdSense (자동 광고)

1. **커스텀 도메인 연결 후에만 신청 가능** (`*.vercel.app`은 등록 불가) — 4번을 먼저 완료하세요.
2. https://adsense.google.com → 사이트 추가 → `pcap2ai.com` 입력 후 계정 생성
   → 가입 즉시 `ca-pub-XXXXXXXXXXXXXXXX` 형태의 게시자 ID가 발급됩니다 (심사 승인 전에도 확인 가능)
3. 이 리포지토리의 4개 HTML 파일에서 `ca-pub-XXXXXXXXXXXXXXXX`를 실제 게시자 ID로 모두 교체
4. `frontend/ads.txt`의 `pub-XXXXXXXXXXXXXXXX`도 같은 값으로 교체 (형식: `pub-` 접두어 포함)
5. push 후 Vercel 재배포 → AdSense 심사 신청 (사이트에 스크립트가 이미 심어져 있어야 심사가 진행됩니다)
6. 승인 후 AdSense 대시보드에서 **자동 광고(Auto ads)를 On**으로 켜면 별도 코드 수정 없이
   Google이 페이지 내 적절한 위치에 자동으로 광고를 배치합니다. (이 버전 UI에는 수동 광고
   슬롯을 두지 않았습니다 — 자동 광고 방식과 맞지 않아 제거했습니다.)
