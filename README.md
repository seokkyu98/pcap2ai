# pcap2ai

Wireshark 패킷 캡처(.pcap/.pcapng)를 ChatGPT·Gemini 등 LLM이 분석할 수 있는
구조화 텍스트로 변환하는 웹 유틸리티.

- **frontend/** — 정적 사이트 (Vercel 배포)
- **backend/** — FastAPI 스트리밍 변환 API (Render 배포)
- **render.yaml** — Render Blueprint (백엔드 자동 구성)

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

### 4) 커스텀 도메인 (Cloudflare 구입 후)

1. Vercel 프로젝트 → Settings → Domains → 도메인 추가 → 안내대로 Cloudflare DNS에
   CNAME/A 레코드 등록 (Cloudflare 프록시는 **DNS only** 권장)
2. Render 대시보드 → 환경 변수 `FRONTEND_ORIGINS`에
   `https://도메인,https://www.도메인` 추가 후 재배포
3. frontend 각 HTML의 `canonical` / `og:url`을 실제 도메인으로 교체

### 5) Google AdSense

1. **커스텀 도메인 연결 후에만 신청 가능** (`*.vercel.app`은 등록 불가)
2. https://adsense.google.com → 사이트 추가 → 도메인 입력
3. 발급받은 `ca-pub-XXXX` ID로 각 HTML `<head>`의 주석 처리된 AdSense 스크립트를 해제·교체
4. 루트에 `ads.txt` 생성: `google.com, pub-XXXXXXXXXXXXXXXX, DIRECT, f08c47fec0942fa0`
5. 승인 후 자동 광고 사용 또는 `#ad-top`, `#ad-side`, `#ad-article` 슬롯에 광고 단위 코드 삽입
