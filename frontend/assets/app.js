"use strict";

/* ============================================================================
 * pcap2ai 프론트엔드 컨트롤러
 *  - 서버 헬스 체크(콜드 스타트 감지)
 *  - 파일 선택/드롭 + 용량·형식 검증(초과 시 팝업)
 *  - 스트리밍 변환 수신: File System Access API 지원 브라우저(Chrome/Edge)는
 *    디스크로 직접 스트리밍 저장, 미지원 브라우저는 Blob 폴백.
 * ========================================================================= */

/* ---- 환경 설정 ----------------------------------------------------------- */
// Render 배포가 끝나면 발급받은 백엔드 URL로 아래 값을 교체하세요.
// (예: https://pcap2ai.onrender.com)
const PRODUCTION_API = "https://pcap2ai.onrender.com";

const API_BASE =
  location.hostname === "localhost" || location.hostname === "127.0.0.1"
    ? "http://127.0.0.1:8000"
    : PRODUCTION_API;

const MAX_BYTES = 100 * 1024 * 1024; // 100MB — 백엔드 MAX_UPLOAD_BYTES와 동일하게 유지
const ACCEPT_RE = /\.(pcap|pcapng|cap)$/i;
const COLD_START_HINT_MS = 6000; // 이 시간 안에 응답이 없으면 콜드 스타트 안내

/* ---- DOM ----------------------------------------------------------------- */
const $ = (id) => document.getElementById(id);
const el = {
  chip: $("server-chip"),
  chipText: $("server-chip-text"),
  dropzone: $("dropzone"),
  fileInput: $("file-input"),
  fileRow: $("file-row"),
  fileName: $("file-name"),
  fileSize: $("file-size"),
  fileRemove: $("file-remove"),
  consoleBox: $("console"),
  statbar: $("statbar"),
  statBytes: $("stat-bytes"),
  statLines: $("stat-lines"),
  statTime: $("stat-time"),
  statSpeed: $("stat-speed"),
  convertBtn: $("convert-btn"),
  cancelBtn: $("cancel-btn"),
  modalBackdrop: $("modal-backdrop"),
  modalTitle: $("modal-title"),
  modalBody: $("modal-body"),
  modalOk: $("modal-ok"),
};

const state = {
  file: null,
  running: false,
  aborter: null,
  startedAt: 0,
  bytes: 0,
  lines: 0,
  timer: null,
  serverOnline: false,
};

/* ---- 유틸 ----------------------------------------------------------------- */
function fmtBytes(n) {
  if (n >= 1024 * 1024 * 1024) return (n / (1024 * 1024 * 1024)).toFixed(2) + " GB";
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MB";
  if (n >= 1024) return (n / 1024).toFixed(1) + " KB";
  return n + " B";
}

function fmtClock(ms) {
  const s = Math.floor(ms / 1000);
  return String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0");
}

function nowStamp() {
  return new Date().toLocaleTimeString("ko-KR", { hour12: false });
}

function countNewlines(u8) {
  let n = 0;
  for (let i = 0; i < u8.length; i++) if (u8[i] === 10) n++;
  return n;
}

function selectedMode() {
  const checked = document.querySelector('input[name="mode"]:checked');
  return checked ? checked.value : "summary";
}

/* ---- 모달 ----------------------------------------------------------------- */
function showModal(title, bodyHtml) {
  el.modalTitle.textContent = title;
  el.modalBody.innerHTML = bodyHtml;
  el.modalBackdrop.classList.remove("hidden");
  el.modalOk.focus();
}
function hideModal() {
  el.modalBackdrop.classList.add("hidden");
}
el.modalOk.addEventListener("click", hideModal);
el.modalBackdrop.addEventListener("click", (e) => {
  if (e.target === el.modalBackdrop) hideModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !el.modalBackdrop.classList.contains("hidden")) hideModal();
});

/* ---- 콘솔 로그 ------------------------------------------------------------ */
function logLine(text, cls) {
  const line = document.createElement("div");
  const t = document.createElement("span");
  t.className = "t";
  t.textContent = "[" + nowStamp() + "] ";
  line.appendChild(t);
  const body = document.createElement("span");
  if (cls) body.className = cls;
  body.textContent = text;
  line.appendChild(body);
  el.consoleBox.appendChild(line);
  while (el.consoleBox.childElementCount > 250) el.consoleBox.removeChild(el.consoleBox.firstChild);
  el.consoleBox.scrollTop = el.consoleBox.scrollHeight;
}

/* ---- 서버 상태 칩 ---------------------------------------------------------- */
function setChip(status, text) {
  el.chip.classList.remove("is-ok", "is-warn", "is-err");
  if (status) el.chip.classList.add(status);
  el.chipText.textContent = text;
}

async function pingOnce(timeoutMs) {
  const res = await fetch(API_BASE + "/health", {
    method: "GET",
    cache: "no-store",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return true;
}

async function warmUpServer() {
  setChip("is-warn", "서버 확인 중…");
  const started = Date.now();
  for (let attempt = 1; attempt <= 8; attempt++) {
    try {
      await pingOnce(12000);
      state.serverOnline = true;
      setChip("is-ok", "서버 온라인");
      return;
    } catch (_) {
      const elapsed = Math.round((Date.now() - started) / 1000);
      setChip("is-warn", "서버 기동 중… " + elapsed + "s (절전 해제, 최대 90초)");
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
  state.serverOnline = false;
  setChip("is-err", "서버 응답 없음 — 잠시 후 새로고침");
}

/* ---- 파일 선택 ------------------------------------------------------------ */
function validateAndSetFile(file) {
  if (!file) return;
  if (!ACCEPT_RE.test(file.name)) {
    showModal(
      "지원하지 않는 파일 형식",
      "패킷 캡처 파일(<span class='mono'>.pcap · .pcapng · .cap</span>)만 변환할 수 있습니다.<br>" +
        "선택한 파일: <span class='mono'>" + escapeHtml(file.name) + "</span>"
    );
    return;
  }
  if (file.size > MAX_BYTES) {
    showModal(
      "파일 용량 초과",
      "무료 서버 자원 한도로 <strong>최대 100MB</strong>까지 업로드할 수 있습니다.<br>" +
        "선택한 파일: <span class='mono'>" + fmtBytes(file.size) + "</span><br><br>" +
        "Wireshark의 <span class='mono'>File → Export Specified Packets</span> 또는 " +
        "<span class='mono'>editcap -c</span> 명령으로 캡처를 분할한 뒤 다시 시도해 주세요."
    );
    return;
  }
  if (file.size === 0) {
    showModal("빈 파일", "선택한 파일에 데이터가 없습니다.");
    return;
  }
  state.file = file;
  el.fileName.textContent = file.name;
  el.fileSize.textContent = fmtBytes(file.size);
  el.dropzone.classList.add("hidden");
  el.fileRow.classList.remove("hidden");
  el.convertBtn.disabled = false;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function clearFile() {
  state.file = null;
  el.fileInput.value = "";
  el.fileRow.classList.add("hidden");
  el.dropzone.classList.remove("hidden");
  el.convertBtn.disabled = true;
}

el.dropzone.addEventListener("click", () => el.fileInput.click());
el.dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    el.fileInput.click();
  }
});
el.fileInput.addEventListener("change", () => validateAndSetFile(el.fileInput.files[0]));
el.fileRemove.addEventListener("click", clearFile);

["dragenter", "dragover"].forEach((ev) =>
  el.dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    el.dropzone.classList.add("dragover");
  })
);
["dragleave", "drop"].forEach((ev) =>
  el.dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    el.dropzone.classList.remove("dragover");
  })
);
el.dropzone.addEventListener("drop", (e) => {
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  validateAndSetFile(f);
});

// 페이지 전체에 파일을 떨어뜨렸을 때 브라우저가 파일을 열어버리는 것 방지
["dragover", "drop"].forEach((ev) =>
  window.addEventListener(ev, (e) => e.preventDefault())
);

/* ---- 통계 표시 ------------------------------------------------------------ */
function startStats() {
  el.statbar.classList.remove("hidden");
  state.timer = setInterval(() => {
    const elapsed = Date.now() - state.startedAt;
    el.statTime.textContent = fmtClock(elapsed);
    const mbps = state.bytes / 1024 / 1024 / Math.max(elapsed / 1000, 0.5);
    el.statSpeed.textContent = mbps >= 0.05 ? mbps.toFixed(1) + " MB/s" : "—";
    el.statBytes.textContent = fmtBytes(state.bytes);
    el.statLines.textContent = state.lines.toLocaleString("ko-KR");
  }, 400);
}
function stopStats() {
  clearInterval(state.timer);
  state.timer = null;
  el.statBytes.textContent = fmtBytes(state.bytes);
  el.statLines.textContent = state.lines.toLocaleString("ko-KR");
}

/* ---- 변환 실행 ------------------------------------------------------------ */
function setRunning(running) {
  state.running = running;
  el.convertBtn.disabled = running || !state.file;
  el.convertBtn.textContent = running ? "변환 진행 중…" : "변환 시작";
  el.cancelBtn.classList.toggle("hidden", !running);
  el.fileRemove.disabled = running;
}

window.addEventListener("beforeunload", (e) => {
  if (state.running) {
    e.preventDefault();
    e.returnValue = "";
  }
});

el.cancelBtn.addEventListener("click", () => {
  if (state.aborter) state.aborter.abort();
});

async function pickSaveTarget(suggestedName) {
  if (!("showSaveFilePicker" in window)) return { writable: null, fsMode: false };
  const handle = await window.showSaveFilePicker({
    suggestedName,
    types: [{ description: "텍스트 파일", accept: { "text/plain": [".txt"] } }],
  });
  const writable = await handle.createWritable();
  return { writable, fsMode: true };
}

function friendlyHttpError(status, payload) {
  const code = payload && payload.error;
  if (status === 413 || code === "file_too_large")
    return "서버가 파일 용량 초과로 요청을 거부했습니다 (최대 100MB).";
  if (status === 503 || code === "busy")
    return "지금 다른 변환 작업이 진행 중입니다. 무료 서버는 동시에 1건만 처리할 수 있으니 몇 분 뒤 다시 시도해 주세요.";
  if (code === "not_a_capture")
    return "서버가 이 파일을 pcap/pcapng 캡처로 인식하지 못했습니다. 파일이 손상되지 않았는지 확인해 주세요.";
  if (payload && payload.message) return payload.message;
  return "서버 오류가 발생했습니다 (HTTP " + status + ").";
}

async function runConversion() {
  if (!state.file || state.running) return;
  const file = state.file;
  const mode = selectedMode();
  const stem = file.name.replace(ACCEPT_RE, "") || "capture";
  const outName = stem + "_" + mode + ".txt";

  // 저장 위치 선택은 사용자 클릭 제스처 안에서 먼저 실행해야 한다
  let writable = null;
  let fsMode = false;
  try {
    const picked = await pickSaveTarget(outName);
    writable = picked.writable;
    fsMode = picked.fsMode;
  } catch (err) {
    if (err && err.name === "AbortError") return; // 저장 취소 → 조용히 종료
    fsMode = false;
    writable = null;
  }

  setRunning(true);
  state.aborter = new AbortController();
  state.startedAt = Date.now();
  state.bytes = 0;
  state.lines = 0;

  el.consoleBox.classList.remove("hidden");
  el.consoleBox.innerHTML = "";
  logLine("대상: " + file.name + " (" + fmtBytes(file.size) + ") · 모드: " + (mode === "summary" ? "요약" : "상세"), "hl");
  if (fsMode) {
    logLine("저장 방식: 디스크 직접 스트리밍 저장 → " + outName, "ok");
  } else {
    logLine("저장 방식: 브라우저 메모리 경유 (이 브라우저는 스트리밍 저장 미지원 — 대용량은 Chrome/Edge 권장)", "warn");
  }
  logLine("서버로 업로드를 시작합니다…");

  const coldHint = setTimeout(() => {
    logLine("응답 대기 중 — 무료 서버가 절전 상태였다면 깨어나는 데 최대 90초가 걸릴 수 있습니다.", "warn");
  }, COLD_START_HINT_MS);

  const blobParts = [];
  let finishedOk = false;

  try {
    const fd = new FormData();
    fd.append("mode", mode);
    fd.append("file", file, file.name);

    const res = await fetch(API_BASE + "/convert", {
      method: "POST",
      body: fd,
      signal: state.aborter.signal,
    });
    clearTimeout(coldHint);

    if (!res.ok) {
      let payload = null;
      try { payload = await res.json(); } catch (_) { /* 본문 없음 */ }
      throw new Error(friendlyHttpError(res.status, payload));
    }
    if (!res.body) throw new Error("이 브라우저는 스트리밍 응답을 지원하지 않습니다.");

    logLine("서버 연결 완료 — 스트리밍 변환을 수신합니다.", "ok");
    startStats();

    const reader = res.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      state.bytes += value.length;
      state.lines += countNewlines(value);
      if (writable) {
        await writable.write(value);
      } else {
        blobParts.push(value);
      }
    }

    if (writable) {
      await writable.close();
      writable = null;
    } else {
      const blob = new Blob(blobParts, { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = outName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    }

    finishedOk = true;
    stopStats();
    const took = fmtClock(Date.now() - state.startedAt);
    logLine("변환 완료 — " + state.lines.toLocaleString("ko-KR") + "줄 / " + fmtBytes(state.bytes) + " (소요 " + took + ")", "ok");
    logLine(outName + " 파일이 저장되었습니다. 이제 ChatGPT·Gemini에 첨부해 분석을 요청해 보세요. (하단 가이드 참고)", "hl");
  } catch (err) {
    clearTimeout(coldHint);
    stopStats();
    if (err && err.name === "AbortError") {
      logLine("사용자 요청으로 변환을 취소했습니다.", "warn");
    } else if (err instanceof TypeError) {
      // fetch 네트워크 계층 실패 (서버 다운, CORS, 연결 끊김)
      logLine("서버에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요. 무료 서버 특성상 첫 요청은 절전 해제에 시간이 걸립니다.", "err");
      warmUpServer();
    } else {
      logLine(err.message || String(err), "err");
    }
    if (writable) {
      try { await writable.abort(); } catch (_) { /* 이미 닫힘 */ }
    }
  } finally {
    clearTimeout(coldHint);
    if (state.timer) stopStats();
    setRunning(false);
    state.aborter = null;
    if (finishedOk) clearFile();
  }
}

el.convertBtn.addEventListener("click", runConversion);

/* ---- 초기화 ---------------------------------------------------------------- */
el.convertBtn.disabled = true;
warmUpServer();
