from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Body,
    UploadFile,
    File,
    Form,
)
from fastapi.responses import HTMLResponse, FileResponse
from datetime import datetime, timezone
from pathlib import Path
import json, os, hmac, hashlib, time, uuid, mimetypes

app = FastAPI()

# ----------------------------
# Config
# ----------------------------
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

SECRET = os.environ.get("DMCHAT_SECRET", "dev-secret-change-me")
TOKEN_TTL_SECONDS = 60 * 60 * 24  # 24h

USERS = {
    "ali": "1234",
    "sara": "1234",
    "ahmed": "1234",
    "admin": "admin",
}

# ----------------------------
# In-memory state
# ----------------------------
local_clients: dict[str, WebSocket] = {}           # username -> websocket
inbox_store: dict[str, list[dict]] = {}            # username -> queued payloads
file_store: dict[str, dict] = {}                   # file_id -> metadata (in-memory)

# ----------------------------
# Helpers
# ----------------------------
def now_ts() -> int:
    return int(time.time() * 1000)

def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def ensure_user_inbox(user: str):
    if user not in inbox_store:
        inbox_store[user] = []

def sign_token(username: str, exp: int) -> str:
    payload = f"{username}.{exp}".encode()
    sig = hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return f"{username}.{exp}.{sig}"

def verify_token(token: str) -> str | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        username, exp_s, sig = parts
        exp = int(exp_s)
        if time.time() > exp:
            return None
        payload = f"{username}.{exp}".encode()
        expected = hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if username not in USERS:
            return None
        return username
    except Exception:
        return None

def make_token(username: str) -> str:
    exp = int(time.time() + TOKEN_TTL_SECONDS)
    return sign_token(username, exp)

async def ws_send(ws: WebSocket, payload: dict):
    await ws.send_text(json.dumps(payload))

async def deliver_to_user(username: str, payload: dict):
    """
    If user is online -> send immediately
    Else -> queue in inbox_store (in-memory)
    """
    ensure_user_inbox(username)
    ws = local_clients.get(username)
    if ws:
        await ws_send(ws, payload)
    else:
        inbox_store[username].append(payload)

# ----------------------------
# Auth
# ----------------------------
@app.post("/login")
def login(username: str = Body(...), password: str = Body(...)):
    if USERS.get(username) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_token(username)
    return {"token": token, "username": username}

# ----------------------------
# File download endpoint
# ----------------------------
@app.get("/files/{file_id}")
def download_file(file_id: str):
    meta = file_store.get(file_id)
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")
    path = UPLOAD_DIR / meta["stored_name"]
    if not path.exists():
        raise HTTPException(status_code=404, detail="File missing on disk")

    return FileResponse(
        str(path),
        filename=meta.get("name", "download"),
        media_type=meta.get("mime", "application/octet-stream"),
    )

# ----------------------------
# Upload endpoint
# ----------------------------
@app.post("/upload")
async def upload_file(
    token: str = Form(...),
    to: str = Form(...),
    file: UploadFile = File(...),
):
    user = verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    if to not in USERS:
        raise HTTPException(status_code=400, detail="Unknown recipient")

    raw = await file.read()
    file_id = uuid.uuid4().hex

    stored_name = f"{file_id}_{file.filename}"
    path = UPLOAD_DIR / stored_name
    path.write_bytes(raw)

    mime = file.content_type or mimetypes.guess_type(file.filename)[0] or "application/octet-stream"

    file_store[file_id] = {
        "id": file_id,
        "name": file.filename,
        "size": len(raw),
        "mime": mime,
        "stored_name": stored_name,
        "uploaded_by": user,
        "uploaded_at": utc_iso(),
    }

    payload = {
        "type": "file",
        "from": user,
        "to": to,
        "ts": now_ts(),
        "file": {
            "id": file_id,
            "name": file.filename,
            "size": len(raw),
            "mime": mime,
            "url": f"/files/{file_id}",
        },
    }

    await deliver_to_user(to, payload)
    await deliver_to_user(user, payload)  # echo back to sender
    return {"ok": True, "file_id": file_id}

# ----------------------------
# WebSocket: DM + WebRTC signaling
# ----------------------------
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    username = None
    try:
        # First message must be auth
        msg = await ws.receive_text()
        data = json.loads(msg)

        if data.get("type") != "auth":
            await ws_send(ws, {"type": "error", "message": "First message must be auth"})
            await ws.close()
            return

        token = data.get("token", "")
        username = verify_token(token)
        if not username:
            await ws_send(ws, {"type": "error", "message": "Invalid token"})
            await ws.close()
            return

        local_clients[username] = ws
        ensure_user_inbox(username)

        # Send queued inbox messages
        for payload in inbox_store[username]:
            await ws_send(ws, payload)
        inbox_store[username].clear()

        # Broadcast online users to all
        online = list(local_clients.keys())
        for u, sock in list(local_clients.items()):
            try:
                await ws_send(sock, {"type": "presence", "online": online, "ts": now_ts()})
            except Exception:
                pass

        # Notify current
        await ws_send(ws, {"type": "system", "message": f"Logged in as {username}", "ts": now_ts()})

        while True:
            msg = await ws.receive_text()
            data = json.loads(msg)

            t = data.get("type")

            if t == "dm":
                to = data.get("to")
                body = data.get("body", "")
                if not to or to not in USERS:
                    await ws_send(ws, {"type": "error", "message": "Invalid recipient", "ts": now_ts()})
                    continue

                payload = {
                    "type": "dm",
                    "from": username,
                    "to": to,
                    "ts": now_ts(),
                    "body": body,
                }
                await deliver_to_user(to, payload)
                await deliver_to_user(username, payload)  # echo to self
                continue

            # WebRTC signaling (still uses WS): offer/answer/ice/hangup
            if t in ("call_offer", "call_answer", "call_ice", "call_hangup"):
                to = data.get("to")
                if not to or to not in USERS:
                    await ws_send(ws, {"type": "error", "message": "Invalid recipient", "ts": now_ts()})
                    continue

                payload = {
                    "type": t,
                    "from": username,
                    "to": to,
                    "ts": now_ts(),
                    "sdp": data.get("sdp"),
                    "candidate": data.get("candidate"),
                    "reason": data.get("reason"),
                }
                await deliver_to_user(to, payload)
                continue

            await ws_send(ws, {"type": "error", "message": "Unknown message type", "ts": now_ts()})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await ws_send(ws, {"type": "error", "message": f"Server error: {e}", "ts": now_ts()})
        except Exception:
            pass
    finally:
        # remove
        if username and local_clients.get(username) is ws:
            del local_clients[username]

        # broadcast presence
        online = list(local_clients.keys())
        for u, sock in list(local_clients.items()):
            try:
                await ws_send(sock, {"type": "presence", "online": online, "ts": now_ts()})
            except Exception:
                pass

# ----------------------------
# UI
# ----------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>DM Chat</title>
<style>
  :root{
    --bg:#0b1220; --card:rgba(255,255,255,.06); --border:rgba(255,255,255,.14);
    --text:rgba(255,255,255,.92); --muted:rgba(255,255,255,.68);
    --shadow:0 20px 60px rgba(0,0,0,.45); --r:18px;
    --ok:#22c55e; --bad:#ef4444;
    --me:rgba(99,102,241,.95); --other:rgba(255,255,255,.10);
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{
    margin:0;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
    background: radial-gradient(1200px 800px at 20% 0%, rgba(99,102,241,.35), transparent 60%),
                radial-gradient(900px 700px at 90% 40%, rgba(34,197,94,.22), transparent 60%),
                var(--bg);
    color:var(--text);
    display:flex;
    align-items:center;
    justify-content:center;
    padding:24px;
  }
  .shell{
    width:min(1200px, 100%);
    height:min(820px, 94vh);
    display:grid;
    grid-template-columns: 420px 1fr;
    gap:18px;
  }
  .card{
    background:var(--card);
    border:1px solid var(--border);
    border-radius:var(--r);
    box-shadow:var(--shadow);
    overflow:hidden;
    backdrop-filter: blur(10px);
  }
  .left{display:flex; flex-direction:column}
  .right{display:flex; flex-direction:column}
  .head{
    padding:18px 18px 12px;
    border-bottom:1px solid var(--border);
    display:flex; align-items:center; justify-content:space-between;
    background: linear-gradient(180deg, rgba(255,255,255,.06), transparent);
  }
  .title{font-weight:800; letter-spacing:.2px; font-size:18px;}
  .badge{display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted);}
  .dot{width:10px; height:10px; border-radius:999px; background:var(--bad)}
  .dot.ok{background:var(--ok)}
  .section{padding:14px 18px}
  label{display:block; font-size:12px; color:var(--muted); margin-bottom:6px}
  input,button{
    width:100%;
    padding:11px 12px;
    border-radius:14px;
    border:1px solid rgba(255,255,255,.14);
    background:rgba(0,0,0,.18);
    color:var(--text);
    outline:none;
  }
  input::placeholder{color:rgba(255,255,255,.35)}
  .btnrow{display:grid; grid-template-columns: 1fr 1fr 1fr; gap:10px; margin-top:10px}
  button{cursor:pointer;font-weight:700;background:rgba(255,255,255,.10)}
  button.primary{background:rgba(99,102,241,.85)}
  button.danger{background:rgba(239,68,68,.85)}
  button:disabled{opacity:.5; cursor:not-allowed}
  .hint{color:var(--muted); font-size:12px; margin-top:8px}
  .users{display:flex; flex-wrap:wrap; gap:10px; margin-top:10px}
  .pill{
    padding:8px 10px;
    border-radius:999px;
    border:1px solid rgba(255,255,255,.14);
    background:rgba(255,255,255,.06);
    font-size:13px;
    cursor:pointer;
  }
  .pill.me{border-color:rgba(99,102,241,.6); background:rgba(99,102,241,.15)}
  .chat{
    flex:1;
    padding:16px;
    overflow:auto;
    display:flex;
    flex-direction:column;
    gap:10px;
  }
  .msg{max-width:78%; display:flex; flex-direction:column; gap:4px}
  .bubble{
    padding:10px 12px;
    border-radius:16px;
    border:1px solid rgba(255,255,255,.16);
    background:rgba(255,255,255,.10);
    font-size:14px;
    line-height:1.35;
    white-space:pre-wrap;
    word-wrap:break-word;
  }
  .meta{font-size:11px; color:var(--muted); padding-left:6px}
  .me{align-self:flex-end}
  .me .bubble{background:var(--me); border-color:rgba(255,255,255,.12)}
  .me .meta{text-align:right; padding-right:6px; padding-left:0}
  .system{align-self:center; max-width:92%}
  .system .bubble{
    background:rgba(255,255,255,.06);
    border-color:rgba(255,255,255,.10);
    font-size:12px;
    border-radius:999px;
    padding:8px 12px;
  }

  /* --- File message UI --- */
  .filebox{display:flex;flex-direction:column;gap:8px}
  .filemeta{font-size:12px;color:rgba(255,255,255,.78)}
  .fileactions{display:flex;gap:10px;flex-wrap:wrap}
  .fileactions a{
    display:inline-flex;align-items:center;gap:8px;
    padding:8px 10px;border-radius:12px;
    border:1px solid rgba(255,255,255,.14);
    background:rgba(255,255,255,.08);
    color:rgba(255,255,255,.92);
    text-decoration:none;font-weight:600;font-size:13px;
  }
  .fileactions a:hover{background:rgba(255,255,255,.12)}
  .filepreview{max-width:260px;border-radius:12px;border:1px solid rgba(255,255,255,.14)}

  /* Composer */
  .composer{
    display:grid; grid-template-columns: 1fr auto; gap:10px;
    padding:14px 16px; border-top:1px solid var(--border);
    background: linear-gradient(0deg, rgba(255,255,255,.06), transparent);
  }
  .composer button{width:auto; padding:11px 16px}

  /* Call controls */
  .callrow{display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin-top:10px}

  /* Call videos */
  .callwrap{
    display:grid;
    grid-template-columns: 1fr 1fr;
    gap:12px;
    padding:12px 16px;
    border-top:1px solid var(--border);
    background:rgba(255,255,255,.03);
  }
  .videoBox{
    border:1px solid rgba(255,255,255,.14);
    border-radius:16px;
    overflow:hidden;
    position:relative;
    background:rgba(0,0,0,.35);
    min-height:160px;
  }
  video{width:100%; height:100%; object-fit:cover; display:block;}
  .vlabel{
    position:absolute; left:10px; bottom:10px;
    font-size:12px; color:rgba(255,255,255,.85);
    background:rgba(0,0,0,.35);
    border:1px solid rgba(255,255,255,.14);
    padding:6px 10px; border-radius:999px;
    backdrop-filter: blur(8px);
  }

  /* ✅ Incoming call MODAL (always visible) */
  .incomingModal{
    position:fixed;
    inset:0;
    display:none;
    align-items:center;
    justify-content:center;
    background:rgba(0,0,0,.55);
    z-index:9999;
    padding:20px;
  }
  .incomingCard{
    width:min(420px, 100%);
    background:rgba(20, 20, 30, .92);
    border:1px solid rgba(255,255,255,.18);
    border-radius:18px;
    box-shadow:0 20px 60px rgba(0,0,0,.6);
    padding:16px;
    backdrop-filter: blur(10px);
  }
  .incomingTitle{
    font-weight:800;
    font-size:16px;
    margin-bottom:8px;
  }
  .incomingFrom{
    font-size:13px;
    color:rgba(255,255,255,.8);
    margin-bottom:12px;
  }
  .incomingBtns{display:flex; gap:10px;}
  .incomingBtns button{width:100%}

  .mini{display:flex; align-items:center; gap:10px; margin-top:10px;}
  .mini input{flex:1}
</style>
</head>
<body>
  <div class="shell">
    <div class="card left">
      <div class="head">
        <div>
          <div class="title">DM Chat</div>
          <div class="subhead" style="font-size:12px;color:var(--muted);margin-top:2px;"></div>
        </div>
        <div class="badge"><span class="dot" id="dot"></span><span id="status">Offline</span></div>
      </div>

      <div class="section">
        <div>
          <label>Username</label>
          <input id="username" placeholder="ali / sara / ahmed" />
        </div>
        <div style="margin-top:12px">
          <label>Password</label>
          <input id="password" type="password" placeholder="1234" />
        </div>
        <div class="btnrow">
          <button class="primary" id="btnLogin">Login</button>
          <button class="danger" id="btnLogout" disabled>Logout</button>
          <button id="btnReconnect" disabled>Reconnect</button>
        </div>

        <div style="margin-top:14px">
          <label>Send To (username)</label>
          <input id="toUser" placeholder="sara" />
          <div class="hint">Tip: Click an online user tag to auto-fill “Send To”.</div>
          <div class="users" id="users"></div>
        </div>

        <div style="margin-top:14px">
          <label>File sharing</label>
          <div class="mini">
            <input type="file" id="filePick" />
            <button id="btnSendFile" class="primary" style="width:auto">Upload + Send</button>
          </div>
          <div class="hint"></div>
        </div>

        <div style="margin-top:14px">
          <label>Audio/Video calling</label>
          <div class="callrow">
            <button id="btnCall" class="primary">Start Call</button>
            <button id="btnHang" class="danger" disabled>Hang Up</button>
          </div>
          <div class="hint"></div>
        </div>
      </div>
    </div>

    <div class="card right">
      <div class="head">
        <div class="title">Chat</div>
        <button id="btnClear" style="width:auto">Clear</button>
      </div>

      <div class="chat" id="chat"></div>

      <div class="composer">
        <input id="msg" placeholder="Type message and press Enter..." />
        <button id="btnSend" class="primary">Send</button>
      </div>

      <div class="callwrap">
        <div class="videoBox">
          <video id="localVideo" autoplay playsinline muted></video>
          <div class="vlabel">Local</div>
        </div>
        <div class="videoBox">
          <video id="remoteVideo" autoplay playsinline></video>
          <div class="vlabel">Remote</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ✅ Incoming Call Modal -->
  <div class="incomingModal" id="incomingModal">
    <div class="incomingCard">
      <div class="incomingTitle">Incoming call</div>
      <div class="incomingFrom" id="incomingText">Incoming call…</div>
      <div class="incomingBtns">
        <button id="btnAccept" class="primary">Accept</button>
        <button id="btnReject" class="danger">Reject</button>
      </div>
    </div>
  </div>

<script>
  const el = (id) => document.getElementById(id);

  let token = null;
  let myUser = null;
  let selectedTo = null;
  let ws = null;

  // WebRTC state
  let pc = null;
  let localStream = null;
  let currentPeer = null;
  let callActive = false;
  let pendingOffer = null;
  let pendingOfferFrom = null;

  const rtcConfig = {
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun1.l.google.com:19302" }
    ]
  };

  function escapeHtml(s){
    return String(s)
      .replaceAll("&","&amp;")
      .replaceAll("<","&lt;")
      .replaceAll(">","&gt;")
      .replaceAll('"',"&quot;")
      .replaceAll("'","&#039;");
  }

  function setStatus(ok, text){
    el("status").textContent = text;
    el("dot").className = "dot" + (ok ? " ok" : "");
  }

  function formatTime(ts){
    try{
      const d = new Date(ts);
      return d.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
    }catch(e){ return ""; }
  }

  function addMessage({ kind="other", text="", html="", meta="" }) {
    const chat = el("chat");
    const wrap = document.createElement("div");
    wrap.className = "msg " + kind;

    const bubble = document.createElement("div");
    bubble.className = "bubble";

    if (html) bubble.innerHTML = html;
    else bubble.innerHTML = escapeHtml(text);

    wrap.appendChild(bubble);

    if (meta) {
      const m = document.createElement("div");
      m.className = "meta";
      m.textContent = meta;
      wrap.appendChild(m);
    }
    chat.appendChild(wrap);
    chat.scrollTop = chat.scrollHeight;
  }

  function addSystem(text) { addMessage({ kind: "system", text }); }

  function setToUser(u) {
    selectedTo = u;
    el("toUser").value = u;
  }

  function renderUsers(list){
    const box = el("users");
    box.innerHTML = "";
    list.forEach(u=>{
      const p = document.createElement("div");
      p.className = "pill" + (u === myUser ? " me" : "");
      p.textContent = u + (u === myUser ? " (you)" : "");
      p.onclick = ()=>{ if(u!==myUser) setToUser(u); };
      box.appendChild(p);
    });
  }

  async function doLogin(){
    const username = el("username").value.trim();
    const password = el("password").value.trim();
    if(!username || !password) return;

    const res = await fetch("/login", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ username, password })
    });

    if(!res.ok){
      addSystem("Login failed");
      return;
    }
    const data = await res.json();
    token = data.token;
    myUser = data.username;

    el("btnLogin").disabled = true;
    el("btnLogout").disabled = false;
    el("btnReconnect").disabled = false;

    connectWS();
  }

  function doLogout(){
    token = null;
    myUser = null;
    selectedTo = null;
    if(ws){ ws.close(); ws=null; }
    setStatus(false, "Offline");
    renderUsers([]);
    el("btnLogin").disabled = false;
    el("btnLogout").disabled = true;
    el("btnReconnect").disabled = true;

    endCall("logout");
    addSystem("Logged out.");
  }

  function connectWS(){
    if(!token) return;
    if(ws){ ws.close(); ws=null; }

    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.onopen = ()=>{
      setStatus(true, "Online");
      ws.send(JSON.stringify({ type:"auth", token }));
      addSystem("Connected.");
    };

    ws.onclose = ()=>{
      setStatus(false, "Offline");
      addSystem("Disconnected.");
    };

    ws.onerror = ()=>{
      setStatus(false, "Offline");
      addSystem("Socket error.");
    };

    ws.onmessage = async (evt)=>{
      const payload = JSON.parse(evt.data);

      if (payload.type === "system") { addSystem(payload.message); return; }
      if (payload.type === "presence") { renderUsers(payload.online || []); return; }
      if (payload.type === "error") { addSystem("Error: " + payload.message); return; }

      if (payload.type === "dm") {
        const mine = payload.from === myUser;
        if (payload.to !== myUser && payload.from !== myUser) return;

        addMessage({
          kind: mine ? "me" : "other",
          text: `${payload.from} → ${payload.to}: ${payload.body || ""}`,
          meta: formatTime(payload.ts)
        });
        return;
      }

      if (payload.type === "file") {
        const mine = payload.from === myUser;
        if (payload.to !== myUser && payload.from !== myUser) return;

        const f = payload.file || {};
        const absUrl = `${location.origin}${f.url || ""}`;
        const name = escapeHtml(f.name || "file");
        const kb = Math.round((f.size || 0) / 1024);
        const mime = (f.mime || "").toLowerCase();

        let previewHtml = "";
        if (mime.startsWith("image/")) {
          previewHtml = `<img class="filepreview" src="${absUrl}" alt="${name}" />`;
        }

        const html = `
          <div class="filebox">
            <div class="filemeta"><b>${escapeHtml(payload.from)}</b> → <b>${escapeHtml(payload.to)}</b></div>
            <div class="filemeta">📎 ${name} (${kb} KB)</div>
            ${previewHtml}
            <div class="fileactions">
              <a href="${absUrl}" target="_blank" rel="noopener">Open</a>
              <a href="${absUrl}" download>Download</a>
            </div>
          </div>
        `;

        addMessage({
          kind: mine ? "me" : "other",
          html,
          meta: formatTime(payload.ts)
        });
        return;
      }

      // --- WebRTC signaling handling ---
      if (payload.type === "call_offer") {
        if (callActive) {
          sendSignal("call_hangup", payload.from, null, null, "busy");
          return;
        }
        pendingOffer = payload.sdp;
        pendingOfferFrom = payload.from;
        showIncoming(payload.from);
        return;
      }

      if (payload.type === "call_answer") {
        if (!pc) return;
        await pc.setRemoteDescription(payload.sdp);
        addSystem("Call connected.");
        setCallActive(true, payload.from);
        return;
      }

      if (payload.type === "call_ice") {
        if (!pc || !payload.candidate) return;
        try { await pc.addIceCandidate(payload.candidate); } catch(e) {}
        return;
      }

      if (payload.type === "call_hangup") {
        addSystem(`Call ended (${payload.reason || "hangup"}).`);
        endCall("remote_hangup");
        hideIncoming();
        return;
      }
    };
  }

  function sendMsg(){
    if(!ws || ws.readyState !== 1) return;
    const to = el("toUser").value.trim();
    const body = el("msg").value;
    if(!to || !body) return;

    ws.send(JSON.stringify({ type:"dm", to, body }));
    el("msg").value = "";
  }

  async function sendFile(){
    if(!token) return;
    const to = el("toUser").value.trim();
    const fp = el("filePick").files[0];
    if(!to || !fp) return;

    const fd = new FormData();
    fd.append("token", token);
    fd.append("to", to);
    fd.append("file", fp);

    const btn = el("btnSendFile");
    btn.disabled = true;
    btn.textContent = "Uploading...";

    try{
      const res = await fetch("/upload", { method:"POST", body: fd });
      if(!res.ok){
        const t = await res.text();
        addSystem("Upload failed: " + t);
      } else {
        addSystem("File sent.");
      }
    }catch(e){
      addSystem("Upload error.");
    }finally{
      btn.disabled = false;
      btn.textContent = "Upload + Send";
      el("filePick").value = "";
    }
  }

  // ----------------------------
  // WebRTC helpers
  // ----------------------------
  function setCallActive(active, peer=null){
    callActive = active;
    currentPeer = peer;
    el("btnHang").disabled = !active;
    el("btnCall").disabled = active;
  }

  // ✅ modal show/hide
  function showIncoming(from){
    el("incomingText").textContent = `Incoming call from ${from}`;
    el("incomingModal").style.display = "flex";
  }

  function hideIncoming(){
    el("incomingModal").style.display = "none";
    pendingOffer = null;
    pendingOfferFrom = null;
  }

  function sendSignal(type, to, sdp=null, candidate=null, reason=null){
    if(!ws || ws.readyState !== 1) return;
    ws.send(JSON.stringify({ type, to, sdp, candidate, reason }));
  }

  async function ensureLocalMedia(){
    if (localStream) return localStream;
    localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video:true });
    el("localVideo").srcObject = localStream;
    return localStream;
  }

  function createPeerConnection(peerUser){
    pc = new RTCPeerConnection(rtcConfig);

    pc.onicecandidate = (e)=>{
      if(e.candidate && peerUser){
        sendSignal("call_ice", peerUser, null, e.candidate, null);
      }
    };

    pc.ontrack = (e)=>{
      el("remoteVideo").srcObject = e.streams[0];
    };

    return pc;
  }

  async function startCall(){
    if (callActive) return;
    const to = el("toUser").value.trim();
    if(!to) { addSystem("Select a user to call."); return; }

    try{
      await ensureLocalMedia();
      createPeerConnection(to);

      localStream.getTracks().forEach(t => pc.addTrack(t, localStream));

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      sendSignal("call_offer", to, offer, null, null);
      addSystem("Calling " + to + "...");
      setCallActive(true, to);
    }catch(e){
      addSystem("Call failed to start (permission/network).");
      endCall("start_failed");
    }
  }

  async function acceptCall(){
    if (!pendingOffer || !pendingOfferFrom) return;
    const from = pendingOfferFrom;

    try{
      await ensureLocalMedia();
      createPeerConnection(from);

      localStream.getTracks().forEach(t => pc.addTrack(t, localStream));

      await pc.setRemoteDescription(pendingOffer);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);

      sendSignal("call_answer", from, answer, null, null);
      addSystem("Call accepted.");
      setCallActive(true, from);
      hideIncoming();
    }catch(e){
      addSystem("Failed to accept call.");
      sendSignal("call_hangup", from, null, null, "accept_failed");
      endCall("accept_failed");
      hideIncoming();
    }
  }

  function rejectCall(){
    if (!pendingOfferFrom) { hideIncoming(); return; }
    sendSignal("call_hangup", pendingOfferFrom, null, null, "rejected");
    addSystem("Call rejected.");
    hideIncoming();
  }

  function endCall(why="hangup"){
    if (callActive && currentPeer) {
      sendSignal("call_hangup", currentPeer, null, null, why);
    }
    setCallActive(false, null);
    hideIncoming();

    try{ if (pc) pc.close(); }catch(e){}
    pc = null;

    el("remoteVideo").srcObject = null;

    if (localStream) {
      localStream.getTracks().forEach(t => t.stop());
      localStream = null;
    }
    el("localVideo").srcObject = null;
  }

  // ----------------------------
  // Wire UI events
  // ----------------------------
  el("btnLogin").onclick = doLogin;
  el("btnLogout").onclick = doLogout;
  el("btnReconnect").onclick = connectWS;
  el("btnSend").onclick = sendMsg;
  el("btnSendFile").onclick = sendFile;
  el("btnCall").onclick = startCall;
  el("btnHang").onclick = ()=> endCall("hangup");
  el("btnAccept").onclick = acceptCall;
  el("btnReject").onclick = rejectCall;
  el("btnClear").onclick = ()=> el("chat").innerHTML = "";

  // click outside modal to ignore (optional)
  el("incomingModal").addEventListener("click", (e)=>{
    if (e.target.id === "incomingModal") {
      // don't auto-reject; just close the popup view
      // hideIncoming();
    }
  });

  el("msg").addEventListener("keydown", (e)=>{
    if(e.key === "Enter"){
      sendMsg();
    }
  });
</script>
</body>
</html>
"""

# to run: uvicorn main:app --reload