const { spawn } = require("child_process");
const express = require("express");
const fs = require("fs");

const app = express();
app.use(express.json());

/* ======================================================
   CONFIG
====================================================== */
const AUTH_KEY_FILE = "/root/.key";
const PORT = process.env.PORT || 5888;

/* ======================================================
   UTIL: LOAD AUTH KEY
====================================================== */
function getAuthKey() {
  return fs.readFileSync(AUTH_KEY_FILE, "utf8").trim();
}

/* ======================================================
   AUTH MIDDLEWARE
====================================================== */
// Legacy auth (?auth=)
function legacyAuth(req, res, next) {
  try {
    if (req.query.auth !== getAuthKey()) {
      return res.status(401).json({ status: "error", message: "Unauthorized" });
    }
    next();
  } catch {
    res.status(500).json({ status: "error", message: "Auth config missing" });
  }
}

// Modern auth (X-API-Key)
function headerAuth(req, res, next) {
  try {
    if (req.headers["x-api-key"] !== getAuthKey()) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }
    next();
  } catch {
    res.status(500).json({ success: false, error: "Auth config missing" });
  }
}

/* ======================================================
   SAFE BINARY RUNNER (CORE)
====================================================== */
function runBinary(res, cmd, args) {
  const start = Date.now();
  let output = '';
  let finished = false;

  const child = spawn(cmd, args, {
    stdio: ['ignore', 'pipe', 'pipe']
  });

  // 🔥 HARD TIMEOUT (REAL)
  const killer = setTimeout(() => {
    if (finished) return;
    console.error('[BIN TIMEOUT]', cmd, args);
    finished = true;
    child.kill('SIGKILL');
    res.status(504).json({
      status: 'error',
      message: 'Service timeout'
    });
  }, 20000); // ⬅️ SAMA DENGAN axios timeout

  child.stdout.on('data', d => {
    output += d.toString();
  });

  child.stderr.on('data', d => {
    output += d.toString();
  });

  child.on('error', err => {
    if (finished) return;
    finished = true;
    clearTimeout(killer);
    console.error('[BIN SPAWN ERROR]', err.message);
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  });

  child.on('close', code => {
    if (finished) return;
    finished = true;
    clearTimeout(killer);

    const duration = Date.now() - start;
    console.log('[BIN DONE]', cmd, 'exit:', code, 'time:', duration, 'ms');

    try {
      const json = JSON.parse(output.trim());
      const ok = json.status === 'success' || json.success === true;

      if (!ok) {
        return res.status(500).json({
          status: 'error',
          message: json.message || json.error || 'Operation failed'
        });
      }

      res.json({
        status: 'success',
        data: json.data || json
      });

    } catch (e) {
      console.error('[BIN JSON ERROR]', output);
      res.status(500).json({
        status: 'error',
        message: 'Invalid service output',
        detail: output
      });
    }
  });
}
/* ======================================================
   GENERIC XRAY HANDLER (SSH / VMESS / VLESS / TROJAN / SS)
====================================================== */
function createXray(proto, req, res) {
  const { user, password, exp, quota, iplimit } = req.query;
  if (!user || !exp || !iplimit) {
    return res.status(400).json({ status: "error", message: "Invalid parameter" });
  }

  const args = ["apicreate", proto, user];
  if (password) args.push(password);
  args.push(exp);
  if (quota) args.push(quota);
  args.push(iplimit);

  runBinary(res, "bash", ["-c", args.join(" ")]);
}

function renewXray(proto, req, res) {
  const { user, exp, quota, iplimit } = req.query;
  if (!user || !exp) {
    return res.status(400).json({ status: "error", message: "Invalid parameter" });
  }

  const args = ["apirenew", proto, user, exp];
  if (quota) args.push(quota);
  if (iplimit) args.push(iplimit);

  runBinary(res, "bash", ["-c", args.join(" ")]);
}

function deleteXray(proto, req, res) {
  const { user } = req.query;
  if (!user) {
    return res.status(400).json({ status: "error", message: "Invalid parameter" });
  }
  runBinary(res, "bash", ["-c", `apidelete ${proto} ${user}`]);
}

/* ======================================================
   XRAY LEGACY ENDPOINTS (BOT)
====================================================== */
app.get("/createssh", legacyAuth, (r, s) => createXray("ssh", r, s));
app.get("/createvmess", legacyAuth, (r, s) => createXray("vmess", r, s));
app.get("/createvless", legacyAuth, (r, s) => createXray("vless", r, s));
app.get("/createtrojan", legacyAuth, (r, s) => createXray("trojan", r, s));
app.get("/createshadowsocks", legacyAuth, (r, s) => createXray("shadowsocks", r, s));

app.get("/renewssh", legacyAuth, (r, s) => renewXray("ssh", r, s));
app.get("/renewvmess", legacyAuth, (r, s) => renewXray("vmess", r, s));
app.get("/renewvless", legacyAuth, (r, s) => renewXray("vless", r, s));
app.get("/renewtrojan", legacyAuth, (r, s) => renewXray("trojan", r, s));
app.get("/renewshadowsocks", legacyAuth, (r, s) => renewXray("shadowsocks", r, s));

app.get("/deletessh", legacyAuth, (r, s) => deleteXray("ssh", r, s));
app.get("/deletevmess", legacyAuth, (r, s) => deleteXray("vmess", r, s));
app.get("/deletevless", legacyAuth, (r, s) => deleteXray("vless", r, s));
app.get("/deletetrojan", legacyAuth, (r, s) => deleteXray("trojan", r, s));
app.get("/deleteshadowsocks", legacyAuth, (r, s) => deleteXray("shadowsocks", r, s));

/* ======================================================
   ZIVPN CORE LOGIC (NO TRIAL BINARY)
====================================================== */
function createZiVPN(res, password, days, ipLimit) {
  runBinary(res, "/usr/bin/apicreate-zivpn", [
    password,
    String(days),
    String(ipLimit)
  ]);
}

function renewZiVPN(res, password, days) {
  runBinary(res, "/usr/bin/apirenew-zivpn", [
    password,
    String(days)
  ]);
}

function deleteZiVPN(res, password) {
  runBinary(res, "/usr/bin/apidelete-zivpn", [password]);
}

// 🔥 Trial ZiVPN = Create ZiVPN (enterprise way)
function trialZiVPN(res, durationMinutes, ipLimit) {
  const days = Math.max(1, Math.ceil(Number(durationMinutes) / 1440));
  const password = "trial" + Math.random().toString(36).slice(2, 8);

  runBinary(res, "/usr/bin/apicreate-zivpn", [
    password,
    String(days),
    String(ipLimit)
  ]);
}

/* ======================================================
   ZIVPN LEGACY (BOT)
====================================================== */
app.get("/createzivpn", legacyAuth, (req, res) => {
  const { password, exp, iplimit } = req.query;
  if (!password || !exp || !iplimit) {
    return res.status(400).json({ status: "error", message: "Invalid parameter" });
  }
  createZiVPN(res, password, exp, iplimit);
});

app.get("/renewzivpn", legacyAuth, (req, res) => {
  const { password, exp } = req.query;
  if (!password || !exp) {
    return res.status(400).json({ status: "error", message: "Invalid parameter" });
  }
  renewZiVPN(res, password, exp);
});

app.get("/deletezivpn", legacyAuth, (req, res) => {
  const { password } = req.query;
  if (!password) {
    return res.status(400).json({ status: "error", message: "Invalid parameter" });
  }
  deleteZiVPN(res, password);
});

// ✅ TRIAL ZIVPN (BOT)
app.get("/trialzivpn", legacyAuth, (req, res) => {
  const { duration = 60, iplimit = 1 } = req.query;
  trialZiVPN(res, duration, iplimit);
});

/* ======================================================
   ZIVPN API v2 (OFFICIAL / ENTERPRISE)
====================================================== */
app.post("/api/user/create", headerAuth, (req, res) => {
  const { password, days, ip_limit } = req.body;
  if (!password || !days || !ip_limit) {
    return res.status(400).json({ success: false, error: "Invalid payload" });
  }
  createZiVPN(res, password, days, ip_limit);
});

app.post("/api/user/renew", headerAuth, (req, res) => {
  const { password, days } = req.body;
  if (!password || !days) {
    return res.status(400).json({ success: false, error: "Invalid payload" });
  }
  renewZiVPN(res, password, days);
});

app.post("/api/user/delete", headerAuth, (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ success: false, error: "Invalid payload" });
  }
  deleteZiVPN(res, password);
});

// ✅ TRIAL ZIVPN (ENTERPRISE)
app.post("/api/user/trial", headerAuth, (req, res) => {
  const { duration = 60, ip_limit = 1 } = req.body;
  trialZiVPN(res, duration, ip_limit);
});

/* ======================================================
   HEALTH CHECK
====================================================== */
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "vpn-api-enterprise-clean",
    port: PORT
  });
});

/* ======================================================
   START SERVER
====================================================== */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Master VPN API ENTERPRISE CLEAN running on port ${PORT}`);
});