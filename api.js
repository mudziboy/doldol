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
UTIL: SAVE QUOTA
====================================================== */
function saveQuota(protocol, user, quotaGb) {
  if (!quotaGb || quotaGb <= 0 || quotaGb === "0") return;

  let path = "";
  if (protocol === "zivpn") {
    path = `/etc/zivpn/${user}.quota`;
  } else if (protocol === "ssh") {
    path = `/etc/ssh/${user}.quota`;
  } else {
    path = `/etc/xray/${protocol}/${user}.quota`;
  }

  try {
    const dir = path.substring(0, path.lastIndexOf('/'));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    fs.writeFileSync(path, quotaGb.toString());
    console.log(`[QUOTA] Saved ${quotaGb}GB for ${user} (${protocol})`);

  } catch (err) {
    console.error(`[QUOTA ERROR] Failed for ${user}:`, err.message);
  }
}

/* ======================================================
UTIL: SAVE IP LIMIT
====================================================== */
function saveIPLimit(protocol, user, ipLimit) {
  if (!ipLimit || ipLimit <= 0 || ipLimit === "0") return;

  let path = "";
  if (protocol === "zivpn") {
    path = `/etc/zivpn/${user}.iplimit`;
  } else if (protocol === "ssh") {
    path = `/etc/ssh/${user}`;
  } else {
    path = `/etc/xray/${protocol}/${user}IP`;
  }

  try {
    const dir = path.substring(0, path.lastIndexOf('/'));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    fs.writeFileSync(path, ipLimit.toString());
    console.log(`[LIMIT-IP] Saved ${ipLimit} for ${user} (${protocol})`);

  } catch (err) {
    console.error(`[LIMIT-IP ERROR] Failed for ${user}:`, err.message);
  }
}

/* ======================================================
AUTH MIDDLEWARE
====================================================== */
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
🔥 PRIORITAS ROUTE (FIX 404)
====================================================== */
app.get("/api/user/quota",
  (req, res, next) => {
    console.log(`[API-IN] Request quota user: ${req.query.user}`);
    next();
  },
  headerAuth,
  (req, res) => {
    const { user, protocol } = req.query;

    if (!user || !protocol) {
      return res.status(400).json({ success: false, error: "Missing user or protocol" });
    }

    let path = "";
    const proto = protocol.toLowerCase();

    if (proto === "zivpn") {
      path = `/etc/zivpn/${user}.quota`;
    } else if (proto === "ssh") {
      path = `/etc/ssh/${user}.quota`;
    } else {
      path = `/etc/xray/${proto}/${user}.quota`;
    }

    try {
      if (fs.existsSync(path)) {
        const quotaValue = fs.readFileSync(path, "utf8").trim();
        return res.json({ success: true, quota: quotaValue });
      } else {
        return res.json({ success: true, quota: "Unlimited" });
      }
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }
);

/* ======================================================
SAFE BINARY RUNNER
====================================================== */
function runBinary(res, cmd, args, quotaInfo = null) {
  const start = Date.now();
  let output = '';
  let finished = false;

  const child = spawn(cmd, args, {
    stdio: ['ignore', 'pipe', 'pipe']
  });

  const killer = setTimeout(() => {
    if (finished) return;
    finished = true;
    child.kill('SIGKILL');
    res.status(504).json({ status: 'error', message: 'Service timeout' });
  }, 20000);

  child.stdout.on('data', d => output += d.toString());
  child.stderr.on('data', d => output += d.toString());

  child.on('error', err => {
    if (finished) return;
    finished = true;
    clearTimeout(killer);
    res.status(500).json({ status: 'error', message: err.message });
  });

  child.on('close', () => {
    if (finished) return;
    finished = true;
    clearTimeout(killer);

    try {
      const json = JSON.parse(output.trim());
      const ok = json.status === 'success' || json.success === true;

      if (!ok) {
        return res.status(500).json({
          status: 'error',
          message: json.message || json.error || 'Operation failed'
        });
      }

      if (quotaInfo && quotaInfo.user) {
        if (quotaInfo.quota) saveQuota(quotaInfo.proto, quotaInfo.user, quotaInfo.quota);
        if (quotaInfo.iplimit) saveIPLimit(quotaInfo.proto, quotaInfo.user, quotaInfo.iplimit);
      }

      res.json({ status: 'success', data: json.data || json });

    } catch {
      res.status(500).json({
        status: 'error',
        message: 'Invalid service output',
        detail: output
      });
    }
  });
}

/* ======================================================
XRAY HANDLER
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

  runBinary(res, "bash", ["-c", args.join(" ")], { proto, user, quota, iplimit });
}

function renewXray(proto, req, res) {
  const { user, exp, quota, iplimit } = req.query;
  if (!user || !exp) {
    return res.status(400).json({ status: "error", message: "Invalid parameter" });
  }

  const args = ["apirenew", proto, user, exp];
  if (quota) args.push(quota);
  if (iplimit) args.push(iplimit);

  runBinary(res, "bash", ["-c", args.join(" ")], { proto, user, quota, iplimit });
}

function deleteXray(proto, req, res) {
  const { user } = req.query;
  if (!user) {
    return res.status(400).json({ status: "error", message: "Invalid parameter" });
  }

  runBinary(res, "bash", ["-c", `apidelete ${proto} ${user}`]);
}

function trialXray(proto, req, res) {
  const { duration = 60 } = req.query;
  const bin = `apitrial-${proto}`;
  runBinary(res, bin, [String(duration)]);
}

/* ======================================================
XRAY ROUTES
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

app.get("/trialvmess", legacyAuth, (r, s) => trialXray("vmess", r, s));
app.get("/trialvless", legacyAuth, (r, s) => trialXray("vless", r, s));
app.get("/trialtrojan", legacyAuth, (r, s) => trialXray("trojan", r, s));
app.get("/trialshadowsocks", legacyAuth, (r, s) => trialXray("shadowsocks", r, s));

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