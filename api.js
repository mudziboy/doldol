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

function getAuthKey() {
  return fs.readFileSync(AUTH_KEY_FILE, "utf8").trim();
}

/* ======================================================
   AUTH MIDDLEWARE
====================================================== */
function headerAuth(req, res, next) {
  try {
    if (req.headers["x-api-key"] !== getAuthKey()) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }
    next();
  } catch {
    res.status(500).json({ status: "error", message: "Auth config missing" });
  }
}

/* ======================================================
   HELPER: SAVE QUOTA
====================================================== */
function saveQuota(protocol, user, quotaGb) {
  if (!quotaGb || quotaGb <= 0) return;
  let path = "";
  if (protocol === "zivpn") path = `/etc/zivpn/${user}.quota`;
  else if (protocol === "ssh") path = `/etc/ssh/${user}.quota`;
  else path = `/etc/xray/${protocol}/${user}.quota`;

  try {
    fs.writeFileSync(path, quotaGb.toString());
  } catch (err) {
    console.error(`Gagal menulis quota untuk ${user}:`, err);
  }
}

/* ======================================================
   SAFE BINARY RUNNER
====================================================== */
function runBinary(res, args, callback) {
  const child = spawn("/usr/bin/apicreate", args);
  let output = "";
  child.stdout.on("data", (data) => (output += data.toString()));
  child.stderr.on("data", (data) => (output += data.toString()));
  child.on("close", () => {
    try {
      const json = JSON.parse(output);
      if (callback) callback(json);
      else res.json(json);
    } catch {
      res.status(500).json({ success: false, output });
    }
  });
}

/* ======================================================
   ENDPOINTS (XRAY & SSH)
====================================================== */
app.post("/api/user/create/xray", headerAuth, (req, res) => {
  const { protocol, user, days, ip_limit, quota_gb } = req.body;
  if (!protocol || !user || !days) return res.status(400).json({ success: false, error: "Missing params" });

  runBinary(res, [protocol, user, days, "0", ip_limit], (json) => {
    if (json.status === "success" || json.success) {
      saveQuota(protocol, user, quota_gb);
    }
    res.json(json);
  });
});

app.post("/api/user/create/ssh", headerAuth, (req, res) => {
  const { user, password, days, ip_limit, quota_gb } = req.body;
  if (!user || !password || !days) return res.status(400).json({ success: false, error: "Missing params" });

  runBinary(res, ["ssh", user, password, days, ip_limit], (json) => {
    if (json.status === "success" || json.success) {
      // Daftarkan ke iptables untuk tracking (Jika SSH)
      spawn("iptables", ["-A", "USAGE_SSH", "-p", "tcp", "-m", "comment", "--comment", user]);
      saveQuota("ssh", user, quota_gb);
    }
    res.json(json);
  });
});

/* ======================================================
   ZIVPN ENDPOINTS
====================================================== */
function runZiVPN(res, args, user, quota) {
  const child = spawn("/usr/bin/apicreate-zivpn", args);
  let output = "";
  child.stdout.on("data", (data) => (output += data.toString()));
  child.on("close", () => {
    try {
      const json = JSON.parse(output);
      if (json.status === "success") saveQuota("zivpn", user, quota);
      res.json(json);
    } catch {
      res.status(500).json({ success: false, output });
    }
  });
}

app.post("/api/user/create", headerAuth, (req, res) => {
  const { password, days, ip_limit, quota_gb } = req.body;
  runZiVPN(res, [password, days, ip_limit], password, quota_gb);
});

// Endpoint Delete & Health tetap sama
app.post("/api/user/delete", headerAuth, (req, res) => {
  const { password, protocol } = req.body;
  const bin = protocol === "zivpn" ? "/usr/bin/apidelete-zivpn" : "/usr/bin/apidelete";
  const args = protocol === "zivpn" ? [password] : [password, protocol];
  
  const child = spawn(bin, args);
  child.on("close", () => res.json({ success: true }));
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

app.listen(PORT, () => console.log(`API Server running on port ${PORT}`));