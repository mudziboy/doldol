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
   1. XRAY ENDPOINTS (Dahulukan agar tidak tertabrak)
====================================================== */
app.post("/api/user/create/xray", headerAuth, (req, res) => {
  const { protocol, user, days, quota_gb, ip_limit } = req.body;
  
  const bin = `/usr/bin/apicreate-${protocol}`;
  const child = spawn(bin, [user, days, ip_limit]);
  let output = "";

  child.stdout.on("data", (data) => (output += data.toString()));
  child.on("close", () => {
    try {
      const json = JSON.parse(output);
      if (json.status === "success" || json.success) {
        saveQuota(protocol, user, quota_gb);
      }
      res.json(json);
    } catch (err) {
      res.status(500).json({ success: false, message: "Error parsing output", output });
    }
  });
});

/* ======================================================
   2. SSH ENDPOINTS
====================================================== */
app.post("/api/user/create/ssh", headerAuth, (req, res) => {
  const { user, password, days, ip_limit, quota_gb } = req.body;
  const child = spawn("/usr/bin/apicreate", ["ssh", user, password, days, ip_limit]);
  let output = "";
  child.stdout.on("data", (data) => (output += data.toString()));
  child.on("close", () => {
    try {
      const json = JSON.parse(output);
      if (json.status === "success" || json.success) {
        spawn("iptables", ["-A", "USAGE_SSH", "-p", "tcp", "-m", "comment", "--comment", user]);
        saveQuota("ssh", user, quota_gb);
      }
      res.json(json);
    } catch {
      res.status(500).json({ success: false, output });
    }
  });
});

/* ======================================================
   3. ZIVPN ENDPOINTS (Diletakkan terakhir)
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

// Rute ZiVPN ditaruh di bawah agar tidak 'menangkap' rute /xray atau /ssh
app.post("/api/user/create", headerAuth, (req, res) => {
  const { password, days, ip_limit, quota_gb } = req.body;
  runZiVPN(res, [password, days, ip_limit], password, quota_gb);
});

/* ======================================================
   SYSTEM ENDPOINTS
====================================================== */
app.post("/api/user/delete", headerAuth, (req, res) => {
  const { password, protocol } = req.body;
  const bin = protocol === "zivpn" ? "/usr/bin/apidelete-zivpn" : "/usr/bin/apidelete";
  const args = protocol === "zivpn" ? [password] : [password, protocol];
  const child = spawn(bin, args);
  child.on("close", () => res.json({ success: true }));
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

app.listen(PORT, () => console.log(`API Server running on port ${PORT}`));