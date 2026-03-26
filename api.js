const { spawn } = require("child_process");
const express = require("express");
const fs = require("fs");
const app = express();

app.use(express.json());

/* ======================================================
CONFIG
====================================================== */
const AUTH_KEY_FILE = "/root/.key";
const PORT = process.env.PORT || 5889;

/* ======================================================
UTIL: AUTH
====================================================== */
function getAuthKey() {
  return fs.readFileSync(AUTH_KEY_FILE, "utf8").trim();
}

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

/* ======================================================
UTIL: QUOTA & IP LIMIT
====================================================== */
function saveQuota(protocol, user, quotaGb) {
  if (!quotaGb || quotaGb <= 0 || quotaGb === "0") return;

  let path = "";
  if (protocol === "zivpn") path = `/etc/zivpn/${user}.quota`;
  else if (protocol === "ssh") path = `/etc/ssh/${user}.quota`;
  else path = `/etc/xray/${protocol}/${user}.quota`;

  try {
    const dir = path.substring(0, path.lastIndexOf("/"));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path, quotaGb.toString());
  } catch {}
}

function saveIPLimit(protocol, user, ipLimit) {
  if (!ipLimit || ipLimit <= 0 || ipLimit === "0") return;

  let path = "";
  if (protocol === "zivpn") path = `/etc/zivpn/${user}.iplimit`;
  else if (protocol === "ssh") path = `/etc/ssh/${user}`;
  else path = `/etc/xray/${protocol}/${user}IP`;

  try {
    const dir = path.substring(0, path.lastIndexOf("/"));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path, ipLimit.toString());
  } catch {}
}

/* ======================================================
RUN BINARY
====================================================== */
function runBinary(res, cmd, args, quotaInfo = null) {
  let output = "";
  let finished = false;

  const child = spawn(cmd, args);

  const killer = setTimeout(() => {
    if (finished) return;
    finished = true;
    child.kill("SIGKILL");
    res.status(504).json({ status: "error", message: "Timeout" });
  }, 20000);

  child.stdout.on("data", (d) => (output += d.toString()));
  child.stderr.on("data", (d) => (output += d.toString()));

  child.on("close", () => {
    if (finished) return;
    finished = true;
    clearTimeout(killer);

    try {
      const json = JSON.parse(output.trim());
      const ok = json.status === "success" || json.success === true;

      if (!ok) {
        return res.status(500).json({
          status: "error",
          message: json.message || "Unknown error",
        });
      }

      if (quotaInfo && quotaInfo.user) {
        if (quotaInfo.quota)
          saveQuota(quotaInfo.proto, quotaInfo.user, quotaInfo.quota);
        if (quotaInfo.iplimit)
          saveIPLimit(
            quotaInfo.proto,
            quotaInfo.user,
            quotaInfo.iplimit
          );
      }

      res.json({
  status: "success",
  ...(json.data || {})
});
    } catch {
      res
        .status(500)
        .json({ status: "error", message: "Invalid output", raw: output });
    }
  });
}

/* ======================================================
CREATE HANDLER
====================================================== */
function createXray(proto, req, res) {
  const { user, password, exp, quota, iplimit } = req.query;

  const args = ["apicreate", proto, user];
  if (password) args.push(password);
  args.push(exp);
  if (quota) args.push(quota);
  args.push(iplimit);

  runBinary(res, "bash", ["-c", args.join(" ")], {
    proto,
    user,
    quota,
    iplimit,
  });
}

/* ======================================================
TRIAL HANDLER
====================================================== */
function trialXray(proto, req, res) {
  const { duration } = req.query;

  let cmd = `apitrial-${proto}`;
  if (duration) cmd += ` ${duration}`;

  runBinary(res, "bash", ["-c", cmd]);
}

function trialSSH(req, res) {
  const { duration = 60, server_id } = req.query;

  let cmd = `apitrial-ssh ${duration}`;
  if (server_id) cmd += ` ${server_id}`;

  runBinary(res, "bash", ["-c", cmd]);
}

function trialZivpn(req, res) {
  const { duration = 60, iplimit = 1 } = req.query;

  let cmd = `apitrial-zivpn ${duration} ${iplimit}`;

  runBinary(res, "bash", ["-c", cmd]);
}

/* ======================================================
ROUTES
====================================================== */

// CREATE
app.get("/createssh", legacyAuth, (r, s) => createXray("ssh", r, s));
app.get("/createvmess", legacyAuth, (r, s) => createXray("vmess", r, s));
app.get("/createvless", legacyAuth, (r, s) => createXray("vless", r, s));
app.get("/createtrojan", legacyAuth, (r, s) => createXray("trojan", r, s));
app.get("/createshadowsocks", legacyAuth, (r, s) =>
  createXray("shadowsocks", r, s)
);

app.get("/createzivpn", legacyAuth, (req, res) => {
  const { password, exp, iplimit } = req.query;

  if (!password || !exp) {
    return res.status(400).json({
      status: "error",
      message: "Missing params"
    });
  }

  const cmd = `apicreate-zivpn ${password} ${exp} ${iplimit || 1}`;

  runBinary(res, "bash", ["-c", cmd], {
    proto: "zivpn",
    user: password,
    iplimit
  });
});

// TRIAL
app.get("/trialvmess", legacyAuth, (r, s) => trialXray("vmess", r, s));
app.get("/trialvless", legacyAuth, (r, s) => trialXray("vless", r, s));
app.get("/trialtrojan", legacyAuth, (r, s) => trialXray("trojan", r, s));
app.get("/trialshadowsocks", legacyAuth, (r, s) =>
  trialXray("shadowsocks", r, s)
);

app.get("/trialssh", legacyAuth, trialSSH);
app.get("/trialzivpn", legacyAuth, trialZivpn);

/* ======================================================
HEALTH
====================================================== */
app.get("/health", (req, res) => {
  res.json({ status: "ok", port: PORT });
});

/* ======================================================
START
====================================================== */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 API running on port ${PORT}`);
});