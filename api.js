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
UTIL: LOAD AUTH KEY
====================================================== */
function getAuthKey() {
  return fs.readFileSync(AUTH_KEY_FILE, "utf8").trim();
}

/* ======================================================
UTIL: SAVE QUOTA (XRAY ONLY)
====================================================== */
function saveQuota(protocol, user, quotaGb) {
  if (!quotaGb || quotaGb <= 0 || quotaGb === "0") return;

  let path = `/etc/xray/${protocol}/${user}.quota`;

  try {
    const dir = path.substring(0, path.lastIndexOf("/"));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path, quotaGb.toString());
  } catch {}
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
    const dir = path.substring(0, path.lastIndexOf("/"));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path, ipLimit.toString());
  } catch {}
}

/* ======================================================
AUTH
====================================================== */
function legacyAuth(req, res, next) {
  try {
    if (req.query.auth !== getAuthKey()) {
      return res.status(401).json({
        status: "error",
        message: "Unauthorized",
      });
    }
    next();
  } catch {
    res.status(500).json({
      status: "error",
      message: "Auth config missing",
    });
  }
}

/* ======================================================
RUN BINARY (ANTI ERROR + STABIL)
====================================================== */
function runBinary(res, cmd, args, quotaInfo = null) {
  let output = "";
  let finished = false;

  const child = spawn(cmd, args);

  const killer = setTimeout(() => {
    if (finished) return;
    finished = true;
    child.kill("SIGKILL");
    return res.status(504).json({
      status: "error",
      message: "Timeout",
    });
  }, 20000);

  child.stdout.on("data", (d) => (output += d.toString()));
  child.stderr.on("data", (d) => (output += d.toString()));

  child.on("close", () => {
    if (finished) return;
    finished = true;
    clearTimeout(killer);

    if (!output.trim()) {
      return res.status(500).json({
        status: "error",
        message: "No output from script",
      });
    }

    try {
      const json = JSON.parse(output.trim());
      const ok = json.status === "success" || json.success === true;

      if (!ok) {
        return res.status(500).json({
          status: "error",
          message: json.message || "Script error",
        });
      }

      if (quotaInfo && quotaInfo.user) {
        // quota hanya untuk XRAY
        if (quotaInfo.proto !== "zivpn" && quotaInfo.proto !== "ssh") {
          if (quotaInfo.quota) {
            saveQuota(quotaInfo.proto, quotaInfo.user, quotaInfo.quota);
          }
        }

        if (quotaInfo.iplimit) {
          saveIPLimit(
            quotaInfo.proto,
            quotaInfo.user,
            quotaInfo.iplimit
          );
        }
      }

      res.json({
        status: "success",
        data: json.data || json,
      });
    } catch {
      res.status(500).json({
        status: "error",
        message: "Invalid JSON output",
        raw: output,
      });
    }
  });
}

/* ======================================================
XRAY CREATE
====================================================== */
function createXray(proto, req, res) {
  const { user, password, exp, quota, iplimit } = req.query;

  if (!user || !exp) {
    return res.status(400).json({
      status: "error",
      message: "user & exp required",
    });
  }

  const args = ["apicreate", proto, user];

  if (password) args.push(password);
  args.push(exp);

  if (quota) args.push(quota);
  if (iplimit) args.push(iplimit);

  runBinary(res, "bash", ["-c", args.join(" ")], {
    proto,
    user,
    quota,
    iplimit,
  });
}

/* ======================================================
ZIVPN CREATE
====================================================== */
function createZivpn(req, res) {
  const { password, exp, iplimit } = req.query;

  if (!password || !exp || !iplimit) {
    return res.status(400).json({
      status: "error",
      message: "password, exp, iplimit required",
    });
  }

  let cmd = `apicreate-zivpn ${password} ${exp} ${iplimit}`;

  runBinary(res, "bash", ["-c", cmd], {
    proto: "zivpn",
    user: password,
    quota: null,
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
app.get("/createshadowsocks", legacyAuth, (r, s) => createXray("shadowsocks", r, s));
app.get("/createzivpn", legacyAuth, createZivpn);

// TRIAL
app.get("/trialvmess", legacyAuth, (r, s) => trialXray("vmess", r, s));
app.get("/trialvless", legacyAuth, (r, s) => trialXray("vless", r, s));
app.get("/trialtrojan", legacyAuth, (r, s) => trialXray("trojan", r, s));
app.get("/trialshadowsocks", legacyAuth, (r, s) => trialXray("shadowsocks", r, s));
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