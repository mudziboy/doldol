
const { spawn, exec } = require("child_process");
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
        if (quotaInfo.proto !== "zivpn" && quotaInfo.proto !== "ssh") {
          if (quotaInfo.quota) {
            saveQuota(quotaInfo.proto, quotaInfo.user, quotaInfo.quota);
          }
        }

        if (quotaInfo.iplimit) {
          saveIPLimit(quotaInfo.proto, quotaInfo.user, quotaInfo.iplimit);
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
TRIAL
====================================================== */
function trialXray(proto, req, res) {
  const { duration } = req.query;
  let cmd = `apitrial-${proto}`;
  if (duration) cmd += ` ${duration}`;
  runBinary(res, "bash", ["-c", cmd]);
}

function trialSSH(req, res) {
  const { duration = 60 } = req.query;
  runBinary(res, "bash", ["-c", `apitrial-ssh ${duration}`]);
}

function trialZivpn(req, res) {
  const { duration = 60, iplimit = 1 } = req.query;
  runBinary(res, "bash", ["-c", `apitrial-zivpn ${duration} ${iplimit}`]);
}

/* ======================================================
SERVER HEALTH STATUS (CPU, RAM, UPTIME)
====================================================== */
app.get("/api/server/status", legacyAuth, (req, res) => {
  const script = `
    # CPU (lebih akurat & stabil)
    cpu=$(mpstat 1 1 | awk '/Average/ {print 100 - $NF}')
    
    # RAM
    ram=$(free -m | awk 'NR==2{printf "%.2f", $3*100/$2 }')
    
    # Uptime
    up=$(uptime -p)

    echo '{"cpu": "'"$cpu"'", "ram": "'"$ram"'", "uptime": "'"$up"'"}'
  `;

  exec(script, (err, stdout) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Gagal membaca resource VPS"
      });
    }

    try {
      const sysData = JSON.parse(stdout.trim());

      let cpu = parseFloat(sysData.cpu);
      let ram = parseFloat(sysData.ram);

      // 🔥 VALIDASI WAJIB
      if (isNaN(cpu) || cpu < 0 || cpu > 100) cpu = 0;
      if (isNaN(ram) || ram < 0 || ram > 100) ram = 0;

      res.json({
        success: true,
        status: "ON",
        cpu_usage: Number(cpu.toFixed(2)),
        ram_usage: Number(ram.toFixed(2)),
        uptime: sysData.uptime || "-"
      });

    } catch (e) {
      res.status(500).json({
        success: false,
        message: "Parsing error",
        raw: stdout
      });
    }
  });
});

/* ======================================================
ROUTES
====================================================== */
app.get("/createssh", legacyAuth, (r, s) => createXray("ssh", r, s));
app.get("/createvmess", legacyAuth, (r, s) => createXray("vmess", r, s));
app.get("/createvless", legacyAuth, (r, s) => createXray("vless", r, s));
app.get("/createtrojan", legacyAuth, (r, s) => createXray("trojan", r, s));
app.get("/createshadowsocks", legacyAuth, (r, s) => createXray("shadowsocks", r, s));
app.get("/createzivpn", legacyAuth, createZivpn);

app.get("/trialvmess", legacyAuth, (r, s) => trialXray("vmess", r, s));
app.get("/trialvless", legacyAuth, (r, s) => trialXray("vless", r, s));
app.get("/trialtrojan", legacyAuth, (r, s) => trialXray("trojan", r, s));
app.get("/trialshadowsocks", legacyAuth, (r, s) => trialXray("shadowsocks", r, s));
app.get("/trialssh", legacyAuth, trialSSH);
app.get("/trialzivpn", legacyAuth, trialZivpn);

app.post("/api/user/renew", (req, res) => {
  const auth = req.headers['x-api-key'];

  if (auth !== getAuthKey()) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized"
    });
  }

  const { password, days } = req.body;

  if (!password || !days) {
    return res.status(400).json({
      success: false,
      message: "password & days required"
    });
  }

  const cmd = `apirenew-zivpn ${password} ${days}`;

  runBinary(res, "bash", ["-c", cmd]);
});

app.post("/api/user/renew/xray", (req, res) => {
  const auth = req.headers['x-api-key'];

  if (auth !== getAuthKey()) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized"
    });
  }

  const { protocol, user, days, quota_gb, ip_limit } = req.body;

  if (!protocol || !user || !days) {
    return res.status(400).json({
      success: false,
      message: "protocol, user, days required"
    });
  }

  let cmd = `apirenew ${protocol} ${user} ${days}`;

  if (quota_gb) cmd += ` ${quota_gb}`;
  if (ip_limit) cmd += ` ${ip_limit}`;

  runBinary(res, "bash", ["-c", cmd], {
    proto: protocol,
    user,
    quota: quota_gb,
    iplimit: ip_limit
  });
});

app.post("/api/user/renew/ssh", (req, res) => {
  const auth = req.headers['x-api-key'];

  if (auth !== getAuthKey()) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized"
    });
  }

  const { user, days } = req.body;

  if (!user || !days) {
    return res.status(400).json({
      success: false,
      message: "user & days required"
    });
  }

  const cmd = `apirenew ssh ${user} ${days}`;

  runBinary(res, "bash", ["-c", cmd]);
});


/* ======================================================
DELETE USER
====================================================== */
app.get("/api/delete", legacyAuth, (req, res) => {
  const { user, protocol } = req.query;

  if (!user || !protocol) {
    return res.status(400).json({
      status: "error",
      message: "user & protocol required",
    });
  }

  let cmd = "";

  if (protocol === "zivpn") {
    cmd = `apidelete-zivpn ${user}`;
  } else {
    cmd = `apidelete ${user} ${protocol}`;
  }

  runBinary(res, "bash", ["-c", cmd]);
});

/* ======================================================
USAGE (FIX PORT)
====================================================== */
app.get("/api/user/usage", legacyAuth, (req, res) => {
  const { user, protocol } = req.query;

  const PORT_MAP = {
    vmess: 20001,
    vless: 20002,
    trojan: 20003,
    shadowsocks: 20004
  };

  const port = PORT_MAP[protocol] || 20001;

  const cmd = `xray api statsquery --server=127.0.0.1:${port} | grep "user>>>${user}>>>"`;

  const child = spawn("bash", ["-c", cmd]);

  let output = "";

  child.stdout.on("data", d => output += d.toString());

  child.on("close", () => {
    let uplink = 0, downlink = 0;

    output.split("\n").forEach(line => {
      if (line.includes("uplink")) uplink = parseInt(line.split(" ").pop()) || 0;
      if (line.includes("downlink")) downlink = parseInt(line.split(" ").pop()) || 0;
    });

    const gb = (uplink + downlink) / 1024 / 1024 / 1024;

    res.json({ success: true, usage: gb.toFixed(2) });
  });
});

/* ======================================================
AUTO SUSPEND
====================================================== */
function suspendUser(protocol, username) {
  try {
    const path = `/etc/xray/${protocol}/config.json`;
    if (!fs.existsSync(path)) return;

    let config = fs.readFileSync(path, "utf8");

    const regex = new RegExp(`\\{[^\\{\\}]*"email":\\s*"${username}"[^\\{\\}]*\\},?`, "g");

    config = config.replace(regex, "");

    fs.writeFileSync(path, config);

    setTimeout(() => {
      spawn("systemctl", ["restart", `${protocol}@config`]);
    }, 1000);

  } catch {}
}

/* ======================================================
QUOTA (AUTO SUSPEND)
====================================================== */
app.get("/api/user/quota", legacyAuth, (req, res) => {
  const { user, protocol } = req.query;

  if (protocol === "ssh" || protocol === "zivpn") {
    return res.json({ success: true, quota: "Unlimited" });
  }

  const PORT_MAP = {
    vmess: 20001,
    vless: 20002,
    trojan: 20003,
    shadowsocks: 20004
  };

  const port = PORT_MAP[protocol] || 20001;

  const cmd = `xray api statsquery --server=127.0.0.1:${port}`;

  const child = spawn("bash", ["-c", cmd]);

  let output = "";

  child.stdout.on("data", d => output += d.toString());

  child.on("close", () => {
    const json = JSON.parse(output);
    let up = 0, down = 0;

    (json.stat || []).forEach(s => {
      if (s.name.includes(`${user}>>>traffic>>>uplink`)) up = +s.value;
      if (s.name.includes(`${user}>>>traffic>>>downlink`)) down = +s.value;
    });

    const usage = (up + down) / 1024 / 1024 / 1024;

    const path = `/etc/xray/${protocol}/${user}`;
    const limit = fs.existsSync(path) ? +fs.readFileSync(path) : 0;

    if (!limit) return res.json({ success: true, quota: "Unlimited" });

    const limitGB = limit / 1024 / 1024 / 1024;
    const remain = limitGB - usage;

    if (remain <= 0) {
      suspendUser(protocol, user);

      return res.json({
        success: true,
        quota: "0",
        usage: usage.toFixed(2),
        limit: limitGB.toFixed(2),
        status: "suspended"
      });
    }

    res.json({
      success: true,
      quota: remain.toFixed(2),
      usage: usage.toFixed(2),
      limit: limitGB.toFixed(2)
    });
  });
});

/* ======================================================
RESET TRAFFIC
====================================================== */
app.get("/api/user/reset", legacyAuth, (req, res) => {
  spawn("bash", ["-c", "xray api statsquery --reset"]);
  res.json({ success: true });
});

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