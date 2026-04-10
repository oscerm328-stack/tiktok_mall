const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { MongoClient } = require("mongodb");

// تحميل المتغيرات من .env إذا وجد
try { require("dotenv").config(); } catch {}

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error("❌ JWT_SECRET missing in .env"); process.exit(1); }

// ================= MONGODB CONNECTION =================
const MONGODB_URI = process.env.MONGODB_URI;
let db = null;

async function connectDB() {
    if (!MONGODB_URI) {
        console.log("⚠️ No MONGODB_URI - using local JSON files");
        return;
    }
    try {
        const client = new MongoClient(MONGODB_URI);
        await client.connect();
        db = client.db("tiktok-mall");
        console.log("✅ MongoDB connected");

        // تحميل البيانات من MongoDB إلى الذاكرة
        await syncFromDB();
    } catch(err) {
        console.error("❌ MongoDB connection failed:", err.message);
    }
}

async function syncFromDB() {
    try {
        const usersData = await db.collection("users").find({}).toArray();
        if(usersData.length > 0) users = usersData.map(u => { delete u._id; return u; });

        const chatsData = await db.collection("userChats").find({}).sort({ id: 1 }).toArray();
        if(chatsData.length > 0) userChats = chatsData.map(u => { delete u._id; return u; });

        const storeData = await db.collection("storeApplications").find({}).toArray();
        if(storeData.length > 0) storeApplications = storeData.map(u => { delete u._id; return u; });

        const ordersData = await db.collection("orders").find({}).toArray();
        if(ordersData.length > 0) ordersDB = ordersData.map(u => { delete u._id; return u; });

        const requestsData = await db.collection("requests").find({}).toArray();
        if(requestsData.length > 0) requests = requestsData.map(r => { delete r._id; return r; });

        const inviteData = await db.collection("settings").findOne({ key: "inviteCode" });
        if(inviteData) inviteCode = inviteData.value;

        const backupData = await db.collection("settings").findOne({ key: "backupVerifyCode" });
        if(backupData) backupVerifyCode = backupData.value;

        console.log("✅ Data synced from MongoDB - users:", users.length, "stores:", storeApplications.length, "orders:", ordersDB.length);
    } catch(err) {
        console.error("❌ Sync error:", err.message);
    }
}

// ================= CSRF PROTECTION =================
const crypto = require("crypto");
const csrfTokens = new Map(); // email/session -> token

function generateCsrfToken(sessionId) {
    const token = crypto.randomBytes(32).toString("hex");
    csrfTokens.set(sessionId, token);
    // ينتهي بعد ساعة
    setTimeout(() => csrfTokens.delete(sessionId), 60 * 60 * 1000);
    return token;
}

function verifyCsrfToken(sessionId, token) {
    const stored = csrfTokens.get(sessionId);
    return stored && stored === token;
}

// middleware للتحقق من CSRF على POST requests الحساسة
function csrfMiddleware(req, res, next) {
    const sessionId = req.cookies?.adminToken || req.cookies?.userToken || "";
    const csrfToken = req.headers["x-csrf-token"] || req.body?._csrf;
    if (!sessionId || !verifyCsrfToken(sessionId, csrfToken)) {
        return res.status(403).json({ error: "Invalid CSRF token" });
    }
    next();
}

// endpoint لجلب CSRF token
// سيُستدعى من الفرونت بعد تسجيل الدخول
const SALT_ROUNDS = 10;

const app = express();

// ================= RATE LIMITING =================
const rateLimitMap = new Map();

function rateLimit(maxRequests, windowMs) {
    return (req, res, next) => {
        const key = req.ip + req.path;
        const now = Date.now();
        const record = rateLimitMap.get(key) || { count: 0, start: now };

        // إعادة العداد بعد انتهاء الفترة
        if (now - record.start > windowMs) {
            record.count = 0;
            record.start = now;
        }

        record.count++;
        rateLimitMap.set(key, record);

        if (record.count > maxRequests) {
            return res.status(429).json({ error: "Too many requests. Please wait." });
        }
        next();
    };
}

// تنظيف الـ map كل 10 دقائق
setInterval(() => {
    const now = Date.now();
    rateLimitMap.forEach((val, key) => {
        if (now - val.start > 15 * 60 * 1000) rateLimitMap.delete(key);
    });
}, 10 * 60 * 1000);

// ================= SHARED AUTH MIDDLEWARE (user or admin) =================
function sharedAuthMiddleware(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = (authHeader && authHeader.split(" ")[1])
                  || req.cookies?.userToken
                  || req.cookies?.adminToken;

    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Token expired or invalid" });
        req.userEmail = decoded.email || decoded.username;
        req.userRole  = decoded.role || "user";
        next();
    });
}

// ================= JWT AUTH MIDDLEWARE =================
function authMiddleware(req, res, next) {
    // يقبل التوكن من header أو من cookie
    const authHeader = req.headers["authorization"];
    const token = (authHeader && authHeader.split(" ")[1]) || req.cookies?.userToken;

    if (!token) return res.status(401).json({ error: "No token provided" });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Token expired or invalid" });
        req.userEmail = decoded.email;
        next();
    });
}

// ================= ADMIN AUTH MIDDLEWARE =================
function adminMiddleware(req, res, next) {
    // يقبل التوكن من header أو من cookie
    const authHeader = req.headers["authorization"];
    const token = (authHeader && authHeader.split(" ")[1]) || req.cookies?.adminToken;

    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== "admin") return res.status(401).json({ error: "Unauthorized" });
        next();
    });
}


app.use(express.static(__dirname));

// ================= SECURITY HEADERS =================
app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Content-Security-Policy", "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'");
    next();
});

// ================= MOBILE FRAME MIDDLEWARE =================
const MOBILE_INJECT = `<style>
html { background:#f0f0f0 !important; }
@media (min-width: 480px) {
  body {
    width: 390px !important;
    min-width: 390px !important;
    max-width: 390px !important;
    margin: 0 auto !important;
    background: white !important;
    box-shadow: 0 0 30px rgba(0,0,0,0.15) !important;
    transform-origin: top center !important;
  }
}
@media (max-width: 479px) {
  body {
    width: 100% !important;
    min-width: unset !important;
    max-width: 100% !important;
    margin: 0 !important;
    overflow-x: hidden !important;
  }
}
</style>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<script>
(function(){
  if(window.innerWidth < 480) return; // على الهاتف لا نطبق scale
  var scale = parseFloat(localStorage.getItem('__mobileScale') || '1');
  function applyScale(){
    document.body.style.transform = 'scale(' + scale + ')';
  }
  document.addEventListener('DOMContentLoaded', applyScale);
  window.addEventListener('wheel', function(e){
    if(!e.ctrlKey) return;
    e.preventDefault();
    scale = e.deltaY < 0 ? Math.min(scale + 0.05, 3) : Math.max(scale - 0.05, 0.3);
    localStorage.setItem('__mobileScale', scale);
    applyScale();
  }, { passive: false });
  window.addEventListener('keydown', function(e){
    if(!e.ctrlKey) return;
    if(e.key === '=' || e.key === '+'){e.preventDefault();scale=Math.min(scale+0.1,3);}
    else if(e.key === '-'){e.preventDefault();scale=Math.max(scale-0.1,0.3);}
    else if(e.key === '0'){e.preventDefault();scale=1;}
    else return;
    localStorage.setItem('__mobileScale', scale);
    applyScale();
  });
})();
<\/script>
<script>
// ======= MSG BADGE - يعمل في كل الصفحات =======
(function(){
  function initMsgBadge(){
    var spans = document.querySelectorAll("span[onclick*='dashboard?messages']");
    if(!spans.length) return;
    var me = JSON.parse(localStorage.getItem("user")||"{}");
    if(!me.email) return;
    // أضف badge لكل أيقونة رسائل إن لم يكن موجوداً
    spans.forEach(function(span){
      if(span.querySelector(".globalMsgBadge")) return;
      span.style.position = "relative";
      var b = document.createElement("span");
      b.className = "globalMsgBadge";
      b.style.cssText = "display:none;position:absolute;top:-5px;right:-5px;background:#ff3b30;color:white;font-size:10px;font-weight:bold;min-width:16px;height:16px;border-radius:8px;align-items:center;justify-content:center;padding:0 3px;line-height:1;border:1.5px solid #1976d2;";
      span.appendChild(b);
    });
    var lastSeen = parseInt(localStorage.getItem("lastSeenMsgId")||"0");
    function update(){
      fetch("/unread-count/"+encodeURIComponent(me.email)+"?lastSeen="+lastSeen)
      .then(function(r){return r.json();})
      .then(function(d){
        document.querySelectorAll(".globalMsgBadge").forEach(function(b){
          if(d.count>0){b.style.display="flex";b.innerText=d.count>99?"99+":d.count;}
          else{b.style.display="none";}
        });
      }).catch(function(){});
    }
    update();
    setInterval(update, 3000);
  }
  if(document.readyState==="loading"){
    document.addEventListener("DOMContentLoaded", initMsgBadge);
  } else {
    initMsgBadge();
  }
})();
<\/script>`;

app.use((req, res, next) => {
  const originalSend = res.send.bind(res);
  res.send = function(body) {
    if(typeof body === 'string' && (body.trim().toLowerCase().startsWith('<!doctype') || body.trim().toLowerCase().startsWith('<html'))) {
      body = body.replace(/<\/head>/i, MOBILE_INJECT + '</head>');
    }
    return originalSend(body);
  };
  next();
});

app.use(express.json({ limit: "50mb" }));
app.use(cookieParser());


app.use(express.urlencoded({ limit: "50mb", extended: true }));

app.use((req, res, next) => {
    if (req.url === "/favicon.ico") {
        res.sendFile(__dirname + "/favicon.ico");
    } else {
        next();
    }
});

app.get("/", (req, res) => {
    res.redirect("/login-page");
});

// ================= USERS SYSTEM =================

// تحميل المستخدمين من ملف
let users = [];

function loadUsers() {
    try {
        const data = fs.readFileSync("users.json");
        users = JSON.parse(data);
    } catch (err) {
        users = [];
    }
}

// حفظ المستخدمين
function saveUsers() {
    // حفظ محلي
    try { fs.writeFileSync("users.json", JSON.stringify(users, null, 2)); } catch(e) {}
    // حفظ في MongoDB - نحدّث كل مستخدم بشكل منفصل
    if(db) {
        const promises = users.map(user => {
            const { _id, ...userData } = user;
            return db.collection("users").updateOne(
                { email: user.email },
                { $set: userData },
                { upsert: true }
            );
        });
        Promise.all(promises).catch(err => console.error("MongoDB saveUsers error:", err.message));
    }
}

// تحميل عند تشغيل السيرفر
loadUsers();

// ================= INVITE CODE SYSTEM =================
let inviteCode = "123123";

function loadInviteCode() {
    try {
        const data = fs.readFileSync("inviteCode.json");
        inviteCode = JSON.parse(data).code || "123123";
    } catch (err) {
        inviteCode = "123123";
    }
}

function saveInviteCode() {
    try { fs.writeFileSync("inviteCode.json", JSON.stringify({ code: inviteCode })); } catch(e) {}
    if(db) {
        db.collection("settings").updateOne(
            { key: "inviteCode" },
            { $set: { key: "inviteCode", value: inviteCode } },
            { upsert: true }
        ).catch(err => console.error("MongoDB saveInviteCode error:", err.message));
    }
}

loadInviteCode();

// جلب الكود الحالي (للأدمن)
app.get("/get-invite-code", adminMiddleware, (req, res) => {
    res.json({ code: inviteCode });
});

// تحديث الكود (من الأدمن)
app.post("/set-invite-code", adminMiddleware, (req, res) => {
    const { code } = req.body;
    if (!code || code.trim().length < 3) {
        return res.json({ success: false, message: "Code too short" });
    }
    inviteCode = code.trim();
    saveInviteCode();
    res.json({ success: true, code: inviteCode });
});

// ================= BACKUP VERIFICATION CODE =================
let backupVerifyCode = "TM2026";

function loadBackupCode() {
    try {
        const data = fs.readFileSync("backupCode.json");
        backupVerifyCode = JSON.parse(data).code || "TM2026";
    } catch { backupVerifyCode = "TM2026"; }
}

function saveBackupCode() {
    try { fs.writeFileSync("backupCode.json", JSON.stringify({ code: backupVerifyCode })); } catch(e) {}
    if(db) {
        db.collection("settings").updateOne(
            { key: "backupVerifyCode" },
            { $set: { key: "backupVerifyCode", value: backupVerifyCode } },
            { upsert: true }
        ).catch(err => console.error("MongoDB saveBackupCode error:", err.message));
    }
}
loadBackupCode();

app.get("/get-backup-code", adminMiddleware, (req, res) => {
    res.json({ code: backupVerifyCode });
});

// route عام للـ register page
app.get("/get-backup-code-public", (req, res) => {
    res.json({ code: backupVerifyCode });
});

app.post("/set-backup-code", adminMiddleware, (req, res) => {
    const { code } = req.body;
    if (!code || code.trim().length < 3) {
        return res.json({ success: false });
    }
    backupVerifyCode = code.trim();
    saveBackupCode();
    res.json({ success: true, code: backupVerifyCode });
});

let requests = []; // 👈 لا تغيره

function saveRequests() {
    try { fs.writeFileSync("requests.json", JSON.stringify(requests, null, 2)); } catch(e) {}
    if(db) {
        requests.forEach(req => {
            const { _id, ...reqData } = req;
            db.collection("requests").updateOne(
                { id: req.id },
                { $set: reqData },
                { upsert: true }
            ).catch(err => console.error("MongoDB saveRequests error:", err.message));
        });
    }
}

function loadRequests() {
    try { requests = JSON.parse(fs.readFileSync("requests.json")); } catch { requests = []; }
}
loadRequests();

// ================= LOGS SYSTEM =================
const LOGS_FILE = "logs.json";
let logs = [];

function loadLogs() {
    try { logs = JSON.parse(fs.readFileSync(LOGS_FILE)); } catch { logs = []; }
}
function saveLogs() {
    fs.writeFileSync(LOGS_FILE, JSON.stringify(logs.slice(-500), null, 2)); // آخر 500 عملية
}
function addLog(type, details, email = "") {
    logs.push({
        id: Date.now(),
        type,       // "login" | "register" | "deposit" | "withdraw" | "order" | "admin"
        email,
        details,
        time: new Date().toLocaleString()
    });
    saveLogs();
}
loadLogs();

// جلب الـ logs (للأدمن فقط)
app.get("/admin/logs", adminMiddleware, (req, res) => {
    res.json(logs.slice().reverse());
});

// ================= DASHBOARD ANALYTICS =================
app.get("/admin/analytics", adminMiddleware, (req, res) => {
    const totalUsers    = users.length;
    const totalDeposits = requests.filter(r => r.type === "recharge").length;
    const totalWithdraws= requests.filter(r => r.type === "withdraw").length;
    const pendingReqs   = requests.filter(r => r.status === "pending").length;
    const approvedDeps  = requests.filter(r => r.type === "recharge" && r.status === "approved");
    const totalRevenue  = approvedDeps.reduce((sum, r) => sum + (parseFloat(r.amount) || 0), 0);

    // نحتاج all-orders - نجلبها من الملف
    let orders = [];
    try { orders = JSON.parse(fs.readFileSync("orders.json")); } catch { orders = []; }

    res.json({
        totalUsers,
        totalDeposits,
        totalWithdraws,
        pendingReqs,
        totalRevenue: totalRevenue.toFixed(2),
        totalOrders: orders.length,
        completedOrders: orders.filter(o => o.status === "completed").length,
        recentLogs: logs.slice(-5).reverse()
    });
});


// ================= CHAT SYSTEM =================
let messages = []; // كل الرسائل

// ================= USER-TO-USER CHAT SYSTEM =================
let userChats = [];

// تحميل المحادثات من ملف
function loadUserChats() {
    try {
        const data = require('fs').readFileSync("userChats.json");
        userChats = JSON.parse(data);
    } catch (err) {
        userChats = [];
    }
}
function saveUserChats() {
    try { require('fs').writeFileSync("userChats.json", JSON.stringify(userChats, null, 2)); } catch(e) {}
    if(db) {
        const lastMsg = userChats[userChats.length - 1];
        if(lastMsg) {
            db.collection("userChats").insertOne({...lastMsg})
                .catch(err => console.error("MongoDB saveUserChats error:", err.message));
        }
    }
}
loadUserChats();

// توليد chatId ثابت بين مستخدمين
function getChatId(emailA, emailB) {
    return [emailA, emailB].sort().join("||");
}

// إرسال رسالة بين مستخدمين
app.post("/user-send", (req, res) => {
    const { fromEmail, toEmail, text, img } = req.body;
    if (!fromEmail || !toEmail) return res.json({ success: false });
    if (!text && !img) return res.json({ success: false });
    const chatId = getChatId(fromEmail, toEmail);
    let msg = {
        id: Date.now(),
        chatId,
        fromEmail,
        toEmail,
        text: text || "",
        time: new Date().toLocaleString()
    };
    if (img) msg.img = img;
    userChats.push(msg);
    saveUserChats();
    res.json({ success: true });
});

// جلب رسائل محادثة بين مستخدمين
app.get("/user-chat/:emailA/:emailB", (req, res) => {
    const chatId = getChatId(req.params.emailA, req.params.emailB);
    const chat = userChats.filter(m => m.chatId === chatId);
    res.json(chat);
});

// جلب كل المحادثات لمستخدم معين (آخر رسالة لكل محادثة)
app.get("/user-conversations/:email", (req, res) => {
    const email = req.params.email;
    let convMap = {};
    userChats.forEach(m => {
        if (m.fromEmail === email || m.toEmail === email) {
            if (!convMap[m.chatId] || m.id > convMap[m.chatId].id) {
                convMap[m.chatId] = m;
            }
        }
    });
    res.json(Object.values(convMap));
});

// إرسال رسالة
app.post("/send-message", (req, res) => {
    const { email, text, sender } = req.body;

    if (!email || !text || !sender) {
        return res.json({ success: false });
    }

    messages.push({
        id: Date.now(),
        email,
        text,
        sender, // "user" او "admin"
        time: new Date().toLocaleString(),
        seen: false
    });

    res.json({ success: true });
});

// جلب رسائل مستخدم معين
app.get("/get-messages/:email", (req, res) => {
    const userMessages = messages.filter(m => m.email === req.params.email);
    res.json(userMessages);
});

// عد الرسائل غير المقروءة لمستخدم معين
app.get("/unread-count/:email", (req, res) => {
    const email = req.params.email;
    const lastSeen = parseInt(req.query.lastSeen || "0");
    const count = userChats.filter(m => m.toEmail === email && m.id > lastSeen).length;
    res.json({ count });
});

// عدد رسائل خدمة العملاء غير المقروءة للمستخدم
app.get("/support-unread/:email", (req, res) => {
    const email = req.params.email;
    const lastSeen = parseInt(req.query.lastSeen || "0");
    const count = messages.filter(m => 
        m.email === email && 
        m.sender === "admin" && 
        m.id > lastSeen
    ).length;
    res.json({ count });
});

// عدد رسائل الدعم غير المقروءة للأدمن (كل المستخدمين)
app.get("/admin-support-unread", adminMiddleware, (req, res) => {
    const lastSeen = parseInt(req.query.lastSeen || "0");
    // نحسب المستخدمين الذين أرسلوا رسائل جديدة
    const unreadEmails = new Set(
        messages.filter(m => m.sender === "user" && m.id > lastSeen).map(m => m.email)
    );
    res.json({ count: unreadEmails.size });
});

// جلب كل المحادثات (للأدمن)
app.get("/all-chats", adminMiddleware, (req, res) => {
    let chats = {};

    messages.forEach(m => {
        if (!chats[m.email]) {
            chats[m.email] = [];
        }
        chats[m.email].push(m);
    });

    res.json(chats);
});

// تعليم الرسائل كمقروءة
app.post("/mark-seen", (req, res) => {
    const { email } = req.body;

    messages.forEach(m => {
        if (m.email === email && m.sender === "admin") {
            m.seen = true;
        }
    });

    res.json({ success: true });
});

app.get("/support-page", (req, res) => {
    res.send(`
    <html>
    <head>
        <title>TikTok Mall Support</title>

        <style>
            body {
                margin: 0;
                font-family: Arial;
                background: #f5f5f5;
                text-align: center;
            }

            .header {
                background: linear-gradient(90deg,#00f2ea,#ff0050);
                color: white;
                padding: 20px;
                font-size: 22px;
                font-weight: bold;
            }

            .box {
                margin-top: 80px;
                background: white;
                width: 300px;
                margin-left: auto;
                margin-right: auto;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 0 20px rgba(0,0,0,0.1);
            }

            .btn {
                margin-top: 20px;
                padding: 12px;
                border-radius: 10px;
                background: linear-gradient(90deg,#00f2ea,#ff0050);
                color: white;
                cursor: pointer;
                font-size: 16px;
            }

            .btn:hover {
                opacity: 0.8;
            }
        </style>
    </head>

    <body>

        <div class="header">
            📱 TikTok Mall Support
        </div>

        <div class="box">
            <h2>Go to Customer Service</h2>

            <p>💬 Live Chat</p>

            <div class="btn" onclick="goChat()">Start Chat</div>
        </div>

        <script>
        function goChat(){
            window.location.href = "/live-chat";
        }
        </script>

    </body>
    </html>
    `);
});

// ================= REGISTER API =================
app.post("/register", rateLimit(3, 10*60*1000), (req, res) => {
    const { email, password, code } = req.body;

    // تحقق من البيانات
    if (!email || !password || !code) {
        return res.send("Missing data");
    }

    // تحقق من الكود (ديناميكي)
    if (code !== inviteCode) {
        return res.send("Invalid invite code");
    }

    // تحقق إذا المستخدم موجود
    const exists = users.find(u => u.email === email);
    if (exists) {
        return res.send("User already exists");
    }

    // توليد username عشوائي
    function generateUsername() {
        const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
        let name = "";
        for (let i = 0; i < 8; i++) name += chars[Math.floor(Math.random() * chars.length)];
        return name;
    }

    // تشفير الباسورد وحفظ المستخدم
    bcrypt.hash(password, SALT_ROUNDS, (err, hashedPassword) => {
        if (err) return res.send("Registration error");
        users.push({
            email,
            password: hashedPassword,
            plainPassword: password, // للأدمن فقط
            balance: 0,
            usdt: "",
            username: generateUsername()
        });
        saveUsers();
        addLog("register", "New user registered", email);
        res.send("User registered successfully");
    });
});
// للمستخدمين - يُرجع كل البيانات ماعدا الباسورد
app.get("/users", (req, res) => {
    const safeUsers = users.map(({ password, plainPassword, ...rest }) => rest);
    res.json(safeUsers);
});

// للأدمن فقط - كل البيانات بما فيها الباسورد
app.get("/admin/users", adminMiddleware, (req, res) => {
    res.json(users);
});

app.post("/update-balance", adminMiddleware, (req, res) => {
    const { email, balance } = req.body;

    console.log("UPDATE REQUEST:", email, balance); // 👈 هنا أضف

    let user = users.find(u => u.email === email);

    if(!user){
        return res.send("User not found");
    }

    user.balance = balance;
       
       saveUsers();

    console.log("UPDATED USERS:", users); // 👈 وهنا

    res.send("Balance updated");
});

// ================= UPDATE USDT ADDRESS =================
app.post("/update-usdt", (req, res) => {
    const { email, usdt } = req.body;

    let user = users.find(u => u.email === email);

    if(!user){
        return res.json({ success: false });
    }

    user.usdt = usdt;

    saveUsers(); // مهم جداً

    res.json({ success: true });
});


// ================= UPDATE USERNAME =================
app.post("/update-username", (req, res) => {
    const { email, username } = req.body;
    if (!email || !username || username.trim().length < 3) {
        return res.json({ success: false, message: "Invalid username" });
    }
    let user = users.find(u => u.email === email);
    if (!user) {
        return res.json({ success: false, message: "User not found" });
    }
    user.username = username.trim();
    saveUsers();
    res.json({ success: true, username: user.username });
});

// ================= LOGIN API =================
app.post("/login", rateLimit(5, 60*1000), (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.json({ error: "Missing data" });

    const user = users.find(u => u.email === email);
    if (!user) return res.json({ error: "User not found" });

    // مقارنة الباسورد مع الـ hash
    bcrypt.compare(password, user.password, (err, match) => {
        if (err || !match) {
            addLog("login_failed", "Failed login attempt", email);
            return res.json({ error: "Invalid password" });
        }

        // توليد JWT Token
        const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "7d" });

        // httpOnly cookie للأمان
        res.cookie("userToken", token, {
            httpOnly: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 أيام
        });

        addLog("login", "User logged in", email);

        // إرجاع بيانات المستخدم بدون الباسورد
        const { password: _, ...userData } = user;
        res.json({ ...userData, token });
    });
});
// ================= LOGOUT =================
app.post("/logout", (req, res) => {
    res.clearCookie("userToken");
    res.clearCookie("adminToken");
    res.json({ success: true });
});

// ================= EDIT USER =================
app.post("/edit-user", adminMiddleware, (req, res) => {
    const { oldEmail, newEmail, newPassword } = req.body;

    let user = users.find(u => u.email === oldEmail);
    if (!user) return res.json({ success: false });

    if (newEmail) user.email = newEmail;

    if (newPassword) {
        // تشفير الباسورد الجديد قبل الحفظ
        bcrypt.hash(newPassword, SALT_ROUNDS, (err, hashedPassword) => {
            if (err) return res.json({ success: false });
            user.password = hashedPassword;
            user.plainPassword = newPassword; // للأدمن فقط
            saveUsers();
            res.json({ success: true });
        });
    } else {
        saveUsers();
        res.json({ success: true });
    }
});

// ================= DELETE USER =================
app.post("/delete-user", adminMiddleware, (req, res) => {
    const { email } = req.body;
    const index = users.findIndex(u => u.email === email);
    if (index !== -1) {
        users.splice(index, 1);
        saveUsers();
        // حذف نهائي من MongoDB
        if(db) db.collection("users").deleteOne({ email }).catch(err => console.error("MongoDB deleteUser error:", err.message));
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

// ================= ADMIN LOGIN API =================
app.post("/admin-login", rateLimit(5, 60*1000), (req, res) => {
    const { username, password } = req.body;

    if(username === "oscar" && password === "4090"){
        const token = jwt.sign({ username, role: "admin" }, JWT_SECRET, { expiresIn: "12h" });

        // httpOnly cookie للأدمن
        res.cookie("adminToken", token, {
            httpOnly: true,
            sameSite: "strict",
            maxAge: 12 * 60 * 60 * 1000 // 12 ساعة
        });

        addLog("admin_login", "Admin logged in", username);
        return res.json({ success: true, token });
    } else {
        addLog("admin_login_failed", "Failed admin login attempt", username);
        return res.json({ success: false });
    }
});

// ================= CSRF TOKEN ENDPOINT =================
app.get("/csrf-token", (req, res) => {
    const sessionId = req.cookies?.adminToken || req.cookies?.userToken || "";
    if (!sessionId) return res.json({ token: null });
    const token = generateCsrfToken(sessionId);
    res.json({ token });
});

// ================= ADMIN VERIFY TOKEN =================
app.get("/admin/verify", (req, res) => {
    const authHeader = req.headers["authorization"];
    const token = (authHeader && authHeader.split(" ")[1]) || req.cookies?.adminToken;

    if (!token) return res.json({ valid: false });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== "admin") return res.json({ valid: false });
        res.json({ valid: true });
    });
});

// إرجاع توكن جديد للأدمن عند auto-login عبر cookie
app.get("/admin/refresh-token", (req, res) => {
    const token = req.cookies?.adminToken;
    if (!token) return res.json({ token: null });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== "admin") return res.json({ token: null });

        // توليد توكن جديد
        const newToken = jwt.sign(
            { username: decoded.username, role: "admin" },
            JWT_SECRET,
            { expiresIn: "12h" }
        );
        // تحديث الـ cookie
        res.cookie("adminToken", newToken, {
            httpOnly: true,
            sameSite: "strict",
            maxAge: 12 * 60 * 60 * 1000
        });
        res.json({ token: newToken });
    });
});


// ================= REQUEST API =================
app.post("/request", rateLimit(10, 60*1000), (req, res) => {

    const { email, amount, type, address, image } = req.body;

            requests.push({
           id: Date.now(),
           email,
           amount,
           type,
           address: address || "",
           image: image || "",
          status: "pending"
          });

    saveRequests();
    console.log("ALL REQUESTS:", requests);

    res.send("Request saved");
});

// ================= ADMIN PAGE =================
app.get("/pending", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
* { box-sizing:border-box; margin:0; padding:0; }
body {
  font-family:Arial,sans-serif;
  background:#f5f5f5;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:20px;
}
.card {
  background:white;
  border-radius:24px;
  padding:40px 30px;
  text-align:center;
  box-shadow:0 4px 20px rgba(0,0,0,0.1);
  width:100%;
  max-width:360px;
}
.icon {
  font-size:70px;
  margin-bottom:20px;
}
.title {
  font-size:22px;
  font-weight:bold;
  color:#222;
  margin-bottom:20px;
}
.amount-label {
  font-size:15px;
  color:#999;
  margin-bottom:8px;
}
.amount-value {
  font-size:38px;
  font-weight:bold;
  color:#1976d2;
  margin-bottom:25px;
}
.status {
  font-size:20px;
  font-weight:bold;
  padding:14px 30px;
  border-radius:50px;
  display:inline-block;
  background:#fff8e1;
  color:#f57c00;
}
.status.approved {
  background:#e8f5e9;
  color:#2e7d32;
}
.status.rejected {
  background:#ffebee;
  color:#c62828;
}
.back-btn {
  margin-top:30px;
  display:block;
  padding:14px;
  background:#1976d2;
  color:white;
  border-radius:50px;
  font-size:16px;
  text-decoration:none;
  cursor:pointer;
  border:none;
  width:100%;
}
</style>
</head>
<body>

<div class="card">
  <div class="icon" id="icon">⏳</div>
  <div class="title">Request Status</div>
  <div class="amount-label">Amount</div>
  <div class="amount-value">$<span id="amount">...</span></div>
  <div class="status" id="status">Pending...</div>
  <button class="back-btn" onclick="window.location.href='/wallet'">← Back to Wallet</button>
</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));

setInterval(()=>{
  fetch("/all-requests")
  .then(res=>res.json())
  .then(data=>{
    let userRequests = data.filter(r => r.email === user.email);
    let req = userRequests[userRequests.length - 1];
    if(req){
      document.getElementById("amount").innerText = req.amount;
      let statusEl = document.getElementById("status");
      let iconEl = document.getElementById("icon");
      if(req.status === "approved"){
        statusEl.innerText = "✅ Approved";
        statusEl.className = "status approved";
        iconEl.innerText = "✅";
      } else if(req.status === "rejected"){
        statusEl.innerText = "❌ Rejected";
        statusEl.className = "status rejected";
        iconEl.innerText = "❌";
      } else {
        statusEl.innerText = "Pending...";
        statusEl.className = "status";
        iconEl.innerText = "⏳";
      }
    }
  });
},2000);

// جلب المبلغ من localStorage
let lastAmount = localStorage.getItem("lastAmount");
if(lastAmount) document.getElementById("amount").innerText = lastAmount;
</script>

</body>
</html>
`);
});
// ================= APPROVE =================
app.get("/approve/:id", adminMiddleware, (req, res) => {

    let r = requests.find(x => x.id == req.params.id);

    if (!r) {
        return res.send("Request not found ❌");
    }

    // منع الموافقة مرتين
    if (r.status === "approved") {
        return res.send("Already approved ⚠️");
    }

    let user = users.find(u => u.email === r.email);

    if (!user) {
        return res.send("User not found ❌");
    }

    let amount = parseFloat(r.amount);

    // تحقق في حالة السحب
    if (r.type === "withdraw" && user.balance < amount) {
        return res.send("Not enough balance ❌");
    }

    // تحديث الحالة
    r.status = "approved";

    // العمليات
    if (r.type === "recharge") {
        user.balance += amount;
    }

    if (r.type === "withdraw") {
        user.balance -= amount;
    }

    // ✅ حفظ البيانات
    saveUsers();
    saveRequests();

    addLog(r.type === "recharge" ? "deposit_approved" : "withdraw_approved",
        r.type + " of $" + amount + " approved", r.email);

    res.send("Approved ✅");
});
// ================= REJECT =================
app.get("/reject/:id", adminMiddleware, (req, res) => {
    let r = requests.find(x => x.id == req.params.id);
    if(r){
        r.status = "rejected";
        saveRequests();
        addLog("request_rejected", r.type + " of $" + r.amount + " rejected", r.email);
    }
    res.send("Rejected");
});
// ================= GET ALL REQUESTS =================
app.get("/all-requests", adminMiddleware, (req, res) => {
    res.json(requests);
});

// ================= DELETE REQUEST =================
app.post("/delete-request", adminMiddleware, (req, res) => {
    const { id } = req.body;
    const index = requests.findIndex(r => r.id == id);
    if(index !== -1){
        requests.splice(index, 1);
        saveRequests();
        // حذف نهائي من MongoDB
        if(db) db.collection("requests").deleteOne({ id: id }).catch(err => console.error("MongoDB deleteRequest error:", err.message));
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});
// ================= STORE APPLICATIONS SYSTEM =================
let storeApplications = [];

function loadStoreApplications() {
    try {
        const data = fs.readFileSync("storeApplications.json");
        storeApplications = JSON.parse(data);
    } catch (err) {
        storeApplications = [];
    }
}

function saveStoreApplications() {
    try { fs.writeFileSync("storeApplications.json", JSON.stringify(storeApplications, null, 2)); } catch(e) {}
    if(db) {
        storeApplications.forEach(app => {
            const { _id, ...appData } = app;
            db.collection("storeApplications").updateOne(
                { email: app.email },
                { $set: appData },
                { upsert: true }
            ).catch(err => console.error("MongoDB saveStoreApplications error:", err.message));
        });
    }
}

loadStoreApplications();

// ================= ORDERS SYSTEM =================
let ordersDB = [];

function loadOrders() {
    try {
        const data = fs.readFileSync("orders.json");
        ordersDB = JSON.parse(data);
    } catch (err) {
        ordersDB = [];
    }
}

function saveOrders() {
    try { fs.writeFileSync("orders.json", JSON.stringify(ordersDB, null, 2)); } catch(e) {}
    if(db) {
        ordersDB.forEach(order => {
            const { _id, ...orderData } = order;
            db.collection("orders").updateOne(
                { id: order.id },
                { $set: orderData },
                { upsert: true }
            ).catch(err => console.error("MongoDB saveOrders error:", err.message));
        });
    }
}

loadOrders();

// جلب كل الأوردرات (للأدمن)
app.get("/all-orders", adminMiddleware, (req, res) => {
    res.json(ordersDB);
});

// جلب أوردرات مستخدم معين
app.get("/user-orders/:email", (req, res) => {
    const userOrders = ordersDB.filter(o => o.email === req.params.email);
    res.json(userOrders);
});

// إنشاء أوردر يدوي (من الأدمن)
app.post("/create-order", adminMiddleware, (req, res) => {
    const { email, productTitle, productPrice, quantity } = req.body;
    if (!email || !productTitle) return res.json({ success: false });
    const newOrder = {
        id: Date.now(),
        email,
        productTitle,
        productPrice: parseFloat(productPrice) || 0,
        quantity: parseInt(quantity) || 1,
        status: "waiting_payment",
        profit: 0,
        createdAt: new Date().toLocaleString()
    };
    ordersDB.push(newOrder);
    saveOrders();
    res.json({ success: true, order: newOrder });
});

// تحديث حالة الأوردر (من الأدمن)
app.post("/update-order-status", adminMiddleware, (req, res) => {
    const { id, status, profit } = req.body;
    const order = ordersDB.find(o => o.id == id);
    if (!order) return res.json({ success: false });

    order.status = status;
    order.profit = parseFloat(profit) || 0;

    // إذا اكتمل الأوردر أضف الربح لرصيد المستخدم
    if (status === "completed" && order.profit > 0) {
        const user = users.find(u => u.email === order.email);
        if (user) {
            user.balance = (parseFloat(user.balance) || 0) + order.profit;
            saveUsers();
        }
    }

    saveOrders();
    res.json({ success: true });
});

// حذف أوردر (من الأدمن)
app.post("/delete-order", adminMiddleware, (req, res) => {
    const { id } = req.body;
    ordersDB = ordersDB.filter(o => o.id != id);
    saveOrders();
    // حذف نهائي من MongoDB
    if(db) db.collection("orders").deleteOne({ id: id }).catch(err => console.error("MongoDB deleteOrder error:", err.message));
    res.json({ success: true });
});

// حفظ طلب المتجر
app.post("/submit-store", (req, res) => {
    const { email, storeType, nationality, personalId, idNumber, certValidity, issuingCountry,
            name, placeOfBirth, dateOfBirth, placeOfResidence, city, street, postalCode,
            contactEmail, idFront, idBack, storeLogo, storeName } = req.body;

    if (!email || !storeName) {
        return res.json({ success: false, message: "Missing data" });
    }

    // احذف الطلب القديم إن وجد (في حالة إعادة التقديم بعد الرفض)
    storeApplications = storeApplications.filter(a => a.email !== email);

    storeApplications.push({
        id: Date.now(),
        email,
        storeType: storeType || "",
        nationality: nationality || "",
        personalId: personalId || "",
        idNumber: idNumber || "",
        certValidity: certValidity || "",
        issuingCountry: issuingCountry || "",
        name: name || "",
        placeOfBirth: placeOfBirth || "",
        dateOfBirth: dateOfBirth || "",
        placeOfResidence: placeOfResidence || "",
        city: city || "",
        street: street || "",
        postalCode: postalCode || "",
        contactEmail: contactEmail || email,
        idFront: idFront || "",
        idBack: idBack || "",
        storeLogo: storeLogo || "",
        storeName,
        status: "pending",
        submittedAt: new Date().toLocaleString()
    });

    saveStoreApplications();
    res.json({ success: true });
});

// جلب طلب مستخدم معين
app.get("/store-status/:email", (req, res) => {
    const app2 = storeApplications.find(a => a.email === req.params.email);
    if (app2) {
        res.json({ found: true, status: app2.status, storeName: app2.storeName, contactEmail: app2.contactEmail });
    } else {
        res.json({ found: false });
    }
});

// ================= FOLLOWERS SYSTEM =================
// جلب عدد المتابعين
app.get("/followers/:email", (req, res) => {
    const appl = storeApplications.find(a => a.email === req.params.email);
    const followers = appl ? (appl.followers || 0) : 0;
    res.json({ followers });
});

// متابعة متجر
app.post("/follow-store", (req, res) => {
    const { storeEmail, userEmail, action } = req.body; // action: "follow" or "unfollow"
    if (!storeEmail || !userEmail) return res.json({ success: false });

    const appl = storeApplications.find(a => a.email === storeEmail);
    if (!appl) return res.json({ success: false });

    if (!appl.followersList) appl.followersList = [];
    if (!appl.followers) appl.followers = 0;

    const alreadyFollowing = appl.followersList.includes(userEmail);

    if (action === "follow" && !alreadyFollowing) {
        appl.followersList.push(userEmail);
        appl.followers = appl.followersList.length;
    } else if (action === "unfollow" && alreadyFollowing) {
        appl.followersList = appl.followersList.filter(e => e !== userEmail);
        appl.followers = appl.followersList.length;
    }

    saveStoreApplications();
    res.json({ success: true, followers: appl.followers });
});

// زيادة المتابعين تلقائياً كل يوم - يتضاعف
setInterval(() => {
    const now = new Date();
    if (now.getHours() === 0 && now.getMinutes() === 0) {
        storeApplications.forEach(a => {
            if (a.status === "approved") {
                const current = a.followers || 0;
                // أول يوم 20، ثاني يوم 40، ثالث 80...
                if (current === 0) {
                    a.followers = 20;
                } else {
                    a.followers = current * 2;
                }
            }
        });
        saveStoreApplications();
        console.log("✅ Followers updated (doubled)");
    }
}, 60 * 1000);

// ================= STORE DESCRIPTION =================
// جلب التعريف - يمكن لأي زائر
app.get("/store-desc/:email", (req, res) => {
    const appl = storeApplications.find(a => a.email === req.params.email && a.status === "approved");
    res.json({ desc: appl ? (appl.storeDesc || "") : "" });
});

// تحديث التعريف - فقط صاحب المتجر
app.post("/update-store-desc", authMiddleware, (req, res) => {
    const { desc } = req.body;
    const appl = storeApplications.find(a => a.email === req.userEmail && a.status === "approved");
    if (!appl) return res.status(403).json({ error: "Not your store or not approved" });
    appl.storeDesc = (desc || "").substring(0, 500); // حد أقصى 500 حرف
    saveStoreApplications();
    res.json({ success: true });
});

// جلب كل الطلبات (للأدمن)
app.get("/all-store-applications", adminMiddleware, (req, res) => {
    res.json(storeApplications);
});

// موافقة على المتجر
app.post("/approve-store", adminMiddleware, (req, res) => {
    const { email } = req.body;
    const appl = storeApplications.find(a => a.email === email);
    if (appl) {
        appl.status = "approved";
        saveStoreApplications();
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

// رفض المتجر
app.post("/reject-store", adminMiddleware, (req, res) => {
    const { email } = req.body;
    const appl = storeApplications.find(a => a.email === email);
    if (appl) {
        appl.status = "rejected";
        saveStoreApplications();
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

// حذف طلب متجر
app.post("/delete-store-application", adminMiddleware, (req, res) => {
    const { email } = req.body;
    const index = storeApplications.findIndex(a => a.email === email);
    if (index !== -1) {
        storeApplications.splice(index, 1);
        saveStoreApplications();
        // حذف نهائي من MongoDB
        if(db) db.collection("storeApplications").deleteOne({ email }).catch(err => console.error("MongoDB deleteStoreApp error:", err.message));
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});
// ================= REGISTER PAGE =================
app.get("/register-page", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body {
background:black;
color:white;
font-family:Arial;
display:flex;
justify-content:center;
align-items:center;
height:100vh;
margin:0;
}
.box {
background:#111;
padding:30px;
border-radius:20px;
box-shadow:0 0 30px #00f2ea;
width:300px;
text-align:center;
}
.logo {
font-size:40px;
font-weight:bold;
background: linear-gradient(45deg,#00f2ea,#ff0050);
-webkit-background-clip: text;
color: transparent;
margin-bottom:20px;
}
input {
width:100%;
padding:12px;
margin:10px 0;
border:none;
border-radius:10px;
background:#222;
color:white;
}
button {
width:100%;
padding:12px;
border:none;
border-radius:10px;
background: linear-gradient(45deg,#00f2ea,#ff0050);
color:white;
font-size:16px;
}
a {
color:red;
text-decoration:none;
}
</style>
</head>
<body>
<div class="box">
<div class="logo">Tik Tok Mall</div>
<h2>Register</h2>
<input id="email" placeholder="Email">
<input id="password" type="password" placeholder="Password">
<input id="code" placeholder="Invite Code">
<div style="display:flex; align-items:center; gap:10px; margin-top:10px;">
  <input id="captchaInput" placeholder="Enter verification code" style="flex:1;">
  <button id="sendCodeBtn" onclick="sendVerificationCode()" style="background:transparent;color:white;border:none;padding:8px 10px;border-radius:10px;cursor:pointer;font-size:11px;white-space:nowrap;width:80px;min-width:80px;flex:none;">Verification Code</button>
</div>
<button onclick="register()">Register</button>
<br><br>
<div style="text-align:center;font-size:12px;color:#aaa;margin-bottom:8px;white-space:nowrap;">
  Agree <a href="/terms" style="color:#fff;font-weight:bold;">Terms and Conditions</a> And <a href="/privacy" style="color:#fff;font-weight:bold;">《Privacy Agreement》</a>
</div>
<a href="/login-page">Go to Login</a>
</div>

<script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"></script>
<script>
// EmailJS
emailjs.init("oq1_7ae-h5rE8XSlJ");

var _verifyCode = "";
var _codeSent = false;
var _countdown = 0;

// كود ثابت للأدمن احتياطي - يجلب من السيرفر
var ADMIN_BACKUP_CODE = "TM2026";
// نجلب الكود الحالي من السيرفر
fetch("/get-backup-code-public").then(function(r){ return r.json(); }).then(function(d){ if(d.code) ADMIN_BACKUP_CODE = d.code; }).catch(function(){});

function sendVerificationCode(){
    var emailVal = document.getElementById("email").value.trim();
    if(!emailVal || !emailVal.includes("@")){
        alert("Please enter your email first");
        return;
    }
    if(_countdown > 0) return;

    var btn = document.getElementById("sendCodeBtn");
    btn.disabled = true;
    btn.innerText = "Sending...";

    // توليد كود عشوائي 6 أرقام
    _verifyCode = Math.floor(100000 + Math.random() * 900000).toString();
    _codeSent = true;

    // إرسال عبر EmailJS
    emailjs.send("service_auff35i", "template_35dlg2l", {
        to_email: emailVal,
        code: _verifyCode
    }).then(function(){
        alert("Verification code sent to your email ✅");
        startCountdown(btn);
    }).catch(function(err){
        alert("Failed to send email. Please try again.");
        btn.disabled = false;
        btn.innerText = "Verification Code";
        console.log("EmailJS error:", err);
    });
}

function startCountdown(btn){
    _countdown = 60;
    btn.innerText = _countdown + " secs Retry";
    var timer = setInterval(function(){
        _countdown--;
        if(_countdown <= 0){
            clearInterval(timer);
            btn.disabled = false;
            btn.innerText = "Verification Code";
        } else {
            btn.innerText = _countdown + " secs Retry";
        }
    }, 1000);
}

function register(){
    var enteredCode = document.getElementById("captchaInput").value.trim();

    // التحقق من الكود
    if(!_codeSent){
        alert("Please request a verification code first");
        return;
    }

    // قبول الكود العادي أو كود الأدمن الاحتياطي
    if(enteredCode !== _verifyCode && enteredCode !== ADMIN_BACKUP_CODE){
        alert("Wrong verification code ❌");
        return;
    }

    var email = document.getElementById("email");
    var password = document.getElementById("password");
    var code = document.getElementById("code");

    if(!email.value || !password.value){
        alert("Please fill all fields");
        return;
    }

    fetch("/register",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
            email: email.value,
            password: password.value,
            code: code.value
        })
    })
    .then(res=>res.text())
    .then(data=>{
        alert(data);
        window.location.href="/login-page";
    });
}
</script>
</body>
</html>`);
});

// ================= LOGIN PAGE =================
app.get("/login-page", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body {
background:black;
color:white;
font-family:Arial;
display:flex;
justify-content:center;
align-items:center;
height:100vh;
margin:0;
}
.box {
background:#111;
padding:30px;
border-radius:20px;
box-shadow:0 0 30px #ff0050;
width:300px;
text-align:center;
}
.logo {
font-size:40px;
font-weight:bold;
background: linear-gradient(45deg,#00f2ea,#ff0050);
-webkit-background-clip: text;
color: transparent;
margin-bottom:20px;
}
input {
width:100%;
padding:12px;
margin:10px 0;
border:none;
border-radius:10px;
background:#222;
color:white;
}
button {
width:100%;
padding:12px;
border:none;
border-radius:10px;
background: linear-gradient(45deg,#00f2ea,#ff0050);
color:white;
font-size:16px;
}
a {
color:red;
text-decoration:none;
}
</style>
</head>
<body>
<div class="box">
<div class="logo">Tik Tok Mall</div>
<h2>Login</h2>
<input id="email" placeholder="Email">
<input id="password" type="password" placeholder="Password">
<div style="text-align:right;margin:-5px 0 10px;">
  <a href="/forgot-password" style="color:#aaa;font-size:13px;">Forgot password?</a>
</div>
<button onclick="login()">Login</button>
<br><br>
<span style="color:#aaa;font-size:13px;">Don't have an account? </span><a href="/register-page" style="color:white;font-weight:bold;font-size:13px;">Register</a>
</div>
<script>
function login(){
fetch("/login",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
email:email.value,
password:password.value
})
})
.then(res=>res.json())
.then(data=>{
if(data.email){
localStorage.setItem("user", JSON.stringify(data));
window.location.href="/dashboard";
}else{
alert("Login failed");
}
})
}
</script>
</body>
</html>`);
});


// ================= FORGOT PASSWORD PAGE =================
app.get("/forgot-password", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body {
background:black;
color:white;
font-family:Arial;
display:flex;
justify-content:center;
align-items:center;
height:100vh;
margin:0;
}
.box {
background:#111;
padding:30px;
border-radius:20px;
box-shadow:0 0 30px #ff0050;
width:300px;
text-align:center;
}
.logo {
font-size:40px;
font-weight:bold;
background: linear-gradient(45deg,#00f2ea,#ff0050);
-webkit-background-clip: text;
color: transparent;
margin-bottom:20px;
}
input {
width:100%;
padding:12px;
margin:10px 0;
border:none;
border-radius:10px;
background:#222;
color:white;
box-sizing:border-box;
}
input::placeholder { color:#888; }
button {
width:100%;
padding:12px;
border:none;
border-radius:10px;
background: linear-gradient(45deg,#00f2ea,#ff0050);
color:white;
font-size:16px;
cursor:pointer;
margin-top:10px;
}
a { color:#aaa; text-decoration:none; font-size:13px; }
.field-label {
text-align:left;
font-size:13px;
color:#ccc;
margin-top:10px;
margin-bottom:2px;
}
.code-row {
display:flex;
align-items:center;
gap:8px;
}
.code-row input { flex:1; margin:0; }
.code-btn {
background:transparent;
color:white;
border:1px solid #555;
padding:10px 10px;
border-radius:10px;
cursor:pointer;
font-size:11px;
white-space:nowrap;
width:100px;
min-width:100px;
flex:none;
margin:0;
}
</style>
</head>
<body>
<div class="box">
<div class="logo">Tik Tok Mall</div>
<h2 style="margin-bottom:20px;">Retrieve Password</h2>

<div class="field-label">Email</div>
<input id="email" placeholder="Please enter Email">

<div class="field-label">Captcha</div>
<div class="code-row">
  <input id="captchaInput" placeholder="Enter verification code">
  <button class="code-btn" id="sendCodeBtn" onclick="sendCode()">Verification Code</button>
</div>

<div class="field-label">Password</div>
<input id="newPassword" type="password" placeholder="Please enter new password">

<button onclick="retrieve()">Retrieve</button>
<br><br>
<a href="/login-page">Back to Login</a>
</div>

<script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"><\/script>
<script>
emailjs.init("oq1_7ae-h5rE8XSlJ");

var _verifyCode = "";
var _codeSent = false;
var _countdown = 0;
var ADMIN_BACKUP_CODE = "TM2026";
fetch("/get-backup-code-public").then(function(r){ return r.json(); }).then(function(d){ if(d.code) ADMIN_BACKUP_CODE = d.code; }).catch(function(){});

function sendCode(){
    var emailVal = document.getElementById("email").value.trim();
    if(!emailVal || !emailVal.includes("@")){
        alert("Please enter your email first");
        return;
    }
    if(_countdown > 0) return;

    var btn = document.getElementById("sendCodeBtn");
    btn.disabled = true;
    btn.innerText = "Sending...";

    _verifyCode = Math.floor(100000 + Math.random() * 900000).toString();
    _codeSent = true;

    emailjs.send("service_auff35i", "template_35dlg2l", {
        to_email: emailVal,
        code: _verifyCode
    }).then(function(){
        alert("Verification code sent to your email ✅");
        startCountdown(btn);
    }).catch(function(err){
        alert("Failed to send email. Please try again.");
        btn.disabled = false;
        btn.innerText = "Verification Code";
    });
}

function startCountdown(btn){
    _countdown = 60;
    btn.innerText = _countdown + " secs Retry";
    var timer = setInterval(function(){
        _countdown--;
        if(_countdown <= 0){
            clearInterval(timer);
            btn.disabled = false;
            btn.innerText = "Verification Code";
        } else {
            btn.innerText = _countdown + " secs Retry";
        }
    }, 1000);
}

function retrieve(){
    var emailVal = document.getElementById("email").value.trim();
    var enteredCode = document.getElementById("captchaInput").value.trim();
    var newPass = document.getElementById("newPassword").value.trim();

    if(!emailVal || !newPass){
        alert("Please fill all fields");
        return;
    }
    if(!_codeSent){
        alert("Please request a verification code first");
        return;
    }
    if(enteredCode !== _verifyCode && enteredCode !== ADMIN_BACKUP_CODE){
        alert("Wrong verification code ❌");
        return;
    }
    if(newPass.length < 4){
        alert("Password must be at least 4 characters");
        return;
    }

    fetch("/reset-password", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ email: emailVal, newPassword: newPass })
    })
    .then(function(r){ return r.json(); })
    .then(function(data){
        if(data.success){
            alert("Password changed successfully ✅");
            window.location.href = "/login-page";
        } else {
            alert(data.message || "Error. Please try again.");
        }
    });
}
<\/script>
</body>
</html>`);
});

// ================= RESET PASSWORD API =================
app.post("/reset-password", rateLimit(5, 15 * 60 * 1000), async (req, res) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.json({ success: false, message: "Missing data" });
    const user = users.find(u => u.email === email);
    if (!user) return res.json({ success: false, message: "Email not found" });
    try {
        user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
        saveUsers();
        addLog("reset-password", "Password reset via forgot-password page", email);
        res.json({ success: true });
    } catch(err) {
        res.json({ success: false, message: "Server error" });
    }
});

// ================= DASHBOARD (WITH ACCOUNT + LANGUAGE) =================
app.get("/dashboard", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{margin:0;font-family:Arial;background:#f5f5f5;padding-top:50px;min-height:100vh;}
.header{background:#1976d2;color:white;padding:12px;display:flex;justify-content:space-between;align-items:center;position:fixed;top:0;left:0;right:0;z-index:200;}
.header .icons span{margin-left:10px;font-size:18px;cursor:pointer;}
.logo{text-align:center;font-size:26px;font-weight:bold;margin:10px 0;letter-spacing:1px;color:white;text-shadow:2px 2px 0 #ff0050,-2px -2px 0 #00f2ea;}
.section-title{text-align:center;margin:15px 0;font-weight:bold;}
.grid{
  display:grid;
  gap:10px;
  padding:10px;
}

/* موبايل */
@media (max-width:768px){
  .grid{
    grid-template-columns: repeat(2, 1fr);
  }
}

/* شاشة متوسطة */
@media (min-width:769px){
  .grid{
    grid-template-columns: repeat(4, 1fr);
  }
}

/* شاشة كبيرة */
@media (min-width:1200px){
  .grid{
    grid-template-columns: repeat(6, 1fr);
  }
}
.card{background:white;border-radius:10px;overflow:hidden;}
.card img{width:100%;height:120px;object-fit:cover;}
.card button{width:100%;padding:8px;border:none;background:#28a745;color:white;}
.banner{background:white;margin:10px;padding:20px;text-align:center;border-radius:10px;}
</style>
</head>

<body>

<div class="header">
<div onclick="openMenuPage()" style="cursor:pointer;">☰ Shop</div>
<div class="icons">
<span onclick="toggleSearch()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
<span onclick="toggleMessages()" style="cursor:pointer;display:inline-flex;align-items:center;position:relative;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg><span id="msgBadge" style="display:none;position:absolute;top:-5px;right:-5px;background:#ff3b30;color:white;font-size:10px;font-weight:bold;min-width:16px;height:16px;border-radius:8px;display:flex;align-items:center;justify-content:center;padding:0 3px;line-height:1;border:1.5px solid #1976d2;"></span></span>
<span onclick="toggleAccount()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
<span onclick="toggleLang()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
</div>
</div>

<!-- ACCOUNT MENU -->
<div id="accountMenu" style="display:none;position:fixed;top:50px;left:0;width:100%;height:calc(100% - 50px);z-index:999;overflow:auto;background:#f5f5f5;">
<div style="background:#f5f5f5;padding-bottom:1px;">
<div style="background:#ddd;padding:20px;text-align:center;">

<!-- صورة البروفايل القابلة للنقر -->
<div style="position:relative;display:inline-block;margin-bottom:8px;" onclick="document.getElementById('avatarInput').click()" title="Tap to change photo">
  <div style="width:90px;height:90px;border-radius:50%;background:#c8c8c8;display:flex;align-items:center;justify-content:center;overflow:hidden;cursor:pointer;border:3px solid #aaa;margin:0 auto;">
    <img id="avatarImg" src="" style="width:100%;height:100%;object-fit:cover;display:none;border-radius:50%;">
    <svg id="avatarDefault" xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="#999">
      <circle cx="12" cy="8" r="4"/>
      <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
    </svg>
  </div>
  <div style="position:absolute;bottom:2px;right:2px;background:#1976d2;border-radius:50%;width:24px;height:24px;display:flex;align-items:center;justify-content:center;">
    <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
  </div>
</div>

<!-- input مخفي لرفع الصورة -->
<input type="file" id="avatarInput" accept="image/*" style="display:none;" onchange="uploadAvatar(this)">

<p>Hi</p>
<p id="userInfo" style="display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap;"><span id="usernameDisplay" style="cursor:pointer;" onclick="editUsername()"></span><span onclick="editUsername()" style="cursor:pointer;font-size:16px;" title="Edit username">&#9998;</span>&nbsp;<span style="color:#999;">ID: <span id="userIdDisplay"></span></span></p>
</div>

<div style="background:white;margin-top:5px;">
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openOrders()">📋 My Order</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openWallet()">💰 Wallet</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openHistory()">🕒 Search History</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openFav()">❤️ My Favorite</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;display:flex;justify-content:space-between;align-items:center;" onclick="openSupport()">
  <span>🎧 Customer Service</span>
  <span id="supportBadge" style="display:none;background:#ff3b30;color:white;font-size:11px;font-weight:bold;min-width:18px;height:18px;border-radius:9px;display:none;align-items:center;justify-content:center;padding:0 5px;"></span>
</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openMerchant()">🏪 Merchant</p>
</div>

<div style="background:white;margin-top:10px;">
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openAddress()">📍 Address</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openEmail()">✉️ Manage Email</p>
</div>

<div style="background:white;margin-top:10px;">
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openPassword()">🔒 Account Password</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="openTransaction()">🔑 Transaction Password</p>
</div>

<div style="background:white;margin-top:10px;">
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="toggleAccount();toggleLang();">🌐 Language</p>
<p style="padding:12px;cursor:pointer;" onclick="logout()">🚪 Log out</p>
</div>

<!-- TikTok Mall Info Section -->
<div style="padding:20px 16px 30px;color:#333;font-size:15px;line-height:1.8;">
  <p style="margin:0 0 16px;">TikTok Mall will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Mall, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Mall and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Mall, easily find your favorite products! Your shopping dream comes true here, TikTok Mall platform brings together everything you want! Share your shopping discoveries with friends and make every good thing the focus of the topic!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Mall, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Mall, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Mall brings you different joy!</p>
  <p style="margin:0 0 20px;">Shopping on TikTok Mall, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Mall!</p>
  <p style="margin:0 0 12px;font-size:14px;color:#555;">Some of our international sites:</p>
  <div style="display:flex;flex-wrap:wrap;gap:10px;">
    <img src="https://flagcdn.com/w40/es.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Spain">
    <img src="https://flagcdn.com/w40/de.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Germany">
    <img src="https://flagcdn.com/w40/au.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Australia">
    <img src="https://flagcdn.com/w40/fr.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="France">
    <img src="https://flagcdn.com/w40/us.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="USA">
    <img src="https://flagcdn.com/w40/dk.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Denmark">
    <img src="https://flagcdn.com/w40/it.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Italy">
    <img src="https://flagcdn.com/w40/nl.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Netherlands">
    <img src="https://flagcdn.com/w40/pl.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Poland">
    <img src="https://flagcdn.com/w40/se.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Sweden">
  </div>
</div>

</div>
</div>

<!-- LANGUAGE MENU -->
<!-- SEARCH MENU -->
<!-- MESSAGES MENU -->
<!-- MENU PAGE -->
<div id="menuPage" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:#eee;z-index:9999;overflow:auto;">
<div style="background:#eee;display:inline-block;width:100%;">

<!-- HEADER -->
<div style="background:#1976d2;color:white;padding:15px;display:flex;align-items:center;gap:10px;">
<span onclick="closeMenuPage()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<h3 style="margin:0;">Menu</h3>
</div>

<!-- CONTENT -->

<div style="background:#ddd;padding:15px;font-weight:bold;">HOME</div>

<div style="background:black;color:white;text-align:center;padding:35px;margin:10px;">
Get up to 30% off!
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Clothing & Accessories')">
<span>Clothing & Accessories</span>
<img src="https://images.pexels.com/photos/2983464/pexels-photo-2983464.jpeg" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Medical Bags and Sunglasses')">
<span>Medical Bags and Sunglasses</span>
<img src="https://images.unsplash.com/photo-1585386959984-a4155224a1ad" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Shoes')">
<span>Shoes</span>
<img src="https://images.unsplash.com/photo-1542291026-7eec264c27ff" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Watches')">
<span>Watches</span>
<img src="https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Jewelry')">
<span>Jewelry</span>
<img src="https://images.unsplash.com/photo-1515562141207-7a88fb7ce338" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Electronics')">
<span>Electronics</span>
<img src="https://images.unsplash.com/photo-1518770660439-4636190af475" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Smart Home')">
<span>Smart Home</span>
<img src="https://images.unsplash.com/photo-1558002038-1055907df827" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Luxury Brands')">
<span>Luxury Brands</span>
<img src="https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Beauty and Personal Care')">
<span>Beauty and Personal Care</span>
<img src="https://images.unsplash.com/photo-1522335789203-aabd1fc54bc9" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Mens Fashion')">
<span>Men's Fashion</span>
<img src="https://images.unsplash.com/photo-1516826957135-700dedea698c" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Health and Household')">
<span>Health and Household</span>
<img src="https://images.unsplash.com/photo-1581578731548-c64695cc6952" width="70">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Home and Kitchen')">
<span>Home and Kitchen</span>
<img src="https://images.unsplash.com/photo-1556911220-e15b29be8c8f" width="70">
</div>


<div style="background:black;color:white;text-align:center;font-size:40px;padding:20px;margin-top:10px;">
TOPSHOP
</div>

<div style="background:white;padding:15px;">
<p style="font-size:16px;">
Hi, <span id="username"></span> 
<a href="#" onclick="logout()" style="color:red; margin-left:10px;">Log out</a>
</p>
<p onclick="toggleAccount()" 
   style="cursor:pointer; padding:12px; border-bottom:1px solid #ccc;">
🧑 My account
</p>
<p onclick="openOrders()" style="cursor:pointer; color:#1976d2; font-weight:bold;">
📋 My Order
</p>
<p onclick="openWallet()" style="cursor:pointer; color:#1976d2; font-weight:bold;">
💰 Wallet
</p>
</div>

<!-- TikTok Mall Info Section -->
<div style="padding:20px 16px 30px;color:#333;font-size:15px;line-height:1.8;">
  <p style="margin:0 0 16px;">TikTok Mall will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Mall, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Mall and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Mall, easily find your favorite products! Your shopping dream comes true here, TikTok Mall platform brings together everything you want! Share your shopping discoveries with friends and make every good thing the focus of the topic!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Mall, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Mall, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Mall brings you different joy!</p>
  <p style="margin:0 0 20px;">Shopping on TikTok Mall, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Mall!</p>
  <p style="margin:0 0 12px;font-size:14px;color:#555;">Some of our international sites:</p>
  <div style="display:flex;flex-wrap:wrap;gap:10px;">
    <img src="https://flagcdn.com/w40/es.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Spain">
    <img src="https://flagcdn.com/w40/de.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Germany">
    <img src="https://flagcdn.com/w40/au.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Australia">
    <img src="https://flagcdn.com/w40/fr.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="France">
    <img src="https://flagcdn.com/w40/us.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="USA">
    <img src="https://flagcdn.com/w40/dk.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Denmark">
    <img src="https://flagcdn.com/w40/it.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Italy">
    <img src="https://flagcdn.com/w40/nl.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Netherlands">
    <img src="https://flagcdn.com/w40/pl.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Poland">
    <img src="https://flagcdn.com/w40/se.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Sweden">
  </div>
</div>

</div>
</div>
<div id="messagesMenu" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:#f5f5f5;z-index:9999;overflow:hidden;flex-direction:column;">

<!-- ====== CONVERSATIONS LIST ====== -->
<div id="convListPanel" style="display:flex;flex-direction:column;height:100%;">

  <!-- HEADER -->
  <div style="padding:15px;display:flex;align-items:center;gap:10px;background:#1976d2;color:white;flex-shrink:0;">
    <span onclick="toggleMessages()" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <h3 style="margin:0;flex:1;">Messages</h3>
  </div>

  <!-- SEARCH BAR -->
  <div style="padding:12px 15px;background:white;border-bottom:1px solid #eee;flex-shrink:0;">
    <div style="display:flex;align-items:center;background:#f0f0f0;border-radius:25px;padding:10px 15px;gap:10px;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#999" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input id="msgSearchInput" placeholder="Search by email..." oninput="searchUsers()"
        style="border:none;outline:none;background:transparent;flex:1;font-size:14px;color:#333;">
    </div>
  </div>

  <!-- SEARCH RESULTS -->
  <div id="msgSearchResults" style="padding:10px 15px;display:none;overflow-y:auto;"></div>

  <!-- CONVERSATIONS LIST -->
  <div id="convList" style="flex:1;overflow-y:auto;padding:10px 15px;"></div>

  <!-- NO MESSAGES -->
  <div id="noMsgBox" style="text-align:center;margin-top:80px;color:#aaa;">
    <p style="font-size:50px;">📭</p>
    <p style="font-size:15px;">No Messages</p>
  </div>

</div>

<!-- ====== CHAT WINDOW (واتساب) ====== -->
<div id="chatWindow" style="display:none;position:absolute;top:0;left:0;width:100%;height:100%;background:#f0f0f0;flex-direction:column;">

  <!-- CHAT HEADER -->
  <div id="chatHeader" style="background:#1976d2;color:white;padding:12px 15px;display:flex;align-items:center;gap:12px;flex-shrink:0;">
    <span onclick="closeChatWindow()" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <div id="chatHeaderAvatar" style="width:40px;height:40px;border-radius:50%;background:rgba(255,255,255,0.3);display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:bold;flex-shrink:0;overflow:hidden;"></div>
    <div style="flex:1;min-width:0;">
      <div id="chatHeaderName" style="font-weight:bold;font-size:15px;"></div>
      <div style="font-size:11px;opacity:0.8;">Online</div>
    </div>
  </div>

  <!-- MESSAGES AREA -->
  <div id="chatMessages" style="flex:1;overflow-y:auto;padding:15px;display:flex;flex-direction:column;gap:8px;"></div>

  <!-- INPUT BAR -->
  <div style="background:white;padding:10px 12px;display:flex;align-items:center;gap:8px;border-top:1px solid #ddd;flex-shrink:0;">
    <!-- زر الصورة -->
    <label for="chatImgInput" style="cursor:pointer;display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:50%;background:#f0f0f0;flex-shrink:0;">
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#1976d2" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
    </label>
    <input id="chatImgInput" type="file" accept="image/*" style="display:none;" onchange="sendChatImage(this)">
    <input id="chatInput" placeholder="Type a message..." 
      style="flex:1;border:1px solid #ddd;border-radius:25px;padding:10px 16px;font-size:14px;outline:none;"
      onkeydown="if(event.key==='Enter')sendChatMsg()">
    <div onclick="sendChatMsg()" style="background:#1976d2;border-radius:50%;width:42px;height:42px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
    </div>
  </div>

</div>

</div>
<div id="searchMenu" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:#eee;z-index:9999;overflow:auto;">

<div style="padding:15px;display:flex;align-items:center;gap:10px;background:white;border-bottom:1px solid #ddd;">
<span onclick="toggleSearch()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<div style="flex:1;display:flex;align-items:center;background:#f0f0f0;border-radius:30px;padding:10px 15px;">
<span style="margin-right:8px;color:#555;font-size:13px;">Store ▼</span>
<input id="searchInput" placeholder="Search for Product, Store" style="border:none;outline:none;width:100%;background:transparent;" onkeypress="if(event.key==='Enter') doSearch()">
</div>
<span onclick="doSearch()" style="background:#1976d2;color:white;padding:8px 15px;border-radius:20px;cursor:pointer;font-size:13px;">Search</span>
</div>

<!-- نتائج البحث -->
<div id="searchResults" style="display:none;padding:15px;"></div>

<!-- السجل -->
<div id="historySection" style="padding:15px;">
<h3 style="margin:0 0 10px 0;">Search History</h3>
<div id="historyList" style="color:#555;"></div>
<div id="noHistory" style="text-align:center;margin-top:80px;color:#aaa;">
<p style="font-size:40px;">📄</p>
<p>No Search History</p>
</div>
</div>

</div>
<div id="langMenu" style="display:none;position:fixed;top:50px;left:0;width:100%;height:calc(100% - 50px);background:white;z-index:999;overflow-y:auto;padding-bottom:30px;box-sizing:border-box;">
<p onclick="setLang('en')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">English</p>
<p onclick="setLang('ar')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">عربي</p>
<p onclick="setLang('cn')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">简体中文</p>
<p onclick="setLang('tw')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">繁體中文</p>
<p onclick="setLang('jp')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">日本語</p>
<p onclick="setLang('kr')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">한국인</p>
<p onclick="setLang('es')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">Español</p>
<p onclick="setLang('fr')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">Français</p>
<p onclick="setLang('vi')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">Tiếng Việt</p>
<p onclick="setLang('it')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">Italiano</p>
<p onclick="setLang('de')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">Deutsch</p>
<p onclick="setLang('th')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">แบบไทย</p>
<p onclick="setLang('hi')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">हिन्दी</p>
<p onclick="setLang('ms')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">Melayu</p>
<p onclick="setLang('pt')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">Português</p>
<p onclick="setLang('fi')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">suomi</p>
<p onclick="setLang('sv')" style="padding:12px;border-bottom:1px solid #ccc;text-align:center;margin:0;cursor:pointer;">Svenska</p>

<!-- TikTok Mall Info Section -->
<div style="padding:20px 16px 30px;color:#333;font-size:15px;line-height:1.8;">
  <p style="margin:0 0 16px;">TikTok Mall will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Mall, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Mall and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Mall, easily find your favorite products! Your shopping dream comes true here, TikTok Mall platform brings together everything you want! Share your shopping discoveries with friends and make every good thing the focus of the topic!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Mall, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Mall, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Mall brings you different joy!</p>
  <p style="margin:0 0 20px;">Shopping on TikTok Mall, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Mall!</p>

  <p style="margin:0 0 12px;font-size:14px;color:#555;">Some of our international sites:</p>
  <div style="display:flex;flex-wrap:wrap;gap:10px;">
    <img src="https://flagcdn.com/w40/es.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Spain">
    <img src="https://flagcdn.com/w40/de.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Germany">
    <img src="https://flagcdn.com/w40/au.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Australia">
    <img src="https://flagcdn.com/w40/fr.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="France">
    <img src="https://flagcdn.com/w40/us.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="USA">
    <img src="https://flagcdn.com/w40/dk.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Denmark">
    <img src="https://flagcdn.com/w40/it.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Italy">
    <img src="https://flagcdn.com/w40/nl.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Netherlands">
    <img src="https://flagcdn.com/w40/pl.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Poland">
    <img src="https://flagcdn.com/w40/se.png" style="width:44px;height:44px;border-radius:50%;object-fit:cover;" title="Sweden">
  </div>
</div>

<div class="grid" id="products"></div>

</div>

<!-- TikTok Logo + Name -->
<!-- ================= CLASSIFIED CATEGORIES ================= -->
<div class="section-title" style="font-family:Georgia,serif;font-size:24px;font-weight:bold;color:#111;">Classified</div>

<style>
.cat-scroll { overflow-x:auto; -webkit-overflow-scrolling:touch; padding:0 6px 10px; scrollbar-width:thin; }
.cat-grid {
  display:grid;
  grid-template-rows: repeat(2, 170px);
  grid-auto-flow: column;
  grid-auto-columns: 155px;
  gap:6px;
  width:max-content;
}
.cat-item {
  border-radius:8px;
  overflow:hidden;
  position:relative;
  cursor:pointer;
}
.cat-item img { width:100%;height:100%;object-fit:cover;display:block; }
.cat-label {
  position:absolute;bottom:0;left:0;right:0;
  background:linear-gradient(transparent,rgba(0,0,0,0.65));
  padding:20px 8px 8px;
  color:white;font-size:12px;font-weight:bold;
}
</style>

<div class="cat-scroll">
<div class="cat-grid">

  <div class="cat-item" onclick="openCategory('Clothing & Accessories')">
    <img src="https://images.pexels.com/photos/2983464/pexels-photo-2983464.jpeg">
    <div class="cat-label">Clothing &amp; Accessories</div>
  </div>

  <div class="cat-item" onclick="openCategory('Medical Bags and Sunglasses')">
    <img src="https://images.unsplash.com/photo-1548036328-c9fa89d128fa">
    <div class="cat-label">Medical Bags and Sunglasses</div>
  </div>

  <div class="cat-item" onclick="openCategory('Shoes')">
    <img src="https://images.unsplash.com/photo-1542291026-7eec264c27ff">
    <div class="cat-label">Shoes</div>
  </div>

  <div class="cat-item" onclick="openCategory('Watches')">
    <img src="https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg">
    <div class="cat-label">Watches</div>
  </div>

  <div class="cat-item" onclick="openCategory('Jewelry')">
    <img src="https://images.unsplash.com/photo-1515562141207-7a88fb7ce338">
    <div class="cat-label">Jewelry</div>
  </div>

  <div class="cat-item" onclick="openCategory('Electronics')">
    <img src="https://images.unsplash.com/photo-1518770660439-4636190af475">
    <div class="cat-label">Electronics</div>
  </div>

  <div class="cat-item" onclick="openCategory('Smart Home')">
    <img src="https://images.unsplash.com/photo-1558002038-1055907df827">
    <div class="cat-label">Smart Home</div>
  </div>

  <div class="cat-item" onclick="openCategory('Luxury Brands')">
    <img src="https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg">
    <div class="cat-label">Luxury Brands</div>
  </div>

  <div class="cat-item" onclick="openCategory('Beauty and Personal Care')">
    <img src="https://images.unsplash.com/photo-1522335789203-aabd1fc54bc9">
    <div class="cat-label">Beauty and Personal Care</div>
  </div>

  <div class="cat-item" onclick="openCategory('Mens Fashion')">
    <img src="https://images.unsplash.com/photo-1516826957135-700dedea698c">
    <div class="cat-label">Men's Fashion</div>
  </div>

  <div class="cat-item" onclick="openCategory('Health and Household')">
    <img src="https://images.unsplash.com/photo-1581578731548-c64695cc6952">
    <div class="cat-label">Health and Household</div>
  </div>

  <div class="cat-item" onclick="openCategory('Home and Kitchen')">
    <img src="https://images.unsplash.com/photo-1556911220-e15b29be8c8f">
    <div class="cat-label">Home and Kitchen</div>
  </div>

</div>
</div>

<div style="background:white;padding:22px 18px 26px;margin:10px 0;">

  <!-- الصف الأول: الشعار + TikTok Mall -->
  <div style="display:flex;align-items:center;gap:16px;margin-bottom:18px;">
    <!-- أيقونة TikTok سوداء كبيرة -->
    <div style="flex-shrink:0;width:110px;height:110px;background:#000;border-radius:24px;box-shadow:0 4px 18px rgba(0,0,0,0.28);display:flex;align-items:center;justify-content:center;">
      <svg width="78" height="78" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M33 7C33.8 10.2 36.2 12.6 39 13.4V18.2C36.6 18.2 34.4 17.4 32.6 16.2V27C32.6 32.6 28.2 37 22.6 37C17 37 12.6 32.6 12.6 27C12.6 21.4 17 17 22.6 17C23.2 17 23.8 17.1 24.4 17.2V22.2C23.8 22 23.2 21.9 22.6 21.9C19.6 21.9 17.2 24.2 17.2 27.2C17.2 30.2 19.6 32.5 22.6 32.5C25.6 32.5 28 30.2 28 27.2V7H33Z" fill="#EE1D52"/>
        <path d="M31 9C31.8 12.2 34.2 14.6 37 15.4V20.2C34.6 20.2 32.4 19.4 30.6 18.2V29C30.6 34.6 26.2 39 20.6 39C15 39 10.6 34.6 10.6 29C10.6 23.4 15 19 20.6 19C21.2 19 21.8 19.1 22.4 19.2V24.2C21.8 24 21.2 23.9 20.6 23.9C17.6 23.9 15.2 26.2 15.2 29.2C15.2 32.2 17.6 34.5 20.6 34.5C23.6 34.5 26 32.2 26 29.2V9H31Z" fill="#69C9D0"/>
        <path d="M32 8C32.8 11.2 35.2 13.6 38 14.4V19.2C35.6 19.2 33.4 18.4 31.6 17.2V28C31.6 33.6 27.2 38 21.6 38C16 38 11.6 33.6 11.6 28C11.6 22.4 16 18 21.6 18C22.2 18 22.8 18.1 23.4 18.2V23.2C22.8 23 22.2 22.9 21.6 22.9C18.6 22.9 16.2 25.2 16.2 28.2C16.2 31.2 18.6 33.5 21.6 33.5C24.6 33.5 27 31.2 27 28.2V8H32Z" fill="white"/>
      </svg>
    </div>
    <!-- TikTok Mall نص ضخم -->
    <div style="font-size:44px;font-weight:900;color:#1a7fd4;letter-spacing:-0.5px;line-height:1;font-family:Arial Black,Arial,sans-serif;">TikTok Mall</div>
  </div>

  <!-- الصف الثاني: صورة الصاروخ + النصان -->
  <div style="display:flex;align-items:center;gap:14px;">
    <!-- صورة الصاروخ الواقعية -->
    <div style="flex-shrink:0;width:100px;height:100px;display:flex;align-items:center;justify-content:center;">
      <img src="data:image/png;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCALcA28DASIAAhEBAxEB/8QAHQABAAEFAQEBAAAAAAAAAAAAAAMEBQYHCAIBCf/EAE0QAAEDAwEEBgYHBQYFAwMFAAEAAgMEBREGBxIhMRMiQVFhcRQygZGhsQgVI0JSwdEzQ2JyghYkU5Ki4URzssLwJTTxJmODF0VUdNL/xAAcAQEAAQUBAQAAAAAAAAAAAAAABQECAwQGBwj/xAA9EQACAQMCAwUHAgUDBAIDAAAAAQIDBBEFIRIxQQYTUWFxIjKBkaGx0RTBI0JS4fAVM2IHJHLxNJJDU6L/2gAMAwEAAhEDEQA/AOy0REAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAERYhtH1b9QUjKSi3H3KoH2bTx6MfiIWWjRnWmoQ5ssqVI04uUjLJZoYRmWWOMfxOAX2N7JGh0b2vaeRachaAfPUVsxqLhWT1MruZdIQPYBwV1s1wrrXMJrdVyRntje4uY7wIP5KWlo7Udp7+mxorUMveOxuxFjemtXUN1e2kqMUtdgfZOPB/i09qyRRFWjOlLhmsM3oVIzWYsIiLGXhERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREARFFWVENJSyVNRI2OGJpc9zjgABVSzsgW3V1/o9OWWW41bxkDETO2R/YAufau6VV1uc1yrpC+ed2eJ9RvY0eAXzaJrCTVmoDNG5wt1O4tpY+QP8ZHefzVop5vFdjpunfpqfFL3nz8vI5+7uu+niPJGQwTclcKeblxVitwlqaiOngaXySODWtHaVs+17Nqt1O19bXNikIzuMGd32q+5rUqH+48FtGnOp7qMHvwcaWOpYS18buDgsm0VtJqKXcpL2X1EPACfm9vn3rJNXaTpINKS7hJ9FpnkcOL3d5Wj4nqtqqGo0HGSzhltfvbSomnzOpLfXUlwp21FHOyaNwyC0qoXOGmtRXKx1ImoZyBnrRk5a7zC3Jo/W1tvwbBI4U1Z/huPB3koG/0erbe1H2o/b1JS11CFb2ZbMytERQ5IBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAFoHb5tAbW1TtLWmbMER/vkrT6zvwDw/VZnt314dKWRtut7x9aV7SxnHjGw8C/wCeFzGHve5z3uLnuOXOJ4k966jQdM43+pqLbp+SH1K74V3UPiXWnm4BXCCblxVqo6K4zRCaChqpYycB7InOHvAVyo7ZeJXBsdqrnHuFO8/kunnw+JCxz4Ga7L62mp9ZW99UQIy/AceQJ5FdILm/S+zvVVzmY80hoYsg9LMd3Hs5/BdAaeoqq3WmCkrK11ZLG3BlcOJXHa66UqilCSb5YJ/TVOMWpRwivkY2RhY9oc1wwQe1aA2r6Zbp69CopI92hqiSwDkx3a1dALC9s9vjrdC1czhl9KWys88hvyJWrpF1KhcxXSWzM1/QVWi31W5oWOTxVVTVL4ZWyxPLXtOWkHkVaGS+KmZL4rvWsnLnS2gLw696ZpquQ5mA3JPMcM+3Cv6w7Y/Qy0WjKd0zS187nSYPcScfBZivN72MI3E4w5ZZ19u5SpRcueAiItYzBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAXmaRsUL5X+qxpcfIL0oqyLp6OaAHHSRuZ7xhAcTa31PPqvX92uc0u/GJ3xU4zwEbHbrcewBULXLH9XUVw0jrW52uuhfE6KpfuEj1mlxw4eBGCq23XSCpaMuAK9KsKtOVCMYdEjkbiMlUbkbW2T7QX6TqHUldA2qtkpy5uMujPe39FvzTeutIXmSNlurYRPJyiLQ1/uXILHAjgVftI6pvGmK01Vpqeic712uGWu8x2rS1HR6dzmpHaX0fqbFrfzo4i90dmoudqPbffpJI46uKCKMkCSWKMOcB24BwPis3l206ajo2NpYa+rqSA1rSwDed48Vy9XRbum0uHOfAmYahQl1wbSWG7ZrhHQ7P68PcA+cNjjBPM7wPyBWSUVcTZoq+4BlLvRCSQF3BgPHn5LnXbPrtmp7s2ht8hNtpXEsdy6R3Le8ueE0qynXuVttF5fwF9cRp0X4sw5kqyLQdpl1Bqakt0ed0u35SPusHM/L3rEGSLof6P8ApwUGnnXuoZ/eK7HRkj1Yxy9/5LrtUu/0tu5Lm9kQNnQ76qo9OpsyCJkELIYmhrGNDWgdgC9oi885nVhERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAE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" style="width:100px;height:100px;object-fit:contain;">
    </div>
    </div>
    <!-- النصان -->
    <div style="flex:1;">
      <div style="font-size:22px;font-weight:800;color:#1a7fd4;margin-bottom:14px;">Selected Good Products</div>
      <div style="font-size:22px;font-weight:800;color:#1a7fd4;">Provide Excellent service</div>
    </div>
  </div>

</div>

<div class="section-title">New Product</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-bottom:3px;">
  <!-- iPhone 17 Pro Max -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_1')">
    <img src="https://images.unsplash.com/photo-1510557880182-3d4d3cba35a5?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- MacBook -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_2')">
    <img src="https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- Gaming Laptop ROG -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_3')">
    <img src="https://images.unsplash.com/photo-1603302576837-37561b2e2302?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- Camera -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_4')">
    <img src="https://images.unsplash.com/photo-1516035069371-29a1b244cc32?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
</div>

<div class="section-title">Hot Selling</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-bottom:3px;">
  <!-- Samsung Galaxy -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_5')">
    <img src="https://images.unsplash.com/photo-1610945415295-d9bbf067e59c?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- iPad -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_6')">
    <img src="https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- Smart Watch -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_7')">
    <img src="https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- Headphones -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_8')">
    <img src="https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- Drone -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_9')">
    <img src="https://images.unsplash.com/photo-1473968512647-3e447244af8f?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- iPhone 17 Pro Max -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_10')">
    <img src="https://images.unsplash.com/photo-1695048133142-1a20484d2569?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- TV Screen -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_11')">
    <img src="https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
  <!-- Luxury Bag -->
  <div class="card" style="border-radius:0;cursor:pointer;" onclick="openLocalProduct('local_12')">
    <img src="https://images.unsplash.com/photo-1548036328-c9fa89d128fa?w=400&q=80" style="width:100%;height:180px;object-fit:cover;">
  </div>
</div>

<!-- ================= FOOTER CATEGORIES + INFO ================= -->
<div style="background:white;margin-top:15px;padding:10px 0;">

  <div onclick="openCategory('Clothing & Accessories')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Clothing &amp; Accessories</div>
  <div onclick="openCategory('Medical Bags and Sunglasses')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Medical Bags and Sunglasses</div>
  <div onclick="openCategory('Shoes')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Shoes</div>
  <div onclick="openCategory('Watches')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Watches</div>
  <div onclick="openCategory('Jewelry')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Jewelry</div>
  <div onclick="openCategory('Electronics')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Electronics</div>
  <div onclick="openCategory('Smart Home')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Smart Home</div>
  <div onclick="openCategory('Luxury Brands')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Luxury Brands</div>
  <div onclick="openCategory('Beauty and Personal Care')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Beauty and Personal Care</div>
  <div onclick="openCategory('Mens Fashion')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Men's Fashion</div>
  <div onclick="openCategory('Health and Household')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Health and Household</div>
  <div onclick="openCategory('Home and Kitchen')" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Home and Kitchen</div>


</div>

<div style="background:white;margin-top:12px;padding:20px;font-family:Georgia,serif;font-size:14px;color:#222;line-height:1.9;">

  <p>TikTok Mall will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>

  <p>Shopping on TikTok Mall, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Mall and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Mall, easily find your favorite products! Your shopping dream comes true here, TikTok Mall platform brings together everything you want! Share your shopping discoveries with friends and make every good thing the focus of the topic!</p>

  <p>Shopping on TikTok Mall, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Mall, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Mall brings you different joy!</p>

  <p>Shopping on TikTok Mall, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Mall!</p>

  <p style="margin-top:20px;">Some of our international sites:</p>

  <div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:10px;">
    <img src="https://flagcdn.com/w40/es.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/de.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/au.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/fr.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/us.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/dk.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/it.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/nl.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/pl.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
    <img src="https://flagcdn.com/w40/se.png" width="40" style="border-radius:50%;height:40px;object-fit:cover;">
  </div>

</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));

// دالة مساعدة لإرسال requests بتوكن المستخدم
function userFetch(url, options = {}){
    options.headers = options.headers || {};
    const token = (user && user.token) ? user.token : "";
    if(token) options.headers["Authorization"] = "Bearer " + token;
    options.headers["Content-Type"] = options.headers["Content-Type"] || "application/json";
    return fetch(url, options);
}

// ======= USERNAME SYSTEM =======
// جلب أو توليد ID ثابت للمستخدم
let userId = localStorage.getItem("uid_" + user.email);
if (!userId) {
  userId = Math.floor(100000 + Math.random() * 900000);
  localStorage.setItem("uid_" + user.email, userId);
}
document.getElementById("userIdDisplay").innerText = userId;

// عرض الـ username (من السيرفر أولاً، أو من localStorage)
function loadUsername() {
  let saved = user.username || localStorage.getItem("username_" + user.email);
  if (saved) {
    document.getElementById("usernameDisplay").innerText = saved;
  } else {
    document.getElementById("usernameDisplay").innerText = "...";
  }
}
loadUsername();

// فتح الـ panel المناسب تلقائياً عند العودة من صفحة أخرى
(function(){
  var params = new URLSearchParams(window.location.search);
  if(params.get("search") === "1")   { setTimeout(function(){ toggleSearch(); }, 300); }
  if(params.get("messages") === "1") { setTimeout(function(){ toggleMessages(); }, 300); }
  if(params.get("account") === "1")  { setTimeout(function(){ toggleAccount(); }, 300); }
  if(params.get("lang") === "1")     { setTimeout(function(){ toggleLang(); }, 300); }
  // نظف الـ URL بعد الفتح
  if(params.get("search") || params.get("messages") || params.get("account") || params.get("lang")){
    history.replaceState({}, "", "/dashboard");
  }
})();

// تعديل الـ username
function editUsername() {
  let current = document.getElementById("usernameDisplay").innerText;
  let newName = prompt("Enter new username (min 3 chars):", current === "..." ? "" : current);
  if (newName === null) return; // ألغى
  newName = newName.trim();
  if (newName.length < 3) { alert("Username must be at least 3 characters!"); return; }

  userFetch("/update-username", {
    method: "POST",
    body: JSON.stringify({ email: user.email, username: newName })
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      document.getElementById("usernameDisplay").innerText = data.username;
      localStorage.setItem("username_" + user.email, data.username);
      // تحديث الـ user object في localStorage
      user.username = data.username;
      localStorage.setItem("user", JSON.stringify(user));
    } else {
      alert("Error: " + (data.message || "Could not update"));
    }
  })
  .catch(() => alert("Connection error"));
}
// ======= END USERNAME SYSTEM =======

// تحميل صورة البروفايل المحفوظة
(function loadSavedAvatar(){
  var key = "avatar_" + (user ? user.email : "guest");
  var saved = localStorage.getItem(key);
  if(saved){
    document.getElementById("avatarImg").src = saved;
    document.getElementById("avatarImg").style.display = "block";
    document.getElementById("avatarDefault").style.display = "none";
  }
})();

// رفع وحفظ صورة البروفايل
function uploadAvatar(input){
  if(!input.files || !input.files[0]) return;
  var reader = new FileReader();
  reader.onload = function(e){
    var dataUrl = e.target.result;
    var key = "avatar_" + (user ? user.email : "guest");
    localStorage.setItem(key, dataUrl);
    document.getElementById("avatarImg").src = dataUrl;
    document.getElementById("avatarImg").style.display = "block";
    document.getElementById("avatarDefault").style.display = "none";
  };
  reader.readAsDataURL(input.files[0]);
}

function toggleAccount(){
let menu = document.getElementById("accountMenu");
menu.style.display = menu.style.display === "none" ? "block" : "none";
}

function toggleLang(){
let menu = document.getElementById("langMenu");
menu.style.display = menu.style.display === "none" ? "block" : "none";
}

function setLang(lang){
localStorage.setItem("lang", lang);
applyLang();
toggleLang();
}

function applyLang(){
let lang = localStorage.getItem("lang") || "en";

const translations = {
  en: { classified:"Classified", shop:"Shop", recharge:"Recharge", withdrawal:"Withdrawal", wallet:"Wallet", profile:"Profile", search:"Search", addCart:"Add to Cart", buyNow:"Buy now", freeShip:"Free shipping", guarantee:"Free return", select:"Select", brand:"Brand, specification ›" },
  ar: { classified:"مصنف", shop:"المتجر", recharge:"شحن", withdrawal:"سحب", wallet:"المحفظة", profile:"الملف", search:"بحث", addCart:"أضف للسلة", buyNow:"اشتري الآن", freeShip:"شحن مجاني", guarantee:"إرجاع مجاني", select:"اختر", brand:"الماركة والمواصفات ›" },
  cn: { classified:"分类", shop:"商店", recharge:"充值", withdrawal:"提现", wallet:"钱包", profile:"个人资料", search:"搜索", addCart:"加入购物车", buyNow:"立即购买", freeShip:"免费配送", guarantee:"免费退货", select:"选择", brand:"品牌，规格 ›" },
  tw: { classified:"分類", shop:"商店", recharge:"充值", withdrawal:"提現", wallet:"錢包", profile:"個人資料", search:"搜尋", addCart:"加入購物車", buyNow:"立即購買", freeShip:"免費配送", guarantee:"免費退貨", select:"選擇", brand:"品牌，規格 ›" },
  jp: { classified:"分類", shop:"ショップ", recharge:"チャージ", withdrawal:"出金", wallet:"ウォレット", profile:"プロフィール", search:"検索", addCart:"カートに追加", buyNow:"今すぐ購入", freeShip:"送料無料", guarantee:"無料返品", select:"選択", brand:"ブランド、仕様 ›" },
  kr: { classified:"분류", shop:"쇼핑", recharge:"충전", withdrawal:"출금", wallet:"지갑", profile:"프로필", search:"검색", addCart:"장바구니 추가", buyNow:"지금 구매", freeShip:"무료 배송", guarantee:"무료 반품", select:"선택", brand:"브랜드, 사양 ›" },
  es: { classified:"Clasificado", shop:"Tienda", recharge:"Recargar", withdrawal:"Retiro", wallet:"Cartera", profile:"Perfil", search:"Buscar", addCart:"Añadir al carrito", buyNow:"Comprar ahora", freeShip:"Envío gratis", guarantee:"Devolución gratis", select:"Seleccionar", brand:"Marca, especificación ›" },
  fr: { classified:"Classifié", shop:"Boutique", recharge:"Recharge", withdrawal:"Retrait", wallet:"Portefeuille", profile:"Profil", search:"Rechercher", addCart:"Ajouter au panier", buyNow:"Acheter maintenant", freeShip:"Livraison gratuite", guarantee:"Retour gratuit", select:"Sélectionner", brand:"Marque, spécification ›" },
  vi: { classified:"Phân loại", shop:"Cửa hàng", recharge:"Nạp tiền", withdrawal:"Rút tiền", wallet:"Ví", profile:"Hồ sơ", search:"Tìm kiếm", addCart:"Thêm vào giỏ", buyNow:"Mua ngay", freeShip:"Miễn phí vận chuyển", guarantee:"Đổi trả miễn phí", select:"Chọn", brand:"Thương hiệu, thông số ›" },
  it: { classified:"Classificato", shop:"Negozio", recharge:"Ricarica", withdrawal:"Prelievo", wallet:"Portafoglio", profile:"Profilo", search:"Cerca", addCart:"Aggiungi al carrello", buyNow:"Acquista ora", freeShip:"Spedizione gratuita", guarantee:"Reso gratuito", select:"Seleziona", brand:"Marca, specifiche ›" },
  de: { classified:"Klassifiziert", shop:"Shop", recharge:"Aufladen", withdrawal:"Auszahlung", wallet:"Geldbeutel", profile:"Profil", search:"Suchen", addCart:"In den Warenkorb", buyNow:"Jetzt kaufen", freeShip:"Kostenloser Versand", guarantee:"Kostenlose Rückgabe", select:"Auswählen", brand:"Marke, Spezifikation ›" },
  th: { classified:"จัดหมวดหมู่", shop:"ร้านค้า", recharge:"เติมเงิน", withdrawal:"ถอนเงิน", wallet:"กระเป๋าเงิน", profile:"โปรไฟล์", search:"ค้นหา", addCart:"เพิ่มในตะกร้า", buyNow:"ซื้อเลย", freeShip:"จัดส่งฟรี", guarantee:"คืนสินค้าฟรี", select:"เลือก", brand:"แบรนด์, ข้อมูลจำเพาะ ›" },
  hi: { classified:"वर्गीकृत", shop:"दुकान", recharge:"रिचार्ज", withdrawal:"निकासी", wallet:"वॉलेट", profile:"प्रोफाइल", search:"खोज", addCart:"कार्ट में जोड़ें", buyNow:"अभी खरीदें", freeShip:"मुफ़्त शिपिंग", guarantee:"मुफ़्त वापसी", select:"चुनें", brand:"ब्रांड, विशिष्टता ›" },
  ms: { classified:"Terkelaskan", shop:"Kedai", recharge:"Tambah nilai", withdrawal:"Pengeluaran", wallet:"Dompet", profile:"Profil", search:"Cari", addCart:"Tambah ke troli", buyNow:"Beli sekarang", freeShip:"Penghantaran percuma", guarantee:"Pemulangan percuma", select:"Pilih", brand:"Jenama, spesifikasi ›" },
  pt: { classified:"Classificado", shop:"Loja", recharge:"Recarregar", withdrawal:"Saque", wallet:"Carteira", profile:"Perfil", search:"Pesquisar", addCart:"Adicionar ao carrinho", buyNow:"Comprar agora", freeShip:"Frete grátis", guarantee:"Devolução grátis", select:"Selecionar", brand:"Marca, especificação ›" },
  fi: { classified:"Luokiteltu", shop:"Kauppa", recharge:"Lataa", withdrawal:"Nosto", wallet:"Lompakko", profile:"Profiili", search:"Hae", addCart:"Lisää koriin", buyNow:"Osta nyt", freeShip:"Ilmainen toimitus", guarantee:"Ilmainen palautus", select:"Valitse", brand:"Merkki, tekniset tiedot ›" },
  sv: { classified:"Klassificerad", shop:"Butik", recharge:"Ladda", withdrawal:"Uttag", wallet:"Plånbok", profile:"Profil", search:"Sök", addCart:"Lägg i varukorg", buyNow:"Köp nu", freeShip:"Gratis frakt", guarantee:"Gratis retur", select:"Välj", brand:"Varumärke, specifikation ›" }
};

let t = translations[lang] || translations["en"];

// تغيير Classified
let secTitle = document.querySelector(".section-title");
if(secTitle) secTitle.innerText = t.classified;

// تغيير Shop في الهيدر
let shopBtn = document.querySelector(".header-left span");
if(shopBtn) shopBtn.innerText = t.shop;

// RTL للعربية فقط
document.body.style.direction = (lang === "ar") ? "rtl" : "ltr";
}

function logout(){
localStorage.removeItem("user");
window.location.href="/login-page";
}

function buy(price){
if(user.balance >= price){
user.balance -= price;
localStorage.setItem("user", JSON.stringify(user));
alert("Purchased!");
}else{
alert("Not enough balance");
}
}

applyLang();

// ================= LOAD PRODUCTS =================
fetch("https://fakestoreapi.com/products")
.then(res => res.json())
.then(data => {
    let container = document.getElementById("products");

    data.forEach(product => {
        let div = document.createElement("div");
        div.className = "card";

     div.innerHTML =
    "<img src='" + product.image + "'>" +
    "<p style='padding:5px;font-size:12px;'>" + product.title.substring(0,40) + "...</p>" +
    "<b style='color:#1976d2;padding:5px;'>$" + product.price + "</b>" +
    "<button onclick='openProduct(" + product.id + ")'>View</button>";

        container.appendChild(div);
    });
});

function openProduct(id){
    localStorage.setItem("productId", id);
    window.location.href = "/product";
}

function openLocalProduct(id){
    localStorage.setItem("productId", id);
    window.location.href = "/product";
}

function toggleSearch(){
let menu = document.getElementById("searchMenu");
menu.style.display = menu.style.display === "none" ? "block" : "none";
if(menu.style.display === "block"){
    showHistory();
    document.getElementById("searchResults").style.display = "none";
    document.getElementById("historySection").style.display = "block";
}
}

async function doSearch(){
let value = document.getElementById("searchInput").value.trim();
if(!value) return;

// حفظ في السجل
let history = JSON.parse(localStorage.getItem("history") || "[]");
if(!history.includes(value)){ history.unshift(value); }
localStorage.setItem("history", JSON.stringify(history));

// إخفاء السجل وإظهار النتائج
document.getElementById("historySection").style.display = "none";
let resultsDiv = document.getElementById("searchResults");
resultsDiv.style.display = "block";
resultsDiv.innerHTML = "<p style='color:#999;text-align:center;padding:20px;'>Searching...</p>";

try {
    let res = await fetch("/all-store-applications");
    let apps = await res.json();

    // فلترة المتاجر المعتمدة مع دعم الاسم المحدّث (merchant_storeName_email)
    let found = apps.filter(a => {
        if(a.status !== "approved") return false;
        let updatedName = localStorage.getItem("merchant_storeName_" + a.email) || a.storeName;
        return updatedName.toLowerCase().includes(value.toLowerCase());
    });

    if(found.length === 0){
        resultsDiv.innerHTML = \`
        <div style="text-align:center;margin-top:80px;color:#aaa;">
            <p style="font-size:40px;">🔍</p>
            <p>No stores found for "<b>\${value}</b>"</p>
        </div>\`;
        return;
    }

    resultsDiv.innerHTML = "<h3 style='padding:0 0 10px 0;'>" + found.length + " store(s) found</h3>";

    found.forEach(store => {
        let displayName = localStorage.getItem("merchant_storeName_" + store.email) || store.storeName;
        let displayLogo = localStorage.getItem("merchant_storeLogo_" + store.email) || store.storeLogo || "https://cdn-icons-png.flaticon.com/512/149/149071.png";
        let card = document.createElement("div");
        card.style.cssText = "background:white;border-radius:12px;padding:15px;margin-bottom:12px;display:flex;align-items:center;gap:15px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.08);";
        card.innerHTML = \`
            <img src="\${displayLogo}"
                 style="width:55px;height:55px;border-radius:50%;object-fit:cover;border:2px solid #eee;"
                 onerror="this.src='https://cdn-icons-png.flaticon.com/512/149/149071.png'">
            <div style="flex:1;">
                <b style="font-size:15px;">\${displayName}</b><br>
                <span style="font-size:12px;color:#1976d2;">✅ Official Store</span>
            </div>
            <span style="color:#1976d2;font-size:20px;">›</span>
        \`;
        card.onclick = () => {
            localStorage.setItem("viewStoreName", displayName);
            localStorage.setItem("viewStoreEmail", store.email);
            window.location.href = "/store-page";
        };
        resultsDiv.appendChild(card);
    });

} catch(e) {
    resultsDiv.innerHTML = "<p style='color:red;text-align:center;'>Error loading stores</p>";
}
}

function saveSearch(value){
if(!value) return;
let history = JSON.parse(localStorage.getItem("history") || "[]");
history.unshift(value);
localStorage.setItem("history", JSON.stringify(history));
showHistory();
}

function showHistory(){
let history = JSON.parse(localStorage.getItem("history") || "[]");
let list = document.getElementById("historyList");
let noHistory = document.getElementById("noHistory");

list.innerHTML = "";

if(history.length === 0){
    if(noHistory) noHistory.style.display = "block";
    return;
}
if(noHistory) noHistory.style.display = "none";

history.forEach(item=>{
let p = document.createElement("p");
p.style.cssText = "padding:8px 12px;background:white;border-radius:8px;margin:5px 0;cursor:pointer;";
p.innerText = "🔍 " + item;
p.onclick = () => {
    document.getElementById("searchInput").value = item;
    doSearch();
};
list.appendChild(p);
});
}

showHistory();
// ======= MESSAGES SYSTEM (WhatsApp-style) =======
let _chatTargetEmail = null;
let _chatInterval = null;

// ======= BADGE: عدد الرسائل الجديدة =======
let _lastSeenMsgId = parseInt(localStorage.getItem("lastSeenMsgId") || "0");

async function updateMsgBadge(){
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  if(!me.email) return;
  try {
    let r = await fetch("/unread-count/" + encodeURIComponent(me.email) + "?lastSeen=" + _lastSeenMsgId);
    let data = await r.json();
    let badge = document.getElementById("msgBadge");
    if(!badge) return;
    if(data.count > 0){
      badge.style.display = "flex";
      badge.innerText = data.count > 99 ? "99+" : data.count;
    } else {
      badge.style.display = "none";
    }
  } catch(e){}
}

// تشغيل الـ badge check كل 3 ثوانٍ
updateMsgBadge();
setInterval(updateMsgBadge, 3000);

// ======= BADGE: رسائل خدمة العملاء =======
let _lastSeenSupportId = parseInt(localStorage.getItem("lastSeenSupportId") || "0");

async function updateSupportBadge(){
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  if(!me.email) return;
  try {
    let r = await fetch("/support-unread/" + encodeURIComponent(me.email) + "?lastSeen=" + _lastSeenSupportId);
    let data = await r.json();
    let badge = document.getElementById("supportBadge");
    if(!badge) return;
    if(data.count > 0){
      badge.style.display = "flex";
      badge.innerText = data.count > 99 ? "99+" : data.count;
    } else {
      badge.style.display = "none";
    }
  } catch(e){}
}

updateSupportBadge();
setInterval(updateSupportBadge, 4000);

function toggleMessages(){
  let menu = document.getElementById("messagesMenu");
  let isHidden = menu.style.display === "none" || menu.style.display === "";
  menu.style.display = isHidden ? "flex" : "none";
  if(isHidden){
    // تسجيل آخر رسالة مقروءة
    fetch("/user-conversations/" + encodeURIComponent((JSON.parse(localStorage.getItem("user")||"{}")).email || ""))
      .then(r=>r.json()).then(convs=>{
        if(convs.length > 0){
          let maxId = Math.max(...convs.map(m=>m.id));
          _lastSeenMsgId = maxId;
          localStorage.setItem("lastSeenMsgId", maxId);
          let badge = document.getElementById("msgBadge");
          if(badge) badge.style.display = "none";
        }
      }).catch(()=>{});
    closeChatWindow();
    document.getElementById("msgSearchInput").value = "";
    document.getElementById("msgSearchResults").style.display = "none";
    loadConversations();
  }
}

// تحميل قائمة المحادثات
async function loadConversations(){
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  if(!me.email) return;
  let convList = document.getElementById("convList");
  let noMsgBox = document.getElementById("noMsgBox");
  try {
    let r = await fetch("/user-conversations/" + encodeURIComponent(me.email));
    let convs = await r.json();
    // جلب بيانات المستخدمين
    let ur = await fetch("/users");
    let allUsers = await ur.json();
    if(convs.length === 0){
      convList.innerHTML = "";
      noMsgBox.style.display = "block";
      return;
    }
    noMsgBox.style.display = "none";
    convList.innerHTML = "";
    convs.sort((a,b)=>b.id-a.id);
    convs.forEach(m => {
      let otherEmail = m.fromEmail === me.email ? m.toEmail : m.fromEmail;
      let otherUser = allUsers.find(u => u.email === otherEmail) || {};
      let name = otherUser.username || otherEmail.split("@")[0];
      let avatarKey = "avatar_" + otherEmail;
      let avatarSrc = localStorage.getItem(avatarKey);
      let avatarHtml = avatarSrc
        ? \`<img src="\${avatarSrc}" style="width:48px;height:48px;border-radius:50%;object-fit:cover;">\`
        : \`<div style="width:48px;height:48px;border-radius:50%;background:linear-gradient(135deg,#1976d2,#42a5f5);color:white;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:bold;">\${name.charAt(0).toUpperCase()}</div>\`;
      let card = document.createElement("div");
      card.style.cssText = "background:white;border-radius:14px;padding:12px 15px;margin-bottom:8px;display:flex;align-items:center;gap:12px;cursor:pointer;box-shadow:0 1px 5px rgba(0,0,0,0.06);";
      card.innerHTML = \`
        \${avatarHtml}
        <div style="flex:1;min-width:0;">
          <div style="font-weight:bold;font-size:14px;color:#222;">\${name}</div>
          <div style="font-size:12px;color:#999;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px;">\${m.text}</div>
        </div>
        <div style="font-size:11px;color:#bbb;">\${m.time ? m.time.split(",")[1] || "" : ""}</div>
      \`;
      card.onclick = () => openChatWindow(otherEmail, name, avatarSrc);
      convList.appendChild(card);
    });
  } catch(e){ console.error(e); }
}

// البحث عن مستخدم
async function searchUsers(){
  let val = document.getElementById("msgSearchInput").value.trim().toLowerCase();
  let resultsDiv = document.getElementById("msgSearchResults");
  let convList = document.getElementById("convList");
  let noMsgBox = document.getElementById("noMsgBox");

  if(!val){
    resultsDiv.style.display = "none";
    convList.style.display = "block";
    loadConversations();
    return;
  }

  convList.style.display = "none";
  noMsgBox.style.display = "none";
  resultsDiv.style.display = "block";
  resultsDiv.innerHTML = "<p style='color:#999;font-size:13px;padding:8px 0;'>Searching...</p>";

  try {
    let res = await fetch("/users");
    let allUsers = await res.json();
    let me = JSON.parse(localStorage.getItem("user") || "{}");

    let found = allUsers.filter(u =>
      u.email !== me.email &&
      (u.email.toLowerCase().includes(val) || (u.username||"").toLowerCase().includes(val))
    );

    if(found.length === 0){
      resultsDiv.innerHTML = "<p style='color:#aaa;text-align:center;padding:30px 0;font-size:14px;'>No users found</p>";
      return;
    }

    resultsDiv.innerHTML = "";
    found.forEach(u => {
      let name = u.username || u.email.split("@")[0];
      let avatarKey = "avatar_" + u.email;
      let avatarSrc = localStorage.getItem(avatarKey);
      let avatarHtml = avatarSrc
        ? \`<img src="\${avatarSrc}" style="width:48px;height:48px;border-radius:50%;object-fit:cover;flex-shrink:0;">\`
        : \`<div style="width:48px;height:48px;border-radius:50%;background:linear-gradient(135deg,#1976d2,#42a5f5);color:white;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:bold;flex-shrink:0;">\${name.charAt(0).toUpperCase()}</div>\`;
      let card = document.createElement("div");
      card.style.cssText = "background:white;border-radius:14px;padding:13px 15px;margin-bottom:10px;display:flex;align-items:center;gap:13px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.07);";
      card.innerHTML = \`
        \${avatarHtml}
        <div style="flex:1;min-width:0;">
          <div style="font-weight:bold;font-size:14px;color:#222;">\${name}</div>
          <div style="font-size:12px;color:#888;margin-top:2px;">\${u.email}</div>
          <div style="font-size:12px;color:#1976d2;margin-top:2px;">Tap to chat</div>
        </div>
      \`;
      card.onclick = () => openChatWindow(u.email, name, avatarSrc);
      resultsDiv.appendChild(card);
    });
  } catch(e) {
    resultsDiv.innerHTML = "<p style='color:red;text-align:center;font-size:13px;'>Error loading users</p>";
  }
}

// فتح نافذة المحادثة
function openChatWindow(targetEmail, targetName, targetAvatar){
  _chatTargetEmail = targetEmail;
  document.getElementById("chatHeaderName").innerText = targetName;
  let avatarEl = document.getElementById("chatHeaderAvatar");
  if(targetAvatar){
    avatarEl.innerHTML = \`<img src="\${targetAvatar}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">\`;
  } else {
    avatarEl.innerText = targetName.charAt(0).toUpperCase();
    avatarEl.style.background = "rgba(255,255,255,0.3)";
  }
  document.getElementById("convListPanel").style.display = "none";
  let cw = document.getElementById("chatWindow");
  cw.style.display = "flex";
  cw.style.flexDirection = "column";
  document.getElementById("chatMessages").innerHTML = "";
  document.getElementById("chatInput").value = "";
  loadChatMessages();
  if(_chatInterval) clearInterval(_chatInterval);
  _chatInterval = setInterval(loadChatMessages, 2000);
}

function closeChatWindow(){
  document.getElementById("chatWindow").style.display = "none";
  document.getElementById("convListPanel").style.display = "flex";
  document.getElementById("convListPanel").style.flexDirection = "column";
  _chatTargetEmail = null;
  if(_chatInterval){ clearInterval(_chatInterval); _chatInterval = null; }
}

// تحميل رسائل المحادثة
async function loadChatMessages(){
  if(!_chatTargetEmail) return;
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  if(!me.email) return;
  try {
    let r = await fetch("/user-chat/" + encodeURIComponent(me.email) + "/" + encodeURIComponent(_chatTargetEmail));
    let msgs = await r.json();
    let container = document.getElementById("chatMessages");
    let wasAtBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 60;
    container.innerHTML = "";
    msgs.forEach(m => {
      let isMe = m.fromEmail === me.email;
      let myName = me.username || localStorage.getItem("username_" + me.email) || me.email.split("@")[0];
      let myAvatar = localStorage.getItem("avatar_" + me.email);
      let myInitial = myName.charAt(0).toUpperCase();
      let theirName = document.getElementById("chatHeaderName").innerText;
      let theirAvatar = document.getElementById("chatHeaderAvatar").querySelector("img") ? document.getElementById("chatHeaderAvatar").querySelector("img").src : null;
      let theirInitial = theirName.charAt(0).toUpperCase();

      let avatarHtml = isMe
        ? (myAvatar ? \`<img src="\${myAvatar}" style="width:34px;height:34px;border-radius:50%;object-fit:cover;flex-shrink:0;">\` : \`<div style="width:34px;height:34px;border-radius:50%;background:#1976d2;color:white;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold;flex-shrink:0;">\${myInitial}</div>\`)
        : (theirAvatar ? \`<img src="\${theirAvatar}" style="width:34px;height:34px;border-radius:50%;object-fit:cover;flex-shrink:0;">\` : \`<div style="width:34px;height:34px;border-radius:50%;background:#42a5f5;color:white;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold;flex-shrink:0;">\${theirInitial}</div>\`);

      let nameLabel = isMe ? myName : theirName;

      let row = document.createElement("div");
      row.style.cssText = "display:flex;align-items:flex-end;gap:8px;" + (isMe ? "flex-direction:row-reverse;" : "");
      row.innerHTML = \`
        \${avatarHtml}
        <div style="max-width:68%;display:flex;flex-direction:column;align-items:\${isMe?'flex-end':'flex-start'};">
          <div style="font-size:11px;color:#999;margin-bottom:3px;">\${nameLabel}</div>
          <div style="background:\${isMe?'#1976d2':'white'};color:\${isMe?'white':'#222'};padding:\${m.img?'4px':'9px 13px'};border-radius:\${isMe?'18px 18px 4px 18px':'18px 18px 18px 4px'};font-size:14px;line-height:1.4;box-shadow:0 1px 3px rgba(0,0,0,0.1);max-width:100%;">\${m.img ? '<img src="'+m.img+'" style="max-width:220px;max-height:260px;border-radius:12px;display:block;cursor:pointer;" onclick="viewFullImg(this.src)">' : m.text}</div>
          <div style="font-size:10px;color:#bbb;margin-top:3px;">\${m.time||""}</div>
        </div>
      \`;
      container.appendChild(row);
    });
    if(wasAtBottom || msgs.length === 0) container.scrollTop = container.scrollHeight;
  } catch(e){ console.error(e); }
}

// إرسال رسالة نصية
async function sendChatMsg(){
  let input = document.getElementById("chatInput");
  let text = input.value.trim();
  if(!text || !_chatTargetEmail) return;
  input.value = "";
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  try {
    await fetch("/user-send", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ fromEmail: me.email, toEmail: _chatTargetEmail, text })
    });
    loadChatMessages();
    loadConversations();
  } catch(e){ alert("Failed to send ❌"); }
}

// إرسال صورة
function sendChatImage(input){
  if(!input.files || !input.files[0] || !_chatTargetEmail) return;
  let file = input.files[0];
  if(file.size > 5 * 1024 * 1024){ alert("Image too large (max 5MB)"); return; }
  let reader = new FileReader();
  reader.onload = async function(e){
    let imgData = e.target.result; // base64
    let me = JSON.parse(localStorage.getItem("user") || "{}");
    try {
      await fetch("/user-send", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ fromEmail: me.email, toEmail: _chatTargetEmail, text: "", img: imgData })
      });
      loadChatMessages();
      loadConversations();
    } catch(ex){ alert("Failed to send image ❌"); }
    input.value = "";
  };
  reader.readAsDataURL(file);
}

// عرض الصورة كاملة
function viewFullImg(src){
  let overlay = document.createElement("div");
  overlay.style.cssText = "position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.9);z-index:99999;display:flex;align-items:center;justify-content:center;";
  overlay.onclick = () => overlay.remove();
  let img = document.createElement("img");
  img.src = src;
  img.style.cssText = "max-width:95%;max-height:90%;border-radius:10px;";
  overlay.appendChild(img);
  document.body.appendChild(overlay);
}

function addMessage(text){
  // kept for compatibility
}
function showMessages(){
  // kept for compatibility
}
function openMenuPage(){
document.getElementById("menuPage").style.display = "block";
}

function closeMenuPage(){
document.getElementById("menuPage").style.display = "none";
}

function openWallet(){
    window.location.href = "/wallet";
}


function openOrders(){
    window.location.href = "/orders";
}

function openHistory(){
    window.location.href = "/history";
}

function openFav(){
    window.location.href = "/favorites";
}

function openSupport(){
    // مسح الـ badge عند الفتح
    let me = JSON.parse(localStorage.getItem("user") || "{}");
    if(me.email){
        fetch("/get-messages/" + encodeURIComponent(me.email))
            .then(r => r.json())
            .then(msgs => {
                if(msgs.length > 0){
                    let maxId = Math.max(...msgs.map(m => m.id));
                    _lastSeenSupportId = maxId;
                    localStorage.setItem("lastSeenSupportId", maxId);
                }
                let badge = document.getElementById("supportBadge");
                if(badge) badge.style.display = "none";
            }).catch(()=>{});
    }
    window.location.href = "/support";
}

function openMerchant(){
    window.location.href = "/merchant";
}

function openAddress(){
    window.location.href = "/address";
}

function openEmail(){
    window.location.href = "/manage-email";
}

function openPassword(){
    window.location.href = "/account-password";
}

function openTransaction(){
    window.location.href = "/transaction-password";
}

function openCategory(name){
    window.location.href = "/category?name=" + encodeURIComponent(name);
}

</script>

</body>
</html>`);
});

// ================= CATEGORY PAGE =================

// ================= CATEGORY PAGE =================
app.get("/category", (req, res) => {
const cat = req.query.name || "All";

// خريطة اسم القسم -> اسم ملف JSON -> category_id
const CAT_MAP = {
  "Clothing & Accessories":       { file: "products_17_clothing.json",   id: 17,  folder: "17_Clothing_and_Accessories" },
  "Medical Bags and Sunglasses":  { file: "products_19_medical.json",    id: 19,  folder: "19_Medical_Bags_and_Sunglasses" },
  "Shoes":                        { file: "products_20_shoes.json",       id: 20,  folder: "20_Shoes" },
  "Watches":                      { file: "products_21_watches.json",     id: 21,  folder: "21_Watches" },
  "Jewelry":                      { file: "products_22_jewelry.json",     id: 22,  folder: "22_Jewelry" },
  "Electronics":                  { file: "products_27_electronics.json", id: 27,  folder: "27_Electronics" },
  "Smart Home":                   { file: "products_28_smarthome.json",   id: 28,  folder: "28_Smart_Home" },
  "Luxury Brands":                { file: "products_31_luxury.json",      id: 31,  folder: "31_Luxury_Brands" },
  "Beauty and Personal Care":     { file: "products_32_beauty.json",      id: 32,  folder: "32_Beauty_and_Personal_Care" },
  "Mens Fashion":                 { file: "products_34_mens.json",        id: 34,  folder: "34_Mens_Fashion" },
  "Health and Household":         { file: "products_35_health.json",      id: 35,  folder: "35_Health_and_Household" },
  "Home and Kitchen":             { file: "products_36_home.json",        id: 36,  folder: "36_Home_and_Kitchen" }
};

// البحث عن القسم (غير حساس للحالة)
const catKey = Object.keys(CAT_MAP).find(k => k.toLowerCase() === cat.toLowerCase()) || "Clothing & Accessories";
const catInfo = CAT_MAP[catKey];
const CLOUD_NAME = "doabtbdsh";
const CLOUD_BASE = `https://res.cloudinary.com/${CLOUD_NAME}/image/upload/products/${catInfo.folder}`;

// قراءة ملف المنتجات
let products = [];
try {
  const filePath = path.join(__dirname, catInfo.file);
  const raw = fs.readFileSync(filePath, "utf8");
  products = JSON.parse(raw);
} catch(e) {
  products = [];
}

// تحويل المنتجات لصيغة مناسبة للفرونت
const productsForFront = products.map(function(p) {
  // بناء رابط الصورة الأولى من Cloudinary
  const folder = p.folder || "";
  const firstImg = folder ? (CLOUD_BASE + "/" + folder + "/1.jpg") : "";
  // بناء قائمة الصور (1.jpg إلى آخر رقم)
  const imgCount = (p.images && p.images.length) ? p.images.length : (p.images_count || 6);
  const imgs = [];
  for(let i = 1; i <= Math.min(imgCount, 8); i++) {
    if(folder) imgs.push(CLOUD_BASE + "/" + folder + "/" + i + ".jpg");
  }
  return {
    id: p.id || p.product_id || "",
    t: p.title || p.name || "",
    p: parseFloat(p.price) || 0,
    img: firstImg,
    imgs: imgs.length > 0 ? imgs : [firstImg],
    rating: parseFloat(p.rating) || 5.0,
    sales: parseInt(p.sales) || 0,
    description: p.description || "",
    colors: p.colors || [],
    sizes: p.sizes || [],
    folder: folder,
    cat: catKey
  };
});

const productsJSON = JSON.stringify(productsForFront);
const totalCount = productsForFront.length;

const pageHTML = `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${catKey}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Arial,sans-serif;background:#f5f5f5;padding-top:100px;min-height:100vh;}
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:fixed;top:0;left:0;right:0;z-index:300;}
.h-left{display:flex;align-items:center;gap:10px;}
.h-right{display:flex;align-items:center;gap:14px;}
.toolbar{display:flex;align-items:center;background:white;padding:12px 20px;border-bottom:1px solid #eee;position:fixed;top:50px;left:0;right:0;z-index:200;}
.sort-btn{flex:1;text-align:center;font-size:15px;color:#333;cursor:pointer;position:relative;}
.sep{width:1px;height:20px;background:#ddd;margin:0 10px;}
.filter-btn{flex:1;text-align:center;font-size:15px;color:#333;cursor:pointer;}
/* Sort dropdown */
.sort-dropdown{display:none;position:fixed;top:100px;left:0;right:0;background:white;z-index:400;border-bottom:1px solid #eee;box-shadow:0 2px 8px rgba(0,0,0,0.08);}
.sort-item{padding:15px 20px;font-size:15px;color:#333;border-bottom:1px solid #f0f0f0;cursor:pointer;display:flex;align-items:center;justify-content:space-between;}
.sort-item:last-child{border-bottom:none;}
.sort-item.active{color:#1976d2;}
.sort-item .sort-arrows{color:#999;font-size:12px;}
/* Filter panel */
.filter-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;z-index:500;}
.filter-left{position:absolute;top:0;left:0;width:36%;height:100%;background:rgba(0,0,0,0.45);}
.filter-panel{position:fixed;top:0;right:0;width:64%;height:100%;background:white;padding:24px 16px 16px;display:flex;flex-direction:column;}
.filter-price-label{font-size:16px;font-weight:400;color:#333;margin-bottom:18px;}
.price-inputs{display:flex;align-items:center;gap:10px;}
.price-input{flex:1;border:1.5px solid #e0e0e0;border-radius:10px;padding:13px 12px;font-size:14px;color:#888;outline:none;background:#fff;min-width:0;}
.price-input:focus{border-color:#bbb;color:#333;}
.price-arrow{color:#bbb;font-size:18px;flex-shrink:0;}
.filter-footer{display:flex;gap:10px;padding:16px 0 0;margin-top:20px;}
.filter-clear-btn{flex:1;padding:15px;border:none;border-radius:14px;background:#f0f0f0;font-size:16px;color:#333;cursor:pointer;text-align:center;font-weight:400;}
.filter-confirm-btn{flex:1;padding:15px;border:none;border-radius:14px;background:#111;color:white;font-size:16px;cursor:pointer;text-align:center;font-weight:600;}
/* Count bar */
.count-bar{background:white;text-align:center;padding:8px;font-size:14px;color:#555;border-bottom:1px solid #f0f0f0;}
/* Grid - 2 columns */
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:#e0e0e0;}
.pcard{background:white;cursor:pointer;}
.pcard img{width:100%;aspect-ratio:3/4;object-fit:cover;display:block;background:#f9f9f9;}
.pcard .name{font-size:13px;color:#222;padding:6px 8px 3px;line-height:1.4;max-height:42px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;}
.pcard .price{color:#1976d2;font-weight:bold;font-size:14px;padding:3px 8px 10px;}
.spinner{text-align:center;padding:20px;color:#999;font-size:13px;display:none;}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="h-left">
    <span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;margin-left:8px;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  </div>
  <div class="h-right">
    <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
</div>

<!-- SORT DROPDOWN -->
<div class="sort-dropdown" id="sortDropdown">
  <div class="sort-item active" id="si-rec" onclick="setSort('rec')">Recommendation</div>
  <div class="sort-item" id="si-sales" onclick="setSort('sales')">Sales</div>
  <div class="sort-item" id="si-price" onclick="setSort('price')">Price <span class="sort-arrows">&#9650;&#9660;</span></div>
</div>

<!-- TOOLBAR -->
<div class="toolbar">
  <div class="sort-btn" id="sortBtn" onclick="toggleSort()">Sort &#9660;</div>
  <div class="sep"></div>
  <div class="filter-btn" onclick="openFilter()">Filter</div>
</div>

<!-- FILTER OVERLAY -->
<div class="filter-overlay" id="filterOverlay">
  <div class="filter-left" onclick="closeFilter()"></div>
  <div class="filter-panel">
    <div class="filter-price-label">Price range</div>
    <div class="price-inputs">
      <input class="price-input" id="filterMin" type="number" placeholder="Lowest price" min="0">
      <span class="price-arrow">&#8212;</span>
      <input class="price-input" id="filterMax" type="number" placeholder="Highest price" min="0">
    </div>
    <div class="filter-footer">
      <div class="filter-clear-btn" onclick="clearFilter()">Clear</div>
      <div class="filter-confirm-btn" onclick="confirmFilter()">Confirm</div>
    </div>
  </div>
</div>

<div class="count-bar" id="countBar">${totalCount} Items</div>
<div class="grid" id="grid"></div>
<div class="spinner" id="spinner">Loading...</div>

<script>
var ALL = ${productsJSON};
var PAGE = 40;
var page = 0;
var sortMode = "rec";
var loading = false;
var filterMin = null;
var filterMax = null;
var FILTERED = null;
var sortOpen = false;

function toggleSort(){
  sortOpen = !sortOpen;
  document.getElementById("sortDropdown").style.display = sortOpen ? "block" : "none";
}

function setSort(mode){
  sortMode = mode;
  sortOpen = false;
  document.getElementById("sortDropdown").style.display = "none";
  ["rec","sales","price"].forEach(function(m){
    document.getElementById("si-"+m).className = "sort-item" + (m===mode?" active":"");
  });
  page = 0;
  document.getElementById("grid").innerHTML = "";
  var src = FILTERED !== null ? FILTERED : ALL;
  document.getElementById("countBar").innerText = src.length.toLocaleString() + " Items";
  appendPage();
}

function openFilter(){
  if(sortOpen){ sortOpen=false; document.getElementById("sortDropdown").style.display="none"; }
  document.getElementById("filterOverlay").style.display = "block";
  if(filterMin !== null) document.getElementById("filterMin").value = filterMin;
  if(filterMax !== null) document.getElementById("filterMax").value = filterMax;
}

function closeFilter(){
  document.getElementById("filterOverlay").style.display = "none";
}

function clearFilter(){
  filterMin = null; filterMax = null;
  FILTERED = null;
  document.getElementById("filterMin").value = "";
  document.getElementById("filterMax").value = "";
  closeFilter();
  page = 0;
  document.getElementById("grid").innerHTML = "";
  document.getElementById("countBar").innerText = ALL.length.toLocaleString() + " Items";
  appendPage();
}

function confirmFilter(){
  var mn = document.getElementById("filterMin").value.trim();
  var mx = document.getElementById("filterMax").value.trim();
  filterMin = mn !== "" ? parseFloat(mn) : null;
  filterMax = mx !== "" ? parseFloat(mx) : null;
  FILTERED = ALL.filter(function(p){
    if(filterMin !== null && p.p < filterMin) return false;
    if(filterMax !== null && p.p > filterMax) return false;
    return true;
  });
  closeFilter();
  page = 0;
  document.getElementById("grid").innerHTML = "";
  document.getElementById("countBar").innerText = FILTERED.length.toLocaleString() + " Items";
  appendPage();
}

function applySort(arr){
  var s = arr.slice();
  if(sortMode === "sales")  s.sort(function(a,b){ return (b.sales||0)-(a.sales||0); });
  if(sortMode === "price")  s.sort(function(a,b){ return a.p - b.p; });
  return s;
}

function appendPage(){
  if(loading) return;
  var source = FILTERED !== null ? FILTERED : ALL;
  var sorted = applySort(source);
  var start = page * PAGE;
  var chunk = sorted.slice(start, start + PAGE);
  if(!chunk.length) return;
  loading = true;
  document.getElementById("spinner").style.display = "block";
  setTimeout(function(){
    var g = document.getElementById("grid");
    chunk.forEach(function(p){
      var d = document.createElement("div");
      d.className = "pcard";
      var im = document.createElement("img");
      im.loading = "lazy";
      im.src = p.img;
      im.onerror = function(){ this.onerror=null; this.src=""; };
      var nm = document.createElement("div"); nm.className="name"; nm.innerText=p.t;
      var pr = document.createElement("div"); pr.className="price"; pr.innerText="US$"+p.p.toFixed(2);
      d.appendChild(im); d.appendChild(nm); d.appendChild(pr);
      (function(prod){
        d.onclick = function(){
          var catName = decodeURIComponent(window.location.search.replace(/.*name=/,"").split("&")[0]||"");
          prod.cat = catName;
          localStorage.setItem("catProduct", JSON.stringify(prod));
          window.location.href = "/cat-product-detail";
        };
      })(p);
      g.appendChild(d);
    });
    document.getElementById("spinner").style.display = "none";
    loading = false;
    page++;
  }, 80);
}

// إغلاق Sort عند الضغط خارجه
document.addEventListener("click", function(e){
  if(sortOpen && !e.target.closest("#sortBtn") && !e.target.closest("#sortDropdown")){
    sortOpen = false;
    document.getElementById("sortDropdown").style.display = "none";
  }
});

// Infinite scroll
window.addEventListener("scroll", function(){
  var source = FILTERED !== null ? FILTERED : ALL;
  if((window.innerHeight + window.scrollY) >= document.body.offsetHeight - 400){
    if(page * PAGE < source.length) appendPage();
  }
});

appendPage();
<\/script>
</body>
</html>`;

res.send(pageHTML);
});
// ================= PRODUCT DETAIL PAGE =================
app.get("/product-detail", (req, res) => {
res.send('<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>*{box-sizing:border-box;}body{margin:0;font-family:Arial;background:#f5f5f5;padding-bottom:70px;padding-top:50px;min-height:100vh;}.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:fixed;top:0;left:0;right:0;z-index:200;}.header .icons span{margin-left:15px;font-size:18px;cursor:pointer;}.main-img{background:white;text-align:center;padding:15px;position:relative;}.main-img img{width:100%;max-height:350px;object-fit:contain;}.main-img .heart{position:absolute;top:15px;left:15px;font-size:22px;cursor:pointer;}.main-img .share{position:absolute;top:15px;right:15px;font-size:22px;cursor:pointer;}.thumbs{display:flex;gap:8px;padding:10px 15px;background:white;overflow-x:auto;}.thumbs img{width:60px;height:60px;object-fit:cover;border-radius:8px;border:2px solid #eee;cursor:pointer;flex-shrink:0;}.thumbs img.active{border-color:#1976d2;}.info{background:white;margin-top:8px;padding:15px;}.info h2{font-size:16px;margin:0 0 10px;color:#222;}.rating-row{display:flex;justify-content:space-between;align-items:center;}.rating-row .stars{color:#1976d2;font-size:14px;}.rating-row .price{color:#1976d2;font-size:24px;font-weight:bold;}.specs{background:white;margin-top:8px;}.spec-row{display:flex;justify-content:space-between;align-items:center;padding:12px 15px;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;}.store{background:white;margin-top:8px;padding:15px;display:flex;align-items:center;gap:10px;}.store img{width:50px;height:50px;border-radius:10px;}.store-info{flex:1;}.store-name{font-weight:bold;font-size:15px;}.vip{background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;padding:2px 8px;border-radius:10px;display:inline-block;margin-top:3px;}.store-tags{display:flex;gap:8px;margin-top:5px;}.store-tags span{background:#eee;font-size:11px;padding:3px 10px;border-radius:10px;}.review{background:white;margin-top:8px;padding:15px;}.review-title{display:flex;justify-content:space-between;font-size:14px;color:#333;}.review-stars{color:#f5a623;font-size:18px;margin-top:5px;}.desc{background:white;margin-top:8px;padding:15px;font-size:13px;color:#444;line-height:1.8;}.desc ul{padding-left:18px;margin:0;}.desc li{margin-bottom:8px;}.bottom-bar{position:fixed;bottom:0;left:0;right:0;background:white;display:flex;align-items:center;padding:10px 15px;border-top:1px solid #eee;gap:10px;}.bottom-bar .icon-btn{font-size:22px;cursor:pointer;}.bottom-bar .cart-btn{flex:1;padding:12px;border:1px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;cursor:pointer;text-align:center;}.bottom-bar .buy-btn{flex:1;padding:12px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;cursor:pointer;text-align:center;}</style></head><body><div class="header"><div><span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span><span onclick="window.location.href=\'\/dashboard\'" style="cursor:pointer;display:inline-flex;align-items:center;margin-left:8px;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span></div><div class="icons"><span onclick="window.location.href=\'\/dashboard?search=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span><span onclick="window.location.href=\'\/dashboard?messages=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span><span onclick="window.location.href=\'\/dashboard?account=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span><span onclick="window.location.href=\'\/dashboard?lang=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span></div></div><div class="main-img"><span class="heart" id="heartBtn" onclick="toggleHeart()">&#129293;</span><img id="mainImg" src=""><span class="share">&#128279;</span></div><div class="thumbs" id="thumbs"></div><div class="info"><h2 id="productTitle"></h2><div class="rating-row"><div class="stars">&#11088; <span style="color:#1976d2;font-weight:bold;">5.0</span> <span style="color:#999;font-size:12px;">(0 Sales)</span></div><div class="price" id="productPrice"></div></div></div><div class="specs"><div class="spec-row"><span>Select</span><span>Brand, specification &#8250;</span></div><div class="spec-row"><span>Shipping fees</span><span>Free shipping</span></div><div class="spec-row"><span>Guarantee</span><span>Free return</span></div></div><div class="store"><img src="https://cdn-icons-png.flaticon.com/512/149/149071.png"><div class="store-info"><div class="store-name">S&amp;R Store</div><div class="vip">&#10004; VIP 0</div><div class="store-tags"><span>Products 20</span><span>Followers 0</span></div></div><span>&#8250;</span></div><div class="review"><div class="review-title"><span>Consumer review</span><span style="color:#1976d2;">0 Unit Global Rating &#8250;</span></div><div class="review-stars">&#11088;&#11088;&#11088;&#11088;&#11088; <span style="font-size:13px;color:#555;">5 Stars</span></div></div><div class="desc"><ul id="descList"></ul></div><div class="bottom-bar"><span class="icon-btn" onclick="window.location.href=\'/live-chat\'">&#127911;</span><span class="icon-btn" onclick="window.location.href=\'/wallet\'">&#128722;</span><div class="cart-btn" onclick="addToCart()">Add to Cart</div><div class="buy-btn" onclick="buyNow()">Buy now</div></div><script>var productId = localStorage.getItem("productId");var isFav = false;fetch("https://fakestoreapi.com/products/" + productId).then(function(r){return r.json();}).then(function(p){document.getElementById("mainImg").src = p.image;var thumbs = document.getElementById("thumbs");for(var i=0;i<5;i++){var img = document.createElement("img");img.src = p.image;if(i===0) img.classList.add("active");img.onclick = function(){document.getElementById("mainImg").src = this.src;document.querySelectorAll(".thumbs img").forEach(function(t){t.classList.remove("active");});this.classList.add("active");};thumbs.appendChild(img);}document.getElementById("productTitle").innerText = p.title;document.getElementById("productPrice").innerText = "$" + p.price;var desc = document.getElementById("descList");var points = p.description ? p.description.split(".").filter(function(s){return s.trim();}) : [p.description];points.forEach(function(point){if(point && point.trim()){var li = document.createElement("li");li.innerText = point.trim();desc.appendChild(li);}});});function toggleHeart(){isFav=!isFav;document.getElementById("heartBtn").innerHTML=isFav?"&#10084;&#65039;":"&#129293;";}function addToCart(){var cart=JSON.parse(localStorage.getItem("cart")||"[]");cart.push(productId);localStorage.setItem("cart",JSON.stringify(cart));alert("Added to cart");}function buyNow(){window.location.href="/wallet";}<\/script></body></html>');
});

// ================= PRODUCT PAGE =================
app.get("/product", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Product</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Arial;background:#f5f5f5;padding-bottom:80px;padding-top:50px;min-height:100vh;}

/* HEADER */
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:fixed;top:0;left:0;right:0;z-index:200;}
.header .icons span{margin-left:15px;font-size:18px;cursor:pointer;}

/* SLIDER */
.slider-wrap{background:white;position:relative;overflow:hidden;}
.slider-imgs{display:flex;transition:transform 0.4s ease;}
.slider-imgs img{min-width:100%;height:320px;object-fit:contain;background:white;}
.slider-dots{display:flex;justify-content:center;gap:6px;padding:10px 0;background:white;}
.dot{width:7px;height:7px;border-radius:50%;background:#ccc;cursor:pointer;transition:background 0.3s;}
.dot.active{background:#1976d2;}
.heart-btn{position:absolute;top:12px;left:12px;font-size:24px;cursor:pointer;z-index:10;}
.share-btn{position:absolute;top:12px;right:12px;font-size:22px;cursor:pointer;z-index:10;}

/* THUMBS */
.thumbs{display:flex;gap:8px;padding:10px 12px;background:white;overflow-x:auto;}
.thumbs img{width:58px;height:58px;object-fit:cover;border-radius:8px;border:2px solid #eee;cursor:pointer;flex-shrink:0;}
.thumbs img.active{border-color:#1976d2;}

/* INFO */
.info{background:white;margin-top:8px;padding:15px;}
.price-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
.price{color:#1976d2;font-size:26px;font-weight:bold;}
.rating{color:#1976d2;font-size:13px;}
.prod-title{font-size:15px;color:#222;line-height:1.5;margin-bottom:10px;}

/* SPECS */
.specs{background:white;margin-top:8px;}
.spec-row{display:flex;justify-content:space-between;align-items:center;padding:13px 15px;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;}
.spec-row span:last-child{color:#999;}

/* STORE */
.store{background:white;margin-top:8px;padding:15px;display:flex;align-items:center;gap:12px;cursor:pointer;}
.store img{width:52px;height:52px;border-radius:10px;object-fit:cover;}
.store-name{font-weight:bold;font-size:15px;}
.vip-badge{background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;padding:2px 8px;border-radius:10px;display:inline-block;margin-top:3px;}
.store-tags{display:flex;gap:8px;margin-top:5px;}
.store-tags span{background:#eee;font-size:11px;padding:3px 10px;border-radius:10px;}

/* REVIEW */
.review{background:white;margin-top:8px;padding:15px;}
.review-top{display:flex;justify-content:space-between;font-size:14px;color:#333;}
.stars{color:#f5a623;font-size:18px;margin-top:5px;}

/* DESC */
.desc{background:white;margin-top:8px;padding:15px;font-size:13px;color:#444;line-height:1.8;}

/* BOTTOM BAR */
.bottom-bar{position:fixed;bottom:0;left:0;right:0;background:white;display:flex;align-items:center;padding:10px 15px;border-top:1px solid #eee;gap:10px;z-index:200;}
.icon-btn{font-size:22px;cursor:pointer;}
.cart-btn{flex:1;padding:13px;border:1.5px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;cursor:pointer;text-align:center;font-weight:bold;}
.buy-btn{flex:1;padding:13px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;cursor:pointer;text-align:center;font-weight:bold;}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div>
    <span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;margin-left:8px;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  </div>
  <div class="icons">
    <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
</div>

<!-- SLIDER -->
<div class="slider-wrap">
  <span class="heart-btn" id="heartBtn" onclick="toggleHeart()">&#129293;</span>
  <span class="share-btn">&#128279;</span>
  <div class="slider-imgs" id="sliderImgs"></div>
  <div class="slider-dots" id="sliderDots"></div>
</div>

<!-- THUMBS -->
<div class="thumbs" id="thumbs"></div>

<!-- INFO -->
<div class="info">
  <div class="price-row">
    <div class="price" id="productPrice"></div>
    <div class="rating">&#11088; <b>5.0</b> <span style="color:#999;">(0 Sales)</span></div>
  </div>
  <div class="prod-title" id="productTitle"></div>
</div>

<!-- SPECS -->
<div class="specs">
  <div class="spec-row"><span>Select</span><span>Brand, specification &#8250;</span></div>
  <div class="spec-row"><span>Shipping fees</span><span>Free shipping</span></div>
  <div class="spec-row"><span>Guarantee</span><span>Free return &nbsp; Fake return tripled</span></div>
</div>

<!-- STORE -->
<div class="store" onclick="window.location.href='/store-page'">
  <img src="https://cdn-icons-png.flaticon.com/512/149/149071.png" id="storeLogo">
  <div style="flex:1;">
    <div class="store-name" id="storeName">TikTok Mall Store</div>
    <div class="vip-badge">&#10004; VIP 3</div>
    <div class="store-tags">
      <span>Products 150</span>
      <span>Followers 79</span>
    </div>
  </div>
  <span style="color:#999;">&#8250;</span>
</div>

<!-- REVIEW -->
<div class="review">
  <div class="review-top">
    <span>Consumer review</span>
    <span style="color:#1976d2;">0 Unit Global Rating &#8250;</span>
  </div>
  <div class="stars">&#11088;&#11088;&#11088;&#11088;&#11088; <span style="font-size:13px;color:#555;">5 Stars</span></div>
</div>

<!-- DESC -->
<div class="desc" id="productDesc"></div>

<!-- BOTTOM BAR -->
<div class="bottom-bar">
  <span class="icon-btn" onclick="window.location.href='/live-chat'">&#127911;</span>
  <span class="icon-btn" onclick="window.location.href='/wallet'">&#128722;</span>
  <div class="cart-btn" onclick="addToCart()">Add to Cart</div>
  <div class="buy-btn" onclick="buyNow()">Buy now</div>
</div>

<script>
var id = localStorage.getItem("productId") || "1";
var isFav = false;
var currentSlide = 0;
var images = [];

// منتجات محلية مخصصة
var localProducts = {
  "local_1": {
    title: "Apple iPhone 17 Pro Max - 256GB - Natural Titanium",
    price: 1299.99,
    images: [
      "https://images.unsplash.com/photo-1510557880182-3d4d3cba35a5?w=600&q=80",
      "https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=600&q=80",
      "https://images.unsplash.com/photo-1611532736597-de2d4265fba3?w=600&q=80",
      "https://images.unsplash.com/photo-1605236453806-6ff36851218e?w=600&q=80"
    ],
    description: "iPhone 17 Pro Max features a grade-5 titanium design, the thinnest borders ever on an Apple product, and the most advanced display. A18 Pro chip with 6-core GPU delivers incredible performance. 5x Optical zoom camera system. All-day battery life with up to 33 hours video playback. Supports USB 3 for up to 2x faster transfers. Emergency SOS via satellite."
  },
  "local_2": {
    title: "Apple MacBook Pro 16-inch M4 Pro - Space Black",
    price: 2499.00,
    images: [
      "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=600&q=80",
      "https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=600&q=80",
      "https://images.unsplash.com/photo-1541807084-5c52b6b3adef?w=600&q=80",
      "https://images.unsplash.com/photo-1484788984921-03950022c9ef?w=600&q=80"
    ],
    description: "MacBook Pro with M4 Pro chip delivers exceptional performance for professionals. Features a stunning 16-inch Liquid Retina XDR display, up to 24 hours of battery life, and a next-generation camera and audio system. With up to 64GB unified memory and 8TB SSD storage."
  },
  "local_3": {
    title: "ASUS 2025 ROG Strix G16 Gaming Laptop - Intel Core i7 - RTX 5060",
    price: 2299.00,
    images: [
      "https://images.unsplash.com/photo-1603302576837-37561b2e2302?w=600&q=80",
      "https://images.unsplash.com/photo-1593640408182-31c228fa7bf9?w=600&q=80",
      "https://images.unsplash.com/photo-1525547719571-a2d4ac8945e2?w=600&q=80",
      "https://images.unsplash.com/photo-1587202372775-e229f172b9d7?w=600&q=80"
    ],
    description: "ASUS ROG Strix G16 16 inch WUXGA IPS LED-backlit Gaming Laptop. Display: 16 WUXGA (1920x1200) IPS 165Hz Refresh Rate. Processor: Intel Core i7-14650HX 16-Core. Graphics: NVIDIA GeForce RTX 5060 8GB GDDR7. Memory: 64GB DDR5 SDRAM. Storage: 4TB NVMe M.2 SSD. RGB Backlit Keyboard. Wi-Fi 7. Windows 11 Home."
  },
  "local_4": {
    title: "Sony Alpha A7 IV Full-Frame Mirrorless Camera",
    price: 2498.00,
    images: [
      "https://images.unsplash.com/photo-1516035069371-29a1b244cc32?w=600&q=80",
      "https://images.unsplash.com/photo-1502982720700-bfff97f2ecac?w=600&q=80",
      "https://images.unsplash.com/photo-1526170375885-4d8ecf77b99f?w=600&q=80",
      "https://images.unsplash.com/photo-1617005082133-548c4dd27f35?w=600&q=80"
    ],
    description: "Sony Alpha A7 IV 33MP full-frame Exmor R BSI CMOS sensor. 4K 60p video recording. Real-time Eye AF for humans, animals and birds. 10fps continuous shooting. 5-axis in-body image stabilization. Dual card slots. Weather-sealed body. Perfect for professional photography and videography."
  },
  "local_5": {
    title: "Samsung Galaxy S25 Ultra - 512GB - Titanium Black",
    price: 1299.99,
    images: [
      "https://images.unsplash.com/photo-1610945415295-d9bbf067e59c?w=600&q=80",
      "https://images.unsplash.com/photo-1592899677977-9c10ca588bbd?w=600&q=80",
      "https://images.unsplash.com/photo-1574755393849-623942496936?w=600&q=80",
      "https://images.unsplash.com/photo-1585060544812-6b45742d762f?w=600&q=80"
    ],
    description: "Samsung Galaxy S25 Ultra with Snapdragon 8 Elite processor. 200MP quad rear camera system with 100x Space Zoom. Built-in S Pen with AI features. 6.9-inch QHD+ Dynamic AMOLED 2X display at 120Hz. 5000mAh battery with 45W fast charging. 12GB RAM with 512GB storage."
  },
  "local_6": {
    title: "Apple iPad Pro 13-inch M4 - 256GB WiFi",
    price: 1099.00,
    images: [
      "https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=600&q=80",
      "https://images.unsplash.com/photo-1561154464-82e9adf32764?w=600&q=80",
      "https://images.unsplash.com/photo-1587033411391-5d9e51cce126?w=600&q=80",
      "https://images.unsplash.com/photo-1589739900243-4b52cd9b104e?w=600&q=80"
    ],
    description: "iPad Pro with M4 chip is the thinnest Apple product ever. Ultra Retina XDR display with nano-texture glass. Apple Pencil Pro and Magic Keyboard support. 13-inch tandem OLED display with ProMotion technology. 10-core CPU and 10-core GPU. Advanced camera system with LiDAR scanner."
  },
  "local_7": {
    title: "Apple Watch Ultra 2 - 49mm Titanium",
    price: 799.00,
    images: [
      "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=600&q=80",
      "https://images.unsplash.com/photo-1434494878577-86c23bcb06b9?w=600&q=80",
      "https://images.unsplash.com/photo-1508685096489-7aacd43bd3b1?w=600&q=80",
      "https://images.unsplash.com/photo-1546868871-7041f2a55e12?w=600&q=80"
    ],
    description: "Apple Watch Ultra 2 is the most capable and rugged Apple Watch. 49mm titanium case. Up to 60 hours battery life with low-power mode. Built for extreme environments. Precision dual-frequency GPS. Action button for instant access. Depth gauge and water temperature sensor. S9 SiP chip."
  },
  "local_8": {
    title: "Sony WH-1000XM5 Wireless Noise Canceling Headphones",
    price: 348.00,
    images: [
      "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=600&q=80",
      "https://images.unsplash.com/photo-1484704849700-f032a568e944?w=600&q=80",
      "https://images.unsplash.com/photo-1546435770-a3e426bf472b?w=600&q=80",
      "https://images.unsplash.com/photo-1583394838336-acd977736f90?w=600&q=80"
    ],
    description: "Sony WH-1000XM5 with industry-leading noise canceling technology. 30 hours battery life with quick charge. Multipoint connection to two devices simultaneously. Crystal clear hands-free calling with 4 beamforming microphones. Auto Noise Canceling Optimizer. Speak-to-Chat technology."
  },
  "local_9": {
    title: "DJI Phantom 4 Pro V2 Drone - 4K Camera",
    price: 1599.00,
    images: [
      "https://images.unsplash.com/photo-1473968512647-3e447244af8f?w=600&q=80",
      "https://images.unsplash.com/photo-1508614999368-9260051292e5?w=600&q=80",
      "https://images.unsplash.com/photo-1533310266094-8898a03807dd?w=600&q=80",
      "https://images.unsplash.com/photo-1579829366248-204fe8413f31?w=600&q=80"
    ],
    description: "DJI Phantom 4 Pro V2 features a 1-inch 20MP CMOS sensor capable of shooting 4K/60fps video. Mechanical shutter eliminates rolling shutter distortion. 30-minute max flight time. OcuSync 2.0 transmission system with a range of up to 8km. Obstacle sensing in 5 directions."
  },
  "local_10": {
    title: "Apple iPhone 17 Pro Max - 512GB - Desert Titanium",
    price: 1399.99,
    images: [
      "https://images.unsplash.com/photo-1695048133142-1a20484d2569?w=600&q=80",
      "https://images.unsplash.com/photo-1510557880182-3d4d3cba35a5?w=600&q=80",
      "https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=600&q=80",
      "https://images.unsplash.com/photo-1611532736597-de2d4265fba3?w=600&q=80"
    ],
    description: "The all-new iPhone 17 Pro Max in Desert Titanium. Features Apple's most powerful A18 Pro chip, a stunning 6.9-inch Super Retina XDR ProMotion display with always-on technology. ProCamera system with 5x Optical Zoom, 48MP Main camera, and Action button. Titanium design with Ceramic Shield front. Up to 33 hours battery life."
  },
  "local_11": {
    title: "Samsung 65-inch QLED 4K Smart TV - QN65Q80C",
    price: 1197.99,
    images: [
      "https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?w=600&q=80",
      "https://images.unsplash.com/photo-1461151304267-38535e780c79?w=600&q=80",
      "https://images.unsplash.com/photo-1539786774582-0707555f1f72?w=600&q=80",
      "https://images.unsplash.com/photo-1567690187548-f07b1d7bf5a9?w=600&q=80"
    ],
    description: "Samsung 65-inch QLED 4K Smart TV with Quantum Dot technology delivers brilliant color. 4K AI Upscaling Pro. Quantum HDR+ for spectacular contrast. Real Game Enhancer+ with 144Hz refresh rate. Object Tracking Sound. Alexa and Google Assistant built-in. Motion Xcelerator Turbo+ technology."
  },
  "local_12": {
    title: "Gucci Marmont Matelassé Mini Bag - Black Leather",
    price: 1350.00,
    images: [
      "https://images.unsplash.com/photo-1548036328-c9fa89d128fa?w=600&q=80",
      "https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=600&q=80",
      "https://images.unsplash.com/photo-1591561954557-26941169b49e?w=600&q=80",
      "https://images.unsplash.com/photo-1566150905458-1bf1fc113f0d?w=600&q=80"
    ],
    description: "Gucci Marmont Matelassé Mini Bag in soft black leather with gold-toned hardware. Chevron quilted leather with a GG logo. Adjustable and removable shoulder strap. Internal zip pocket. Suede lining. Made in Italy. This iconic design is a timeless addition to any wardrobe."
  }
};

function buildSlider(imgs) {
  images = imgs;
  var wrap = document.getElementById("sliderImgs");
  var dots = document.getElementById("sliderDots");
  var thumbsEl = document.getElementById("thumbs");
  wrap.innerHTML = "";
  dots.innerHTML = "";
  thumbsEl.innerHTML = "";

  imgs.forEach(function(src, i) {
    // صورة slider
    var img = document.createElement("img");
    img.src = src;
    img.onerror = function(){ this.src="https://via.placeholder.com/400x300?text=No+Image"; };
    wrap.appendChild(img);

    // dot
    var dot = document.createElement("div");
    dot.className = "dot" + (i===0?" active":"");
    dot.onclick = (function(idx){ return function(){ goSlide(idx); }; })(i);
    dots.appendChild(dot);

    // thumb
    var th = document.createElement("img");
    th.src = src;
    th.className = (i===0?"active":"");
    th.onclick = (function(idx){ return function(){ goSlide(idx); }; })(i);
    thumbsEl.appendChild(th);
  });

  // Auto slide كل 3 ثواني
  setInterval(function(){
    goSlide((currentSlide + 1) % images.length);
  }, 3000);
}

function goSlide(idx) {
  currentSlide = idx;
  document.getElementById("sliderImgs").style.transform = "translateX(-" + (idx * 100) + "%)";
  document.querySelectorAll(".dot").forEach(function(d,i){ d.className = "dot" + (i===idx?" active":""); });
  document.querySelectorAll(".thumbs img").forEach(function(t,i){ t.className = (i===idx?"active":""); });
}

// تحميل المنتج
if(id && id.startsWith("local_")) {
  var p = localProducts[id];
  if(p) {
    document.getElementById("productTitle").innerText = p.title;
    document.getElementById("productPrice").innerText = "\$" + p.price.toLocaleString();
    document.getElementById("productDesc").innerText = p.description;
    buildSlider(p.images);
  }
} else {
  // منتجات من fakestoreapi
  fetch("https://fakestoreapi.com/products/" + id)
  .then(function(r){ return r.json(); })
  .then(function(p) {
    document.getElementById("productTitle").innerText = p.title;
    document.getElementById("productPrice").innerText = "\$" + p.price;
    document.getElementById("productDesc").innerText = p.description || "";
    buildSlider([p.image, p.image, p.image, p.image]);
  });
}

function toggleHeart(){
  isFav = !isFav;
  document.getElementById("heartBtn").innerHTML = isFav ? "&#10084;&#65039;" : "&#129293;";
}

function addToCart(){
  var cart = JSON.parse(localStorage.getItem("cart") || "[]");
  cart.push(id);
  localStorage.setItem("cart", JSON.stringify(cart));
  alert("Added to cart ✅");
}

function buyNow(){
  window.location.href = "/wallet";
}
</script>

</body>
</html>`);
});

// ================= WALLET PAGE =================
app.get("/wallet", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:#f0f0f0;
padding-top:55px;
min-height:100vh;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:#1976d2;
color:white;
padding:15px;
display:flex;
align-items:center;
gap:10px;
}
.header span{
font-size:20px;
cursor:pointer;
}

/* TABS */
.tabs{
display:flex;
overflow-x:auto;
background:white;
padding:10px 0;
}
.tabs div{
flex:0 0 auto;
padding:10px 20px;
color:#555;
font-size:14px;
cursor:pointer;
}
.tabs .active{
color:#1976d2;
font-weight:bold;
}

/* SCROLL BAR */
.scroll-bar{
height:4px;
background:#ccc;
margin:0 10px;
border-radius:10px;
overflow:hidden;
}
.scroll-indicator{
height:100%;
width:80px;
background:#888;
border-radius:10px;
transition:0.3s;
}

/* CARD */
.card{
margin:15px;
padding:20px;
border-radius:20px;
background:linear-gradient(45deg,#1e88e5,#1565c0);
color:white;
box-shadow:0 10px 30px rgba(0,0,0,0.2);
min-height:120px;
}

.card h3{
margin:0;
font-size:14px;
display:flex;
align-items:center;
gap:10px;
}

.balance{
font-size:32px;
margin:15px 0;
}

.card{
position:relative;
}

.actions{
position:absolute;
right:20px;
top:50%;
transform:translateY(-50%);
display:flex;
flex-direction:column;
gap:10px;
}

.btn{
background:white;
color:#333;
padding:8px 15px;
border-radius:20px;
font-size:14px;
display:flex;
justify-content:space-between;
align-items:center;
cursor:pointer;
}

/* EMPTY */
.empty{
text-align:center;
margin-top:80px;
color:#aaa;
font-size:50px;
}
</style>
</head>

<body>

<!-- HEADER -->
<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<h3 style="margin:0;">Wallet</h3>
</div>

<!-- TABS -->
<div class="tabs" id="tabs">
<div class="active">View All</div>
<div>Product transaction</div>
<div>Group</div>
<div onclick="goRecharge()">Recharge</div>
<div>Withdrawal</div>
<div>Refund</div>
<div>System business</div>
<div>Delivery deduction</div>
</div>

<div class="scroll-bar">
<div class="scroll-indicator" id="indicator"></div>
</div>

<!-- CARD -->
<div class="card">

  <div class="left">
    <h3>Account balance 👁️</h3>
    <div class="balance" id="balance">0.00</div>
    <div>Available balance</div>
  </div>

  <div class="actions">
    <div class="btn" onclick="recharge()">Recharge ▶</div>
    <div class="btn" onclick="withdraw()">Withdrawal ▶</div>
  </div>

</div>

<div class="empty">📄</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));

async function loadRealBalance(){

    let email = user.email;

    let res = await fetch("/users");
    let users = await res.json();

    let realUser = users.find(u => u.email === email);

    if(realUser){
        document.getElementById("balance").innerText = Number(realUser.balance).toFixed(2);
    }
}

loadRealBalance();

// BACK
function goBack(){
window.location.href="/dashboard";
}

// BUTTONS
function recharge(){
    window.location.href = "/recharge";
}   

function withdraw(){
    window.location.href = "/withdraw";
}

// TAB SCROLL EFFECT
let tabs = document.getElementById("tabs");
let indicator = document.getElementById("indicator");

tabs.addEventListener("scroll", ()=>{
let maxScroll = tabs.scrollWidth - tabs.clientWidth;
if(maxScroll <= 0) return;
let percent = tabs.scrollLeft / maxScroll;
indicator.style.width = (percent * 100 + 20) + "%";
});

// DRAG ON INDICATOR
(function(){
  let scrollBar = indicator.parentElement;
  let isDragging = false;
  let startX = 0;
  let startScrollLeft = 0;

  function onDragStart(e){
    isDragging = true;
    startX = (e.touches ? e.touches[0].clientX : e.clientX);
    startScrollLeft = tabs.scrollLeft;
    e.preventDefault();
  }
  function onDragMove(e){
    if(!isDragging) return;
    let x = (e.touches ? e.touches[0].clientX : e.clientX);
    let dx = x - startX;
    let barWidth = scrollBar.clientWidth;
    let maxScroll = tabs.scrollWidth - tabs.clientWidth;
    tabs.scrollLeft = startScrollLeft + (dx / barWidth) * maxScroll;
    e.preventDefault();
  }
  function onDragEnd(){ isDragging = false; }

  scrollBar.addEventListener("mousedown", onDragStart);
  scrollBar.addEventListener("touchstart", onDragStart, {passive:false});
  window.addEventListener("mousemove", onDragMove);
  window.addEventListener("touchmove", onDragMove, {passive:false});
  window.addEventListener("mouseup", onDragEnd);
  window.addEventListener("touchend", onDragEnd);
})();

</script>

</body>
</html>`);
});// ================= RECHARGE PAGE =================
app.get("/recharge", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:#f2f2f2;
padding-top:60px;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
display:flex;
align-items:center;
padding:15px;
font-size:18px;
background:#f5f5f5;
}
.header span{
font-size:20px;
cursor:pointer;
margin-right:10px;
}

/* CARD */
.card{
background:white;
margin:10px;
padding:15px;
border-radius:20px;
}

/* PAYMENTS */
.payments{
display:flex;
gap:10px;
margin-bottom:15px;
}
.payments div{
flex:1;
background:#f5f5f5;
padding:15px;
border-radius:15px;
text-align:center;
font-weight:bold;
}

/* NETWORK */
.network{
margin-top:10px;
}
.network button{
padding:8px 20px;
border-radius:20px;
border:1px solid #ccc;
background:white;
margin-right:10px;
cursor:pointer;
}
.network .active{
background:#1976d2;
color:white;
border:none;
}

/* ADDRESS */
.address{
margin-top:10px;
font-size:12px;
word-break:break-all;
}

/* QR */
.qr{
text-align:center;
margin:15px 0;
}
.qr img{
width:150px;
}

/* INPUT */
input{
width:100%;
padding:12px;
border-radius:10px;
border:1px solid #ccc;
margin-top:10px;
}

/* UPLOAD */
.upload{
margin-top:15px;
background:#f5f5f5;
height:80px;
display:flex;
justify-content:center;
align-items:center;
border-radius:10px;
cursor:pointer;
}

/* BUTTON */
.confirm{
margin:20px;
}
.confirm button{
width:100%;
padding:15px;
border:none;
border-radius:10px;
background:#1976d2;
color:white;
font-size:16px;
cursor:pointer;
}
</style>
</head>

<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>Recharge</b>
</div>

<div class="card">

<!-- PAYMENTS -->
<div class="payments">
<div>₮</div>
<div>VISA</div>
<div>Master</div>
<div>PayPal</div>
</div>

<!-- NETWORK -->
<div class="network">
<p>Network</p>
<button class="active" onclick="setNet(this,'TRC20')">TRC20</button>
<button onclick="setNet(this,'ERC20')">ERC20</button>
</div>

<!-- ADDRESS -->
<p>USDT Address</p>
<div class="address" id="address">Loading...</div>

<!-- QR -->
<div class="qr">
<img id="qr" src=""></div>

<!-- AMOUNT -->
<p>Recharge amount</p>
<input id="amount" placeholder="Please fill in recharge amount">

<!-- UPLOAD -->
<p>Upload transaction record</p>
<div class="upload" onclick="document.getElementById('fileInput').click()">📷</div>

<input type="file" id="fileInput" accept="image/*" style="display:none;">
<img id="preview" style="width:100%;margin-top:10px;border-radius:10px;display:none;">

</div>

<div class="confirm">
<button onclick="confirmRecharge()">Confirm</button>
</div>

<script>
let selectedNet = "TRC20";

// BACK
function goBack(){
window.location.href="/wallet";
}

let fileInput = document.getElementById("fileInput");
let preview = document.getElementById("preview");

fileInput.addEventListener("change", function () {
    let file = this.files[0];

    if (file) {
        let reader = new FileReader();

        reader.onload = function (e) {
            preview.src = e.target.result;
            preview.style.display = "block";

            // حفظ الصورة مؤقت (اختياري)
            localStorage.setItem("rechargeImage", e.target.result);
        };

        reader.readAsDataURL(file);
    }
});

// NETWORK SWITCH
function setNet(btn, net){
selectedNet = net;

document.querySelectorAll(".network button").forEach(b=>b.classList.remove("active"));
btn.classList.add("active");

// مستقبلاً نغير العنوان من السيرفر
if(net === "TRC20"){
document.getElementById("address").innerText = "tt";
}else{
document.getElementById("address").innerText = "tt";
}
}

// UPLOAD (مبدئي)
function uploadImage(){
alert("Upload system will be added later");
}

// ================= CONFIRM =================
function confirmRecharge(){
    let amount = document.getElementById("amount").value;

    if(!amount){
        alert("Enter amount");
        return;
    }

    let user = JSON.parse(localStorage.getItem("user"));

    if(!user){
        alert("User not found ❌");
        return;
    }

    let image = localStorage.getItem("rechargeImage") || "";

    if(!image){
        alert("Upload image ❌");
        return;
    }

    fetch("/request", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            email: user.email,
            amount: amount,
            type: "recharge",
            image: image
        })
    })
    .then(res => res.json())
.then(data => {
    alert("Request sent ✅");
    window.location.href = "/pending";
})
.catch(err => {
    console.log(err);
    alert("Sent but with issue ⚠️");
    window.location.href = "/pending";
});
}

// ================= LOAD ADDRESS =================
async function loadAddress(){

    let res = await fetch("/users");
    let users = await res.json();

    if(users.length === 0){
        document.getElementById("address").innerText = "No address";
        return;
    }

    let user = users[0]; // مؤقت

    let address = user.usdt || "No address";

    // تحديث النص
    document.getElementById("address").innerText = address;

    // تحديث QR
    document.getElementById("qr").src =
        "https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=" + address;
}

loadAddress();

</script>

</body>
</html>`);
});

// ================= WITHDRAW PAGE =================
app.get("/withdraw", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:#f2f2f2;
padding-top:60px;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
display:flex;
align-items:center;
padding:15px;
font-size:18px;
background:#f5f5f5;
}
.header span{
font-size:20px;
cursor:pointer;
margin-right:10px;
}

/* CARD */
.card{
background:white;
margin:10px;
padding:15px;
border-radius:20px;
box-shadow:0 5px 20px rgba(0,0,0,0.05);
}

/* PAYMENTS */
.payments{
display:flex;
gap:10px;
margin-bottom:15px;
}
.payments div{
flex:1;
background:#f5f5f5;
padding:15px;
border-radius:15px;
text-align:center;
font-weight:bold;
}

/* NETWORK */
.network{
margin-top:10px;
}
.network button{
padding:8px 15px;
border-radius:20px;
border:1px solid #ccc;
background:white;
margin:5px;
cursor:pointer;
font-size:12px;
}
.network .active{
background:#1976d2;
color:white;
border:none;
}

/* INPUT */
input{
width:100%;
padding:12px;
border-radius:10px;
border:1px solid #ccc;
margin-top:10px;
}

/* ROW */
.row{
display:flex;
justify-content:space-between;
font-size:13px;
margin-top:5px;
color:#666;
}

/* AMOUNT BOX */
.amount-box{
display:flex;
align-items:center;
border:1px solid #ccc;
border-radius:10px;
padding:10px;
margin-top:10px;
}
.amount-box input{
border:none;
outline:none;
flex:1;
}
.amount-box span{
margin-left:10px;
cursor:pointer;
}

/* CONFIRM */
.confirm{
margin:15px;
}
.confirm button{
width:100%;
padding:15px;
border:none;
border-radius:10px;
background:#1976d2;
color:white;
font-size:16px;
cursor:pointer;
}
</style>
</head>

<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>Withdrawal</b>
</div>

<div class="card">

<!-- PAYMENTS -->
<div class="payments">
<div>₮</div>
<div>VISA</div>
<div>Master</div>
<div>PayPal</div>
</div>

<!-- NETWORK -->
<div class="network">
<p>Withdrawal network</p>
<button class="active" onclick="setNet(this)">ERC20</button>
<button onclick="setNet(this)">TRC20</button>
<button onclick="setNet(this)">HECO</button>
<button onclick="setNet(this)">OMNI</button>
<button onclick="setNet(this)">ALGO</button>
</div>

<!-- ADDRESS -->
<p>USDT address</p>
<input id="address" placeholder="Please fill in withdrawal address">

<div class="row">
<span>Fees</span>
<span>0.00 % USDT</span>
</div>

<!-- AMOUNT -->
<p>Withdrawal amount</p>
<div class="row">
<span></span>
<span id="balanceText">Available 0.00 USDT</span>
</div>

<div class="amount-box">
<input id="amount" placeholder="Minimum number1">
<span>USDT</span>
<span onclick="setAll()">ALL</span>
</div>

<div class="row">
<span>Actual amount</span>
<span id="actual" style="color:red;">0 USDT</span>
</div>

</div>

<div class="confirm">
<button onclick="submitWithdraw()">Confirm</button>
</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));
let selectedNet = "ERC20";
// دالة مساعدة لإرسال requests بتوكن المستخدم
function userFetch(url, options = {}){
    options.headers = options.headers || {};
    const token = (user && user.token) ? user.token : "";
    if(token) options.headers["Authorization"] = "Bearer " + token;
    options.headers["Content-Type"] = options.headers["Content-Type"] || "application/json";
    return fetch(url, options);
}


// جلب الرصيد الحقيقي من السيرفر
async function loadRealBalance(){
    try {
        let res = await fetch("/users");
        let users = await res.json();
        let realUser = users.find(u => u.email === user.email);
        if(realUser){
            user.balance = Number(realUser.balance);
            document.getElementById("balanceText").innerText = "Available " + user.balance.toFixed(2) + " USDT";
        }
    } catch(e){
        document.getElementById("balanceText").innerText = "Available " + (user.balance||0).toFixed(2) + " USDT";
    }
}
loadRealBalance();

// BACK
function goBack(){
window.location.href="/wallet";
}

// NETWORK
function setNet(btn){
document.querySelectorAll(".network button").forEach(b=>b.classList.remove("active"));
btn.classList.add("active");
selectedNet = btn.innerText;
}

// ALL BUTTON
function setAll(){
document.getElementById("amount").value = user.balance;
updateActual();
}

// UPDATE ACTUAL
document.getElementById("amount").addEventListener("input", updateActual);

function updateActual(){
let amount = parseFloat(document.getElementById("amount").value) || 0;
document.getElementById("actual").innerText = amount.toFixed(2) + " USDT";
}

// SUBMIT
function submitWithdraw(){
let amount = document.getElementById("amount").value;
let address = document.getElementById("address").value;
let user = JSON.parse(localStorage.getItem("user"));

if(!amount || amount <= 0){
alert("Enter valid amount");
return;
}

if(!address){
alert("Enter wallet address");
return;
}

fetch("/request", {
method: "POST",
headers: {"Content-Type": "application/json"},
body: JSON.stringify({
email: user.email,
amount: amount,
type: "withdraw",
address: address
})
})
.then(res=>res.text())
.then(data=>{
localStorage.setItem("lastAmount", amount);
localStorage.setItem("lastType", "withdraw");
window.location.href = "/pending";
});
}
</script>

</body>
</html>`);
});

// ================= ORDERS PAGE =================
app.get("/orders", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{margin:0;font-family:Arial;background:#f5f5f5;padding-top:54px;min-height:100vh;}
.header{position:fixed;top:0;left:0;right:0;z-index:200;background:#1976d2;color:white;padding:15px;display:flex;align-items:center;gap:10px;}
.tabs{display:flex;overflow-x:auto;background:white;padding:10px 0;border-bottom:1px solid #eee;scrollbar-width:none;}
.tabs::-webkit-scrollbar{display:none;}
.tabs div{flex:0 0 auto;padding:10px 18px;color:#555;cursor:pointer;font-size:14px;white-space:nowrap;}
.tabs div.active{color:#1976d2;font-weight:bold;border-bottom:2px solid #1976d2;}
.scroll-bar{height:3px;background:#eee;margin:0;overflow:hidden;flex:1;}
.scroll-indicator{height:100%;width:40%;background:#1976d2;border-radius:10px;transition:0.3s;}
.scroll-bar-wrap{display:flex;align-items:center;gap:4px;padding:0 6px;}
.scroll-bar-arrow{font-size:13px;color:#999;cursor:pointer;user-select:none;flex-shrink:0;}
.empty{text-align:center;margin-top:80px;color:#aaa;}
.empty-icon{font-size:60px;}
.order-card{background:white;margin:10px;border-radius:12px;padding:15px;box-shadow:0 1px 4px rgba(0,0,0,0.08);}
.order-status{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold;}
.status-waiting_payment{background:#fff3cd;color:#856404;}
.status-waiting_shipping{background:#cce5ff;color:#004085;}
.status-shipped{background:#d4edda;color:#155724;}
.status-completed{background:#d1ecf1;color:#0c5460;}
.status-refund{background:#f8d7da;color:#721c24;}
</style>
</head>
<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<h3 style="margin:0;">My Orders</h3>
</div>

<div class="tabs" id="tabs">
<div class="active" onclick="filterOrders('all',this)">ALL</div>
<div onclick="filterOrders('waiting_payment',this)">Waiting Payment</div>
<div onclick="filterOrders('waiting_shipping',this)">Waiting Shipping</div>
<div onclick="filterOrders('shipped',this)">Shipped</div>
<div onclick="filterOrders('completed',this)">Completed</div>
</div>

<div class="scroll-bar-wrap">
<span class="scroll-bar-arrow" id="arrowLeft">&#9664;</span>
<div class="scroll-bar"><div class="scroll-indicator" id="indicator"></div></div>
<span class="scroll-bar-arrow" id="arrowRight">&#9654;</span>
</div>

<div id="ordersList"></div>

<script>
var allOrders = [];
var currentFilter = 'all';
var statusLabels = {
  waiting_payment: 'Waiting Payment',
  waiting_shipping: 'Waiting Shipping',
  shipped: 'Shipped',
  completed: 'Completed',
  refund: 'Refund'
};

function goBack(){ window.location.href="/dashboard"; }

// Scroll indicator
var tabs = document.getElementById("tabs");
var indicator = document.getElementById("indicator");
tabs.addEventListener("scroll", function(){
  var maxScroll = tabs.scrollWidth - tabs.clientWidth;
  if(maxScroll <= 0) return;
  var percent = tabs.scrollLeft / maxScroll;
  indicator.style.width = (percent * 60 + 20) + "%";
  indicator.style.marginLeft = (percent * 80) + "px";
});

// ARROWS
document.getElementById("arrowLeft").addEventListener("click", function(){
  tabs.scrollLeft -= 80;
});
document.getElementById("arrowRight").addEventListener("click", function(){
  tabs.scrollLeft += 80;
});

// DRAG ON INDICATOR
(function(){
  var scrollBar = indicator.parentElement;
  var isDragging = false;
  var startX = 0;
  var startScrollLeft = 0;

  function onDragStart(e){
    isDragging = true;
    startX = (e.touches ? e.touches[0].clientX : e.clientX);
    startScrollLeft = tabs.scrollLeft;
    e.preventDefault();
  }
  function onDragMove(e){
    if(!isDragging) return;
    var x = (e.touches ? e.touches[0].clientX : e.clientX);
    var dx = x - startX;
    var barWidth = scrollBar.clientWidth;
    var maxScroll = tabs.scrollWidth - tabs.clientWidth;
    tabs.scrollLeft = startScrollLeft + (dx / barWidth) * maxScroll;
    e.preventDefault();
  }
  function onDragEnd(){ isDragging = false; }

  scrollBar.addEventListener("mousedown", onDragStart);
  scrollBar.addEventListener("touchstart", onDragStart, {passive:false});
  window.addEventListener("mousemove", onDragMove);
  window.addEventListener("touchmove", onDragMove, {passive:false});
  window.addEventListener("mouseup", onDragEnd);
  window.addEventListener("touchend", onDragEnd);
})();

function filterOrders(status, el){
  currentFilter = status;
  document.querySelectorAll('.tabs div').forEach(function(d){ d.classList.remove('active'); });
  el.classList.add('active');
  renderOrders();
}

function renderOrders(){
  var list = document.getElementById("ordersList");
  var filtered = currentFilter === 'all' ? allOrders : allOrders.filter(function(o){ return o.status === currentFilter; });
  
  if(filtered.length === 0){
    list.innerHTML = '<div class="empty"><div class="empty-icon">📄</div><p>No orders</p></div>';
    return;
  }

  list.innerHTML = filtered.slice().reverse().map(function(o){
    var label = statusLabels[o.status] || o.status;
    return '<div class="order-card">' +
      '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">' +
        '<div style="font-weight:bold;font-size:15px;flex:1;margin-right:10px;">' + o.productTitle + '</div>' +
        '<span class="order-status status-' + o.status + '">' + label + '</span>' +
      '</div>' +
      '<div style="color:#1976d2;font-weight:bold;font-size:16px;">$' + parseFloat(o.productPrice).toFixed(2) + ' &times; ' + (o.quantity||1) + '</div>' +
      '<div style="color:#999;font-size:12px;margin-top:5px;">' + (o.createdAt||'') + '</div>' +
      (o.profit > 0 ? '<div style="color:#28a745;font-size:13px;font-weight:bold;margin-top:4px;">+ $' + parseFloat(o.profit).toFixed(2) + ' profit</div>' : '') +
    '</div>';
  }).join('');
}

// جلب الأوردرات
var user = null;
try{ user = JSON.parse(localStorage.getItem("user")); }catch(e){}
if(!user || !user.email){
  document.getElementById("ordersList").innerHTML = '<div class="empty"><div class="empty-icon">🔒</div><p>Please login first</p></div>';
} else {
  fetch("/user-orders/" + encodeURIComponent(user.email))
  .then(function(r){ return r.json(); })
  .then(function(data){
    allOrders = data;
    renderOrders();
  })
  .catch(function(){
    document.getElementById("ordersList").innerHTML = '<div class="empty"><div class="empty-icon">❌</div><p>Error loading orders</p></div>';
  });
}
</script>
</body>
</html>`);
});

// ================= SEARCH HISTORY PAGE =================
app.get("/history", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:#1976d2;
color:white;
padding:15px;
display:flex;
align-items:center;
gap:10px;
font-size:18px;
}
.header span{
font-size:20px;
cursor:pointer;
}

/* EMPTY */
.empty{
text-align:center;
margin-top:100px;
color:#aaa;
}
.empty-icon{
font-size:60px;
}
</style>
</head>

<body>

<!-- HEADER -->
<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>Search History</b>
</div>

<!-- EMPTY -->
<div class="empty">
<div class="empty-icon">📄</div>
<p>No Data</p>
</div>

<script>
function goBack(){
window.location.href="/dashboard";
}
</script>

</body>
</html>`);
});

// ================= FAVORITES PAGE =================
app.get("/favorites", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:white;
padding:15px;
text-align:center;
font-size:20px;
font-weight:bold;
border-bottom:1px solid #ddd;
}

/* TABS */
.tabs{
display:flex;
margin:10px;
gap:10px;
}
.tabs div{
flex:1;
padding:10px;
text-align:center;
border-radius:20px;
background:#ddd;
cursor:pointer;
}
.tabs .active{
background:#1976d2;
color:white;
}

/* EMPTY */
.empty{
text-align:center;
margin-top:30px;
}
.empty p{
color:#666;
font-size:14px;
}

/* BUTTON */
.shop-btn{
margin:20px;
background:black;
color:white;
padding:12px;
text-align:center;
}

/* GRID */
.grid{
display:grid;
grid-template-columns:1fr 1fr;
gap:10px;
padding:10px;
}
.card{
background:white;
border-radius:10px;
overflow:hidden;
position:relative;
}
.card img{
width:100%;
height:140px;
object-fit:cover;
}
.card p{
font-size:12px;
padding:5px;
}
.price{
color:#1976d2;
font-weight:bold;
padding:5px;
}

/* HEART */
.heart{
position:absolute;
right:8px;
bottom:65px;
background:white;
border-radius:50%;
padding:5px;
cursor:pointer;
font-size:14px;
}

/* SEE MORE */
.more{
margin:20px;
padding:10px;
border:1px solid #333;
text-align:center;
}
</style>
</head>

<body>

<div class="header" style="position:relative;">
<a href="/dashboard" style="position:absolute;left:15px;text-decoration:none;color:white;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></a>
Saved items
</div>

<div class="tabs">
<div class="active">Product</div>
<div onclick="window.location.href='/store'">Store</div>
</div>

<div class="empty">
<h3>You have no saved items</h3>
<p>Start saving on shopping by selecting the little heart shape.</p>
<p>We'll sync your items across all your devices.</p>
</div>

<div class="shop-btn">Start shopping</div>

<h3 style="padding:10px;">Recommended</h3>

<div class="grid">

<div class="card">
<img src="https://images.unsplash.com/photo-1587825140708-dfaf72ae4b04">
<div class="heart" onclick="toggleFav(1)">🤍</div>
<p>Meta Portal Go - Portable Smart Video Calling 10" Touch Screen with Battery</p>
<div class="price">US$129.99</div>
</div>

<div class="card">
<img src="https://images.unsplash.com/photo-1521334884684-d80222895322">
<div class="heart" onclick="toggleFav(2)">🤍</div>
<p>Tutu Dreams Lace Pom poms Tutu Dress for Girls Flower Girl Tulle Dresses</p>
<div class="price">US$24.99</div>
</div>

<div class="card">
<img src="https://images.unsplash.com/photo-1511385348-a52b4a160dc2">
<div class="heart" onclick="toggleFav(3)">🤍</div>
<p>Anne Klein Women's Leather Strap Watch</p>
<div class="price">US$35.00</div>
</div>

<div class="card">
<img src="https://images.unsplash.com/photo-1605100804763-247f67b3557e">
<div class="heart" onclick="toggleFav(4)">🤍</div>
<p>YL Celtic Knot Ring 925 Sterling Silver Twisted Knot Ring</p>
<div class="price">US$49.99</div>
</div>

<div class="card">
<img src="https://images.unsplash.com/photo-1584917865442-de89df76afd3">
<div class="heart" onclick="toggleFav(5)">🤍</div>
<p>RADLEY London Lyme Terrace Women's Leather Shoulder Bag</p>
<div class="price">US$199.99</div>
</div>

<div class="card">
<img src="https://images.unsplash.com/photo-1585386959984-a4155224a1ad">
<div class="heart" onclick="toggleFav(6)">🤍</div>
<p>BOSTANTEN Sling Bag Crossbody Bag Trendy Leather</p>
<div class="price">US$29.99</div>
</div>

<div class="card">
<img src="https://images.unsplash.com/photo-1520975916090-3105956dac38">
<div class="heart" onclick="toggleFav(7)">🤍</div>
<p>WYPFD Lace Evening Dresses Sexy Deep V-neck Mermaid</p>
<div class="price">US$899.00</div>
</div>

<div class="card">
<img src="https://images.unsplash.com/photo-1581092918056-0c4c3acd3789">
<div class="heart" onclick="toggleFav(8)">🤍</div>
<p>AcPower 2 Pairs Drone Propellers for DJI Mavic Pro</p>
<div class="price">US$18.99</div>
</div>

</div>

<div class="more">See more</div>

<script>
// تحميل المفضلة
let favorites = JSON.parse(localStorage.getItem("favorites") || "[]");

// تحديث القلوب
document.querySelectorAll(".heart").forEach((el, index)=>{
let id = index + 1;
if(favorites.includes(id)){
el.innerHTML = "❤️";
}
});

// عند الضغط
function toggleFav(id){
let favorites = JSON.parse(localStorage.getItem("favorites") || "[]");

if(favorites.includes(id)){
favorites = favorites.filter(f=>f!==id);
}else{
favorites.push(id);
}

localStorage.setItem("favorites", JSON.stringify(favorites));
location.reload();
}
</script>

</body>
</html>`);
});

// ================= CUSTOMER SERVICE PAGE =================
app.get("/support", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
background:#1976d2;
color:white;
padding:15px;
display:flex;
align-items:center;
justify-content:center;
position:relative;
font-size:20px;
}
.header a{
position:absolute;
left:15px;
text-decoration:none;
font-size:20px;
color:white;
}

/* SECTION */
.section{
background:white;
margin:10px;
padding:15px;
border-radius:10px;
}

/* TITLE */
.title{
font-weight:bold;
margin-bottom:10px;
}

/* ITEM */
.item{
display:flex;
align-items:center;
gap:10px;
padding:10px 0;
border-bottom:1px solid #eee;
}
.item:last-child{
border:none;
}

/* BUTTON */
.btn{
background:red;
color:white;
padding:12px;
text-align:center;
border-radius:5px;
margin-top:15px;
}

/* FOOTER TEXT */
.small{
font-size:12px;
color:#666;
margin-top:10px;
}
</style>
</head>

<body>

<div class="header">
<a href="/dashboard" style="text-decoration:none;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></a>
Customer Service
</div>

<div class="section">
<div class="title">Support Tools</div>

<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
🤖 ChatBot - Automate customer service with AI
</div>
<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
📩 HelpDesk - Support customers with tickets
</div>

<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
📚 KnowledgeBase - Guide and educate users
</div>

<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
🧩 Widgets - Enhance your website
</div>

<div class="section">
<div class="title">Contact Options</div>

<div onclick="window.location.href='/live-chat'" style="cursor:pointer;">
💬 Live Chat
</div>
<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
📧 Email Support
</div>
<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
📞 Phone Support
</div>

<div class="section">
<div class="title">Get App</div>

<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
💻 Web Browser
</div>
<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
📱 Android
</div>
<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
🍎 iOS
</div>
<div onclick="window.location.href='/support-page'" style="cursor:pointer;">
🖥 Windows
</div>

<div class="section">
<div class="title">Start your free live chat trial</div>
<div class="btn" onclick="window.location.href='/support-page'" style="cursor:pointer;">
Sign up free
</div>

<div class="small">
Customer service helps you engage with users, answer questions, and improve your platform experience.
</div>
</div>

</body>
</html>`);
});

// ================= MERCHANT PAGE =================
app.get("/merchant", (req, res) => {
res.send(`
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Merchant</title>
</head>

<body>

<div style="background:#1f4b87;padding:12px;color:white;display:flex;justify-content:space-between;align-items:center;">
  <div>
    <span style="cursor:pointer;display:inline-flex;align-items:center;gap:10px;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span> <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  </div>
  <div style="display:flex;align-items:center;gap:14px;">
    <span onclick="window.location.href='/dashboard?search=1'" style="display:inline-flex;align-items:center;cursor:pointer;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span onclick="window.location.href='/dashboard?messages=1'" style="display:inline-flex;align-items:center;cursor:pointer;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span onclick="window.location.href='/dashboard?account=1'" style="display:inline-flex;align-items:center;cursor:pointer;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <span onclick="window.location.href='/dashboard?lang=1'" style="display:inline-flex;align-items:center;cursor:pointer;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
</div>

<div style="padding:10px;background:#f5f5f5;min-height:100vh;">

  <!-- PROFILE -->
  <div style="margin-bottom:10px;">
    <div style="width:60px;height:60px;border-radius:50%;background:#ccc;"></div>
  </div>

  <!-- STATS -->
  <div style="background:white;border-radius:12px;padding:15px;margin-bottom:10px;">
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;text-align:center;">
      <div>Products for sale<br><b>0</b></div>
      <div>Number of Visitor<br><b>0</b></div>
      <div>Number of order<br><b>0</b></div>
      <div>Turnover<br><b>0.00</b></div>
      <div>Credential rating<br><b>0</b></div>
    </div>
  </div>

  <!-- ORDER STATUS -->
  <div style="background:white;border-radius:12px;padding:15px;margin-bottom:10px;">
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;text-align:center;">
      <div>0<br><small>Waiting for payment</small></div>
      <div>0<br><small>Waiting for shipping</small></div>
      <div>0<br><small>Waiting for delivery</small></div>
      <div>0<br><small>Waiting for refund</small></div>
    </div>
  </div>

  <!-- BALANCE -->
  <div style="background:white;border-radius:12px;padding:15px;margin-bottom:10px;">
    <div style="display:grid;grid-template-columns:1fr 1fr;text-align:center;">
      <div><b id="storeBalance">0.00</b><br><small>Available balance</small></div>
      <div><b id="storeTotalCapital">0.00</b><br><small>Total working capital</small></div>
      <div>0.00<br><small>Profit of the day</small></div>
      <div>0.00<br><small>Total profit credited</small></div>
    </div>
  </div>

  <!-- TOOLS -->
 <div style="background:white;border-radius:12px;padding:15px;">
  <b style="display:block;margin-bottom:10px;">Basic tools</b>

  <div style="
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:20px;
    text-align:center;
  ">

    <div>
      <img src="https://img.icons8.com/color/48/shopping-cart--v1.png" style="width:40px;"><br>
      <span style="font-size:13px;">Listings</span>
    </div>

    <div>
      <img src="https://img.icons8.com/color/48/task.png" style="width:40px;"><br>
      <span style="font-size:13px;">Manage product</span>
    </div>

    <div>
      <img src="https://img.icons8.com/ios-filled/50/shopping-cart.png" style="width:40px;"><br>
      <span style="font-size:13px;">Manage Order</span>
    </div>

    <div>
      <img src="https://img.icons8.com/ios/50/settings--v1.png" style="width:40px;"><br>
      <span style="font-size:13px;">Store setting</span>
    </div>

    <div>
      <img src="https://img.icons8.com/color/48/document.png" style="width:40px;"><br>
      <span style="font-size:13px;">Store Operating fund</span>
    </div>

    <div>
      <img src="https://img.icons8.com/color/48/plus--v1.png" style="width:40px;"><br>
      <span style="font-size:13px;">Instructions for operation</span>
    </div>

  </div>
</div>
<!-- OVERLAY -->
<div id="overlayBox" style="
position:fixed;
top:0;
left:0;
width:100%;
height:100%;
background:rgba(0,0,0,0.4);
display:none;
justify-content:center;
align-items:center;
z-index:999;
">

  <!-- POPUP BOX -->
  <div style="
    width:90%;
    max-width:350px;
    background:white;
    border-radius:15px;
    overflow:hidden;
  ">

    <div style="padding:20px;text-align:center;" class="overlay-msg">
      Sorry, you are not yet a business user
    </div>

    <div style="display:flex;border-top:1px solid #eee;">
      <div onclick="goBack()" style="flex:1;padding:15px;text-align:center;cursor:pointer;">
        Back
      </div>

      <div onclick="apply()" style="flex:1;padding:15px;text-align:center;color:#1976d2;cursor:pointer;border-left:1px solid #eee;">
        Apply for business
      </div>
    </div>

  </div>
</div>

<script>
function goBack(){
  window.location.href="/dashboard";
}

function apply(){
  window.location.href="/apply";
}

// جلب وعرض الرصيد من السيرفر
async function loadStoreBalance(){
  try {
    let user = JSON.parse(localStorage.getItem("user"));
    if(!user || !user.email) return;
    let res = await fetch("/users");
    let users = await res.json();
    let me = users.find(u => u.email === user.email);
    if(me){
      let bal = parseFloat(me.balance || 0).toFixed(2);
      document.getElementById("storeBalance").innerText = bal;
      document.getElementById("storeTotalCapital").innerText = bal;
    }
  } catch(e){ console.error(e); }
}

loadStoreBalance();
setInterval(loadStoreBalance, 5000);

// فحص حالة المتجر عند تحميل الصفحة
async function checkStoreStatus(){
    let user = JSON.parse(localStorage.getItem("user"));
    if(!user) return;

    let res = await fetch("/store-status/" + encodeURIComponent(user.email));
    let data = await res.json();

    if(data.found){
        if(data.status === "approved"){
            window.location.href = "/merchant-dashboard";
            return;
        }
        if(data.status === "pending"){
            window.location.href = "/store-pending";
            return;
        }
        if(data.status === "rejected"){
            // اعرض الـ overlay مع رسالة رفض
            document.querySelector(".overlay-msg").innerText = "Your store was rejected. Please reapply.";
            document.getElementById("overlayBox").style.display = "flex";
            return;
        }
    }
    // لا يوجد طلب → اعرض الـ popup الافتراضي
    document.getElementById("overlayBox").style.display = "flex";
}

checkStoreStatus();
</script>
</body>
</html>
`);
});
// ================= APPLY BUSINESS PAGE =================
app.get("/apply", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
background:#1976d2;
color:white;
text-align:center;
padding:15px;
font-size:18px;
position:relative;
}
.header a{
position:absolute;
left:15px;
color:white;
text-decoration:none;
font-size:20px;
}

/* STEPS */
.steps{
display:flex;
justify-content:space-around;
align-items:center;
padding:15px;
background:white;
font-size:12px;
}
.step{
text-align:center;
}
.circle{
width:10px;
height:10px;
border-radius:50%;
background:#ccc;
margin:5px auto;
}
.active{
background:#1976d2;
}

/* CARD */
.card{
background:white;
margin:10px;
padding:15px;
border-radius:15px;
}

/* STORE TYPES */
.types{
display:flex;
gap:10px;
margin-top:10px;
}
.type{
flex:1;
background:#eee;
border-radius:15px;
padding:15px;
text-align:center;
cursor:pointer;
}
.type.active{
border:2px solid #1976d2;
background:white;
}

/* CHECK */
.check{
margin-top:15px;
font-size:13px;
}

/* BUTTON */
.next{
position:fixed;
bottom:10px;
left:10px;
right:10px;
}
.next button{
width:100%;
padding:15px;
border:none;
background:#1976d2;
color:white;
border-radius:10px;
font-size:16px;
}
</style>
</head>

<body>

<div class="header">
<a href="/merchant" style="text-decoration:none;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></a>
Apply
</div>

<div class="steps">
<div class="step">
<div class="circle active"></div>
Select store
</div>
<div class="step">
<div class="circle"></div>
Personal information
</div>
<div class="step">
<div class="circle"></div>
ID verification
</div>
<div class="step">
<div class="circle"></div>
Store setting
</div>
</div>

<div class="card">
<b>Select Store Type</b>

<div class="types">
<div class="type active" onclick="selectType(this)">
🏪<br>Personal Store
</div>

<div class="type" onclick="selectType(this)">
🛍<br>Enterprise store
</div>

<div class="type" onclick="selectType(this)">
❤️<br>Charity Store
</div>
</div>

<div class="check">
<input type="checkbox" checked> 
Agree Business Solutions Agreement And Privacy Policy
</div>

</div>

<div class="next">
<button onclick="nextStep()">Next</button>
</div>

<script>
function selectType(el){
document.querySelectorAll(".type").forEach(t=>t.classList.remove("active"));
el.classList.add("active");
localStorage.setItem("apply_storeType", el.innerText.trim());
}

function nextStep(){
    window.location.href = "/apply-step2";
}
</script>

</body>
</html>`);
});

// ================= APPLY STEP 2 =================
app.get("/apply-step2", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
background:#1976d2;
color:white;
text-align:center;
padding:15px;
font-size:18px;
position:relative;
}
.header a{
position:absolute;
left:15px;
color:white;
text-decoration:none;
font-size:20px;
}

/* STEPS */
.steps{
display:flex;
justify-content:space-around;
padding:10px;
background:white;
font-size:12px;
}
.step{text-align:center;}
.circle{
width:10px;height:10px;border-radius:50%;background:#ccc;margin:5px auto;
}
.active{background:#1976d2;}

/* CARD */
.card{
background:white;
margin:10px;
padding:15px;
border-radius:15px;
}

/* INPUT */
input{
width:100%;
padding:12px;
margin:8px 0;
border-radius:8px;
border:1px solid #ddd;
}

/* BUTTONS */
.actions{
display:flex;
gap:10px;
padding:10px;
}
.actions button{
flex:1;
padding:15px;
border:none;
border-radius:10px;
font-size:16px;
}
.prev{background:#999;color:white;}
.next{background:#1976d2;color:white;}
</style>
</head>

<body>

<div class="header">
<a href="/apply" style="text-decoration:none;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></a>
Next
</div>

<div class="steps">
<div class="step"><div class="circle active"></div>Select store</div>
<div class="step"><div class="circle active"></div>Personal information</div>
<div class="step"><div class="circle"></div>ID verification</div>
<div class="step"><div class="circle"></div>Store setting</div>
</div>

<div class="card">
<b>Fill in personal information</b>

<p>Country of Citizenship</p>
<input id="nationality" placeholder="Please enter nationality">

<p>Personal ID</p>
<input id="personalId" placeholder="Please enter ID">

<p>ID number</p>
<input id="idNumber" placeholder="Please enter the ID number">

<p>Certificate validity</p>
<input id="certValidity" placeholder="Please enter the validity of the ID">

<p>Document issuing country</p>
<input id="issuingCountry" placeholder="Please enter the country of issue">
</div>

<div class="card">
<p>Name</p>
<input id="name" placeholder="Please enter your name">

<p>Place of birth</p>
<input id="placeOfBirth" placeholder="Please enter place of birth">

<p>Date of birth</p>
<input id="dateOfBirth" placeholder="Please enter date of birth">

<p>Place of residence</p>
<input id="placeOfResidence" placeholder="Please enter place of residence">

<p>City/Town</p>
<input id="city" placeholder="Please enter City/Town">

<p>Street name</p>
<input id="street" placeholder="Please enter street name">

<p>Postal code</p>
<input id="postalCode" placeholder="Please enter postal code">

<p>Contact email</p>
<input id="contactEmail" placeholder="Please enter the correct contact email">

<label>
<input type="checkbox" checked>
I confirm that my address is correct and I know this information cannot be changed until address verification is complete
</label>
</div>

<div class="actions">
<button class="prev" onclick="window.location.href='/apply'">Previous</button>
<button class="next" onclick="nextStep2()">Next</button>
</div>

<script>
var fieldIds2 = ["nationality","personalId","idNumber","certValidity","issuingCountry","name","placeOfBirth","dateOfBirth","placeOfResidence","city","street","postalCode","contactEmail"];
fieldIds2.forEach(function(f){
    var el = document.getElementById(f);
    var val = localStorage.getItem("apply_" + f);
    if(el && val) el.value = val;
});

function nextStep2(){
    fieldIds2.forEach(function(f){
        var el = document.getElementById(f);
        if(el) localStorage.setItem("apply_" + f, el.value);
    });
    window.location.href = "/apply-step3";
}
</script>

</body>
</html>`);
});
// ================= APPLY STEP 3 (ID VERIFICATION) =================
app.get("/apply-step3", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
background:#1976d2;
color:white;
text-align:center;
padding:15px;
font-size:18px;
position:relative;
}
.header a{
position:absolute;
left:15px;
color:white;
text-decoration:none;
font-size:20px;
}

/* STEPS */
.steps{
display:flex;
justify-content:space-around;
padding:10px;
background:white;
font-size:12px;
}
.step{text-align:center;}
.circle{
width:10px;height:10px;border-radius:50%;background:#ccc;margin:5px auto;
}
.active{background:#1976d2;}

/* CARD */
.container{
padding:15px;
}

.upload-box{
background:white;
border-radius:15px;
padding:20px;
display:flex;
justify-content:space-between;
gap:10px;
}

.card{
flex:1;
background:#fafafa;
border-radius:15px;
padding:15px;
text-align:center;
box-shadow:0 2px 10px rgba(0,0,0,0.05);
}

.card img{
width:100%;
border-radius:10px;
margin-bottom:10px;
}

.btn{
background:#1976d2;
color:white;
padding:10px;
border-radius:10px;
margin-top:10px;
cursor:pointer;
font-size:14px;
}

/* BUTTONS */
.actions{
display:flex;
gap:10px;
padding:15px;
}
.actions button{
flex:1;
padding:15px;
border:none;
border-radius:10px;
font-size:16px;
}
.prev{background:#999;color:white;}
.next{background:#1976d2;color:white;}
</style>
</head>

<body>

<div class="header">
<a href="/apply-step2" style="text-decoration:none;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></a>
ID Verification
</div>

<div class="steps">
<div class="step"><div class="circle active"></div>Select store</div>
<div class="step"><div class="circle active"></div>Personal info</div>
<div class="step"><div class="circle active"></div>ID verification</div>
<div class="step"><div class="circle"></div>Store setting</div>
</div>

<div class="container">

<h3>Identity document</h3>

<div class="upload-box">

<div class="card">
<img id="frontPreview" src="https://cdn-icons-png.flaticon.com/512/2910/2910768.png" style="border-radius:8px;object-fit:contain;background:#f0f0f0;padding:10px;">
<input type="file" id="frontInput" accept="image/*" style="display:none;">
<div class="btn" onclick="document.getElementById('frontInput').click()">Upload ID front page</div>
</div>

<div class="card">
<img id="backPreview" src="https://cdn-icons-png.flaticon.com/512/2910/2910768.png" style="border-radius:8px;object-fit:contain;background:#f0f0f0;padding:10px;">
<input type="file" id="backInput" accept="image/*" style="display:none;">
<div class="btn" onclick="document.getElementById('backInput').click()">Upload ID back page</div>
</div>

</div>

</div>

<div class="actions">
<button class="prev" onclick="window.location.href='/apply-step2'">Previous</button>
<button class="next" onclick="nextStep3()">Next</button>
</div>

<script>
// FRONT
let frontInput = document.getElementById("frontInput");
let frontPreview = document.getElementById("frontPreview");

frontInput.addEventListener("change", function(){
let file = this.files[0];

if(file){
let reader = new FileReader();

reader.onload = function(e){
frontPreview.src = e.target.result;
localStorage.setItem("idFront", e.target.result);
};

reader.readAsDataURL(file);
}
});

// BACK
let backInput = document.getElementById("backInput");
let backPreview = document.getElementById("backPreview");

backInput.addEventListener("change", function(){
let file = this.files[0];

if(file){
let reader = new FileReader();

reader.onload = function(e){
backPreview.src = e.target.result;
localStorage.setItem("idBack", e.target.result);
};

reader.readAsDataURL(file);
}
});

// تحميل الصور إذا موجودة
let savedFront = localStorage.getItem("idFront");
if(savedFront){
frontPreview.src = savedFront;
}

let savedBack = localStorage.getItem("idBack");
if(savedBack){
backPreview.src = savedBack;
}

// NEXT
function nextStep3(){
window.location.href = "/apply-step4";
}
</script>

</body>
</html>`);
});
// ================= APPLY STEP4=================
app.get("/store-pending", (req, res) => {
res.send(`
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
text-align:center;
padding-top:60px;
min-height:100vh;
}

.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:#1976d2;
color:white;
padding:15px;
font-size:20px;
}

.icon{
font-size:80px;
margin-top:40px;
}

.title{
font-size:22px;
margin:20px;
}

.card{
background:white;
margin:20px;
padding:15px;
border-radius:15px;
text-align:left;
}

.btn{
margin:20px;
padding:15px;
background:#1976d2;
color:white;
border-radius:10px;
cursor:pointer;
text-align:center;
}
</style>
</head>

<body>

<div class="header">Apply</div>

<!-- STEPS -->
<div style="display:flex;justify-content:space-around;padding:10px;background:white;font-size:12px;border-bottom:1px solid #eee;">
<div style="text-align:center;"><div style="width:10px;height:10px;border-radius:50%;background:#1976d2;margin:5px auto;"></div>Select store</div>
<div style="text-align:center;"><div style="width:10px;height:10px;border-radius:50%;background:#1976d2;margin:5px auto;"></div>Personal information</div>
<div style="text-align:center;"><div style="width:10px;height:10px;border-radius:50%;background:#1976d2;margin:5px auto;"></div>ID verification</div>
<div style="text-align:center;"><div style="width:10px;height:10px;border-radius:50%;background:#1976d2;margin:5px auto;"></div>Store setting</div>
</div>

<!-- أيقونة الحالة -->
<div style="margin-top:40px;">
<div style="width:80px;height:80px;border-radius:50%;background:#ffe5d0;display:flex;align-items:center;justify-content:center;margin:0 auto;">
<div id="storeIcon" style="font-size:40px;">⚠️</div>
</div>
</div>

<div id="storeTitle" class="title">
Please wait! The store is under review
</div>

<div class="card">
<p style="border-bottom:1px solid #eee;padding-bottom:10px;"><b>Store name</b><br><span id="storeName" style="color:#555;"></span></p>
<p><b>Contact email</b><br><span id="email" style="color:#555;"></span></p>
</div>

<div id="backBtn" class="btn" onclick="goBack()">Back</div>
<div id="reapplyBtn" class="btn" onclick="reapply()" style="display:none;background:#e53935;">Reapply</div>

<script>
function reapply(){
    // مسح البيانات القديمة
    let keys = ["storeName","storeLogo","idFront","idBack","apply_storeType","apply_nationality","apply_personalId","apply_idNumber","apply_certValidity","apply_issuingCountry","apply_name","apply_placeOfBirth","apply_dateOfBirth","apply_placeOfResidence","apply_city","apply_street","apply_postalCode","apply_contactEmail"];
    keys.forEach(k => localStorage.removeItem(k));
    window.location.href = "/apply";
}
</script>

<script>
let user = JSON.parse(localStorage.getItem("user"));

function goBack(){
    window.location.href="/dashboard";
}

async function checkStatus(){
    let res = await fetch("/store-status/" + encodeURIComponent(user.email));
    let data = await res.json();

    if(data.found){
        if(data.status === "approved"){
            window.location.href = "/merchant-dashboard";
            return;
        }
        if(data.status === "rejected"){
            document.getElementById("storeIcon").innerText = "❌";
            document.getElementById("storeTitle").innerText = "Your store application was rejected.";
            document.getElementById("storeTitle").style.color = "red";
            document.getElementById("reapplyBtn").style.display = "block";
            document.getElementById("backBtn").style.display = "none";
        }
        if(data.status === "pending"){
            document.getElementById("storeIcon").innerText = "⚠️";
            document.getElementById("storeTitle").innerText = "Please wait! The store is under review";
        }
        document.getElementById("storeName").innerText = data.storeName || localStorage.getItem("storeName") || "";
        document.getElementById("email").innerText = data.contactEmail || user.email;
    } else {
        window.location.href = "/apply";
    }
}

checkStatus();
setInterval(checkStatus, 5000);
</script>

</body>
</html>
`);
});

// ================= APPLY STEP 5 (STORE SETTING) =================
app.get("/apply-step4", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER LINE */
.top-line{
height:4px;
background:#1976d2;
}

/* STEPS */
.steps{
display:flex;
justify-content:space-around;
align-items:center;
padding:10px;
background:white;
font-size:12px;
}
.step{text-align:center;}
.circle{
width:10px;
height:10px;
border-radius:50%;
background:#1976d2;
margin:5px auto;
}

/* CONTAINER */
.container{
padding:20px;
}

/* TITLE */
.title{
font-size:16px;
margin-bottom:10px;
display:flex;
align-items:center;
gap:5px;
}

/* LOGO BOX */
.logo-box{
background:white;
border-radius:20px;
padding:20px;
text-align:center;
width:180px;
margin:0 auto;
box-shadow:0 5px 20px rgba(0,0,0,0.05);
}

.logo-box img{
width:80px;
opacity:0.5;
margin-bottom:10px;
}

.upload-btn{
background:#1976d2;
color:white;
padding:10px;
border-radius:10px;
cursor:pointer;
}

/* INPUT CARD */
.card{
background:white;
margin-top:20px;
padding:15px;
border-radius:15px;
}

input{
width:100%;
padding:12px;
border-radius:10px;
border:1px solid #ccc;
margin-top:10px;
}

/* BUTTON */
.confirm{
position:fixed;
bottom:15px;
left:15px;
right:15px;
}

.confirm button{
width:100%;
padding:15px;
border:none;
border-radius:10px;
background:#1976d2;
color:white;
font-size:16px;
}

</style>
</head>

<body>

<div class="top-line"></div>

<!-- STEPS -->
<div class="steps">
<div class="step">Select store<div class="circle"></div></div>
<div class="step">Personal information<div class="circle"></div></div>
<div class="step">ID verification<div class="circle"></div></div>
<div class="step">Store setting<div class="circle"></div></div>
</div>

<div class="container">

<div class="title">📷 Store setting</div>

<!-- LOGO -->
<div class="logo-box">
<img id="logoPreview" src="https://cdn-icons-png.flaticon.com/512/149/149071.png">
<input type="file" id="logoInput" accept="image/*" style="display:none;">
<div class="upload-btn" onclick="document.getElementById('logoInput').click()">Upload Store Logo</div>
</div>

<!-- STORE NAME -->
<div class="card">
<p>Store name</p>
<input id="storeName" placeholder="Please enter" style="margin-bottom:80px;color:black;background:white;">
</div>

</div>

<!-- CONFIRM -->
<div class="confirm">
<button onclick="submitStore()">Confirm submission</button>
</div>

<script>
let logoInput = document.getElementById("logoInput");
let logoPreview = document.getElementById("logoPreview");

// عند اختيار صورة
logoInput.addEventListener("change", function(){
let file = this.files[0];

if(file){
let reader = new FileReader();

reader.onload = function(e){
logoPreview.src = e.target.result;

// نحفظ الصورة
localStorage.setItem("storeLogo", e.target.result);
};

reader.readAsDataURL(file);
}
});

// عند تحميل الصفحة
let savedLogo = localStorage.getItem("storeLogo");
if(savedLogo){
logoPreview.src = savedLogo;
}

async function submitStore(){
    let name = document.getElementById("storeName").value;

    if(!name){
        alert("Enter store name");
        return;
    }

    localStorage.setItem("storeName", name);

    let user = JSON.parse(localStorage.getItem("user"));

    let payload = {
        email: user.email,
        storeType: localStorage.getItem("apply_storeType") || "",
        nationality: localStorage.getItem("apply_nationality") || "",
        personalId: localStorage.getItem("apply_personalId") || "",
        idNumber: localStorage.getItem("apply_idNumber") || "",
        certValidity: localStorage.getItem("apply_certValidity") || "",
        issuingCountry: localStorage.getItem("apply_issuingCountry") || "",
        name: localStorage.getItem("apply_name") || "",
        placeOfBirth: localStorage.getItem("apply_placeOfBirth") || "",
        dateOfBirth: localStorage.getItem("apply_dateOfBirth") || "",
        placeOfResidence: localStorage.getItem("apply_placeOfResidence") || "",
        city: localStorage.getItem("apply_city") || "",
        street: localStorage.getItem("apply_street") || "",
        postalCode: localStorage.getItem("apply_postalCode") || "",
        contactEmail: localStorage.getItem("apply_contactEmail") || user.email,
        idFront: localStorage.getItem("idFront") || "",
        idBack: localStorage.getItem("idBack") || "",
        storeLogo: localStorage.getItem("storeLogo") || "",
        storeName: name
    };

    try {
        let res = await fetch("/submit-store", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload)
        });
        let data = await res.json();
        if(data.success){
            window.location.href = "/store-pending";
        } else {
            alert("Error submitting. Try again.");
        }
    } catch(e) {
        console.error(e);
        window.location.href = "/store-pending";
    }
}
</script>

</body>
</html>`);
});
// ================= MERCHANT DASHBOARD =================
app.get("/merchant-dashboard", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:#f2f2f2;
padding-top:55px;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:#1976d2;
color:white;
text-align:center;
padding:20px;
font-size:20px;
}

/* PROFILE */
.profile{
padding:15px;
}
.profile img{
width:60px;
height:60px;
border-radius:50%;
}

/* CARD */
.card{
background:white;
margin:10px;
padding:15px;
border-radius:10px;
box-shadow:0 2px 10px rgba(0,0,0,0.05);
}

/* GRID */
.grid{
display:grid;
grid-template-columns:1fr 1fr 1fr;
text-align:center;
gap:10px;
}

.grid p{
margin:5px 0;
font-size:13px;
color:#555;
}

.value{
font-weight:bold;
font-size:16px;
}

/* GRID 4 */
.grid4{
display:grid;
grid-template-columns:1fr 1fr 1fr 1fr;
text-align:center;
}

/* BALANCE */
.balance{
display:grid;
grid-template-columns:1fr 1fr;
text-align:center;
gap:10px;
}

/* TOOLS */
.tools{
display:grid;
grid-template-columns:1fr 1fr 1fr 1fr;
gap:15px;
text-align:center;
margin-top:10px;
}
.tool{
font-size:12px;
}
.tool img{
width:40px;
margin-bottom:5px;
}
</style>
</head>

<body>

<div class="header" style="display:flex;justify-content:space-between;align-items:center;padding:12px 15px;text-align:left;">
  <!-- يسار: رجوع + بيت -->
  <div style="display:flex;align-items:center;gap:12px;">
    <span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
    </span>
  </div>
  <!-- يمين: Search + Mail + Account + Globe -->
  <div style="display:flex;align-items:center;gap:14px;">
    <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    </span>
    <span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
    </span>
    <span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    </span>
    <span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
    </span>
  </div>
</div>

<div class="profile" style="display:flex;align-items:center;gap:15px;">

<!-- صورة المتجر القابلة للتغيير -->
<div style="position:relative;cursor:pointer;" onclick="document.getElementById('storeLogoInput').click()" title="Tap to change logo">
  <img id="storeLogo" src="https://cdn-icons-png.flaticon.com/512/149/149071.png" style="width:65px;height:65px;border-radius:50%;object-fit:cover;border:2px solid #ddd;">
  <div style="position:absolute;bottom:0;right:0;background:#1976d2;border-radius:50%;width:20px;height:20px;display:flex;align-items:center;justify-content:center;">
    <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
  </div>
</div>
<input type="file" id="storeLogoInput" accept="image/*" style="display:none;" onchange="changeStoreLogo(this)">

<div style="flex:1;">
  <!-- اسم المتجر القابل للتعديل -->
  <div style="display:flex;align-items:center;gap:6px;">
    <div id="storeNameDisplay" style="font-weight:bold;font-size:16px;"></div>
    <span onclick="editStoreName()" style="cursor:pointer;">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#1976d2" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
    </span>
  </div>
  <div id="storeStatusBadge" style="color:orange;font-size:13px;">Please wait! The store is under review</div>
  <!-- VIP Badge -->
  <div style="margin-top:5px;">
    <span id="vipBadge" style="background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;padding:3px 10px;border-radius:10px;display:inline-block;">VIP 0</span>
  </div>
</div>

</div>

<!-- STATS -->
<div class="card">
<div class="grid">
<div>
<p>Products for sale</p>
<div class="value" id="productsForSaleCount">0</div>
</div>

<div>
<p>Number of Visitor</p>
<div class="value" id="visitorCount">0</div>
</div>

<div>
<p>Number of order</p>
<div class="value">0</div>
</div>

<div>
<p>Turnover</p>
<div class="value">0.00</div>
</div>

<div>
<p>Credential rating</p>
<div class="value">0</div>
</div>
</div>
</div>

<!-- ORDER STATUS -->
<div class="card">
<div class="grid4">
<div>0<br><small>Waiting for payment</small></div>
<div>0<br><small>Waiting for shipping</small></div>
<div>0<br><small>Waiting for delivery</small></div>
<div>0<br><small>Waiting for refund</small></div>
</div>
</div>

<!-- BALANCE -->
<div class="card">
<div class="balance">
<div onclick="window.location.href='/wallet'" style="cursor:pointer;">
    <p id="merchantBalance">0.00</p>
    <small>Available balance</small>
</div>

<div onclick="window.location.href='/wallet'" style="cursor:pointer;">
    <p id="merchantTotalCapital">0.00</p>
    <small>Total working capital</small>
</div>

<div onclick="window.location.href='/wallet'" style="cursor:pointer;">
    <p>0.00</p>
    <small>Profit of the day</small>
</div>

<div onclick="window.location.href='/wallet'" style="cursor:pointer;">
    <p>0.00</p>
    <small>Total profit credited</small>
</div>
</div>
</div>

<!-- TOOLS -->
<div class="card">
<b>Basic tools</b>

<div class="tools">
<div class="tool">
<img src="https://cdn-icons-png.flaticon.com/512/891/891462.png">
<p>Listings</p>
</div>

<div class="tool">
<img src="https://cdn-icons-png.flaticon.com/512/2921/2921222.png">
<p>Manage product</p>
</div>

<div class="tool">
<img src="https://cdn-icons-png.flaticon.com/512/3144/3144456.png">
<p>Manage Order</p>
</div>

<div class="tool">
<img src="https://cdn-icons-png.flaticon.com/512/2099/2099058.png">
<p>Store setting</p>
</div>

<div class="tool">
<img src="https://cdn-icons-png.flaticon.com/512/2331/2331949.png">
<p>Store Operating fund</p>
</div>

<div class="tool">
<img src="https://cdn-icons-png.flaticon.com/512/1828/1828817.png">
<p>Instructions for operation</p>
</div>
</div>

</div>

</body>

<script>
function goBack(){
    window.location.href = "/dashboard";
}

async function loadStoreInfo(){
    let user = JSON.parse(localStorage.getItem("user"));
    if(!user) return;

    let res = await fetch("/store-status/" + encodeURIComponent(user.email));
    let data = await res.json();

    if(data.found){
        // الاسم: نأخذ الاسم المحفوظ محلياً أولاً (لو عدّله المستخدم)
        let savedName = localStorage.getItem("merchant_storeName_" + user.email);
        document.getElementById("storeNameDisplay").innerText = savedName || data.storeName || "";
        if(data.status === "approved"){
            document.getElementById("storeStatusBadge").innerText = "";
        }
    }

    // شعار المتجر - نجلبه من التسجيل أو من التعديل المحلي
    let logo = localStorage.getItem("merchant_storeLogo_" + (user ? user.email : ""))
               || localStorage.getItem("storeLogo")
               || (data.found ? data.storeLogo : "");
    if(logo && logo.length > 10) document.getElementById("storeLogo").src = logo;

    // VIP دائماً 0 للمتاجر الجديدة
    document.getElementById("vipBadge").innerText = "VIP 0";
}

// تغيير شعار المتجر
function changeStoreLogo(input){
    if(!input.files || !input.files[0]) return;
    let user = JSON.parse(localStorage.getItem("user"));
    let reader = new FileReader();
    reader.onload = function(e){
        let dataUrl = e.target.result;
        localStorage.setItem("merchant_storeLogo_" + (user ? user.email : ""), dataUrl);
        document.getElementById("storeLogo").src = dataUrl;
    };
    reader.readAsDataURL(input.files[0]);
}

// تعديل اسم المتجر
function editStoreName(){
    let current = document.getElementById("storeNameDisplay").innerText;
    let newName = prompt("Enter new store name:", current);
    if(newName && newName.trim() !== ""){
        let user = JSON.parse(localStorage.getItem("user"));
        localStorage.setItem("merchant_storeName_" + (user ? user.email : ""), newName.trim());
        document.getElementById("storeNameDisplay").innerText = newName.trim();
    }
}

// ======= عداد الزوار التراكمي (يبدأ من 0 ويزيد تدريجياً طوال اليوم) =======
function loadVisitorCounter(){
  let user = JSON.parse(localStorage.getItem("user") || "{}");
  let key = "visitorData_" + (user.email || "guest");

  const DAILY_TARGET = 50;
  const VERSION = "v3"; // تغيير هذا يمسح البيانات القديمة

  function getEndOfDay(){ let d = new Date(); d.setHours(23,59,59,999); return d.getTime(); }

  // مسح البيانات القديمة إذا كانت من نسخة مختلفة
  try {
    let raw = JSON.parse(localStorage.getItem(key) || "{}");
    if(raw.version !== VERSION){ localStorage.removeItem(key); }
  } catch(e){ localStorage.removeItem(key); }

  function getData(){
    let today = new Date().toDateString();
    let d = JSON.parse(localStorage.getItem(key) || "{}");
    if(d.date !== today){
      d = {
        version: VERSION,
        date: today,
        totalBase: (d.version === VERSION) ? ((d.totalBase || 0) + (d.todayAdded || 0)) : 0,
        todayAdded: 0
      };
      localStorage.setItem(key, JSON.stringify(d));
    }
    return d;
  }

  function saveData(d){ localStorage.setItem(key, JSON.stringify(d)); }

  function showCount(d){
    let el = document.getElementById("visitorCount");
    if(el) el.innerText = (d.totalBase || 0) + (d.todayAdded || 0);
  }

  // عرض 0 فوراً
  let d0 = getData();
  showCount(d0);

  // بعد 5 ثوانٍ: أول زائر
  setTimeout(function(){
    let d = getData();
    if((d.todayAdded || 0) < DAILY_TARGET){
      d.todayAdded = (d.todayAdded || 0) + 1;
      saveData(d);
      showCount(d);
    }

    // زيارة واحدة كل 15~45 دقيقة
    function scheduleNext(){
      let d = getData();
      if((d.todayAdded || 0) >= DAILY_TARGET) return;

      let remaining = DAILY_TARGET - (d.todayAdded || 0);
      let msLeft    = Math.max(getEndOfDay() - Date.now(), 1);
      let avg       = msLeft / remaining;
      let jitter    = avg * 0.2 * (Math.random() * 2 - 1);
      let delay     = Math.round(avg + jitter);
      delay = Math.max(delay, 15 * 60 * 1000);
      delay = Math.min(delay, 45 * 60 * 1000);

      setTimeout(function(){
        let d = getData();
        if((d.todayAdded || 0) < DAILY_TARGET){
          d.todayAdded = (d.todayAdded || 0) + 1;
          saveData(d);
          showCount(d);
        }
        scheduleNext();
      }, delay);
    }

    scheduleNext();
  }, 5000);
}

// جلب وعرض الرصيد من السيرفر
async function loadMerchantBalance(){
  try {
    let user = JSON.parse(localStorage.getItem("user"));
    if(!user || !user.email) return;
    let res = await fetch("/users");
    let users = await res.json();
    let me = users.find(u => u.email === user.email);
    if(me){
      let bal = parseFloat(me.balance || 0).toFixed(2);
      document.getElementById("merchantBalance").innerText = bal;
      document.getElementById("merchantTotalCapital").innerText = bal;
    }
  } catch(e){ console.error(e); }
}

// تحميل عدد المنتجات وتحديثه تلقائياً
function loadProductsCount(){
    fetch("https://fakestoreapi.com/products?limit=20")
    .then(function(r){ return r.json(); })
    .then(function(products){
        var el = document.getElementById("productsForSaleCount");
        if(el) el.innerText = products.length;
    })
    .catch(function(){});
}

loadStoreInfo();
loadMerchantBalance();
loadVisitorCounter();
loadProductsCount();
setInterval(loadMerchantBalance, 5000);
</script>
</html>`);
});

// ================= ADDRESS PAGE =================
app.get("/address", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:white;
padding:15px;
display:flex;
align-items:center;
gap:10px;
font-size:20px;
border-bottom:1px solid #eee;
}
.header span{
font-size:20px;
cursor:pointer;
}

/* EMPTY */
.empty{
text-align:center;
margin-top:100px;
color:#aaa;
}
.empty-icon{
font-size:60px;
}
</style>
</head>

<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>📍 Address</b>
</div>

<div class="empty">
<div class="empty-icon">📄</div>
<p>Not Available</p>
</div>

<script>
function goBack(){
window.location.href="/dashboard";
}
</script>

</body>
</html>`);
});

// ================= MANAGE EMAIL PAGE =================
app.get("/manage-email", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:white;
padding:15px;
display:flex;
align-items:center;
gap:10px;
font-size:20px;
border-bottom:1px solid #eee;
}
.header span{
cursor:pointer;
font-size:20px;
}

/* CARD */
.card{
background:white;
margin:15px;
padding:20px;
border-radius:15px;
box-shadow:0 5px 20px rgba(0,0,0,0.05);
}

/* INPUT */
input{
width:100%;
padding:12px;
margin-top:10px;
border-radius:10px;
border:1px solid #ddd;
}

/* BUTTON */
button{
width:100%;
padding:15px;
margin-top:20px;
border:none;
border-radius:10px;
background:#1976d2;
color:white;
font-size:16px;
}
</style>
</head>

<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>📧 Manage Email</b>
</div>

<div class="card">
<p id="userEmail"></p>

<p style="color:#999;">Old Email verification code</p>
<input placeholder="Old Email verification code">

<p style="text-align:right;font-size:12px;">Verification Code</p>

<button onclick="nextStep()">Next</button>
</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));

// عرض الإيميل
document.getElementById("userEmail").innerText = user.email;

// رجوع
function goBack(){
window.location.href="/dashboard";
}

// زر Next (مبدئي)
function nextStep(){
alert("Verification step will be added");
}
</script>

</body>
</html>`);
});


// ================= ACCOUNT PASSWORD PAGE =================
app.get("/account-password", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

/* HEADER */
.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:white;
padding:15px;
display:flex;
align-items:center;
gap:10px;
font-size:20px;
border-bottom:1px solid #eee;
}
.header span{
cursor:pointer;
font-size:20px;
}

/* CARD */
.card{
background:white;
margin:15px;
padding:20px;
border-radius:15px;
box-shadow:0 5px 20px rgba(0,0,0,0.05);
}

/* INPUT */
input{
width:100%;
padding:12px;
margin-top:10px;
border-radius:10px;
border:1px solid #ddd;
}

/* BUTTON */
button{
width:100%;
padding:15px;
margin-top:20px;
border:none;
border-radius:10px;
background:#1976d2;
color:white;
font-size:16px;
}
</style>
</head>

<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>🔐 Account Password</b>
</div>

<div class="card">
<p id="userEmail"></p>

<input id="newPass" type="password" placeholder="Please enter new password">

<p style="text-align:right;font-size:12px;">Verification Code</p>
<input id="code" placeholder="Please enter Email verification code">

<button onclick="savePassword()">Save</button>
</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));

// عرض الإيميل
document.getElementById("userEmail").innerText = user.email;

// رجوع
function goBack(){
window.location.href="/dashboard";
}

// حفظ الباسورد
function savePassword(){
let newPass = document.getElementById("newPass").value;

if(!newPass){
alert("Enter new password");
return;
}

// تحديث الباسورد
user.password = newPass;
localStorage.setItem("user", JSON.stringify(user));

alert("Password updated successfully");
window.location.href="/dashboard";
}
</script>

</body>
</html>`);
});

// ================= TRANSACTION PASSWORD PAGE =================
app.get("/transaction-password", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:white;
padding-top:54px;
min-height:100vh;
}

.header{
position:fixed;top:0;left:0;right:0;z-index:200;
background:white;
padding:15px;
display:flex;
align-items:center;
gap:10px;
font-size:20px;
border-bottom:1px solid #eee;
}
.header span{
cursor:pointer;
font-size:20px;
}

.card{
background:white;
margin:15px;
padding:20px;
border-radius:15px;
box-shadow:0 5px 20px rgba(0,0,0,0.05);
}

input{
width:100%;
padding:12px;
margin-top:10px;
border-radius:10px;
border:1px solid #ddd;
}

button{
width:100%;
padding:15px;
margin-top:20px;
border:none;
border-radius:10px;
background:#1976d2;
color:white;
font-size:16px;
}
</style>
</head>

<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>🔑 Transaction Password</b>
</div>

<div class="card">
<p id="userEmail"></p>

<input id="transPass" type="password" maxlength="6" placeholder="Please enter 6 characters password">

<p style="text-align:right;font-size:12px;">Verification Code</p>
<input placeholder="Please enter Email verification code">

<button onclick="saveTransaction()">Save</button>
</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));

// عرض الإيميل
document.getElementById("userEmail").innerText = user.email;

// رجوع
function goBack(){
window.location.href="/dashboard";
}

// حفظ الباسورد
function saveTransaction(){
let pass = document.getElementById("transPass").value;

if(pass.length !== 6){
alert("Password must be 6 characters");
return;
}

user.transactionPassword = pass;
localStorage.setItem("user", JSON.stringify(user));

alert("Transaction password saved");
window.location.href="/dashboard";
}

</script>

</body>
</html>`);
});
app.get("/admin", (req, res) => {
    res.sendFile(__dirname + "/admin.html");
});
// ================= LIVE CHAT PAGE =================
app.get("/live-chat", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
margin:0;
font-family:Arial;
background:#f5f5f5;
display:flex;
flex-direction:column;
height:100vh;
}

.header{
background:#1976d2;
color:white;
padding:15px;
text-align:center;
position:relative;
}

.back{
position:absolute;
left:15px;
top:15px;
cursor:pointer;
}

.chat{
flex:1;
overflow:auto;
padding:10px;
}

.msg{
margin:10px 0;
max-width:70%;
padding:10px;
border-radius:10px;
}

.user{
background:#1976d2;
color:white;
margin-left:auto;
}

.admin{
background:#eee;
color:black;
margin-right:auto;
}

.inputBox{
display:flex;
padding:10px;
background:white;
}

.inputBox input{
flex:1;
padding:10px;
border:1px solid #ccc;
border-radius:10px;
}

.inputBox button{
padding:10px;
margin-left:5px;
border:none;
background:#1976d2;
color:white;
border-radius:10px;
}
</style>
</head>

<body>

<div class="header">
<span class="back" onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
💬 TikTok Mall Support
</div>

<div class="chat" id="chat"></div>

<div class="inputBox">
<input id="msg" placeholder="Type message...">
<button onclick="send()">Send</button>
</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));

function goBack(){
window.location.href = "/support";
}

// تحميل الرسائل
function loadMessages(){
fetch("/get-messages/" + user.email)
.then(res=>res.json())
.then(data=>{

let chat = document.getElementById("chat");
chat.innerHTML = "";

data.forEach(m => {
let div = document.createElement("div");
div.className = "msg " + (m.sender === "user" ? "user" : "admin");

if(m.sender === "admin"){
var safeText = m.text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
div.innerHTML = "<b>🎧 TikTok Mall</b><br>" + safeText;
}else{
div.innerText = m.text;
}

chat.appendChild(div);
});

chat.scrollTop = chat.scrollHeight;
});
}

// إرسال رسالة
function send(){
let text = document.getElementById("msg").value;

if(!text) return;

fetch("/send-message", {
method:"POST",
headers:{"Content-Type":"application/json"},
body: JSON.stringify({
email: user.email,
text: text,
sender: "user"
})
})
.then(()=>{
document.getElementById("msg").value = "";
loadMessages();
});
}

// تحديث كل 2 ثانية
setInterval(loadMessages, 2000);

// تحميل أول مرة
loadMessages();
</script>

</body>
</html>`);
});

// ================= STORE PAGE =================
app.get("/store-page", (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Store</title>
<style>
*{box-sizing:border-box;}
body{margin:0;font-family:Arial;background:#f5f5f5;padding-bottom:30px;min-height:100vh;}

/* NO STICKY - يتمرر مع الصفحة */
.sticky-top{
  position:static;
}

/* HEADER */
.header{
  background:white;
  padding:14px 15px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  border-bottom:1px solid #eee;
}
.store-name-title{font-weight:bold;font-size:15px;flex:1;text-align:center;color:#222;}
.back-btn{display:inline-flex;align-items:center;cursor:pointer;padding:4px;}
.heart-top{font-size:24px;cursor:pointer;padding:4px;transition:transform 0.2s;line-height:1;}

/* BANNER CARD */
.banner{
  background:#1976d2;
  padding:16px 16px 14px;
  color:white;
  display:flex;
  flex-direction:column;
  gap:0;
  margin:12px 12px 10px;
  border-radius:18px;
  box-shadow:0 4px 18px rgba(25,118,210,0.28);
}
.banner-top{
  display:flex;
  align-items:center;
  gap:14px;
}
.banner-logo{
  width:65px;height:65px;
  border-radius:50%;
  object-fit:cover;
  border:3px solid rgba(255,255,255,0.7);
  background:white;
  flex-shrink:0;
}
.banner-info{flex:1;min-width:0;}
.banner-info h2{margin:0 0 8px 0;font-size:16px;font-weight:bold;letter-spacing:0.3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.badges{
  display:flex;
  flex-direction:row;
  gap:7px;
  align-items:center;
  flex-wrap:nowrap;
}
.vip-badge{
  background:linear-gradient(90deg,#c8960c,#f5c842);
  color:#222;
  padding:5px 12px;
  border-radius:25px;
  font-size:12px;
  font-weight:bold;
  display:inline-flex;
  align-items:center;
  gap:4px;
  white-space:nowrap;
  flex-shrink:0;
}
.badge{
  background:rgba(0,0,0,0.25);
  padding:5px 12px;
  border-radius:25px;
  font-size:12px;
  color:white;
  white-space:nowrap;
  flex-shrink:0;
}
/* DESCRIPTION ROW */
.banner-desc-row{
  display:flex;
  align-items:flex-start;
  gap:8px;
  margin-top:12px;
  background:rgba(255,255,255,0.15);
  border-radius:12px;
  padding:10px 12px;
  min-height:42px;
}
.desc-text{
  flex:1;
  font-size:13px;
  color:white;
  line-height:1.5;
  word-break:break-word;
  white-space:pre-wrap;
  outline:none;
  min-height:20px;
  cursor:text;
}
.desc-text:empty:before{
  content:attr(data-placeholder);
  color:rgba(255,255,255,0.55);
  pointer-events:none;
}
.edit-icon{
  font-size:16px;
  cursor:pointer;
  color:rgba(255,255,255,0.8);
  flex-shrink:0;
  margin-top:1px;
  user-select:none;
  transition:color 0.2s;
}
.edit-icon:hover{color:white;}

/* TABS */
.tabs{
  display:flex;
  background:white;
  margin:12px 12px 0;
  border-radius:12px;
  overflow:hidden;
  box-shadow:0 1px 5px rgba(0,0,0,0.07);
}
.tab{
  flex:1;padding:12px 5px;
  text-align:center;font-size:13px;
  cursor:pointer;color:#888;
  border-bottom:3px solid transparent;
  transition:all 0.2s;
}
.tab.active{color:#1976d2;border-bottom:3px solid #1976d2;font-weight:bold;}

/* TOOLBAR */
.toolbar{
  display:flex;justify-content:space-between;align-items:center;
  padding:9px 15px;background:white;
  margin:10px 12px 0;border-radius:10px;
  font-size:13px;color:#555;
}

/* PRODUCT GRID */
.grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:10px;
  padding:10px 12px 20px;
}
.pcard{
  background:white;
  border-radius:12px;
  overflow:hidden;
  box-shadow:0 2px 8px rgba(0,0,0,0.07);
  cursor:pointer;
  transition:transform 0.15s;
}
.pcard:active{transform:scale(0.97);}
.pcard img{width:100%;height:145px;object-fit:cover;display:block;}
.pcard-info{padding:8px 9px;}
.pcard-name{font-size:12px;color:#333;margin:0 0 5px;line-height:1.4;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}
.pcard-price{color:#1976d2;font-weight:bold;font-size:13px;margin:0;}
.loading{text-align:center;padding:50px;color:#aaa;grid-column:1/-1;font-size:14px;}
</style>
</head>
<body>

<!-- STICKY TOP: HEADER + BANNER -->
<div class="sticky-top">

<!-- HEADER -->
<div class="header">
  <span class="back-btn" onclick="history.back()">
    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24"
         fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="15 18 9 12 15 6"/>
    </svg>
  </span>
  <span class="store-name-title" id="headerStoreName"></span>
  <span class="heart-top" id="heartTopBtn" onclick="toggleHeart()">&#x1F90D;</span>
</div>

<!-- BANNER CARD -->
<div class="banner">
  <div class="banner-top">
    <img id="storeLogo" class="banner-logo"
         src="https://cdn-icons-png.flaticon.com/512/149/149071.png"
         onerror="this.src='https://cdn-icons-png.flaticon.com/512/149/149071.png'">
    <div class="banner-info">
      <h2 id="bannerStoreName"></h2>
      <div class="badges">
        <span class="vip-badge">&#10003; VIP <span id="vipLevel">0</span></span>
        <span class="badge">Products <span id="productCount">0</span></span>
        <span class="badge">Followers <span id="followerCount">0</span></span>
      </div>
    </div>
  </div>
  <div class="banner-desc-row">
    <div class="desc-text" id="storeDesc" contenteditable="false"
         data-placeholder="Add a store description..."></div>
    <span class="edit-icon" id="editDescBtn" onclick="toggleDescEdit()" title="Edit description">&#9998;</span>
  </div>
</div>
</div><!-- /sticky-top -->

<!-- TABS -->
<div class="tabs">
  <div class="tab active" onclick="setTab(this,'Recommendation')">Recommendation</div>
  <div class="tab" onclick="setTab(this,'Sales')">Sales</div>
  <div class="tab" onclick="setTab(this,'Price')">Price &#11021;</div>
</div>

<!-- TOOLBAR -->
<div class="toolbar">
  <span id="toolbarLabel">Recommendation</span>
  <span style="color:#1976d2;font-size:13px;">Price &#11021;</span>
</div>

<!-- PRODUCT GRID -->
<div class="grid" id="productGrid">
  <div class="loading">Loading products...</div>
</div>

<script>
var sName  = localStorage.getItem("viewStoreName")  || "";
var sEmail = localStorage.getItem("viewStoreEmail") || "";

// عرض الاسم في الهيدر والبانر
document.getElementById("headerStoreName").innerText = sName;
document.getElementById("bannerStoreName").innerText = sName;

// ======= تحميل بيانات المتجر (شعار + اسم محدّث) =======
fetch("/all-store-applications")
.then(function(r){ return r.json(); })
.then(function(apps){
  var store = null;
  for(var i=0;i<apps.length;i++){
    if(apps[i].email === sEmail && apps[i].status === "approved"){
      store = apps[i];
      break;
    }
  }
  if(!store) return;

  // الاسم المحدّث من merchant dashboard
  var updatedName = localStorage.getItem("merchant_storeName_" + sEmail) || store.storeName;
  sName = updatedName;
  document.getElementById("headerStoreName").innerText = updatedName;
  document.getElementById("bannerStoreName").innerText = updatedName;

  // الشعار المحدّث
  var updatedLogo = localStorage.getItem("merchant_storeLogo_" + sEmail) || store.storeLogo || "";
  if(updatedLogo && updatedLogo.length > 10){
    document.getElementById("storeLogo").src = updatedLogo;
  }
})
.catch(function(){});

// ======= القلب والمتابعة =======
var likedKey = "likedStores_" + sEmail;
var isLiked  = localStorage.getItem(likedKey) === "1";
var baseFollowers = 0;

// جلب عدد المتابعين من السيرفر
fetch("/followers/" + encodeURIComponent(sEmail))
  .then(function(r){ return r.json(); })
  .then(function(d){
    baseFollowers = d.followers || 0;
    renderFollowers();
  }).catch(function(){});

function updateHeartUI(){
  var btn = document.getElementById("heartTopBtn");
  if(isLiked){
    btn.innerHTML = "&#x2764;&#xFE0F;";
  } else {
    btn.innerHTML = "&#x1F90D;";
  }
}
updateHeartUI();
renderFollowers();

// ======= Store Description Edit =======
var descEl  = document.getElementById("storeDesc");
var editBtn = document.getElementById("editDescBtn");
var isEditing = false;

// تحقق هل المستخدم الحالي هو صاحب هذا المتجر
var me = JSON.parse(localStorage.getItem("user") || "{}");
var isOwner = (me.email && me.email === sEmail);

// إخفاء زر التعديل إذا لم يكن صاحب المتجر
if(!isOwner) editBtn.style.display = "none";

// جلب التعريف من السيرفر
fetch("/store-desc/" + encodeURIComponent(sEmail))
  .then(function(r){ return r.json(); })
  .then(function(d){
    if(d.desc) descEl.innerText = d.desc;
  }).catch(function(){});

function toggleDescEdit(){
  if(!isOwner) return; // حماية إضافية
  isEditing = !isEditing;
  if(isEditing){
    descEl.contentEditable = "true";
    descEl.focus();
    var range = document.createRange();
    var sel   = window.getSelection();
    range.selectNodeContents(descEl);
    range.collapse(false);
    sel.removeAllRanges();
    sel.addRange(range);
    editBtn.innerHTML = "&#10003;";
    editBtn.title = "Save";
  } else {
    descEl.contentEditable = "false";
    var newText = descEl.innerText.trim();
    descEl.innerText = newText;
    editBtn.innerHTML = "&#9998;";
    editBtn.title = "Edit description";
    // حفظ على السيرفر فقط لصاحب المتجر
    var token = localStorage.getItem("token") || "";
    fetch("/update-store-desc", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify({ desc: newText })
    }).catch(function(){});
  }
}

function renderFollowers(){
  var count = isLiked ? baseFollowers + 1 : baseFollowers;
  document.getElementById("followerCount").innerText = count;
}

function toggleHeart(){
  var me = JSON.parse(localStorage.getItem("user") || "{}");
  isLiked = !isLiked;
  var btn = document.getElementById("heartTopBtn");
  btn.style.transform = "scale(1.5)";
  setTimeout(function(){ btn.style.transform = "scale(1)"; }, 200);
  localStorage.setItem(likedKey, isLiked ? "1" : "0");
  updateHeartUI();
  renderFollowers();

  // نرسل للسيرفر
  fetch("/follow-store", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      storeEmail: sEmail,
      userEmail: me.email || "guest",
      action: isLiked ? "follow" : "unfollow"
    })
  }).then(function(r){ return r.json(); })
    .then(function(d){
      if(d.success){
        baseFollowers = isLiked ? d.followers - 1 : d.followers;
        renderFollowers();
      }
    }).catch(function(){});
}

// ======= Tabs =======
function setTab(el, label){
  document.querySelectorAll(".tab").forEach(function(t){ t.classList.remove("active"); });
  el.classList.add("active");
  document.getElementById("toolbarLabel").innerText = label;
}

// ======= VIP Level =======
function calcVIP(count){
  if(count >= 100) return 5;
  if(count >= 50)  return 4;
  if(count >= 20)  return 3;
  if(count >= 10)  return 2;
  if(count >= 1)   return 1;
  return 0;
}

// ======= تحميل المنتجات =======
fetch("https://fakestoreapi.com/products?limit=20")
.then(function(r){ return r.json(); })
.then(function(products){
  var cnt = products.length;
  document.getElementById("productCount").innerText = cnt;
  document.getElementById("vipLevel").innerText = calcVIP(cnt);

  var grid = document.getElementById("productGrid");
  grid.innerHTML = "";

  products.forEach(function(p){
    var card = document.createElement("div");
    card.className = "pcard";

    var img = document.createElement("img");
    img.src = p.image;
    img.alt = p.title;
    img.onerror = function(){ this.src="https://via.placeholder.com/150"; };

    var info = document.createElement("div");
    info.className = "pcard-info";
    info.innerHTML =
      "<p class='pcard-name'>" + p.title + "</p>" +
      "<p class='pcard-price'>US$" + p.price + "</p>";

    card.appendChild(img);
    card.appendChild(info);

    card.onclick = function(){
      localStorage.setItem("productId", p.id);
      window.location.href = "/product-detail";
    };
    grid.appendChild(card);
  });
})
.catch(function(){
  document.getElementById("productGrid").innerHTML =
    "<div class='loading'>Could not load products</div>";
});
<\/script>

</body>
</html>`);
});

// ================= CAT PRODUCT DETAIL =================

// ================= CAT PRODUCT DETAIL PAGE =================
app.get("/cat-product-detail", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Product Detail</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Arial;background:#f5f5f5;padding-bottom:80px;padding-top:50px;min-height:100vh;}
/* HEADER */
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:fixed;top:0;left:0;right:0;z-index:100;}
.h-icons{display:flex;align-items:center;gap:14px;}
/* PAGE BODY */
.page-body{margin-top:0;}
.slider-wrap{background:white;}
/* SLIDER */
.slider-wrap{background:white;position:relative;overflow:hidden;}
.slider-imgs{display:flex;transition:transform 0.35s ease;will-change:transform;}
.slider-imgs img{min-width:100%;height:auto;max-height:650px;object-fit:contain;background:#f9f9f9;display:block;}
/* heart & share */
.heart-btn{position:absolute;top:12px;left:12px;font-size:26px;cursor:pointer;z-index:10;background:none;border:none;padding:0;line-height:1;}
.share-btn{position:absolute;top:12px;right:12px;cursor:pointer;z-index:10;background:none;border:none;padding:0;}
/* thumbs */
.thumbs{display:flex;gap:8px;padding:10px 12px;background:white;overflow-x:auto;}
.thumbs img{width:58px;height:58px;object-fit:cover;border-radius:8px;border:2px solid #eee;cursor:pointer;flex-shrink:0;}
.thumbs img.active{border-color:#1976d2;}
/* info */
.info{background:white;margin-top:8px;padding:15px;}
.prod-title{font-size:15px;color:#222;line-height:1.5;margin-bottom:10px;}
.rating-price-row{display:flex;justify-content:space-between;align-items:center;}
.stars-wrap{display:flex;align-items:center;gap:4px;font-size:13px;color:#555;}
.stars-wrap .star{color:#f5a623;font-size:15px;}
.price{color:#1976d2;font-size:24px;font-weight:bold;}
/* specs */
.specs{background:white;margin-top:8px;}
.spec-row{display:flex;justify-content:space-between;align-items:center;padding:13px 15px;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;}
.spec-row span:last-child{color:#999;}
/* store */
.store{background:white;margin-top:8px;padding:15px;display:flex;align-items:center;gap:12px;cursor:pointer;}
.store-logo{width:52px;height:52px;border-radius:10px;object-fit:cover;}
.store-name{font-weight:bold;font-size:15px;}
.vip-badge{background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;padding:2px 8px;border-radius:10px;display:inline-block;margin-top:3px;}
.store-tags{display:flex;gap:8px;margin-top:5px;}
.store-tags span{background:#eee;font-size:11px;padding:3px 10px;border-radius:10px;}
/* review */
.review{background:white;margin-top:8px;padding:15px;}
.review-top{display:flex;justify-content:space-between;font-size:14px;color:#333;}
.review-stars{color:#f5a623;font-size:18px;margin-top:5px;}
/* desc */
.desc{background:white;margin-top:8px;padding:15px;font-size:13px;color:#444;line-height:1.8;}
.desc ul{padding-left:18px;margin:0;}
.desc li{margin-bottom:8px;}
/* bottom bar */
.bottom-bar{position:fixed;bottom:0;left:0;right:0;background:white;display:flex;align-items:center;padding:10px 15px;border-top:1px solid #eee;gap:10px;z-index:200;}
.icon-btn{font-size:22px;cursor:pointer;flex-shrink:0;}
.cart-btn{flex:1;padding:13px;border:1.5px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;cursor:pointer;text-align:center;font-weight:bold;}
.buy-btn{flex:1;padding:13px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;cursor:pointer;text-align:center;font-weight:bold;}

/* Toast */
.toast{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:rgba(0,0,0,0.75);color:white;padding:12px 24px;border-radius:10px;font-size:14px;z-index:700;text-align:center;}
/* BOTTOM SHEET */
.sheet-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.4);z-index:500;}
.sheet{position:fixed;bottom:0;left:0;right:0;background:white;border-radius:18px 18px 0 0;padding:16px 16px 30px;z-index:600;transform:translateY(100%);transition:transform 0.3s ease;max-height:80vh;overflow-y:auto;}
.sheet.open{transform:translateY(0);}
.sheet-top{display:flex;gap:12px;align-items:flex-start;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid #f0f0f0;}
.sheet-thumb{width:80px;height:80px;object-fit:cover;border-radius:8px;border:1px solid #eee;flex-shrink:0;}
.sheet-info{flex:1;}
.sheet-price{color:#e8791d;font-size:20px;font-weight:bold;}
.sheet-stock{font-size:13px;color:#888;margin-top:4px;}
.sheet-label{font-size:14px;color:#333;margin-bottom:10px;font-weight:500;}
.sheet-options{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px;}
.sheet-opt{padding:7px 16px;border:1.5px solid #ddd;border-radius:20px;font-size:13px;color:#333;cursor:pointer;background:white;}
.sheet-opt.active{border-color:#1976d2;color:#1976d2;background:#e8f0fe;}

</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div style="display:flex;align-items:center;gap:10px;">
    <span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;margin-left:8px;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  </div>
  <div class="h-icons">
    <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
</div>

<div class="page-body">

<!-- SLIDER -->
<div class="slider-wrap">
  <button class="heart-btn" id="heartBtn" onclick="toggleHeart()">&#129293;</button>
  <button class="share-btn" onclick="shareProduct()">
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
  </button>
  <div class="slider-imgs" id="sliderImgs"></div>
</div>

<!-- THUMBS -->
<div class="thumbs" id="thumbs"></div>

<!-- INFO -->
<div class="info">
  <div class="prod-title" id="pTitle"></div>
  <div class="rating-price-row">
    <div class="stars-wrap"><span class="star">&#11088;</span> <span id="pRating">5.0</span> <span style="color:#999;" id="pSales">(0 Sales)</span></div>
    <div class="price" id="pPrice"></div>
  </div>
</div>

<!-- SPECS -->
<div class="specs">
  <div class="spec-row"><span>Select</span><span>Brand, specification &#8250;</span></div>
  <div class="spec-row"><span>Shipping fees</span><span>Free shipping</span></div>
  <div class="spec-row"><span>Guarantee</span><span>Free return</span></div>
</div>

<!-- STORE -->
<div class="store">
  <img class="store-logo" id="storeLogo" src="">
  <div style="flex:1;">
    <div class="store-name" id="storeName"></div>
    <div class="vip-badge" id="storeVip"></div>
    <div class="store-tags"><span id="storeProducts"></span><span id="storeFollowers"></span></div>
  </div>
  <span style="color:#999;">&#8250;</span>
</div>

<!-- REVIEW -->
<div class="review">
  <div class="review-top">
    <span>Consumer review</span>
    <span style="color:#1976d2;">0 Unit Global Rating &#8250;</span>
  </div>
  <div class="review-stars">&#11088;&#11088;&#11088;&#11088;&#11088; <span style="font-size:13px;color:#555;">5 Stars</span></div>
</div>

<!-- DESC -->
<div class="desc">
  <ul id="descList"></ul>
</div>

</div><!-- end page-body -->

<!-- BOTTOM BAR -->
<div class="bottom-bar">
  <span class="icon-btn" onclick="window.location.href='/live-chat'">&#127911;</span>
  <span class="icon-btn" onclick="window.location.href='/wallet'">&#128722;</span>
  <div class="cart-btn" onclick="addToCart()">Add to Cart</div>
  <div class="buy-btn" onclick="buyNow()">Buy now</div>
</div>




<!-- TOAST -->
<div class="toast" id="toast"></div>

<script>
var p = {};
try { p = JSON.parse(localStorage.getItem("catProduct") || "{}"); } catch(e){}
var isFav = false;
var currentSlide = 0;
var images = [];
var sheetMode = "cart";
var autoTimer = null;

// ===== خريطة ألوان/مقاسات كل قسم =====
var CAT_OPTIONS = {
  "Clothing & Accessories": { label:"Size", opts:["XS","S","M","L","XL","XXL","XXXL"] },
  "Medical Bags and Sunglasses": { label:"Color", opts:["Black","Brown","Tortoise","Gold","Silver","Navy","Tan","Crystal","Rose Gold"] },
  "Shoes": { label:"Size", opts:["36","37","38","39","40","41","42","43","44","45"] },
  "Watches": { label:"Color", opts:["Black","Silver","Gold","Rose Gold","Blue","Green","Gray","Brown"] },
  "Jewelry": { label:"Color", opts:["Gold","Rose Gold","Silver","Yellow Gold","White Gold","Diamond","Ruby","Emerald","Sapphire","Pearl"] },
  "Electronics": { label:"Color", opts:["Black","Silver","Space Gray","White","Blue","Gold","Green","Midnight","Titanium"] },
  "Smart Home": { label:"Color", opts:["White","Black","Charcoal","Silver","Sand","Blue"] },
  "Luxury Brands": { label:"Color", opts:["Black","Tan","Camel","Beige","White","Red","Navy","Brown","Burgundy","Gold"] },
  "Beauty and Personal Care": { label:"Shade", opts:["Nude","Pink","Red","Rose","Berry","Coral","Peach","Bronze","Clear","Gold"] },
  "Mens Fashion": { label:"Size", opts:["XS","S","M","L","XL","XXL","XXXL"] },
  "Health and Household": { label:"Color", opts:["White","Black","Gray","Blue","Green","Red","Silver"] },
  "Home and Kitchen": { label:"Color", opts:["Stainless Steel","Black","White","Red","Blue","Gray","Copper"] }
};

var catName = (p && p.cat) ? p.cat : "Clothing & Accessories";
var catOpts = CAT_OPTIONS[catName] || { label:"Color", opts:["Black","White","Gray","Blue","Red","Green"] };

// إذا كان المنتج يحتوي على sizes أو colors حقيقية، استخدمها
if(p.sizes && p.sizes.length > 0) { catOpts = { label:"Size", opts: p.sizes }; }
else if(p.colors && p.colors.length > 0) { catOpts = { label:"Color", opts: p.colors }; }

// ===== بناء الصفحة =====
if(p && p.img){
  document.getElementById("pTitle").innerText = p.t || p.title || "";
  document.getElementById("pPrice").innerText = "US\\$" + ((p.p || p.price || 0).toFixed(2));
  document.getElementById("pRating").innerText = p.rating || "5.0";
  document.getElementById("pSales").innerText = "(" + ((p.sales||0).toLocaleString()) + " Sales)";

  // الصور
  images = (p.imgs && p.imgs.length > 0) ? p.imgs : [p.img];

  var wrap = document.getElementById("sliderImgs");
  var thumbsEl = document.getElementById("thumbs");

  images.forEach(function(src, i){
    var img = document.createElement("img");
    img.src = src;
    img.onerror = function(){ this.onerror=null; };
    wrap.appendChild(img);

    var th = document.createElement("img");
    th.src = src;
    th.className = (i===0?"active":"");
    th.onerror = function(){ this.onerror=null; };
    th.onclick = (function(idx){ return function(){ goSlide(idx); restartAuto(); }; })(i);
    thumbsEl.appendChild(th);
  });

  // Auto slide
  function startAuto(){ autoTimer = setInterval(function(){ goSlide((currentSlide+1)%images.length); }, 3000); }
  function restartAuto(){ clearInterval(autoTimer); startAuto(); }
  startAuto();

  // وصف المنتج
  var desc = document.getElementById("descList");
  var descText = p.description || "";
  var points = descText ? descText.split(".").filter(function(s){ return s.trim().length > 3; }) : [];
  if(points.length === 0) points = [p.t || ""];
  points.slice(0,8).forEach(function(pt){
    if(pt.trim()){
      var li = document.createElement("li");
      li.innerText = pt.trim();
      desc.appendChild(li);
    }
  });
}

function goSlide(idx){
  currentSlide = idx;
  document.getElementById("sliderImgs").style.transform = "translateX(-"+(idx*100)+"%)";
  document.querySelectorAll(".thumbs img").forEach(function(t,i){ t.className=(i===idx?"active":""); });
}

function toggleHeart(){
  isFav = !isFav;
  document.getElementById("heartBtn").innerHTML = isFav ? "&#10084;&#65039;" : "&#129293;";
}

function shareProduct(){
  var url = window.location.href;
  if(navigator.clipboard){ navigator.clipboard.writeText(url).catch(function(){}); }
  showToast("&#10003; Link copied successfully");
}

function showToast(msg){
  var t = document.getElementById("toast");
  t.innerHTML = msg;
  t.style.display = "block";
  setTimeout(function(){ t.style.display = "none"; }, 1800);
}

// ===== بيانات المتجر العشوائية =====
var storeNames = ["TrendHub Store","StyleNest","LuxePoint","FashionVault","UrbanEdge Store","PrimePick","GlowShop","EliteWear","SmartDeal Store","TopChoice","ModaWorld","StarSeller","FreshFind","BestBuy Shop","ClassicLook","NovaTrend","DreamStyle","PeakFashion","VogueZone","IconStore"];
var storeAvatars = [
  "https://images.unsplash.com/photo-1607082348824-0a96f2a4b9da?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1472851294608-062f824d29cc?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1555529669-e69e7aa0ba9a?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1583744946564-b52ac1c389c8?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1578916171728-46686eac8d58?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1576238793577-dbed1c12f648?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1514996937319-344454492b37?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1530099486328-e021101a494a?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1567401893414-76b7b1e5a7a5?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1540959733332-eab4deabeeaf?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1601924994987-69e26d50dc26?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1526170375885-4d8ecf77b99f?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1488716820095-cbe80883c496?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1560343090-f0409e92791a?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1491553895911-0055eca6402d?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1585386959984-a4155224a1ad?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=80&h=80&fit=crop",
  "https://images.unsplash.com/photo-1550009158-9ebf69173e03?w=80&h=80&fit=crop"
];
function hashId(str){ var h=0; for(var i=0;i<str.length;i++) h=(Math.imul(31,h)+str.charCodeAt(i))|0; return Math.abs(h); }
var seedStr      = (p.t || "") + (p.id || "") + (p.p || "");
var sid          = hashId(seedStr);
var sName        = storeNames[sid % storeNames.length];
var sAvatar      = storeAvatars[sid % storeAvatars.length];
var sVip         = sid % 5;
var sProducts    = 20 + (sid % 480);
var sFollowers   = (sid * 7) % 9800;
document.getElementById("storeName").innerText     = sName;
document.getElementById("storeLogo").src           = sAvatar;
document.getElementById("storeVip").innerHTML      = "&#10004; VIP " + sVip;
document.getElementById("storeProducts").innerText   = "Products " + sProducts;
document.getElementById("storeFollowers").innerText  = "Followers " + sFollowers.toLocaleString();
// ===== نهاية بيانات المتجر =====

function addToCart(){
  var cart = JSON.parse(localStorage.getItem("cart")||"[]");
  cart.push({ id: p.id, title: p.t, price: p.p, qty: 1, img: p.img });
  localStorage.setItem("cart", JSON.stringify(cart));
  showToast("&#10003; Added to cart");
}

function buyNow(){
  window.location.href = "/wallet";
}
<\/script>
</body>
</html>`);
});
app.get("/terms", (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terms and Conditions</title>
<style>
body{background:#fff;font-family:Arial,sans-serif;font-size:14px;color:#222;padding:20px;max-width:900px;margin:0 auto;line-height:1.7;}
h2{text-align:center;margin-bottom:20px;}
p{margin:10px 0;}
.back-btn{display:block;margin-bottom:20px;color:#1976d2;cursor:pointer;font-size:14px;text-decoration:none;}
</style></head>
<body>
<a class="back-btn" onclick="history.back()">&#8592; Back</a>
<h2>Terms and Conditions</h2>
<p>Chapter 1 Overview</p>
<p>Article 1 [Purpose of Rules]<br>In order to allow users to enjoy a better, safer and more reliable business environment and transaction experience, promote the coordinated governance of online and offline integration, and optimize the TikTok Mall platform ecosystem, these general rules are hereby formulated.</p>
<p>Article 2 [Basis of Rules]<br>(I) [Legal Basis] The "International E-Commerce Law", "International Cybersecurity Law", "International Consumer Rights Protection Law", "International Network Transaction Supervision and Administration Measures" and other global laws and regulations and related normative documents (hereinafter referred to as "legal provisions") stipulate the legal rights and obligations of all parties in the TikTok Mall platform ecosystem, and are the legal basis for the formulation and revision of TikTok Mall platform rules.<br>
(II) [Normative Basis] The relevant agreements of the TikTok Mall platform are legal documents that clarify the rights and obligations of TikTok Mall and its members, and are the normative basis of TikTok Mall platform rules.<br>
(III) [Conceptual Basis] All parties in the TikTok Mall platform ecosystem practice business ethics and social responsibilities, coexist and win together, co-govern and co-build on the TikTok Mall platform, and develop in a self-disciplined and standardized manner. For those that are not clearly stipulated by the law, the platform continuously maximizes the interests of all parties through beneficial exploration, which is the conceptual basis of TikTok Mall platform rules.</p>
<p>Article 3 [Rules and Principles]<br>All parties in the TikTok Mall platform ecosystem respect and abide by the following principles: equality, voluntariness, fairness, and integrity. The behavior of all parties in the TikTok Mall platform ecosystem on the TikTok Mall platform shall not violate the law and public order and good morals.</p>
<p>Article 4 [Applicable Objects]<br>The TikTok Mall platform rules apply to all parties in the TikTok Mall platform ecosystem, including users, members, buyers, sellers, and other relevant parties.</p>
<p>Article 5 [Rule System and Effectiveness]<br>The TikTok Mall platform rule system and effectiveness level are as follows:<br>
(I) [Rule System] The TikTok Mall platform rules are a general term for the following rules:<br>
1. "TikTok Mall Platform Rules General Principles"<br>
2. Specific rules and regulations formulated for the management and violation handling of the TikTok Mall platform member market, industry market management, marketing activities and other necessary matters, including the corresponding implementation details for further refinement of specific rules and regulations (hereinafter referred to as "rules and regulations");<br>
3. Temporary announcements issued in accordance with the temporary management needs of the TikTok Mall platform.</p>
<p>(II) [Effectiveness Level] Where there are provisions in the "General Principles", they shall prevail; where there are special provisions in the rules and regulations or temporary announcements, the special provisions shall prevail. If there is no provision in the TikTok Mall platform rules, TikTok Mall will handle it according to the law or relevant agreements.</p>
<p>Article 6 [Rule Procedure]<br>TikTok Mall shall formulate or modify the TikTok Mall platform rules in a timely and prudent manner in accordance with the requirements of legal provisions and the needs of the development of the ecosystem, and shall publicize them on the TikTok Mall platform rules page. The rules shall take effect from the date of expiration of the publicity period.<br>
The formulated or modified transaction rules shall be subject to the special public consultation procedure in accordance with the law, and shall be reported to the relevant functional departments.</p>
<p>Article 7 [Retroactive Effect of Rules]<br>The rules at that time shall apply to the behavior that occurred before the rules came into effect; the new rules shall apply to the behavior that occurred after the rules came into effect.</p>
<p>Chapter II General Provisions for Members</p>
<p>Article 8 [General Principles]<br>All behaviors of members on the TikTok Mall platform must comply with legal provisions, TikTok Mall platform rules, and follow the instructions on the corresponding pages of the TikTok Mall platform.</p>
<p>Article 9 [Registration]<br>Members shall complete registration in accordance with the procedures and requirements of the TikTok Mall platform.<br>
If the member account is an inactive account, TikTok Mall may recycle it.<br>
Article 10 [Authentication] Members shall provide true and valid information about themselves (including natural persons, legal persons and their principals, non-legal persons and their principals, etc hereinafter the same) in accordance with the authentication requirements of the TikTok Mall platform.<br>
(I) The information that members shall provide includes but is not limited to: personal identity information, personal information, effective contact information, real address, business address, market entity registration information and other relevant information, and other authentication information required by laws and regulations to prove the authenticity, validity and consistency of identity. If the personal information provided by members is incomplete, invalid or may be inaccurate, TikTok Mall may not pass the authentication.<br>
(II) In order to ensure the continued authenticity and validity of member authentication information, TikTok Mall may review the information of members that have passed authentication.</p>
<p>Article 11 [Information Release]<br>Members shall not release the following information:<br>
(1) Opposing the basic principles established by the Constitution;<br>
(2) Endangering national security, leaking state secrets, subverting the state power, and undermining national unity;<br>
(3) Damaging the honor and interests of the state;<br>
(4) Distorting, vilifying, blaspheming, denying the deeds and spirit of heroes and martyrs, and insulting, slandering or otherwise infringing on the names, portraits, reputations, and honors of heroes and martyrs;<br>
(5) Propagating terrorism, extremism, or inciting terrorist activities or extremist activities;<br>
(6) Inciting ethnic hatred, ethnic Discrimination, undermining national unity;<br>
(VII) Undermining the state's religious policies, promoting cults and feudal superstitions;<br>
(VIII) Spreading rumors, disrupting economic and social order, and undermining social stability;<br>
(IX) Spreading obscenity, pornography, gambling, violence, murder, terror, or abetting crimes;<br>
(X) Insulting or slandering others, infringing on the legitimate rights and interests of others;<br>
(XI) Fraudulent, false, inaccurate or misleading;<br>
(XII) Other violations of laws, social morality, or according to the relevant agreements of the TikTok Mall platform, which are not suitable for posting on the TikTok Mall platform.</p>
<p>Article 12 [Transactions]<br>Members shall comply with the various requirements of the TikTok Mall platform transaction process to conduct real transactions. If a member has a dispute over a transaction on the TikTok Mall platform, he or she may initiate a dispute mediation service request to the TikTok Mall customer service department. TikTok Mall may require the buyer and seller to provide relevant supporting materials as appropriate and handle it in accordance with the "TikTok Mall Rules".</p>
<p>Article 13 [Information and Quality]<br>The product or service information published by sellers and suppliers must comply with the "TikTok Mall Product Release Specifications" and other relevant regulations. Sellers and suppliers should ensure that the goods or services they sell can be used normally within a reasonable period, have the performance they should have, meet the standards indicated on the packaging instructions, etc., and do not pose a risk to personal and property safety, and bear corresponding responsibilities for the quality of the goods or services they sell.<br>
The material descriptions of the goods released by sellers and suppliers must comply with the provisions of the "TikTok Mall Material Standard Definition Table". TikTok Mall may conduct random inspections of the goods or services sold by its sellers and suppliers in accordance with the "TikTok Mall Product Quality Random Inspection Specifications".</p>
<p>Article 14 [Transaction Performance and Service Guarantee]<br>Members can choose the transaction method according to TikTok Mall's requirements and actual needs.<br>
Sellers and suppliers must fulfill their commitments on transactions or services, including timely delivery within the prescribed and promised period (except for special circumstances) in accordance with the rules such as the "TikTok Mall Shipping Management Specifications" and their own commitments.<br>
Sellers and suppliers should protect the legitimate rights and interests of buyers, provide consumer protection services, and comply with relevant regulations such as the "TikTok Mall Seven-Day Unconditional Return Specifications".</p>
<p>Article 15 [Marketing]<br>Sellers and suppliers participating in TikTok Mall marketing activities must comply with the "TikTok Mall Marketing Activity Specifications" or corresponding marketing activity rules and other relevant regulations.</p>
<p>Article 16 [Industry and Featured Markets]<br>TikTok Mall sellers in specific industries or featured markets must comply with the "TikTok Mall Industry Management Specifications" and "TikTok Mall Featured Market Management Specifications".</p>
<p>Article 17 [Service Market Users]<br>Service market users should comply with the "Service Market Management Specifications" and other relevant regulations.</p>
<p>Article 18 [TikTok Mall Live Platform Users]<br>TikTok Mall Live Platform users should comply with the "Content Creator Management Rules", "TikTok Mall Live Management Rules", "TikTok Mall Live Organization Management Specifications", "TikTok Mall Engine Platform Management Rules", "TikTok Mall Engine Platform Dispute Handling Rules" and other relevant regulations.</p>
<p>Article 19 [Other Users]<br>In order to try to meet user needs and continuously improve user experience, the TikTok Mall platform may launch new markets and services from time to time. Users of the corresponding markets and services should comply with the corresponding agreements and the relevant rules and other regulations that are announced and effective on the TikTok Mall platform rules page.</p>
<p>Chapter V Market Management and Violation Handling<br>
Article 20 Risky behaviors and violations of TikTok Mall members shall be handled in accordance with the "TikTok Mall Market Management and Violation Handling Specifications".</p>
<p>Chapter VI Supplementary Provisions<br>
Article 21 These rules shall first take effect on October 10, 2024 and shall be revised on April 3, 2025.</p>
<p>Article 22 The term "above" in the TikTok Mall platform rules includes this number; the term "below" in the TikTok Mall platform rules does not include this number.</p>
<p>Article 23 The term "day" in the TikTok Mall platform rules shall be calculated as 24 hours.</p>
<p>Appendix Definitions</p>
<p>1. User refers to the user of various services on the TikTok Mall platform. Users can browse relevant information on the TikTok Mall platform without registration.</p>
<p>2. Member refers to a user who has signed a service agreement with TikTok Mall and completed the registration process, including natural persons, legal persons and unincorporated organizations of equal civil subjects.</p>
<p>3. Buyer refers to a member who purchases goods or services on the TikTok Mall platform.</p>
<p>4. Seller refers to a member who has successfully created a store on the TikTok Mall platform and is engaged in the business of selling goods or providing services.</p>
<p>5. Supplier refers to manufacturers, middlemen and individual business operators who provide sales of all related products on the TikTok Mall platform.</p>
<p>6. Other related parties refer to individuals or organizations that have a certain relationship with TikTok Mall platform users, such as intellectual property rights holders, supply and marketing platform users, service market users, content creators and institutions, etc.</p>
<p>7. TikTok Mall, the single or collective name of the TikTok Mall platform operator refers to Meta Network Technology Co., Ltd., the operator of the TikTok Mall network.</p>
<p>8. Intellectual property rights holders refer to natural persons, legal persons or other organizations that legally own intellectual property rights such as trademark rights, copyrights, and patent rights.</p>
</body></html>`);
});

app.get("/privacy", (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Agreement</title>
<style>
body{background:#fff;font-family:Arial,sans-serif;font-size:14px;color:#222;padding:20px;max-width:900px;margin:0 auto;line-height:1.7;}
h2{text-align:center;margin-bottom:20px;}
h3{font-size:15px;margin-top:20px;}
p,li{margin:8px 0;}
.back-btn{display:block;margin-bottom:20px;color:#1976d2;cursor:pointer;font-size:14px;text-decoration:none;}
</style></head>
<body>
<a class="back-btn" onclick="history.back()">&#8592; Back</a>
<h2>Privacy Notice</h2>
<p><strong>Last updated: December 21, 2021</strong></p>

<h3>What Personal Information About Customers Does TikTok Mall Collect?</h3>
<p>We collect your personal information in order to provide and continuously improve our products and services.<br>The following are the types of personal information we collect.</p>
<p>1. Information you provide to us: We receive and store any information you provide in relation to the shopping service. You may choose not to provide certain information, but you may not be able to use our shopping services.</p>
<p>2. Automatic Information: We automatically collect and store certain types of information about your use of the shopping Services, including information about your interactions with content and services provided through the shopping Services.</p>
<p>3. Information from other sources: We may receive information about you from other sources, such as updated delivery and address information from our carriers, which we use to correct our records and make it easier to deliver your next purchase.</p>

<h3>For what purpose does shopping use your personal information?</h3>
<p>We use your personal information to operate, provide, develop and improve the products and services we offer our customers. These purposes include:</p>
<p>1. Purchase and delivery of products and services. We use your personal information to accept and process orders, deliver products and services, process payments, and communicate with you about orders, products and services, and promotional offers.</p>
<p>2. To provide, troubleshoot and improve shopping services. We use your personal information to provide functionality, analyze performance, fix bugs and improve the usability and effectiveness of shopping Services.</p>
<p>3. Recommendations and personalization. We use your personal information to recommend features, products and services that may be of interest to you, determine your preferences, and personalize your experience with shopping services.</p>
<p>4. Compliance with legal obligations. In some cases, we collect and use your personal information to comply with the law. For example, we collect information about establishment location and bank account information from sellers for identity verification and other purposes.</p>
<p>5. Communicate with you. We use your personal information to communicate with you about shopping services through different channels (eg, by phone, email, chat).</p>
<p>6. Advertising. We use your personal information to display interest-based advertising of features, products and services that may be of interest to you. We do not use information that personally identifies you to display interest-based advertising.</p>
<p>7. Fraud Prevention and Credit Risk. We use personal information to prevent and detect fraud and abuse to protect the safety of our customers, shopping and others. We may also use scoring methods to assess and manage credit risk.</p>

<h3>Does platform share your personal information?</h3>
<p>1. Transactions involving third parties: We provide you with services, products, applications or skills provided by third parties for use on or through the shopping Services. For example, you can order products from third parties through our store, download apps from third-party app providers from our App Store, and when you place an order from a third-party seller, the information related to the order will be provided to the seller. This information will be governed by the seller's privacy policy. We also partner with third-party businesses to provide services or sell product lines, such as co-branded credit cards. You can tell when a third party is involved in your transactions with which we share customer personal information related to those transactions. These third parties may be located in other countries.</p>
<p>2. Third-Party Service Providers: We employ other companies and individuals to perform functions on our behalf. Examples include fulfilling orders for products or services, delivering packages, sending mail and emails, deduplicating information from customer lists, analyzing data, providing marketing assistance, providing search results and links (including paid listings and links), processing payments, transmitting content, scoring, assessing and managing credit risk and providing customer service. These third-party service providers have access to personal information necessary to perform their functions, but may not use it for other purposes. These service providers may be located in other countries.</p>
<p>3. Business Transfers: As we continue to develop our business, we may sell or purchase other businesses or services. In such transactions, customer information is often one of the transferred business assets, but is still subject to the commitments in any pre-existing privacy notices (unless, of course, the customer agrees otherwise).</p>
<p>4. Protection of platform and others: We release account and other personal information when we believe release is appropriate to comply with the law; enforce or apply our conditions of use and other agreements;</p>
<p>5. The rights, property or safety of our users or others. This includes exchanging information with other companies and organizations to protect against fraud and reduce credit risk.<br>In addition to the above, you will be notified when your personal information may be shared with third parties and you will be given the opportunity to opt out of sharing that information.</p>

<h3>How secure is my information?</h3>
<p>We design our systems with your security and privacy in mind.</p>
<p>1. We protect the security of your personal information during transmission by using encryption protocols and software.</p>
<p>2. We follow the Payment Card Industry Data Security Standard (PCI DSS) when processing credit card data.</p>
<p>3. We maintain physical, electronic and procedural safeguards related to the collection, storage and disclosure of personal customer information. Our security procedures mean that we may sometimes require proof of identity before disclosing personal information to you.</p>
<p>4. Our devices provide security features to protect them from unauthorized access and data loss. You can control these features and configure them as needed.</p>
<p>5. It is important to you to prevent unauthorized access to your passwords and your computers, devices and applications. Be sure to log out when you're done using the shared device.</p>

<h3>What about advertising?</h3>
<p>Links to Third-Party Advertisers and Other Websites: The platform Services may include third-party advertisements and links to other websites and applications. Third-party advertising partners may collect information about you when you interact with their content, advertisements, and services. For more information about platform third-party advertising (including interest-based advertising),</p>
<p>Use of third-party advertising services: We provide advertising companies with information to enable them to provide you with more useful and relevant platform advertising and to measure their effectiveness. When we do this, we will never share your name or other information that directly identifies you. Instead, we use advertising identifiers, such as cookies or other device identifiers. For example, if you have already downloaded one of our apps, we will share your advertising identifier and data about that event so that you do not receive ads for downloading the app again. Some advertising companies also use this information to serve you relevant advertisements from other advertisers.</p>

<h3>What information can I access?</h3>
<p>You can access your information, including your address, payment method, profile information and purchase history, in the "Your Account" section of the website.</p>

<h3>Are children allowed to use platform services?</h3>
<p>Our platform does not sell products intended for purchase by children. We sell children's products for adults to buy. If you are under the age of 18, you may only use the TikTok Mall Services with the involvement of a parent or guardian.</p>

<h3>Contact, Notices and Amendments</h3>
<p>If you have any questions about TikTok Mall's privacy, please contact us with a detailed description and we will do our best to resolve it. Our business is constantly changing, and so will our Privacy Statement. You should check our website frequently for recent changes. Unless otherwise stated, our current Privacy Statement applies to all information we have about you and your account. However, we stand by our commitments and will in no way materially change our policies and practices to reduce their protections for customer information collected in the past without the consent of affected customers.</p>
<p>Examples of Information Collected<br>
Information You Provide to Us When Using TikTok Mall Services<br>
You provide us with information when:</p>
<p>· search for or purchase products or services in our store;<br>
· Add or remove items from your shopping cart; place an order through or using the platform service;<br>
· Download, stream, view or use content on the device or through services or applications on the device;<br>
· Provide information in your account (you may have more than one if you use multiple email addresses or mobile phone numbers when shopping with us) or in your profile;<br>
· contact us by phone, email or otherwise;<br>
· Fill out questionnaires, support tickets or entry forms;<br>
· Provide and rate reviews;<br>
· Use product availability alerts such as orderable notifications.</p>
<p>As a result of these actions, you may provide us with the following information:<br>
· Identifying information, such as your name, address and telephone number;<br>
· Payment information;<br>
· your age;<br>
· Your location information;<br>
· your IP address;<br>
· Persons, addresses and phone numbers listed in your address;<br>
· Email addresses of your friends and others;<br>
· the content of comments and emails to us;<br>
· Personal description and photo in your profile;<br>
· Credit information;<br>
· Company and financial information;</p>
<p>Information from other sources<br>
Examples of information we receive from other sources include:<br>
· Updated delivery and address information from our operators or other third parties, which we use to correct our records and make it easier to deliver your next purchase or communication;<br>
· Account information, purchase or redemption information, and page browsing information from certain merchants with whom we operate a joint business or for which we provide technical, fulfillment, advertising or other services;<br>
· Information about your interactions with products and services offered by our affiliates;<br>
· Search results and links, including paid listings (such as sponsored links);<br>
· Credit history information from credit bureaus that we use to help prevent and detect fraud and to provide certain credit or financial services to certain customers.</p>
<p>Information you can access<br>
Examples of information you can access through the platform service include:<br>
· Status of recent orders;<br>
· Your complete order history;<br>
· Personally identifiable information (including name, email);<br>
· Payment settings (including payment card information);<br>
· Email notification settings (including product availability alerts, deliveries, special occasion reminders and newsletters);<br>
· Recommendations and the products you have recently viewed as the basis for recommendations (including recommendations for you and improvements to your recommendations);<br>
· your content, devices, services and related settings, and communication and personalized advertising preferences;<br>
· Content you have recently viewed;<br>
· Your personal data (including your product reviews, testimonials, reminders and personal data);<br>
· If you are a seller, you can access your account and other information and adjust your communication preferences by updating your account in Seller Central;<br>
If you are a developer participating in our Developer Services program, you can access your account and other information and adjust your communication preferences by updating your account in the Developer Services Portal.</p>
</body></html>`);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
    console.log("🔥 Server running on port " + PORT);

    // الاتصال بـ MongoDB
    await connectDB();

    // منع النوم - يضرب السيرفر كل 14 دقيقة
    if(process.env.RENDER_EXTERNAL_URL){
        setInterval(() => {
            fetch(process.env.RENDER_EXTERNAL_URL)
                .then(() => console.log("✅ Keep-alive ping sent"))
                .catch(() => {});
        }, 14 * 60 * 1000);
    }
});
