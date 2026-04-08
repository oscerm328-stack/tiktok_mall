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
<div style="text-align:center;padding:18px 0 8px;">
  <div style="display:inline-flex;flex-direction:column;align-items:center;gap:6px;">
    <!-- شعار TikTok -->
    <div style="width:70px;height:70px;display:flex;align-items:center;justify-content:center;background:white;border-radius:8px;">
      <svg width="55" height="55" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M33 7C33.8 10.2 36.2 12.6 39 13.4V18.2C36.6 18.2 34.4 17.4 32.6 16.2V27C32.6 32.6 28.2 37 22.6 37C17 37 12.6 32.6 12.6 27C12.6 21.4 17 17 22.6 17C23.2 17 23.8 17.1 24.4 17.2V22.2C23.8 22 23.2 21.9 22.6 21.9C19.6 21.9 17.2 24.2 17.2 27.2C17.2 30.2 19.6 32.5 22.6 32.5C25.6 32.5 28 30.2 28 27.2V7H33Z" fill="#EE1D52"/>
        <path d="M31 9C31.8 12.2 34.2 14.6 37 15.4V20.2C34.6 20.2 32.4 19.4 30.6 18.2V29C30.6 34.6 26.2 39 20.6 39C15 39 10.6 34.6 10.6 29C10.6 23.4 15 19 20.6 19C21.2 19 21.8 19.1 22.4 19.2V24.2C21.8 24 21.2 23.9 20.6 23.9C17.6 23.9 15.2 26.2 15.2 29.2C15.2 32.2 17.6 34.5 20.6 34.5C23.6 34.5 26 32.2 26 29.2V9H31Z" fill="#69C9D0"/>
        <path d="M32 8C32.8 11.2 35.2 13.6 38 14.4V19.2C35.6 19.2 33.4 18.4 31.6 17.2V28C31.6 33.6 27.2 38 21.6 38C16 38 11.6 33.6 11.6 28C11.6 22.4 16 18 21.6 18C22.2 18 22.8 18.1 23.4 18.2V23.2C22.8 23 22.2 22.9 21.6 22.9C18.6 22.9 16.2 25.2 16.2 28.2C16.2 31.2 18.6 33.5 21.6 33.5C24.6 33.5 27 31.2 27 28.2V8H32Z" fill="#010101"/>
      </svg>
    </div>
    <!-- الاسم -->
    <div class="logo" style="margin:0;">TikTok Mall</div>
  </div>
</div>

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

<div style="background:white;padding:20px 15px;display:flex;align-items:center;gap:15px;margin:10px 0;">

  <!-- شعار TikTok SVG -->
  <div style="width:80px;height:80px;display:flex;align-items:center;justify-content:center;flex-shrink:0;background:white;border-radius:8px;">
    <svg width="65" height="65" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M33 7C33.8 10.2 36.2 12.6 39 13.4V18.2C36.6 18.2 34.4 17.4 32.6 16.2V27C32.6 32.6 28.2 37 22.6 37C17 37 12.6 32.6 12.6 27C12.6 21.4 17 17 22.6 17C23.2 17 23.8 17.1 24.4 17.2V22.2C23.8 22 23.2 21.9 22.6 21.9C19.6 21.9 17.2 24.2 17.2 27.2C17.2 30.2 19.6 32.5 22.6 32.5C25.6 32.5 28 30.2 28 27.2V7H33Z" fill="#EE1D52"/>
      <path d="M31 9C31.8 12.2 34.2 14.6 37 15.4V20.2C34.6 20.2 32.4 19.4 30.6 18.2V29C30.6 34.6 26.2 39 20.6 39C15 39 10.6 34.6 10.6 29C10.6 23.4 15 19 20.6 19C21.2 19 21.8 19.1 22.4 19.2V24.2C21.8 24 21.2 23.9 20.6 23.9C17.6 23.9 15.2 26.2 15.2 29.2C15.2 32.2 17.6 34.5 20.6 34.5C23.6 34.5 26 32.2 26 29.2V9H31Z" fill="#69C9D0"/>
      <path d="M32 8C32.8 11.2 35.2 13.6 38 14.4V19.2C35.6 19.2 33.4 18.4 31.6 17.2V28C31.6 33.6 27.2 38 21.6 38C16 38 11.6 33.6 11.6 28C11.6 22.4 16 18 21.6 18C22.2 18 22.8 18.1 23.4 18.2V23.2C22.8 23 22.2 22.9 21.6 22.9C18.6 22.9 16.2 25.2 16.2 28.2C16.2 31.2 18.6 33.5 21.6 33.5C24.6 33.5 27 31.2 27 28.2V8H32Z" fill="#010101"/>
    </svg>
  </div>

  <!-- النص -->
  <div style="flex:1;">
    <div style="font-size:26px;font-weight:900;letter-spacing:1px;line-height:1;position:relative;display:inline-block;">
      <span style="position:relative;color:white;text-shadow:-2px -2px 0 #00f2ea, 2px 2px 0 #ff0050;-webkit-text-stroke:1px #010101;">TikTok </span><span style="color:white;text-shadow:-2px -2px 0 #00f2ea, 2px 2px 0 #ff0050;-webkit-text-stroke:1px #010101;">Mall</span>
    </div>
    <div style="display:flex;align-items:center;gap:6px;margin-top:6px;">
      <span style="font-size:13px;color:#00f2ea;font-weight:700;">🛍️ Selected Good Products</span>
    </div>
    <div style="display:flex;align-items:center;gap:6px;margin-top:3px;">
      <span style="font-size:13px;color:#ff0050;font-weight:700;">⭐ Provide Excellent Service</span>
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
app.get("/category", (req, res) => {
const cat = req.query.name || "All";

// =============== قواعد بيانات المنتجات لكل قسم ===============

const CAT_DATA = {

  "Clothing & Accessories": {
    base:[
      {t:"Nike Women Sportswear Phoenix Fleece High-Waisted Wide-Leg Sweatpants",p:65.00,i:["https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1183266/pexels-photo-1183266.jpeg?w=400","https://images.pexels.com/photos/291759/pexels-photo-291759.jpeg?w=400","https://images.pexels.com/photos/996329/pexels-photo-996329.jpeg?w=400"]},
      {t:"Adidas Women Essentials 3-Stripes Full-Zip Hoodie Track Suit",p:75.00,i:["https://images.pexels.com/photos/1183266/pexels-photo-1183266.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/996329/pexels-photo-996329.jpeg?w=400","https://images.pexels.com/photos/291759/pexels-photo-291759.jpeg?w=400"]},
      {t:"Levi's Women 501 Original Fit Jeans High Rise Classic Blue Denim",p:59.50,i:["https://images.pexels.com/photos/1598505/pexels-photo-1598505.jpeg?w=400","https://images.pexels.com/photos/1187720/pexels-photo-1187720.jpeg?w=400","https://images.pexels.com/photos/2220316/pexels-photo-2220316.jpeg?w=400","https://images.pexels.com/photos/1536619/pexels-photo-1536619.jpeg?w=400"]},
      {t:"Zara Women Floral Print Midi Dress Wrap V-Neck Ruffle Hem Boho Style",p:59.99,i:["https://images.pexels.com/photos/2983464/pexels-photo-2983464.jpeg?w=400","https://images.pexels.com/photos/1536619/pexels-photo-1536619.jpeg?w=400","https://images.pexels.com/photos/2220316/pexels-photo-2220316.jpeg?w=400","https://images.pexels.com/photos/1021693/pexels-photo-1021693.jpeg?w=400"]},
      {t:"H&M Women Ribbed Turtleneck Sweater Slim Fit Premium Cotton Long Sleeve",p:24.99,i:["https://images.pexels.com/photos/1021693/pexels-photo-1021693.jpeg?w=400","https://images.pexels.com/photos/996329/pexels-photo-996329.jpeg?w=400","https://images.pexels.com/photos/1183266/pexels-photo-1183266.jpeg?w=400","https://images.pexels.com/photos/934070/pexels-photo-934070.jpeg?w=400"]},
      {t:"Calvin Klein Women Slim Fit Ponte Dress Knee Length Short Sleeve Sheath",p:89.50,i:["https://images.pexels.com/photos/1485031/pexels-photo-1485031.jpeg?w=400","https://images.pexels.com/photos/2220316/pexels-photo-2220316.jpeg?w=400","https://images.pexels.com/photos/2235071/pexels-photo-2235071.jpeg?w=400","https://images.pexels.com/photos/1755428/pexels-photo-1755428.jpeg?w=400"]},
      {t:"Ralph Lauren Women Striped Polo Shirt Classic Fit Short Sleeve Cotton",p:45.00,i:["https://images.pexels.com/photos/996329/pexels-photo-996329.jpeg?w=400","https://images.pexels.com/photos/1021693/pexels-photo-1021693.jpeg?w=400","https://images.pexels.com/photos/1183266/pexels-photo-1183266.jpeg?w=400","https://images.pexels.com/photos/2220316/pexels-photo-2220316.jpeg?w=400"]},
      {t:"Burberry Women Check-Print Cashmere Scarf Classic Plaid Authentic",p:420.00,i:["https://images.pexels.com/photos/1485031/pexels-photo-1485031.jpeg?w=400","https://images.pexels.com/photos/2235071/pexels-photo-2235071.jpeg?w=400","https://images.pexels.com/photos/934070/pexels-photo-934070.jpeg?w=400","https://images.pexels.com/photos/1755428/pexels-photo-1755428.jpeg?w=400"]},
      {t:"Uniqlo Women Heattech Turtleneck Long-Sleeve T-Shirt Extra Warm Inner",p:19.90,i:["https://images.pexels.com/photos/1021693/pexels-photo-1021693.jpeg?w=400","https://images.pexels.com/photos/996329/pexels-photo-996329.jpeg?w=400","https://images.pexels.com/photos/291759/pexels-photo-291759.jpeg?w=400","https://images.pexels.com/photos/1183266/pexels-photo-1183266.jpeg?w=400"]},
      {t:"Strapless Satin Ball Gown Wedding Dress for Bride Split Prom Long",p:95.00,i:["https://images.pexels.com/photos/1755428/pexels-photo-1755428.jpeg?w=400","https://images.pexels.com/photos/2235071/pexels-photo-2235071.jpeg?w=400","https://images.pexels.com/photos/1485031/pexels-photo-1485031.jpeg?w=400","https://images.pexels.com/photos/934070/pexels-photo-934070.jpeg?w=400"]},
      {t:"EXLURA Women Swiss Dot Flowy Mini Dress V Neck Long Puff Sleeve",p:36.00,i:["https://images.pexels.com/photos/2220316/pexels-photo-2220316.jpeg?w=400","https://images.pexels.com/photos/1536619/pexels-photo-1536619.jpeg?w=400","https://images.pexels.com/photos/2983464/pexels-photo-2983464.jpeg?w=400","https://images.pexels.com/photos/1021693/pexels-photo-1021693.jpeg?w=400"]},
      {t:"Free People Women Carter Pullover Sweater Oversized Cozy Knit",p:48.00,i:["https://images.pexels.com/photos/1021693/pexels-photo-1021693.jpeg?w=400","https://images.pexels.com/photos/1183266/pexels-photo-1183266.jpeg?w=400","https://images.pexels.com/photos/934070/pexels-photo-934070.jpeg?w=400","https://images.pexels.com/photos/996329/pexels-photo-996329.jpeg?w=400"]},
      {t:"Mango Women Linen Blend Blazer Suit Jacket Tailored Fit Office Style",p:89.99,i:["https://images.pexels.com/photos/1485031/pexels-photo-1485031.jpeg?w=400","https://images.pexels.com/photos/2220316/pexels-photo-2220316.jpeg?w=400","https://images.pexels.com/photos/934070/pexels-photo-934070.jpeg?w=400","https://images.pexels.com/photos/2235071/pexels-photo-2235071.jpeg?w=400"]},
      {t:"Gap Women Softspun Open-Front Long Cardigan Relaxed Cozy Weekend",p:54.95,i:["https://images.pexels.com/photos/1021693/pexels-photo-1021693.jpeg?w=400","https://images.pexels.com/photos/934070/pexels-photo-934070.jpeg?w=400","https://images.pexels.com/photos/1183266/pexels-photo-1183266.jpeg?w=400","https://images.pexels.com/photos/996329/pexels-photo-996329.jpeg?w=400"]},
      {t:"Banana Republic Women Sloan Slim-Fit Pant Work Trousers Tailored",p:89.50,i:["https://images.pexels.com/photos/291759/pexels-photo-291759.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1183266/pexels-photo-1183266.jpeg?w=400","https://images.pexels.com/photos/996329/pexels-photo-996329.jpeg?w=400"]}
    ],
    colors:["Black","White","Navy","Beige","Ivory","Blush","Emerald","Burgundy","Camel","Lavender","Coral","Mint","Rose","Cobalt","Mauve","Taupe","Forest","Terracotta","Champagne","Slate","Olive","Dusty Pink","Midnight","Stone","Cream"],
    brands:["Zara","H&M","Nike","Adidas","Levi's","Calvin Klein","Ralph Lauren","Burberry","Uniqlo","Mango","Gap","Banana Republic","Tommy Hilfiger","Free People","ASOS","Shein","Forever 21","J.Crew","Ann Taylor","Anthropologie"],
    types:["Dress","Blouse","Top","Skirt","Coat","Jacket","Sweater","Cardigan","Pants","Jeans","Jumpsuit","Romper","Gown","Blazer","Shirt","Vest","Tunic","Cape","Kimono","Wrap"]
  },

  "Medical Bags and Sunglasses": {
    base:[
      {t:"Ray-Ban Aviator Classic Sunglasses UV Protection Polarized Gold Frame",p:154.00,i:["https://images.pexels.com/photos/975250/pexels-photo-975250.jpeg?w=400","https://images.pexels.com/photos/701877/pexels-photo-701877.jpeg?w=400","https://images.pexels.com/photos/1362558/pexels-photo-1362558.jpeg?w=400","https://images.pexels.com/photos/46710/pexels-photo-46710.jpeg?w=400"]},
      {t:"Gucci GG Canvas Tote Bag Women Large Shoulder Handbag Beige Brown Classic",p:1250.00,i:["https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]},
      {t:"Oakley Holbrook Polarized Sunglasses Lightweight UV400 Sport Style",p:196.00,i:["https://images.pexels.com/photos/46710/pexels-photo-46710.jpeg?w=400","https://images.pexels.com/photos/975250/pexels-photo-975250.jpeg?w=400","https://images.pexels.com/photos/1362558/pexels-photo-1362558.jpeg?w=400","https://images.pexels.com/photos/701877/pexels-photo-701877.jpeg?w=400"]},
      {t:"Prada Women Re-Edition Re-Nylon Mini Bag Shoulder Strap Luxury",p:1450.00,i:["https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400"]},
      {t:"Persol PO3152S Square Sunglasses Acetate Frame Polarized Classic Italian",p:275.00,i:["https://images.pexels.com/photos/1362558/pexels-photo-1362558.jpeg?w=400","https://images.pexels.com/photos/975250/pexels-photo-975250.jpeg?w=400","https://images.pexels.com/photos/46710/pexels-photo-46710.jpeg?w=400","https://images.pexels.com/photos/701877/pexels-photo-701877.jpeg?w=400"]},
      {t:"Michael Kors Jet Set Saffiano Leather Top-Zip Tote Bag Black Gold",p:228.00,i:["https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]},
      {t:"Tom Ford Ava Cat-Eye Sunglasses 55mm Acetate Frame Luxury Fashion",p:450.00,i:["https://images.pexels.com/photos/701877/pexels-photo-701877.jpeg?w=400","https://images.pexels.com/photos/46710/pexels-photo-46710.jpeg?w=400","https://images.pexels.com/photos/975250/pexels-photo-975250.jpeg?w=400","https://images.pexels.com/photos/1362558/pexels-photo-1362558.jpeg?w=400"]},
      {t:"Louis Vuitton Neverfull MM Monogram Canvas Tote Shoulder Bag Classic",p:1880.00,i:["https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]},
      {t:"Kate Spade Morgan Embossed Saffiano Leather Top-handle Bag Women",p:199.00,i:["https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400"]},
      {t:"Warby Parker Haskell Sunglasses Crystal Clear Frames Polarized Lens",p:95.00,i:["https://images.pexels.com/photos/975250/pexels-photo-975250.jpeg?w=400","https://images.pexels.com/photos/1362558/pexels-photo-1362558.jpeg?w=400","https://images.pexels.com/photos/701877/pexels-photo-701877.jpeg?w=400","https://images.pexels.com/photos/46710/pexels-photo-46710.jpeg?w=400"]},
      {t:"Coach Women Tabby 26 Pebble Leather Shoulder Bag Signature Lining",p:350.00,i:["https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400"]},
      {t:"Longchamp Le Pliage Original Travel Bag Foldable Nylon Tote Women",p:175.00,i:["https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]},
      {t:"Maui Jim Peahi Polarized Wrap Sunglasses Sport Premium Lens Blue",p:329.00,i:["https://images.pexels.com/photos/1362558/pexels-photo-1362558.jpeg?w=400","https://images.pexels.com/photos/46710/pexels-photo-46710.jpeg?w=400","https://images.pexels.com/photos/701877/pexels-photo-701877.jpeg?w=400","https://images.pexels.com/photos/975250/pexels-photo-975250.jpeg?w=400"]},
      {t:"Baggallini Essential Hobo Crossbody Bag for Women Lightweight Travel",p:51.00,i:["https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400"]},
      {t:"LAORENTOU Cow Leather Purses Small Handbag Women Satchel Tote Bag",p:86.12,i:["https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]}
    ],
    colors:["Black","Brown","Tan","Tortoise","Gold","Silver","Crystal","Navy","Rose Gold","Gunmetal","Havana","Gray","Blue","Green","Red","White"],
    brands:["Ray-Ban","Gucci","Oakley","Prada","Michael Kors","Tom Ford","Louis Vuitton","Kate Spade","Warby Parker","Coach","Longchamp","Persol","Maui Jim","Bottega Veneta","Celine","Fendi"],
    types:["Tote Bag","Shoulder Bag","Crossbody Bag","Clutch","Backpack","Satchel","Hobo Bag","Waist Bag","Sunglasses","Aviators","Cat-Eye","Round Frame","Square Frame","Wraparound"]
  },

  "Shoes": {
    base:[
      {t:"Nike Air Max 270 React ENG Men Running Shoes Triple Black Lightweight",p:150.00,i:["https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400","https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400","https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400"]},
      {t:"Adidas Ultraboost 22 Running Shoes Boost Cushioning Primeknit Women",p:180.00,i:["https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400","https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400"]},
      {t:"Converse Chuck Taylor All Star Classic High Top Canvas Sneaker Unisex",p:55.00,i:["https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400","https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400","https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400"]},
      {t:"Vans Old Skool Classic Skate Shoe Canvas Suede Low Top Unisex",p:70.00,i:["https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400","https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400"]},
      {t:"New Balance 990v5 Made in USA Running Shoe Men Premium Cushion",p:185.00,i:["https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400","https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400","https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400"]},
      {t:"Timberland Men 6-Inch Premium Waterproof Boot Wheat Nubuck Leather",p:198.00,i:["https://images.pexels.com/photos/1638247/pexels-photo-1638247.jpeg?w=400","https://images.pexels.com/photos/298863/pexels-photo-298863.jpeg?w=400","https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400"]},
      {t:"Dr. Martens 1460 Pascal 8-Eye Boot Virginia Leather Women Classic",p:150.00,i:["https://images.pexels.com/photos/298863/pexels-photo-298863.jpeg?w=400","https://images.pexels.com/photos/1638247/pexels-photo-1638247.jpeg?w=400","https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400","https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400"]},
      {t:"Puma RS-X Reinvention Sneaker Men Retro OG Runner Chunky Sole",p:110.00,i:["https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400","https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400"]},
      {t:"Steve Madden Women Irenee Platform Sandal Block Heel Ankle Strap",p:90.00,i:["https://images.pexels.com/photos/1639729/pexels-photo-1639729.jpeg?w=400","https://images.pexels.com/photos/2562992/pexels-photo-2562992.jpeg?w=400","https://images.pexels.com/photos/1638247/pexels-photo-1638247.jpeg?w=400","https://images.pexels.com/photos/298863/pexels-photo-298863.jpeg?w=400"]},
      {t:"Sam Edelman Women Hazel Pointed Toe Stiletto Heels Party Dress Pump",p:120.00,i:["https://images.pexels.com/photos/2562992/pexels-photo-2562992.jpeg?w=400","https://images.pexels.com/photos/1639729/pexels-photo-1639729.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400","https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400"]},
      {t:"Birkenstock Arizona Soft Footbed Sandal Suede Men Women Unisex",p:135.00,i:["https://images.pexels.com/photos/1639729/pexels-photo-1639729.jpeg?w=400","https://images.pexels.com/photos/2562992/pexels-photo-2562992.jpeg?w=400","https://images.pexels.com/photos/298863/pexels-photo-298863.jpeg?w=400","https://images.pexels.com/photos/1638247/pexels-photo-1638247.jpeg?w=400"]},
      {t:"UGG Classic Short II Boot Women Twinface Sheepskin Suede Warm Winter",p:170.00,i:["https://images.pexels.com/photos/1638247/pexels-photo-1638247.jpeg?w=400","https://images.pexels.com/photos/298863/pexels-photo-298863.jpeg?w=400","https://images.pexels.com/photos/1639729/pexels-photo-1639729.jpeg?w=400","https://images.pexels.com/photos/2562992/pexels-photo-2562992.jpeg?w=400"]},
      {t:"Jordan 1 Retro High OG Men Basketball Sneaker Leather Iconic",p:170.00,i:["https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400","https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400"]},
      {t:"ASICS Gel-Nimbus 25 Running Shoe Men Cushioning Stability",p:160.00,i:["https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400","https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400"]},
      {t:"Brooks Ghost 15 Women Neutral Running Shoe DNA Loft Cushion",p:140.00,i:["https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg?w=400","https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg?w=400","https://images.pexels.com/photos/1280064/pexels-photo-1280064.jpeg?w=400","https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg?w=400"]}
    ],
    colors:["Black","White","Red","Navy","Gray","Beige","Brown","Wheat","Triple White","Triple Black","Volt","Blue","Pink","Green","Orange","Tan"],
    brands:["Nike","Adidas","Converse","Vans","New Balance","Timberland","Dr. Martens","Puma","Steve Madden","Sam Edelman","Birkenstock","UGG","Jordan","ASICS","Brooks","Skechers","Reebok","Salomon"],
    types:["Sneaker","Running Shoe","Boot","High Top","Low Top","Sandal","Pump","Loafer","Platform","Slip-On","Athletic Shoe","Ankle Boot","Chelsea Boot","Oxford","Derby","Mule"]
  },

  "Watches": {
    base:[
      {t:"Rolex Submariner Date 41mm Oystersteel Black Dial Ceramic Bezel",p:10550.00,i:["https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400"]},
      {t:"Omega Seamaster Planet Ocean 600M Co-Axial Master Chronometer 43.5mm",p:6900.00,i:["https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400"]},
      {t:"Seiko Prospex Solar Diver SNE573 Stainless Steel Tuna Case 200m",p:525.00,i:["https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400"]},
      {t:"TAG Heuer Carrera Calibre 16 Chronograph Automatic 41mm Men Watch",p:2650.00,i:["https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400"]},
      {t:"Casio G-Shock GA-2100 CasiOak Carbon Core Guard Black Tough Solar",p:99.00,i:["https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400"]},
      {t:"Apple Watch Series 9 GPS 45mm Starlight Aluminum Sport Band",p:429.00,i:["https://images.pexels.com/photos/437037/pexels-photo-437037.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400"]},
      {t:"Tissot PRX Powermatic 80 35mm Stainless Steel Auto Women Bracelet",p:725.00,i:["https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400"]},
      {t:"Longines Master Collection Moon Phase 40mm L2.909.4 Automatic",p:2250.00,i:["https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400"]},
      {t:"Fossil Men Neutra Chronograph Quartz Stainless Steel Brown Leather",p:119.00,i:["https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400"]},
      {t:"Citizen Eco-Drive Chandler Quartz Men Watch BM7460-11X Solar",p:175.00,i:["https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400","https://images.pexels.com/photos/437037/pexels-photo-437037.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400"]},
      {t:"Breitling Navitimer B01 Chronograph 43 Steel Black Dial AB0121211B1A1",p:8900.00,i:["https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400"]},
      {t:"Hamilton Khaki Field Mechanical Men Watch 38mm Black Dial H69439733",p:495.00,i:["https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400"]},
      {t:"Garmin Fenix 7 Pro Solar Multisport GPS Smartwatch Sapphire Solar",p:749.99,i:["https://images.pexels.com/photos/437037/pexels-photo-437037.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400"]},
      {t:"Orient Bambino Version 3 Classic Dress Watch Open Heart Men",p:152.00,i:["https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400","https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400"]},
      {t:"Tudor Black Bay 41mm Steel Bracelet Hawthorn Bezel M79540-0001",p:3550.00,i:["https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg?w=400","https://images.pexels.com/photos/125779/pexels-photo-125779.jpeg?w=400","https://images.pexels.com/photos/190819/pexels-photo-190819.jpeg?w=400","https://images.pexels.com/photos/1697214/pexels-photo-1697214.jpeg?w=400"]}
    ],
    colors:["Black","Silver","Gold","Rose Gold","Blue","Green","White","Gray","Two-Tone","Champagne","Brown","Navy","Titanium","Bronze","Slate"],
    brands:["Rolex","Omega","Seiko","TAG Heuer","Casio","Apple","Tissot","Longines","Fossil","Citizen","Breitling","Hamilton","Garmin","Orient","Tudor","IWC","Patek Philippe","Audemars Piguet","Rado","Bulova"],
    types:["Automatic","Quartz","Chronograph","Diver","Dress Watch","Smartwatch","Solar","Pilot Watch","Field Watch","Sport Watch","GMT","Tourbillon","Skeleton","Moon Phase"]
  },

  "Jewelry": {
    base:[
      {t:"Pandora Rose Gold Sterling Silver Charm Bracelet Love Clasp Women",p:85.00,i:["https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400","https://images.pexels.com/photos/248077/pexels-photo-248077.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400","https://images.pexels.com/photos/177332/pexels-photo-177332.jpeg?w=400"]},
      {t:"Swarovski Crystal Drop Earrings 18K Rose Gold Plated Statement Jewelry",p:129.00,i:["https://images.pexels.com/photos/1191531/pexels-photo-1191531.jpeg?w=400","https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400","https://images.pexels.com/photos/691046/pexels-photo-691046.jpeg?w=400"]},
      {t:"Tiffany 18K Gold Diamond Pendant Necklace Classic Solitaire Women",p:1850.00,i:["https://images.pexels.com/photos/1302307/pexels-photo-1302307.jpeg?w=400","https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400","https://images.pexels.com/photos/248077/pexels-photo-248077.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400"]},
      {t:"Cartier Love Bracelet 18K White Gold 4 Diamonds Classic Luxury Women",p:7200.00,i:["https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400","https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400","https://images.pexels.com/photos/177332/pexels-photo-177332.jpeg?w=400","https://images.pexels.com/photos/2697513/pexels-photo-2697513.jpeg?w=400"]},
      {t:"Missoma Lena Statement Baroque Pearl Necklace 18ct Gold Plated Women",p:195.00,i:["https://images.pexels.com/photos/2849742/pexels-photo-2849742.jpeg?w=400","https://images.pexels.com/photos/1191531/pexels-photo-1191531.jpeg?w=400","https://images.pexels.com/photos/248077/pexels-photo-248077.jpeg?w=400","https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400"]},
      {t:"Kendra Scott Elle Gold Ring Set Adjustable Stacking Band with Stones",p:58.00,i:["https://images.pexels.com/photos/177332/pexels-photo-177332.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400","https://images.pexels.com/photos/691046/pexels-photo-691046.jpeg?w=400","https://images.pexels.com/photos/2697513/pexels-photo-2697513.jpeg?w=400"]},
      {t:"Mejuri Bold Chain Necklace 14K Gold Vermeil Minimalist Fine Jewelry",p:168.00,i:["https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400","https://images.pexels.com/photos/248077/pexels-photo-248077.jpeg?w=400","https://images.pexels.com/photos/1302307/pexels-photo-1302307.jpeg?w=400","https://images.pexels.com/photos/2849742/pexels-photo-2849742.jpeg?w=400"]},
      {t:"Alex and Ani Path of Life Expandable Wire Bangle Bracelet Silver",p:38.00,i:["https://images.pexels.com/photos/248077/pexels-photo-248077.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400","https://images.pexels.com/photos/177332/pexels-photo-177332.jpeg?w=400","https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400"]},
      {t:"Gorjana Power Gemstone Beaded Bracelet Healing Crystal Stack",p:48.00,i:["https://images.pexels.com/photos/691046/pexels-photo-691046.jpeg?w=400","https://images.pexels.com/photos/2697513/pexels-photo-2697513.jpeg?w=400","https://images.pexels.com/photos/177332/pexlas-photo-177332.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400"]},
      {t:"BaubleBar Pisa Drop Earrings Classic Gold Plated Statement Fashion",p:42.00,i:["https://images.pexels.com/photos/1191531/pexels-photo-1191531.jpeg?w=400","https://images.pexels.com/photos/691046/pexels-photo-691046.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400","https://images.pexels.com/photos/2849742/pexels-photo-2849742.jpeg?w=400"]},
      {t:"David Yurman Cable Classics Bracelet Sterling Silver Gold Dome",p:595.00,i:["https://images.pexels.com/photos/248077/pexels-photo-248077.jpeg?w=400","https://images.pexels.com/photos/177332/pexels-photo-177332.jpeg?w=400","https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400"]},
      {t:"Madewell Essential Open Triangle Stud Earrings 14k Gold-Filled",p:22.00,i:["https://images.pexels.com/photos/1191531/pexels-photo-1191531.jpeg?w=400","https://images.pexels.com/photos/2849742/pexels-photo-2849742.jpeg?w=400","https://images.pexels.com/photos/691046/pexels-photo-691046.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400"]},
      {t:"Bulgari B.zero1 Ring 18K Rose Gold Two-Band Iconic Luxury Signature",p:2200.00,i:["https://images.pexels.com/photos/177332/pexels-photo-177332.jpeg?w=400","https://images.pexels.com/photos/2697513/pexels-photo-2697513.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400","https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400"]},
      {t:"Van Cleef & Arpels Alhambra Pendant Yellow Gold Malachite Iconic",p:3950.00,i:["https://images.pexels.com/photos/1302307/pexels-photo-1302307.jpeg?w=400","https://images.pexels.com/photos/2849742/pexels-photo-2849742.jpeg?w=400","https://images.pexels.com/photos/1191531/pexels-photo-1191531.jpeg?w=400","https://images.pexels.com/photos/265906/pexels-photo-265906.jpeg?w=400"]},
      {t:"Mikimoto Pearl Stud Earrings 18K White Gold Classic Akoya Cultured",p:850.00,i:["https://images.pexels.com/photos/2849742/pexels-photo-2849742.jpeg?w=400","https://images.pexels.com/photos/1191531/pexels-photo-1191531.jpeg?w=400","https://images.pexels.com/photos/691046/pexels-photo-691046.jpeg?w=400","https://images.pexels.com/photos/1458867/pexels-photo-1458867.jpeg?w=400"]}
    ],
    colors:["Gold","Rose Gold","Silver","Yellow Gold","White Gold","Platinum","Two-Tone","Black Gold","Copper","Bronze","Crystal","Pearl","Diamond","Ruby","Emerald","Sapphire"],
    brands:["Pandora","Swarovski","Tiffany","Cartier","Missoma","Kendra Scott","Mejuri","Alex and Ani","BaubleBar","David Yurman","Madewell","Bulgari","Van Cleef","Mikimoto","Gorjana","Monica Vinader"],
    types:["Necklace","Bracelet","Earrings","Ring","Pendant","Anklet","Bangle","Charm","Stud Earrings","Drop Earrings","Tennis Bracelet","Cuff","Statement Necklace","Choker","Hoop Earrings"]
  },

  "Electronics": {
    base:[
      {t:"Apple MacBook Pro 14-inch M3 Pro Chip 18GB RAM 512GB SSD Space Black",p:1999.00,i:["https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400","https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400","https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400","https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400"]},
      {t:"Samsung Galaxy S24 Ultra 5G 512GB Titanium Black Snapdragon 8 Gen 3",p:1299.00,i:["https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400","https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400","https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400","https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400"]},
      {t:"Sony WH-1000XM5 Wireless Noise Canceling Over-Ear Headphones Platinum",p:348.00,i:["https://images.pexels.com/photos/3587478/pexels-photo-3587478.jpeg?w=400","https://images.pexels.com/photos/1649771/pexels-photo-1649771.jpeg?w=400","https://images.pexels.com/photos/1038916/pexels-photo-1038916.jpeg?w=400","https://images.pexels.com/photos/3394650/pexels-photo-3394650.jpeg?w=400"]},
      {t:"iPad Pro 13-inch M4 Wi-Fi 256GB Ultra Retina XDR OLED Tandem Space Black",p:1299.00,i:["https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400","https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400","https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400","https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400"]},
      {t:"Dell XPS 15 9530 Intel Core i9-13900H 32GB RAM 1TB SSD RTX 4060",p:2199.00,i:["https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400","https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400","https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400","https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400"]},
      {t:"Bose QuietComfort 45 Wireless Bluetooth Noise Cancelling Headphones White",p:279.00,i:["https://images.pexels.com/photos/1649771/pexels-photo-1649771.jpeg?w=400","https://images.pexels.com/photos/3587478/pexels-photo-3587478.jpeg?w=400","https://images.pexels.com/photos/3394650/pexels-photo-3394650.jpeg?w=400","https://images.pexels.com/photos/1038916/pexels-photo-1038916.jpeg?w=400"]},
      {t:"LG C3 55-Inch OLED evo Smart TV 4K HDR Dolby Vision ThinQ AI",p:1299.00,i:["https://images.pexels.com/photos/1649771/pexels-photo-1649771.jpeg?w=400","https://images.pexels.com/photos/1038916/pexels-photo-1038916.jpeg?w=400","https://images.pexels.com/photos/3394650/pexels-photo-3394650.jpeg?w=400","https://images.pexels.com/photos/3587478/pexels-photo-3587478.jpeg?w=400"]},
      {t:"GoPro HERO12 Black 5.3K60 HDR Action Camera Waterproof HyperSmooth",p:399.00,i:["https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400","https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400","https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400","https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400"]},
      {t:"NVIDIA GeForce RTX 4080 Super Founders Edition 16GB GDDR6X Graphics Card",p:999.00,i:["https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400","https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400","https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400","https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400"]},
      {t:"Amazon Echo Dot 5th Gen Smart Speaker with Alexa Deep Sea Blue",p:49.99,i:["https://images.pexels.com/photos/3394650/pexels-photo-3394650.jpeg?w=400","https://images.pexels.com/photos/1038916/pexels-photo-1038916.jpeg?w=400","https://images.pexels.com/photos/1649771/pexels-photo-1649771.jpeg?w=400","https://images.pexels.com/photos/3587478/pexels-photo-3587478.jpeg?w=400"]},
      {t:"Logitech MX Master 3S Wireless Performance Mouse 8K DPI Quiet Click",p:99.99,i:["https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400","https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400","https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400","https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400"]},
      {t:"Canon EOS R6 Mark II Full-Frame Mirrorless Camera Body 24.2MP",p:2499.00,i:["https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400","https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400","https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400","https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400"]},
      {t:"SanDisk 2TB Extreme Portable SSD 1050MB/s USB-C IP65 Rugged",p:139.99,i:["https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400","https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400","https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400","https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400"]},
      {t:"Anker 737 Power Bank 24000mAh 140W USB-C Portable Charger Black",p:89.99,i:["https://images.pexels.com/photos/1649771/pexels-photo-1649771.jpeg?w=400","https://images.pexels.com/photos/3394650/pexels-photo-3394650.jpeg?w=400","https://images.pexels.com/photos/3587478/pexels-photo-3587478.jpeg?w=400","https://images.pexels.com/photos/1038916/pexels-photo-1038916.jpeg?w=400"]},
      {t:"Samsung 990 Pro 2TB NVMe PCIe Gen 4 M.2 Internal SSD 7450MB/s",p:149.99,i:["https://images.pexels.com/photos/18105/pexels-photo.jpg?w=400","https://images.pexels.com/photos/238118/pexels-photo-238118.jpeg?w=400","https://images.pexels.com/photos/1229861/pexels-photo-1229861.jpeg?w=400","https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg?w=400"]}
    ],
    colors:["Black","Silver","White","Space Gray","Midnight","Starlight","Graphite","Navy","Blue","Green","Gold","Titanium","Jet Black","Deep Purple"],
    brands:["Apple","Samsung","Sony","Dell","Bose","LG","GoPro","NVIDIA","Amazon","Logitech","Canon","SanDisk","Anker","Lenovo","Asus","HP","Microsoft","Intel","AMD","Razer"],
    types:["Laptop","Smartphone","Tablet","Headphones","Smart TV","Camera","GPU","Speaker","Mouse","Keyboard","SSD","Power Bank","Monitor","Printer","Router","Smartwatch"]
  },

  "Smart Home": {
    base:[
      {t:"Amazon Echo Show 10 3rd Gen Smart Display with Motion 10.1-inch HD Screen",p:249.99,i:["https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400"]},
      {t:"Philips Hue Smart Bulb A19 75W Equivalent E26 Color Starter Kit",p:179.99,i:["https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400"]},
      {t:"Ring Video Doorbell 4 1080p HD Video Motion Detection Two-Way Talk",p:99.99,i:["https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400"]},
      {t:"Nest Learning Thermostat 4th Gen Smart Programmable Works Google Home",p:279.99,i:["https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400"]},
      {t:"Roomba j7+ Self-Emptying Robot Vacuum Combo Avoids Obstacles Auto Dirt Disposal",p:799.99,i:["https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400"]},
      {t:"Google Nest Hub 2nd Gen 7-inch Smart Home Display with Sleep Sensing",p:99.99,i:["https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400"]},
      {t:"Samsung SmartThings Hub v3 Control Zigbee Z-Wave IoT Home Hub",p:129.99,i:["https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400"]},
      {t:"Arlo Pro 4 Wireless Security Camera 2K HDR Color Night Vision Spotlight",p:199.99,i:["https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400"]},
      {t:"August Smart Lock Pro 3rd Gen Connect Adapter Z-Wave Plus Keyless Entry",p:229.99,i:["https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400"]},
      {t:"TP-Link Kasa Smart Plug Mini 15A Works Alexa Google Wifi Timer Schedule",p:19.99,i:["https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400"]},
      {t:"Lutron Caseta Wireless Smart Lighting Dimmer Switch Starter Kit",p:79.99,i:["https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400"]},
      {t:"Ecobee SmartThermostat Premium with Smart Sensor Voice Control Alexa",p:249.99,i:["https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400"]},
      {t:"LIFX A19 1100 Lumens Smart Multicolor LED Bulb Wi-Fi No Hub Required",p:49.99,i:["https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400"]},
      {t:"Wyze Cam v3 1080p HD Indoor Outdoor IP65 Night Vision Color Motion",p:35.98,i:["https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400"]},
      {t:"Amazon Alexa Smart Plug 15A Compact WiFi Outlet Schedule Timer Control",p:24.99,i:["https://images.pexels.com/photos/3964704/pexels-photo-3964704.jpeg?w=400","https://images.pexels.com/photos/4790268/pexels-photo-4790268.jpeg?w=400","https://images.pexels.com/photos/1034812/pexels-photo-1034812.jpeg?w=400","https://images.pexels.com/photos/1571458/pexels-photo-1571458.jpeg?w=400"]}
    ],
    colors:["White","Black","Charcoal","Silver","Platinum","Nickel","Bronze","Blue","Sand","Linen"],
    brands:["Amazon","Philips Hue","Ring","Google Nest","iRobot","Samsung","Arlo","August","TP-Link","Lutron","Ecobee","LIFX","Wyze","Eufy","Wemo","Govee","Meross","Yale","Schlage","Eve"],
    types:["Smart Speaker","Smart Bulb","Video Doorbell","Thermostat","Robot Vacuum","Smart Display","Security Camera","Smart Lock","Smart Plug","Dimmer Switch","Hub","Smoke Detector","Motion Sensor","Smart Strip","Air Purifier"]
  },

  "Luxury Brands": {
    base:[
      {t:"Louis Vuitton Monogram Canvas Keepall 55 Bandoulière Travel Bag",p:2150.00,i:["https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]},
      {t:"Chanel Classic Flap Bag Medium Lambskin Gold Hardware Quilted CC",p:9800.00,i:["https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400"]},
      {t:"Hermès Birkin 30 Togo Leather Gold Hardware Palladium Luxury Iconic",p:18500.00,i:["https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400"]},
      {t:"Gucci Dionysus GG Supreme Canvas Shoulder Bag Tiger Head Clasp",p:2350.00,i:["https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400"]},
      {t:"Prada Galleria Saffiano Leather Bag Medium Double Zip Luxury",p:3200.00,i:["https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]},
      {t:"Dior Lady Dior Medium Bag Cannage Lambskin Patent Leather Pink",p:5500.00,i:["https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]},
      {t:"Bottega Veneta Intrecciato Leather Crossbody Bag Woven Classic",p:2800.00,i:["https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400"]},
      {t:"Saint Laurent Loulou Medium Chain Bag Matelasse Chevron Leather",p:2650.00,i:["https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400"]},
      {t:"Fendi Baguette Mini Bag FF Motif Jacquard Fabric Iconic Runway",p:1490.00,i:["https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400"]},
      {t:"Valentino Garavani Rockstud Spike Medium Bag Quilted Calfskin",p:3450.00,i:["https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400"]},
      {t:"Burberry Knight Medium Bag Equestrian Knight Design Leather Archive",p:1950.00,i:["https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400"]},
      {t:"Givenchy Antigona Soft Medium Bag Grained Calfskin Luxury Chain",p:2490.00,i:["https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400"]},
      {t:"Celine Classic Box Bag Smooth Calfskin Small Palladium Iconic",p:3900.00,i:["https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400"]},
      {t:"Balenciaga City Bag Aged Calfskin Oversized Studs Motorcycle Classic",p:2050.00,i:["https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400"]},
      {t:"Off-White Jitney 1.4 Quote Bag Arrow Logo Straps Industrial Chain",p:1295.00,i:["https://images.pexels.com/photos/1839782/pexels-photo-1839782.jpeg?w=400","https://images.pexels.com/photos/1152077/pexels-photo-1152077.jpeg?w=400","https://images.pexels.com/photos/904350/pexels-photo-904350.jpeg?w=400","https://images.pexels.com/photos/2905238/pexels-photo-2905238.jpeg?w=400"]}
    ],
    colors:["Black","Tan","Camel","Beige","White","Red","Pink","Navy","Brown","Burgundy","Nude","Grey","Gold","Silver"],
    brands:["Louis Vuitton","Chanel","Hermès","Gucci","Prada","Dior","Bottega Veneta","Saint Laurent","Fendi","Valentino","Burberry","Givenchy","Celine","Balenciaga","Off-White","Loewe","Jacquemus","Marni","Toteme","The Row"],
    types:["Tote Bag","Shoulder Bag","Crossbody","Clutch","Backpack","Belt Bag","Top Handle","Satchel","Bucket Bag","Mini Bag","Baguette","Flap Bag","Chain Bag","Drawstring"]
  },

  "Beauty and Personal Care": {
    base:[
      {t:"Charlotte Tilbury Airbrush Flawless Foundation 30ml Full Coverage Liquid",p:49.00,i:["https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400"]},
      {t:"Fenty Beauty Pro Filt'r Soft Matte Longwear Foundation Shade 220",p:40.00,i:["https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400"]},
      {t:"NARS Orgasm Blush 4.8g Peachy Pink Golden Shimmer Classic Bestseller",p:34.00,i:["https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400"]},
      {t:"Drunk Elephant Protini Polypeptide Cream Moisturizer Skincare 50ml",p:68.00,i:["https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400"]},
      {t:"La Mer The Moisturizing Cream 60ml Seaweed Miracle Broth Luxury",p:355.00,i:["https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400"]},
      {t:"Olaplex No.3 Hair Perfector Bond-Building Repair Treatment 100ml",p:28.00,i:["https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400"]},
      {t:"Dyson Airwrap Multi-Styler Complete Long Nickel Copper Hair Tool",p:599.99,i:["https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400"]},
      {t:"Urban Decay Naked3 Eyeshadow Palette 12 Rose-Hued Shades Warm",p:54.00,i:["https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400"]},
      {t:"CeraVe Moisturizing Cream 19 oz Body Face Ceramides Hyaluronic Acid",p:16.08,i:["https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400"]},
      {t:"The Ordinary Hyaluronic Acid 2% + B5 Hydration Support Formula 30ml",p:9.90,i:["https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400"]},
      {t:"Pat McGrath Labs MatteTrance Lipstick Flesh 4 Luxe Formula Full Wear",p:40.00,i:["https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400"]},
      {t:"Tatcha The Water Cream Oil-Free Pore Minimizing Moisturizer 50ml",p:72.00,i:["https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400"]},
      {t:"Lancôme Advanced Génifique Serum 30ml Youth Activating Concentrate",p:115.00,i:["https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400"]},
      {t:"MAC Cosmetics Studio Fix Fluid Foundation SPF15 NC25 Long Wear",p:38.00,i:["https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400"]},
      {t:"Benefit Cosmetics Hoola Matte Bronzer 8g Sun-Kissed Glow Classic",p:36.00,i:["https://images.pexels.com/photos/1029896/pexels-photo-1029896.jpeg?w=400","https://images.pexels.com/photos/4041392/pexels-photo-4041392.jpeg?w=400","https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?w=400","https://images.pexels.com/photos/2533266/pexels-photo-2533266.jpeg?w=400"]}
    ],
    colors:["Nude","Pink","Red","Coral","Berry","Mauve","Brown","Peach","Rose","Plum","Bronze","Gold","Clear","Natural","Ivory"],
    brands:["Charlotte Tilbury","Fenty Beauty","NARS","Drunk Elephant","La Mer","Olaplex","Dyson","Urban Decay","CeraVe","The Ordinary","Pat McGrath","Tatcha","Lancôme","MAC","Benefit","Too Faced","Tarte","Rare Beauty","Summer Fridays","Kiehl's"],
    types:["Foundation","Moisturizer","Serum","Lipstick","Eyeshadow Palette","Blush","Bronzer","Concealer","Setting Spray","Toner","Hair Mask","Hair Tool","Sunscreen","Eye Cream","Body Lotion"]
  },

  "Mens Fashion": {
    base:[
      {t:"Levi's Men 511 Slim Fit Jeans Mid Rise Flex Denim Classic Blue",p:59.50,i:["https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400"]},
      {t:"Nike Men Sportswear Club Fleece Pullover Hoodie Standard Fit Gray",p:55.00,i:["https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400"]},
      {t:"Tommy Hilfiger Men Pima Cotton Crewneck Sweater Classic Fit Preppy",p:79.99,i:["https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400"]},
      {t:"Ralph Lauren Men Polo Classic Fit Mesh Polo Short Sleeve Cotton",p:98.50,i:["https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400"]},
      {t:"Calvin Klein Men Regular Fit Long Sleeve Oxford Button Down Dress Shirt",p:69.50,i:["https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400"]},
      {t:"Hugo Boss Men Regular Fit Stretch Chino Trousers Casual Office",p:129.00,i:["https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400"]},
      {t:"Zara Men Slim Fit Technical Jacket Lightweight Windbreaker Outdoor",p:89.99,i:["https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400"]},
      {t:"Patagonia Men Better Sweater Fleece Jacket Full Zip Classic",p:149.00,i:["https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400"]},
      {t:"Banana Republic Men Aiden Skinny-Fit Non-Iron Dress Pant Office",p:89.50,i:["https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400"]},
      {t:"Uniqlo Men Flannel Long-Sleeve Check Shirt Soft Touch Plaid",p:29.90,i:["https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400"]},
      {t:"J.Crew Men Ludlow Slim-Fit Suit Jacket Italian Wool Blend Stretch",p:298.00,i:["https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400"]},
      {t:"Adidas Men Tiro 23 League Training Pants Moisture Wicking Sport",p:45.00,i:["https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400"]},
      {t:"Columbia Men Steens Mountain Full Zip Fleece Soft Plush Outdoor",p:65.00,i:["https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400"]},
      {t:"Dickies Men Original 874 Work Pant Straight Leg Relaxed Fit Classic",p:34.99,i:["https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400","https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400"]},
      {t:"Under Armour Men Tech 2.0 Short Sleeve T-Shirt Anti-Odor HeatGear",p:25.00,i:["https://images.pexels.com/photos/1124468/pexels-photo-1124468.jpeg?w=400","https://images.pexels.com/photos/2220315/pexels-photo-2220315.jpeg?w=400","https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?w=400","https://images.pexels.com/photos/1040945/pexels-photo-1040945.jpeg?w=400"]}
    ],
    colors:["Navy","Black","Gray","White","Khaki","Olive","Charcoal","Blue","Brown","Tan","Burgundy","Forest Green","Slate","Stone","Indigo"],
    brands:["Levi's","Nike","Tommy Hilfiger","Ralph Lauren","Calvin Klein","Hugo Boss","Zara","Patagonia","Banana Republic","Uniqlo","J.Crew","Adidas","Columbia","Dickies","Under Armour","Carhartt","Allen Edmonds","Brooks Brothers","Bonobos","Ted Baker"],
    types:["Jeans","T-Shirt","Hoodie","Polo","Dress Shirt","Chinos","Jacket","Suit","Sweater","Sweatpants","Shorts","Blazer","Vest","Overcoat","Flannel Shirt"]
  },

  "Health and Household": {
    base:[
      {t:"Vitamix 5200 Blender Professional-Grade Container 64oz Self-Cleaning",p:449.95,i:["https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400"]},
      {t:"Theragun Pro Generation 5 Deep Tissue Massage Gun Percussive Therapy",p:599.00,i:["https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400"]},
      {t:"Fitbit Charge 6 Health Fitness Tracker GPS Heart Rate Sleep Tracking",p:159.95,i:["https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400"]},
      {t:"Dyson V15 Detect Absolute Cordless Vacuum Laser Dust Detection HEPA",p:749.99,i:["https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400"]},
      {t:"Instant Pot Duo 7-in-1 Electric Pressure Cooker 8 Quart Slow Cook",p:99.99,i:["https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400"]},
      {t:"NordicTrack Commercial 1750 Treadmill iFIT Enabled 10% Incline 12 MPH",p:1799.00,i:["https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400"]},
      {t:"Garden of Life Vitamin Code Raw Zinc 30mg Immune Support Whole Food",p:19.99,i:["https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400"]},
      {t:"Philips Sonicare ProtectiveClean 6100 Rechargeable Electric Toothbrush",p:119.99,i:["https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400"]},
      {t:"Listerine Cool Mint Antiseptic Mouthwash Oral Care 1.5L Family Value",p:12.97,i:["https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400"]},
      {t:"Clorox Disinfecting Wipes Value Pack Bleach Free Fresh Scent 225 Wipes",p:14.48,i:["https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400"]},
      {t:"Tide Plus Febreze Freshness Liquid Laundry Detergent 92 Oz 64 Loads",p:19.97,i:["https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400"]},
      {t:"Nordic Naturals Omega-3 1280mg DHA EPA Fish Oil Soft Gels 180 Count",p:39.95,i:["https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400"]},
      {t:"Aveeno Daily Moisturizing Body Lotion Oat Extract Dry Skin 18 oz",p:11.97,i:["https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400"]},
      {t:"Bounty Select-A-Size Paper Towels 12 Double Plus Rolls 2-Ply White",p:31.99,i:["https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400","https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400"]},
      {t:"Braun Series 9 Pro 9477cc Electric Shaver Wet Dry Flex Head Recharge",p:299.94,i:["https://images.pexels.com/photos/4397920/pexels-photo-4397920.jpeg?w=400","https://images.pexels.com/photos/1640777/pexels-photo-1640777.jpeg?w=400","https://images.pexels.com/photos/4065891/pexels-photo-4065891.jpeg?w=400","https://images.pexels.com/photos/3737582/pexels-photo-3737582.jpeg?w=400"]}
    ],
    colors:["White","Black","Gray","Blue","Green","Red","Silver","Stainless","Natural","Clear"],
    brands:["Vitamix","Theragun","Fitbit","Dyson","Instant Pot","NordicTrack","Garden of Life","Philips","Listerine","Clorox","Tide","Nordic Naturals","Aveeno","Bounty","Braun","Oral-B","Gillette","Dove","Colgate","OxiClean"],
    types:["Supplement","Fitness Tracker","Kitchen Appliance","Vacuum","Massage Gun","Toothbrush","Shaver","Household Cleaner","Laundry Detergent","Paper Goods","Body Care","Hair Remover","Scale","Blood Pressure Monitor","Blender"]
  },
  "Home and Kitchen": {
    base:[
      {t:"KitchenAid Artisan Series 5-Quart Tilt-Head Stand Mixer Empire Red 10-Speed",p:449.99,i:["https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400"]},
      {t:"Le Creuset Signature Enameled Cast Iron Round Dutch Oven 5.5Qt Flame",p:419.95,i:["https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400"]},
      {t:"Nespresso Vertuo Next Coffee Espresso Machine Bundle with Frother",p:199.00,i:["https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400"]},
      {t:"Cuisinart 14-Cup Food Processor Vegetable Chopper Stainless Bowl",p:199.95,i:["https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400"]},
      {t:"All-Clad D3 Stainless Steel Tri-Ply 12-inch Fry Pan Skillet",p:129.95,i:["https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400"]},
      {t:"Breville Barista Express Espresso Machine BES870BSS Stainless Steel",p:749.95,i:["https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400"]},
      {t:"Ninja Foodi 11-in-1 6.5-Qt Pro Pressure Cooker Air Fryer Tender Crisp",p:229.99,i:["https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400"]},
      {t:"Staub Cast Iron 4-Qt Cocotte Round French Oven Matte Black Enameled",p:329.95,i:["https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400"]},
      {t:"Calphalon Premier Hard-Anodized Nonstick 10-Piece Cookware Set",p:299.99,i:["https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400"]},
      {t:"Vitamix A3300 Ascent Series Smart Blender Stainless 64oz Wireless",p:549.95,i:["https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400"]},
      {t:"OXO Good Grips 15-Piece Everyday Cookware PlatinumForce Nonstick Set",p:349.99,i:["https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400"]},
      {t:"Instant Pot Pro 10-in-1 Pressure Cooker Slow Cook Sous Vide 8Qt",p:149.99,i:["https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400"]},
      {t:"Hamilton Beach Professional 1800W Juicer Centrifugal Large 3-inch Feed",p:79.99,i:["https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400"]},
      {t:"T-fal Ultimate Hard Anodized 17-Piece Nonstick Cookware Set Dishwasher",p:199.99,i:["https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400"]},
      {t:"Cuisinart SS-10 Premium Single-Serve Coffeemaker 72oz Reservoir",p:99.99,i:["https://images.pexels.com/photos/1080696/pexels-photo-1080696.jpeg?w=400","https://images.pexels.com/photos/1599791/pexels-photo-1599791.jpeg?w=400","https://images.pexels.com/photos/4108715/pexels-photo-4108715.jpeg?w=400","https://images.pexels.com/photos/3214120/pexels-photo-3214120.jpeg?w=400"]}
    ],
    colors:["Stainless Steel","Black","White","Red","Empire Red","Cobalt Blue","Matte Black","Gray","Copper","Navy"],
    brands:["KitchenAid","Le Creuset","Nespresso","Cuisinart","All-Clad","Breville","Ninja","Staub","Calphalon","Vitamix","OXO","Instant Pot","Hamilton Beach","T-fal","Lodge","Zwilling","Wusthof","Nordic Ware","Oxo","GreenPan"],
    types:["Stand Mixer","Dutch Oven","Coffee Maker","Food Processor","Cookware Set","Air Fryer","Blender","Skillet","Bakeware","Knife Set","Pressure Cooker","Toaster Oven","Rice Cooker","Waffle Maker","Juicer"]
  }
};

// اختيار البيانات الصحيحة للقسم
const catKey = Object.keys(CAT_DATA).find(k => k.toLowerCase() === cat.toLowerCase()) || "Clothing & Accessories";
const CAT = CAT_DATA[catKey];
const BASE = CAT.base;
const COLORS = CAT.colors;
const BRANDS_EXTRA = CAT.brands;
const TYPES = CAT.types;
const DESCS = ["Premium","Classic","Luxury","Signature","Essential","Ultimate","Pro","Elite","Authentic","Original","Limited","Special Edition","Exclusive","Heritage","Modern"];

// PRNG ثابت
function h(n){n=((n^61)^(n>>>16))>>>0;n=(n+(n<<3))>>>0;n=(n^(n>>>4))>>>0;n=Math.imul(n,0x27d4eb2d)>>>0;return(n^(n>>>15))>>>0;}
function rng(seed){return h(seed)/4294967296;}

// توليد منتج فريد لكل قسم
function makeProduct(idx){
  var bi  = idx % BASE.length;
  var b   = BASE[bi];
  var r1=rng(idx*7+1),r2=rng(idx*13+2),r3=rng(idx*17+3);
  var r4=rng(idx*19+4),r5=rng(idx*23+5),r6=rng(idx*29+6);
  var col = COLORS[Math.floor(r1*COLORS.length)];
  var des = DESCS[Math.floor(r2*DESCS.length)];
  var namePool = [
    b.t + " - " + col,
    des + " " + b.t,
    BRANDS_EXTRA[Math.floor(r3*BRANDS_EXTRA.length)] + " " + TYPES[Math.floor(r4*TYPES.length)] + " " + col + " | " + des,
    b.t + " | " + des + " " + col,
    des + " " + TYPES[Math.floor(r5*TYPES.length)] + " " + col + " #" + (1000+idx),
    BRANDS_EXTRA[Math.floor(r6*BRANDS_EXTRA.length)] + " " + des + " " + b.t
  ];
  var title = namePool[idx % namePool.length];
  var price = parseFloat((b.p * (0.75 + r1*0.55)).toFixed(2));
  var io = Math.floor(r2*b.i.length);
  var imgs = [b.i[(io)%b.i.length],b.i[(io+1)%b.i.length],b.i[(io+2)%b.i.length],b.i[(io+3)%b.i.length]];
  var rating = parseFloat((3.6 + r3*1.4).toFixed(1));
  var sales  = Math.floor(r4*9800);
  return {id:"cl_"+idx,t:title,p:price,img:imgs[0],imgs:imgs,rating:rating,sales:sales};
}

// توليد 5000 منتج
const TOTAL = 5000;
var allProducts = [];
for(var i=0;i<TOTAL;i++){
  var pr = makeProduct(i);
  allProducts.push({id:pr.id,t:pr.t,p:pr.p,img:pr.img,imgs:pr.imgs,rating:pr.rating,sales:pr.sales});
}
const productsJSON = JSON.stringify(allProducts);

const pageHTML = `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${cat}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Arial,sans-serif;background:#f5f5f5;padding-top:50px;min-height:100vh;}
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:fixed;top:0;left:0;right:0;z-index:200;}
.h-left{display:flex;align-items:center;gap:10px;}
.h-right{display:flex;align-items:center;gap:14px;font-size:20px;}
.toolbar{display:flex;align-items:center;background:white;padding:12px 20px;border-bottom:1px solid #eee;}
.sort-btn{flex:1;text-align:center;font-size:15px;color:#333;cursor:pointer;}
.sep{width:1px;height:20px;background:#ddd;margin:0 10px;}
.filter-btn{flex:1;text-align:center;font-size:15px;color:#333;cursor:pointer;}
.count-bar{background:white;text-align:center;padding:8px;font-size:14px;color:#555;border-bottom:1px solid #f0f0f0;}
/* ===== FILTER PANEL ===== */
.filter-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;z-index:500;}
.filter-left{position:absolute;top:0;left:0;width:36%;height:100%;background:rgba(0,0,0,0.45);}
.filter-panel{position:fixed;top:0;right:0;width:64%;height:auto;background:white;padding:24px 16px 16px;}
.filter-price-label{font-size:16px;font-weight:400;color:#333;margin-bottom:18px;}
.price-inputs{display:flex;align-items:center;gap:10px;margin-bottom:0;}
.price-input{flex:1;border:1.5px solid #e0e0e0;border-radius:10px;padding:13px 12px;font-size:14px;color:#888;outline:none;background:#fff;min-width:0;}
.price-input:focus{border-color:#bbb;color:#333;}
.price-arrow{color:#bbb;font-size:18px;flex-shrink:0;}
.filter-footer{display:flex;gap:10px;padding:16px 0 0;border-top:none;}
.filter-clear-btn{flex:1;padding:15px;border:none;border-radius:14px;background:#f0f0f0;font-size:16px;color:#333;cursor:pointer;text-align:center;font-weight:400;}
.filter-confirm-btn{flex:1;padding:15px;border:none;border-radius:14px;background:#111;color:white;font-size:16px;cursor:pointer;text-align:center;font-weight:600;}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:#e0e0e0;}
.pcard{background:white;cursor:pointer;}
.pcard img{width:100%;aspect-ratio:3/4;object-fit:cover;display:block;}
.pcard .name{font-size:12px;color:#222;padding:5px 6px 3px;line-height:1.4;height:36px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;}
.pcard .price{color:#1976d2;font-weight:bold;font-size:13px;padding:2px 6px 8px;}
.spinner{display:none;text-align:center;padding:20px;color:#999;font-size:13px;}
</style>
</head>
<body>
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
<!-- FILTER OVERLAY -->
<div class="filter-overlay" id="filterOverlay">
  <div class="filter-left" onclick="closeFilterClick()"></div>
  <div class="filter-panel" id="filterPanel">
    <div class="filter-price-label">Price range</div>
    <div class="price-inputs">
      <input class="price-input" id="filterMinPrice" type="number" placeholder="Lowest price" min="0">
      <span class="price-arrow">&#8212;</span>
      <input class="price-input" id="filterMaxPrice" type="number" placeholder="Highest price" min="0">
    </div>
    <div class="filter-footer">
      <div class="filter-clear-btn" onclick="clearFilter()">Clear</div>
      <div class="filter-confirm-btn" onclick="confirmFilter()">Confirm</div>
    </div>
  </div>
</div>

<div class="toolbar">
  <div class="sort-btn" onclick="cycleSort()">Sort &#9660;</div>
  <div class="sep"></div>
  <div class="filter-btn" onclick="openFilter()">Filter</div>
</div>
<div class="count-bar" id="countBar">5,000 Items</div>
<div class="grid" id="grid"></div>
<div class="spinner" id="spinner">Loading...</div>

<script>
var ALL    = ${productsJSON};
var PAGE   = 60;
var page   = 0;
var sortMode = "default";
var loading  = false;
var filterMin = null;
var filterMax = null;
var FILTERED = null; // null = no filter active

var SORT_CYCLE  = ["default","asc","desc","rating"];
var SORT_LABELS = {default:"Sort \u25bc",asc:"Price \u2191",desc:"Price \u2193",rating:"\u2b50 Top"};

// ===== FILTER PANEL FUNCTIONS =====
function openFilter(){
  document.getElementById("filterOverlay").style.display = "block";
  // Sync sort buttons
  ["default","asc","desc","rating"].forEach(function(m){
    var el = document.getElementById("fs-"+m);
    if(el) el.className = "filter-sort-item" + (m===sortMode?" active":"");
  });
  if(filterMin !== null) document.getElementById("filterMinPrice").value = filterMin;
  if(filterMax !== null) document.getElementById("filterMaxPrice").value = filterMax;
}

function closeFilterClick(){
  document.getElementById("filterOverlay").style.display = "none";
}

function setFilterSort(mode){
  sortMode = mode;
  ["default","asc","desc","rating"].forEach(function(m){
    var el = document.getElementById("fs-"+m);
    if(el) el.className = "filter-sort-item" + (m===mode?" active":"");
  });
  document.querySelector(".sort-btn").innerText = SORT_LABELS[sortMode];
}

function clearFilter(){
  filterMin = null; filterMax = null;
  sortMode = "default";
  FILTERED = null;
  document.getElementById("filterMinPrice").value = "";
  document.getElementById("filterMaxPrice").value = "";
  ["default","asc","desc","rating"].forEach(function(m){
    var el = document.getElementById("fs-"+m);
    if(el) el.className = "filter-sort-item" + (m==="default"?" active":"");
  });
  document.querySelector(".sort-btn").innerText = SORT_LABELS["default"];
  document.getElementById("filterOverlay").style.display = "none";
  page = 0;
  document.getElementById("grid").innerHTML = "";
  document.getElementById("countBar").innerText = "5,000 Items";
  appendPage();
}

function confirmFilter(){
  var minVal = document.getElementById("filterMinPrice").value.trim();
  var maxVal = document.getElementById("filterMaxPrice").value.trim();
  filterMin = minVal !== "" ? parseFloat(minVal) : null;
  filterMax = maxVal !== "" ? parseFloat(maxVal) : null;

  // Apply price filter
  FILTERED = ALL.filter(function(p){
    if(filterMin !== null && p.p < filterMin) return false;
    if(filterMax !== null && p.p > filterMax) return false;
    return true;
  });

  document.getElementById("filterOverlay").style.display = "none";
  page = 0;
  document.getElementById("grid").innerHTML = "";
  var count = FILTERED.length.toLocaleString();
  document.getElementById("countBar").innerText = count + " Items";
  appendPage();
}
// ===== END FILTER =====

function applySort(arr){
  var s = arr.slice();
  if(sortMode==="asc")    s.sort(function(a,b){return a.p-b.p;});
  if(sortMode==="desc")   s.sort(function(a,b){return b.p-a.p;});
  if(sortMode==="rating") s.sort(function(a,b){return b.rating-a.rating;});
  return s;
}

function cycleSort(){
  var i = SORT_CYCLE.indexOf(sortMode);
  sortMode = SORT_CYCLE[(i+1)%SORT_CYCLE.length];
  document.querySelector(".sort-btn").innerText = SORT_LABELS[sortMode];
  page = 0;
  document.getElementById("grid").innerHTML = "";
  appendPage();
}

function appendPage(){
  if(loading) return;
  var source = FILTERED !== null ? FILTERED : ALL;
  var sorted = applySort(source);
  var start  = page * PAGE;
  var chunk  = sorted.slice(start, start + PAGE);
  if(!chunk.length) return;
  loading = true;
  document.getElementById("spinner").style.display = "block";

  setTimeout(function(){
    var g = document.getElementById("grid");
    chunk.forEach(function(p){
      var d  = document.createElement("div");
      d.className = "pcard";
      var im = document.createElement("img");
      im.loading = "lazy";
      im.src = p.img;
      im.onerror = function(){
        var fb = (p.imgs||[]).filter(function(u){return u!==this.src;},this);
        if(fb.length) this.src = fb[0];
        else this.src = "https://images.pexels.com/photos/2983464/pexels-photo-2983464.jpeg?w=400";
      };
      var nm = document.createElement("div"); nm.className="name"; nm.innerText=p.t;
      var pr = document.createElement("div"); pr.className="price"; pr.innerText="US$"+p.p.toFixed(2);
      d.appendChild(im); d.appendChild(nm); d.appendChild(pr);
      (function(prod){ d.onclick=function(){
        var catName = decodeURIComponent(window.location.search.replace(/.*name=/,'').split('&')[0]||'');
        prod.cat = catName;
        localStorage.setItem("catProduct",JSON.stringify(prod));
        localStorage.setItem("productId",prod.id);
        window.location.href="/cat-product-detail";
      };})(p);
      g.appendChild(d);
    });
    document.getElementById("spinner").style.display = "none";
    loading = false;
    page++;
  }, 100);
}

// Infinite scroll - يحمل تلقائياً عند الوصول للأسفل
window.addEventListener("scroll", function(){
  var source = FILTERED !== null ? FILTERED : ALL;
  if((window.innerHeight + window.scrollY) >= document.body.offsetHeight - 300){
    if(page * PAGE < source.length) appendPage();
  }
});

// أول تحميل
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
app.get("/cat-product-detail", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Product Detail</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Arial;background:#f5f5f5;padding-bottom:80px;min-height:100vh;}
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:fixed;top:0;left:0;right:0;z-index:100;}
.header .icons span{margin-left:15px;font-size:18px;cursor:pointer;}
.page-body{margin-top:50px;}
.slider-wrap{background:white;position:relative;overflow:hidden;}
.slider-imgs{display:flex;transition:transform 0.4s ease;}
.slider-imgs img{min-width:100%;height:360px;object-fit:contain;background:#f9f9f9;}
.slider-dots{display:flex;justify-content:center;gap:6px;padding:10px 0;background:white;}
.dot{width:7px;height:7px;border-radius:50%;background:#ccc;cursor:pointer;transition:background 0.3s;}
.dot.active{background:#1976d2;}
.heart-btn{position:absolute;top:12px;left:12px;font-size:24px;cursor:pointer;z-index:10;}
.thumbs{display:flex;gap:8px;padding:10px 12px;background:white;overflow-x:auto;}
.thumbs img{width:58px;height:58px;object-fit:cover;border-radius:8px;border:2px solid #eee;cursor:pointer;flex-shrink:0;}
.thumbs img.active{border-color:#1976d2;}
.colors-wrap{background:white;padding:10px 15px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;border-top:1px solid #f0f0f0;}
.color-label{font-size:13px;color:#555;margin-right:5px;}
.color-dot{width:26px;height:26px;border-radius:50%;cursor:pointer;border:2px solid #eee;transition:border-color 0.2s;}
.color-dot.active{border-color:#1976d2;transform:scale(1.15);}
.info{background:white;margin-top:8px;padding:15px;}
.price-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
.price{color:#1976d2;font-size:26px;font-weight:bold;}
.rating{color:#1976d2;font-size:13px;}
.prod-title{font-size:15px;color:#222;line-height:1.5;}
.specs{background:white;margin-top:8px;}
.spec-row{display:flex;justify-content:space-between;align-items:center;padding:13px 15px;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;}
.spec-row span:last-child{color:#999;}
.store{background:white;margin-top:8px;padding:15px;display:flex;align-items:center;gap:12px;cursor:pointer;}
.store img{width:52px;height:52px;border-radius:10px;object-fit:cover;}
.store-name{font-weight:bold;font-size:15px;}
.vip-badge{background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;padding:2px 8px;border-radius:10px;display:inline-block;margin-top:3px;}
.store-tags{display:flex;gap:8px;margin-top:5px;}
.store-tags span{background:#eee;font-size:11px;padding:3px 10px;border-radius:10px;}
.review{background:white;margin-top:8px;padding:15px;}
.review-top{display:flex;justify-content:space-between;font-size:14px;color:#333;}
.stars{color:#f5a623;font-size:18px;margin-top:5px;}
.desc{background:white;margin-top:8px;padding:15px;font-size:13px;color:#444;line-height:1.8;}
.desc ul{padding-left:18px;margin:0;}
.desc li{margin-bottom:8px;}
.bottom-bar{position:fixed;bottom:0;left:0;right:0;background:white;display:flex;align-items:center;padding:10px 15px;border-top:1px solid #eee;gap:10px;z-index:200;}
.icon-btn{font-size:22px;cursor:pointer;}
.cart-btn{flex:1;padding:13px;border:1.5px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;cursor:pointer;text-align:center;font-weight:bold;}
.buy-btn{flex:1;padding:13px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;cursor:pointer;text-align:center;font-weight:bold;}
</style>
</head>
<body>

<div class="header">
  <div>
    <span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;margin-left:8px;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  </div>
  <div class="icons">
    <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span><span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span><span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span><span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
</div>

<div class="page-body">
<div class="slider-wrap">
  <span class="heart-btn" id="heartBtn" onclick="toggleHeart()">&#129293;</span>
  <div class="slider-imgs" id="sliderImgs"></div>
  <div class="slider-dots" id="sliderDots"></div>
</div>

<div class="thumbs" id="thumbs"></div>

<div class="colors-wrap" id="colorsWrap">
  <span class="color-label">Color:</span>
</div>

<div class="info">
  <div class="price-row">
    <div class="price" id="pPrice"></div>
    <div class="rating" id="pRating">&#11088; <b>5.0</b> <span style="color:#999;">(0 Sales)</span></div>
  </div>
  <div class="prod-title" id="pTitle"></div>
</div>

<div class="specs">
  <div class="spec-row"><span>Select</span><span>Brand, specification &#8250;</span></div>
  <div class="spec-row"><span>Shipping fees</span><span>Free shipping</span></div>
  <div class="spec-row"><span>Guarantee</span><span>Free return</span></div>
</div>

<div class="store">
  <img src="https://cdn-icons-png.flaticon.com/512/149/149071.png">
  <div style="flex:1;">
    <div class="store-name">TikTok Mall Store</div>
    <div class="vip-badge">&#10004; VIP 3</div>
    <div class="store-tags"><span>Products 150</span><span>Followers 79</span></div>
  </div>
  <span style="color:#999;">&#8250;</span>
</div>

<div class="review">
  <div class="review-top">
    <span>Consumer review</span>
    <span style="color:#1976d2;">0 Unit Global Rating &#8250;</span>
  </div>
  <div class="stars">&#11088;&#11088;&#11088;&#11088;&#11088; <span style="font-size:13px;color:#555;">5 Stars</span></div>
</div>

<div class="desc">
  <ul id="descList"></ul>
</div>

</div>

<div class="bottom-bar">
  <span class="icon-btn" onclick="window.location.href='/live-chat'">&#127911;</span>
  <span class="icon-btn" onclick="window.location.href='/wallet'">&#128722;</span>
  <div class="cart-btn" onclick="addToCart()">Add to Cart</div>
  <div class="buy-btn" onclick="buyNow()">Buy now</div>
</div>

<script>
var p = {};
try { p = JSON.parse(localStorage.getItem("catProduct") || "{}"); } catch(e){}
var isFav = false;
var currentSlide = 0;
var images = [];
var autoSlideTimer = null;

// ===== خريطة ألوان كل قسم =====
var CAT_COLORS = {
  "Shoes":        [{n:"Black",h:"#1a1a1a"},{n:"White",h:"#f5f5f5"},{n:"Red",h:"#cc2200"},{n:"Gray",h:"#888"},{n:"Navy",h:"#1a2a4a"},{n:"Beige",h:"#c8a882"},{n:"Brown",h:"#7a4a2a"},{n:"Blue",h:"#1565c0"},{n:"Green",h:"#2e7d32"},{n:"Orange",h:"#e65100"}],
  "Watches":      [{n:"Black",h:"#1a1a1a"},{n:"Silver",h:"#bdbdbd"},{n:"Gold",h:"#c9a84c"},{n:"Rose Gold",h:"#b76e79"},{n:"Blue",h:"#1565c0"},{n:"Green",h:"#1b5e20"},{n:"Gray",h:"#616161"},{n:"Brown",h:"#5d4037"}],
  "Jewelry":      [{n:"Gold",h:"#c9a84c"},{n:"Rose Gold",h:"#b76e79"},{n:"Silver",h:"#bdbdbd"},{n:"Yellow Gold",h:"#f9a825"},{n:"White Gold",h:"#e0e0e0"},{n:"Diamond",h:"#e3f2fd"},{n:"Ruby",h:"#b71c1c"},{n:"Emerald",h:"#1b5e20"},{n:"Sapphire",h:"#0d47a1"},{n:"Pearl",h:"#fafafa"}],
  "Electronics":  [{n:"Black",h:"#1a1a1a"},{n:"Silver",h:"#bdbdbd"},{n:"Space Gray",h:"#4a4a4a"},{n:"White",h:"#f5f5f5"},{n:"Blue",h:"#1565c0"},{n:"Gold",h:"#c9a84c"},{n:"Green",h:"#1b5e20"},{n:"Midnight",h:"#1a1a2e"},{n:"Titanium",h:"#8d8d8d"}],
  "Smart Home":   [{n:"White",h:"#f5f5f5"},{n:"Black",h:"#1a1a1a"},{n:"Charcoal",h:"#424242"},{n:"Silver",h:"#bdbdbd"},{n:"Sand",h:"#d7ccc8"},{n:"Blue",h:"#1565c0"}],
  "Luxury Brands":[{n:"Black",h:"#1a1a1a"},{n:"Tan",h:"#c8a882"},{n:"Camel",h:"#c19a6b"},{n:"Beige",h:"#e8d5b0"},{n:"White",h:"#f5f5f5"},{n:"Red",h:"#b71c1c"},{n:"Navy",h:"#1a2a4a"},{n:"Brown",h:"#5d4037"},{n:"Burgundy",h:"#6d1a2a"},{n:"Gold",h:"#c9a84c"}],
  "Beauty and Personal Care":[{n:"Nude",h:"#d4a574"},{n:"Pink",h:"#f48fb1"},{n:"Red",h:"#c62828"},{n:"Rose",h:"#e91e63"},{n:"Berry",h:"#880e4f"},{n:"Coral",h:"#ff7043"},{n:"Peach",h:"#ffccbc"},{n:"Bronze",h:"#a0522d"},{n:"Clear",h:"#f5f5f5"},{n:"Gold",h:"#c9a84c"}],
  "Medical Bags and Sunglasses":[{n:"Black",h:"#1a1a1a"},{n:"Brown",h:"#5d4037"},{n:"Tortoise",h:"#6d4c41"},{n:"Gold",h:"#c9a84c"},{n:"Silver",h:"#bdbdbd"},{n:"Navy",h:"#1a237e"},{n:"Tan",h:"#c8a882"},{n:"Crystal",h:"#e3f2fd"},{n:"Rose Gold",h:"#b76e79"}],
  "Mens Fashion": [{n:"Navy",h:"#1a2a4a"},{n:"Black",h:"#1a1a1a"},{n:"Gray",h:"#757575"},{n:"White",h:"#f5f5f5"},{n:"Khaki",h:"#b5a642"},{n:"Olive",h:"#6d7c43"},{n:"Charcoal",h:"#424242"},{n:"Blue",h:"#1565c0"},{n:"Brown",h:"#5d4037"},{n:"Burgundy",h:"#6d1a2a"}],
  "default":      [{n:"Black",h:"#1a1a1a"},{n:"White",h:"#f5f5f5"},{n:"Navy",h:"#1a2a4a"},{n:"Beige",h:"#c8a882"},{n:"Blush",h:"#e8a0b0"},{n:"Emerald",h:"#2d6a4f"},{n:"Burgundy",h:"#6d1a2a"},{n:"Camel",h:"#c19a6b"},{n:"Lavender",h:"#b0a0d0"},{n:"Coral",h:"#e87060"},{n:"Mint",h:"#7ec8a0"},{n:"Cobalt",h:"#1a4aaa"}]
};

// اختيار ألوان القسم الصحيح
var catName = (p && p.cat) ? p.cat : "default";
var COLORS = CAT_COLORS[catName] || CAT_COLORS["default"];

// ===== تحديد الصور بناءً على المنتج =====
if(p && p.img){
  document.getElementById("pTitle").innerText  = p.t  || p.title || "";
  document.getElementById("pPrice").innerText  = "US\$" + ((p.p || p.price || 0).toFixed(2));
  if(p.rating) document.getElementById("pRating").innerHTML = "\u2b50 <b>"+p.rating+"</b> <span style='color:#999;'>("+((p.sales||0).toLocaleString())+" Sales)</span>";

  // استخدام الصور الأربعة المخصصة للمنتج
  images = (p.imgs && p.imgs.length >= 4) ? p.imgs : [p.img, p.img, p.img, p.img];

  // بناء الـ slider
  var wrap     = document.getElementById("sliderImgs");
  var dotsEl   = document.getElementById("sliderDots");
  var thumbsEl = document.getElementById("thumbs");

  images.forEach(function(src, i){
    var img = document.createElement("img");
    img.src = src;
    img.onerror = function(){
      this.src = images[(i+1)%images.length] || "https://images.pexels.com/photos/404280/pexels-photo-404280.jpeg?w=400";
    };
    wrap.appendChild(img);

    var dot = document.createElement("div");
    dot.className = "dot" + (i===0?" active":"");
    dot.onclick = (function(idx){ return function(){ goSlide(idx); restartAutoSlide(); }; })(i);
    dotsEl.appendChild(dot);

    var th = document.createElement("img");
    th.src = src;
    th.className = (i===0?"active":"");
    th.onerror = function(){ this.src=images[(i+1)%images.length]||""; };
    th.onclick = (function(idx){ return function(){ goSlide(idx); restartAutoSlide(); }; })(i);
    thumbsEl.appendChild(th);
  });

  // ===== Auto-slide كل 3 ثوانٍ =====
  function startAutoSlide(){
    autoSlideTimer = setInterval(function(){
      var next = (currentSlide + 1) % images.length;
      goSlide(next);
    }, 3000);
  }
  function restartAutoSlide(){
    clearInterval(autoSlideTimer);
    startAutoSlide();
  }
  startAutoSlide();

  // بناء ألوان المنتج (حسب القسم)
  var colorsWrap = document.getElementById("colorsWrap");
  COLORS.forEach(function(c, ci){
    var dot = document.createElement("div");
    dot.className = "color-dot" + (ci===0?" active":"");
    dot.style.background = c.h;
    dot.title = c.n;
    dot.onclick = (function(idx){
      return function(){
        document.querySelectorAll(".color-dot").forEach(function(d){ d.classList.remove("active"); });
        this.classList.add("active");
        goSlide(idx % images.length);
        restartAutoSlide();
      };
    })(ci);
    colorsWrap.appendChild(dot);
  });

  // وصف المنتج (مخصص حسب اسم المنتج)
  var desc = document.getElementById("descList");
  var titleWords = (p.t||"").split(" ").slice(0,4).join(" ");
  var points = [
    titleWords + " — authentic product with full warranty.",
    "Available in " + COLORS.length + " colors. All sizes in stock.",
    "Free worldwide shipping. 30-day hassle-free returns.",
    "Rating: " + (p.rating||5.0) + "/5 from " + ((p.sales||0).toLocaleString()) + " verified buyers.",
    "Secure checkout. Original packaging included."
  ];
  points.forEach(function(point){
    var li = document.createElement("li");
    li.innerText = point;
    desc.appendChild(li);
  });
}

function goSlide(idx){
  currentSlide = idx;
  document.getElementById("sliderImgs").style.transform = "translateX(-"+(idx*100)+"%)";
  document.querySelectorAll(".dot").forEach(function(d,i){ d.className="dot"+(i===idx?" active":""); });
  document.querySelectorAll(".thumbs img").forEach(function(t,i){ t.className=(i===idx?"active":""); });
}

function toggleHeart(){
  isFav = !isFav;
  document.getElementById("heartBtn").innerHTML = isFav ? "&#10084;&#65039;" : "&#129293;";
}
function addToCart(){
  var cart = JSON.parse(localStorage.getItem("cart")||"[]");
  cart.push(p.id||p.title);
  localStorage.setItem("cart", JSON.stringify(cart));
  alert("Added to cart \u2705");
}
function buyNow(){ window.location.href="/wallet"; }
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
