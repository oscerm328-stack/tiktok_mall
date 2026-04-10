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

<div style="background:white;padding:18px 15px 22px;margin:10px 0;">

  <!-- الصف الأول: الشعار + TikTok Mall -->
  <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px;">
    <!-- أيقونة TikTok سوداء كبيرة -->
    <div style="flex-shrink:0;width:90px;height:90px;background:#000;border-radius:22px;box-shadow:0 4px 16px rgba(0,0,0,0.25);display:flex;align-items:center;justify-content:center;">
      <svg width="62" height="62" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M33 7C33.8 10.2 36.2 12.6 39 13.4V18.2C36.6 18.2 34.4 17.4 32.6 16.2V27C32.6 32.6 28.2 37 22.6 37C17 37 12.6 32.6 12.6 27C12.6 21.4 17 17 22.6 17C23.2 17 23.8 17.1 24.4 17.2V22.2C23.8 22 23.2 21.9 22.6 21.9C19.6 21.9 17.2 24.2 17.2 27.2C17.2 30.2 19.6 32.5 22.6 32.5C25.6 32.5 28 30.2 28 27.2V7H33Z" fill="#EE1D52"/>
        <path d="M31 9C31.8 12.2 34.2 14.6 37 15.4V20.2C34.6 20.2 32.4 19.4 30.6 18.2V29C30.6 34.6 26.2 39 20.6 39C15 39 10.6 34.6 10.6 29C10.6 23.4 15 19 20.6 19C21.2 19 21.8 19.1 22.4 19.2V24.2C21.8 24 21.2 23.9 20.6 23.9C17.6 23.9 15.2 26.2 15.2 29.2C15.2 32.2 17.6 34.5 20.6 34.5C23.6 34.5 26 32.2 26 29.2V9H31Z" fill="#69C9D0"/>
        <path d="M32 8C32.8 11.2 35.2 13.6 38 14.4V19.2C35.6 19.2 33.4 18.4 31.6 17.2V28C31.6 33.6 27.2 38 21.6 38C16 38 11.6 33.6 11.6 28C11.6 22.4 16 18 21.6 18C22.2 18 22.8 18.1 23.4 18.2V23.2C22.8 23 22.2 22.9 21.6 22.9C18.6 22.9 16.2 25.2 16.2 28.2C16.2 31.2 18.6 33.5 21.6 33.5C24.6 33.5 27 31.2 27 28.2V8H32Z" fill="white"/>
      </svg>
    </div>
    <!-- TikTok Mall نص ضخم -->
    <div style="font-size:36px;font-weight:900;color:#1a7fd4;letter-spacing:-0.5px;line-height:1;font-family:Arial Black,Arial,sans-serif;">TikTok Mall</div>
  </div>

  <!-- الصف الثاني: صورة الصاروخ + النصان -->
  <div style="display:flex;align-items:center;gap:10px;">
    <!-- صورة الصاروخ الواقعية -->
    <div style="flex-shrink:0;width:100px;height:80px;display:flex;align-items:center;justify-content:center;">
      <img src="data:image/png;base64,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" style="width:95px;height:75px;object-fit:contain;">
    </div>
    </div>
    <!-- النصان -->
    <div style="flex:1;">
      <div style="font-size:17px;font-weight:800;color:#1a7fd4;margin-bottom:10px;">Selected Good Products</div>
      <div style="font-size:17px;font-weight:800;color:#1a7fd4;">Provide Excellent service</div>
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
