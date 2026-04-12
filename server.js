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

        // sync storeOrders from MongoDB
        const storeOrdersData = await db.collection("storeOrders").find({}).toArray();
        if(storeOrdersData.length > 0) {
            storeOrders = storeOrdersData.map(o => { delete o._id; return o; });
        }

        const inviteData = await db.collection("settings").findOne({ key: "inviteCode" });
        if(inviteData) inviteCode = inviteData.value;

        const backupData = await db.collection("settings").findOne({ key: "backupVerifyCode" });
        if(backupData) backupVerifyCode = backupData.value;

        // جلب منتجات البائعين من MongoDB
        const sellerProdsData = await db.collection("sellerProducts").find({}).toArray();
        if(sellerProdsData.length > 0) {
            sellerProdsData.forEach(item => {
                if(item.email && item.products) {
                    sellerProducts[item.email] = item.products;
                }
            });
        }

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

// ================= UPDATE PROFILE (avatar + username) - يحفظ في السيرفر دائماً =================
app.post("/update-profile", (req, res) => {
    const { email, avatar, username } = req.body;
    if (!email) return res.json({ success: false, message: "Missing email" });
    let user = users.find(u => u.email === email);
    if (!user) return res.json({ success: false, message: "User not found" });
    if (avatar && avatar.length > 10) user.avatar = avatar;
    if (username && username.trim().length >= 2) user.username = username.trim();
    saveUsers();
    res.json({ success: true, username: user.username || "", avatar: user.avatar || "" });
});

// ================= GET PROFILE =================
app.get("/get-profile/:email", (req, res) => {
    const user = users.find(u => u.email === req.params.email);
    if (!user) return res.json({ success: false });
    res.json({ success: true, username: user.username || "", avatar: user.avatar || "" });
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
           status: "pending",
           createdAt: new Date().toISOString()
          });

    saveRequests();
    console.log("ALL REQUESTS:", requests);

    res.send("Request saved");
});

// ================= MY REQUESTS (للمستخدم) =================
app.get("/my-requests/:email", (req, res) => {
    const userReqs = requests.filter(r => r.email === req.params.email);
    // ترتيب من الأحدث للأقدم
    userReqs.sort((a, b) => b.id - a.id);
    res.json(userReqs);
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
        res.json({ found: true, status: app2.status, storeName: app2.storeName, contactEmail: app2.contactEmail, storeLogo: app2.storeLogo || "" });
    } else {
        res.json({ found: false });
    }
});

// تحديث صورة المتجر في السيرفر
app.post("/update-store-logo", authMiddleware, (req, res) => {
    const { storeLogo } = req.body;
    const email = req.userEmail;
    if (!storeLogo) return res.json({ success: false, message: "No logo provided" });

    const appl = storeApplications.find(a => a.email === email);
    if (!appl) return res.json({ success: false, message: "Store not found" });

    appl.storeLogo = storeLogo;
    saveStoreApplications();

    // حفظ في MongoDB إن وجد
    if (db) {
        db.collection("storeApplications").updateOne(
            { email },
            { $set: { storeLogo } }
        ).catch(err => console.error("MongoDB logo update error:", err.message));
    }

    res.json({ success: true });
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

// زيادة المتابعين تلقائياً كل ساعة حسب VIP
// VIP 4 = أكثر من 200 متابع يومياً = ~9 كل ساعة
const VIP_FOLLOWERS_PER_HOUR = [1, 3, 6, 10, 15, 25];

setInterval(() => {
    let changed = false;
    storeApplications.forEach(a => {
        if (a.status === "approved") {
            if (!a.followers) a.followers = 0;
            const vipLevel = a.vipLevel || 0;
            const perHour = VIP_FOLLOWERS_PER_HOUR[vipLevel] || 1;
            // إضافة عشوائية ±30% للواقعية
            const jitter = Math.floor(perHour * 0.3 * (Math.random() * 2 - 1));
            const toAdd = Math.max(1, perHour + jitter);
            a.followers += toAdd;
            changed = true;
        }
    });
    if(changed){
        saveStoreApplications();
        console.log("✅ Followers updated hourly");
    }
}, 60 * 60 * 1000); // كل ساعة

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
app.get("/all-store-applications", (req, res) => {
    const token = req.cookies?.adminToken;
    let isAdmin = false;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === "admin") isAdmin = true;
    } catch {}
    if (isAdmin) {
        res.json(storeApplications);
    } else {
        res.json(storeApplications.filter(s => s.status === "approved"));
    }
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
if(data.token) localStorage.setItem("token", data.token);
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
body{margin:0;font-family:Arial;background:#f5f5f5;min-height:100vh;}
.header{background:#1976d2;color:white;padding:12px;display:flex;justify-content:space-between;align-items:center;position:relative;}
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
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/clothing.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Medical Bags and Sunglasses')">
<span>Medical Bags and Sunglasses</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/medical.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Shoes')">
<span>Shoes</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/shoes.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Watches')">
<span>Watches</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/watches.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Jewelry')">
<span>Jewelry</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/jewelry.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Electronics')">
<span>Electronics</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/electronics.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Smart Home')">
<span>Smart Home</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/smarthome.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Luxury Brands')">
<span>Luxury Brands</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/luxury.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Beauty and Personal Care')">
<span>Beauty and Personal Care</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/beauty.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Mens Fashion')">
<span>Men's Fashion</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/mensfashion.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Health and Household')">
<span>Health and Household</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/health.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Home and Kitchen')">
<span>Home and Kitchen</span>
<img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/kitchen.png" width="70" style="height:70px;object-fit:cover;">
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

<!-- ===== HEADER الأزرق الكامل ===== -->
<div style="background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10000;">
  <div onclick="openMenuPage()" style="cursor:pointer;">☰ Shop</div>
  <div style="display:flex;align-items:center;gap:15px;">
    <span onclick="toggleSearch()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span onclick="toggleMessages()" style="cursor:pointer;display:inline-flex;align-items:center;position:relative;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span onclick="toggleAccount()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <span onclick="toggleLang()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
</div>

<!-- ===== شريط البحث ===== -->
<div style="padding:15px;display:flex;align-items:center;gap:10px;background:white;border-bottom:1px solid #ddd;">
<span onclick="toggleSearch()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
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
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/clothing.png">
    <div class="cat-label">Clothing &amp; Accessories</div>
  </div>

  <div class="cat-item" onclick="openCategory('Medical Bags and Sunglasses')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/medical.png">
    <div class="cat-label">Medical Bags and Sunglasses</div>
  </div>

  <div class="cat-item" onclick="openCategory('Shoes')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/shoes.png">
    <div class="cat-label">Shoes</div>
  </div>

  <div class="cat-item" onclick="openCategory('Watches')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/watches.png">
    <div class="cat-label">Watches</div>
  </div>

  <div class="cat-item" onclick="openCategory('Jewelry')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/jewelry.png">
    <div class="cat-label">Jewelry</div>
  </div>

  <div class="cat-item" onclick="openCategory('Electronics')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/electronics.png">
    <div class="cat-label">Electronics</div>
  </div>

  <div class="cat-item" onclick="openCategory('Smart Home')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/smarthome.png">
    <div class="cat-label">Smart Home</div>
  </div>

  <div class="cat-item" onclick="openCategory('Luxury Brands')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/luxury.png">
    <div class="cat-label">Luxury Brands</div>
  </div>

  <div class="cat-item" onclick="openCategory('Beauty and Personal Care')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/beauty.png">
    <div class="cat-label">Beauty and Personal Care</div>
  </div>

  <div class="cat-item" onclick="openCategory('Mens Fashion')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/mensfashion.png">
    <div class="cat-label">Men's Fashion</div>
  </div>

  <div class="cat-item" onclick="openCategory('Health and Household')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/health.png">
    <div class="cat-label">Health and Household</div>
  </div>

  <div class="cat-item" onclick="openCategory('Home and Kitchen')">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/tiktok_mall/main/kitchen.png">
    <div class="cat-label">Home and Kitchen</div>
  </div>

</div>
</div>

<div style="width:100%;margin:0;padding:0;line-height:0;">
  <img src="data:image/jpeg;base64,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AwAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQwAAQQQgwQwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEEkEAQiAQggTlU0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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" style="width:100%;height:auto;display:block;" alt="TikTok Mall">
</div>

<div class="section-title">New Product</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-bottom:3px;">
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165148, "t": "Strapless Satin Ball Gown Wedding Dresses for Bride Split Prom Dress Long A line", "p": 95.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/6.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165148_Strapless Satin Ball Gown Wedding Dresses for Brid", "cat": "Clothing & Accessories"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Strapless Satin Ball Gown Wedding Dresse</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$95.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165070, "t": "LAORENTOU Cow Leather Purses and Small Handbag for Women Satchel Tote Bag Ladies", "p": 86.12, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165070_LAORENTOU Cow Leather Purses and Small Handbag for/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165070_LAORENTOU Cow Leather Purses and Small Handbag for/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165070_LAORENTOU Cow Leather Purses and Small Handbag for/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165070_LAORENTOU Cow Leather Purses and Small Handbag for/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165070_LAORENTOU Cow Leather Purses and Small Handbag for/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165070_LAORENTOU Cow Leather Purses and Small Handbag for/5.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165070_LAORENTOU Cow Leather Purses and Small Handbag for", "cat": "Clothing & Accessories"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/165070_LAORENTOU Cow Leather Purses and Small Handbag for/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">LAORENTOU Cow Leather Purses and Small H</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$86.12</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165150, "t": "Roll over image to zoom in 2022 Carlinkit 3.0 Wireless CarPlay Dongle Adapter U", "p": 95.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/7.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/8.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165150_Roll over image to zoom in 2022 Carlinkit 30 Wire", "cat": "Electronics"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Roll over image to zoom in 2022 Carlinki</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$95.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165149, "t": "Google Nest Security Cam (Wired) - 2nd Generation - Snow", "p": 100.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/7.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/8.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165149_Google Nest Security Cam Wired - 2nd Generation -", "cat": "Electronics"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165149_Google Nest Security Cam Wired - 2nd Generation -/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Google Nest Security Cam (Wired) - 2nd G</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$100.00</div>
  </div>
</div>

<div class="section-title">Hot Selling</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-bottom:3px;">
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165109, "t": "FEICE Mens Automatic Wrist Watch Sapphire Crystal Japanese Movement Skeleton Au", "p": 670.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/7.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/8.jpg"], "rating": 5.0, "sales": 5, "description": "", "colors": [], "sizes": [], "folder": "165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal", "cat": "Watches"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">FEICE Men's Automatic Wrist Watch Sapphi</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$670.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165036, "t": "Invicta Mens Pro Diver Collection Chronograph Watch", "p": 636.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/7.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165036_Invicta Mens Pro Diver Collection Chronograph Watc", "cat": "Watches"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165036_Invicta Mens Pro Diver Collection Chronograph Watc/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Invicta Men's Pro Diver Collection Chron</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$636.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165151, "t": "Braided Diamond Anniversary Ring in 925 Sterling Silver or 18k Yellow Gold Verme", "p": 100.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165151_Braided Diamond Anniversary Ring in 925 Sterling S/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165151_Braided Diamond Anniversary Ring in 925 Sterling S/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165151_Braided Diamond Anniversary Ring in 925 Sterling S/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165151_Braided Diamond Anniversary Ring in 925 Sterling S/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165151_Braided Diamond Anniversary Ring in 925 Sterling S/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165151_Braided Diamond Anniversary Ring in 925 Sterling S/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165151_Braided Diamond Anniversary Ring in 925 Sterling S/6.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165151_Braided Diamond Anniversary Ring in 925 Sterling S", "cat": "Jewelry"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165151_Braided Diamond Anniversary Ring in 925 Sterling S/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Braided Diamond Anniversary Ring in 925 </div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$100.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165145, "t": "GNG 1.00 Cttw Natural Morganite and Diamond Halo Engagement Ring in 10k Rose Gol", "p": 465.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/5.jpg"], "rating": 5.0, "sales": 12, "description": "", "colors": [], "sizes": [], "folder": "165145_GNG 100 Cttw Natural Morganite and Diamond Halo En", "cat": "Jewelry"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">GNG 1.00 Cttw Natural Morganite and Diam</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$465.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 164531, "t": "Apple iPhone 17 Pro Max - 256GB,512GB, 1TB", "p": 1179.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/4.jpg"], "rating": 5.0, "sales": 1, "description": "", "colors": [], "sizes": [], "folder": "164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB", "cat": "Electronics"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Apple iPhone 17 Pro Max</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$1179.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165029, "t": "GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16” WUXGA 1920x1200 Display IPS 165", "p": 1189.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/7.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/8.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU", "cat": "Electronics"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">GIGABYTE A16 CMHI2US893SH Gaming Laptop </div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$1189.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 162914, "t": "Calvin Klein Womens Petite Double Breasted Peacoat", "p": 98.06, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162914_Calvin Klein Womens Petite Double Breasted Peacoat/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162914_Calvin Klein Womens Petite Double Breasted Peacoat/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162914_Calvin Klein Womens Petite Double Breasted Peacoat/2.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "162914_Calvin Klein Womens Petite Double Breasted Peacoat", "cat": "Clothing & Accessories"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162914_Calvin Klein Womens Petite Double Breasted Peacoat/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Calvin Klein Women's Petite Double Breas</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$98.06</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 162911, "t": "GUYRGOT-Formal Wedding Dresses for Women - Womens Lace Applique Long Formal Merm", "p": 80.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/6.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L", "cat": "Clothing & Accessories"})'>
    <img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">GUYRGOT-Formal Wedding Dresses for Women</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$80.00</div>
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
  // تحديث من السيرفر للتأكد دائماً
  if(user && user.email){
    fetch("/get-profile/" + encodeURIComponent(user.email))
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(d.success && d.username){
        document.getElementById("usernameDisplay").innerText = d.username;
        localStorage.setItem("username_" + user.email, d.username);
        user.username = d.username;
        localStorage.setItem("user", JSON.stringify(user));
      }
    }).catch(function(){});
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

// تحميل صورة البروفايل - من السيرفر أولاً ثم localStorage
(function loadSavedAvatar(){
  var key = "avatar_" + (user ? user.email : "guest");
  // محاولة جلب من السيرفر
  if(user && user.email){
    fetch("/get-profile/" + encodeURIComponent(user.email))
    .then(function(r){ return r.json(); })
    .then(function(d){
      var src = (d.success && d.avatar && d.avatar.length > 10) ? d.avatar : localStorage.getItem(key);
      if(src){
        // حفظ محلي للسرعة
        localStorage.setItem(key, src);
        document.getElementById("avatarImg").src = src;
        document.getElementById("avatarImg").style.display = "block";
        document.getElementById("avatarDefault").style.display = "none";
      }
    }).catch(function(){
      // fallback للمحلي
      var saved = localStorage.getItem(key);
      if(saved){
        document.getElementById("avatarImg").src = saved;
        document.getElementById("avatarImg").style.display = "block";
        document.getElementById("avatarDefault").style.display = "none";
      }
    });
  } else {
    var saved = localStorage.getItem(key);
    if(saved){
      document.getElementById("avatarImg").src = saved;
      document.getElementById("avatarImg").style.display = "block";
      document.getElementById("avatarDefault").style.display = "none";
    }
  }
})();

// رفع وحفظ صورة البروفايل - يحفظ في السيرفر دائماً
function uploadAvatar(input){
  if(!input.files || !input.files[0]) return;
  var reader = new FileReader();
  reader.onload = function(e){
    var dataUrl = e.target.result;
    var key = "avatar_" + (user ? user.email : "guest");
    // حفظ محلي فوري
    localStorage.setItem(key, dataUrl);
    document.getElementById("avatarImg").src = dataUrl;
    document.getElementById("avatarImg").style.display = "block";
    document.getElementById("avatarDefault").style.display = "none";
    // رفع للسيرفر للحفظ الدائم
    if(user && user.email){
      fetch("/update-profile", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ email: user.email, avatar: dataUrl })
      }).catch(function(){});
    }
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

function openRealProduct(prod){
  localStorage.setItem("catProduct", JSON.stringify(prod));
  window.location.href = "/cat-product-detail";
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

    // جلب بيانات المتابعين لكل متجر ثم عرض الكروت
    let storePromises = found.map(store => {
        return fetch("/followers/" + encodeURIComponent(store.email))
            .then(r => r.json())
            .then(d => ({ store, followers: d.followers || 0 }))
            .catch(() => ({ store, followers: store.followers || 0 }));
    });

    let storeDescPromises = found.map(store => {
        return fetch("/store-desc/" + encodeURIComponent(store.email))
            .then(r => r.json())
            .then(d => ({ email: store.email, desc: d.desc || "" }))
            .catch(() => ({ email: store.email, desc: "" }));
    });

    let storeVipPromises = found.map(store => {
        return fetch("/store-vip/" + encodeURIComponent(store.email))
            .then(r => r.json())
            .then(d => ({ email: store.email, vipLevel: d.vipLevel || 0 }))
            .catch(() => ({ email: store.email, vipLevel: 0 }));
    });

    let storeProductsPromises = found.map(store => {
        return fetch("/store-products/" + encodeURIComponent(store.email))
            .then(r => r.json())
            .then(d => ({ email: store.email, count: (d.products || []).length }))
            .catch(() => ({ email: store.email, count: 0 }));
    });

    Promise.all([Promise.all(storePromises), Promise.all(storeDescPromises), Promise.all(storeVipPromises), Promise.all(storeProductsPromises)]).then(([storesWithFollowers, storesWithDesc, storesWithVip, storesWithProducts]) => {
        // حذف رسالة "Searching..."
        resultsDiv.innerHTML = "<h3 style='padding:0 0 10px 0;'>" + found.length + " store(s) found</h3>";

        storesWithFollowers.forEach(({ store, followers }) => {
            let displayName = localStorage.getItem("merchant_storeName_" + store.email) || store.storeName;
            let displayLogo = store.storeLogo || localStorage.getItem("merchant_storeLogo_" + store.email) || "https://cdn-icons-png.flaticon.com/512/149/149071.png";
            let descObj = storesWithDesc.find(d => d.email === store.email);
            let storeDesc = descObj ? descObj.desc : "";
            let vipObj = storesWithVip.find(d => d.email === store.email);
            let vipLevel = vipObj ? vipObj.vipLevel : 0;
            let prodsObj = storesWithProducts.find(d => d.email === store.email);
            let productsCount = prodsObj ? prodsObj.count : 0;

            let card = document.createElement("div");
            card.style.cssText = "background:#1976d2;border-radius:16px;padding:18px 15px 15px 15px;margin-bottom:14px;cursor:pointer;box-shadow:0 3px 10px rgba(25,118,210,0.3);";
            card.innerHTML = \`
                <div style="display:flex;align-items:center;gap:14px;">
                    <div style="width:62px;height:62px;border-radius:50%;border:2.5px solid rgba(255,255,255,0.6);overflow:hidden;flex-shrink:0;background:rgba(255,255,255,0.15);display:flex;align-items:center;justify-content:center;">
                        <img src="\${displayLogo}"
                             style="width:100%;height:100%;object-fit:cover;"
                             onerror="this.src='https://cdn-icons-png.flaticon.com/512/149/149071.png'">
                    </div>
                    <div style="flex:1;min-width:0;">
                        <div style="font-size:16px;font-weight:bold;color:white;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">\${displayName}</div>
                        \${storeDesc ? \`<div style="font-size:12px;color:rgba(255,255,255,0.85);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">\${storeDesc}</div>\` : ""}
                        <div style="display:flex;align-items:center;gap:7px;margin-top:8px;flex-wrap:wrap;">
                            <span style="background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;font-weight:bold;padding:3px 10px;border-radius:20px;display:inline-flex;align-items:center;gap:3px;">&#10004; VIP \${vipLevel}</span>
                            <span style="background:rgba(255,255,255,0.18);color:white;font-size:11px;padding:3px 10px;border-radius:20px;">Products \${productsCount}</span>
                            <span style="background:rgba(255,255,255,0.18);color:white;font-size:11px;padding:3px 10px;border-radius:20px;">Followers \${followers}</span>
                        </div>
                    </div>
                </div>
            \`;
            card.onclick = () => {
                localStorage.setItem("viewStoreName", displayName);
                localStorage.setItem("viewStoreEmail", store.email);
                window.location.href = "/store-page";
            };
            resultsDiv.appendChild(card);
        });
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
body{font-family:Arial,sans-serif;background:#f5f5f5;min-height:100vh;}
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:relative;}
.h-left{display:flex;align-items:center;gap:10px;}
.h-right{display:flex;align-items:center;gap:14px;}
.toolbar{display:flex;align-items:center;background:white;padding:12px 20px;border-bottom:1px solid #eee;position:relative;}
.sort-btn{flex:1;text-align:center;font-size:15px;color:#333;cursor:pointer;position:relative;}
.sep{width:1px;height:20px;background:#ddd;margin:0 10px;}
.filter-btn{flex:1;text-align:center;font-size:15px;color:#333;cursor:pointer;}
/* Sort dropdown */
.sort-dropdown{display:none;position:relative;background:white;z-index:400;border-bottom:1px solid #eee;box-shadow:0 2px 8px rgba(0,0,0,0.08);}
.sort-item{padding:15px 20px;font-size:15px;color:#333;border-bottom:1px solid #f0f0f0;cursor:pointer;display:flex;align-items:center;justify-content:space-between;}
.sort-item:last-child{border-bottom:none;}
.sort-item.active{color:#1976d2;}
.sort-item .sort-arrows{color:#999;font-size:12px;}
/* Filter panel */
.filter-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;z-index:500;}
.filter-left{position:absolute;top:0;left:0;width:36%;height:100%;background:rgba(0,0,0,0.45);}
.filter-panel{position:fixed;top:0;right:0;width:64%;height:100%;background:white;padding:24px 16px 16px;display:flex;flex-direction:column;}
.filter-price-label{font-size:16px;font-weight:400;color:#333;margin-bottom:18px;}
.price-inputs{display:flex;align-items:center;gap:6px;}
.price-input{flex:1;border:1.5px solid #e0e0e0;border-radius:8px;padding:8px 8px;font-size:12px;color:#888;outline:none;background:#fff;min-width:0;max-width:100px;}
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
res.send('<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>*{box-sizing:border-box;}body{margin:0;font-family:Arial;background:#f5f5f5;padding-bottom:70px;min-height:100vh;}.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:relative;}.header .icons span{margin-left:15px;font-size:18px;cursor:pointer;}.main-img{background:white;text-align:center;padding:15px;position:relative;}.main-img img{width:100%;max-height:350px;object-fit:contain;}.main-img .heart{position:absolute;top:15px;left:15px;font-size:22px;cursor:pointer;}.main-img .share{position:absolute;top:15px;right:15px;font-size:22px;cursor:pointer;}.thumbs{display:flex;gap:8px;padding:10px 15px;background:white;overflow-x:auto;}.thumbs img{width:60px;height:60px;object-fit:cover;border-radius:8px;border:2px solid #eee;cursor:pointer;flex-shrink:0;}.thumbs img.active{border-color:#1976d2;}.info{background:white;margin-top:8px;padding:15px;}.info h2{font-size:16px;margin:0 0 10px;color:#222;}.rating-row{display:flex;justify-content:space-between;align-items:center;}.rating-row .stars{color:#1976d2;font-size:14px;}.rating-row .price{color:#1976d2;font-size:24px;font-weight:bold;}.specs{background:white;margin-top:8px;}.spec-row{display:flex;justify-content:space-between;align-items:center;padding:12px 15px;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;}.store{background:white;margin-top:8px;padding:15px;display:flex;align-items:center;gap:10px;}.store img{width:50px;height:50px;border-radius:10px;}.store-info{flex:1;}.store-name{font-weight:bold;font-size:15px;}.vip{background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;padding:2px 8px;border-radius:10px;display:inline-block;margin-top:3px;}.store-tags{display:flex;gap:8px;margin-top:5px;}.store-tags span{background:#eee;font-size:11px;padding:3px 10px;border-radius:10px;}.review{background:white;margin-top:8px;padding:15px;}.review-title{display:flex;justify-content:space-between;font-size:14px;color:#333;}.review-stars{color:#f5a623;font-size:18px;margin-top:5px;}.desc{background:white;margin-top:8px;padding:15px;font-size:13px;color:#444;line-height:1.8;}.desc ul{padding-left:18px;margin:0;}.desc li{margin-bottom:8px;}.bottom-bar{position:fixed;bottom:0;left:0;right:0;background:white;display:flex;align-items:center;padding:10px 15px;border-top:1px solid #eee;gap:10px;}.bottom-bar .icon-btn{font-size:22px;cursor:pointer;}.bottom-bar .cart-btn{flex:1;padding:12px;border:1px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;cursor:pointer;text-align:center;}.bottom-bar .buy-btn{flex:1;padding:12px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;cursor:pointer;text-align:center;}</style></head><body><div class="header"><div><span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span><span onclick="window.location.href=\'\/dashboard\'" style="cursor:pointer;display:inline-flex;align-items:center;margin-left:8px;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span></div><div class="icons"><span onclick="window.location.href=\'\/dashboard?search=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span><span onclick="window.location.href=\'\/dashboard?messages=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span><span onclick="window.location.href=\'\/dashboard?account=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span><span onclick="window.location.href=\'\/dashboard?lang=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span></div></div><div class="main-img"><span class="heart" id="heartBtn" onclick="toggleHeart()">&#129293;</span><img id="mainImg" src=""><span class="share">&#128279;</span></div><div class="thumbs" id="thumbs"></div><div class="info"><h2 id="productTitle"></h2><div class="rating-row"><div class="stars">&#11088; <span style="color:#1976d2;font-weight:bold;">5.0</span> <span style="color:#999;font-size:12px;">(0 Sales)</span></div><div class="price" id="productPrice"></div></div></div><div class="specs"><div class="spec-row"><span>Select</span><span>Brand, specification &#8250;</span></div><div class="spec-row"><span>Shipping fees</span><span>Free shipping</span></div><div class="spec-row"><span>Guarantee</span><span>Free return</span></div></div><div class="store"><img src="https://cdn-icons-png.flaticon.com/512/149/149071.png"><div class="store-info"><div class="store-name">S&amp;R Store</div><div class="vip">&#10004; VIP 0</div><div class="store-tags"><span>Products 20</span><span>Followers 0</span></div></div><span>&#8250;</span></div><div class="review"><div class="review-title"><span>Consumer review</span><span style="color:#1976d2;">0 Unit Global Rating &#8250;</span></div><div class="review-stars">&#11088;&#11088;&#11088;&#11088;&#11088; <span style="font-size:13px;color:#555;">5 Stars</span></div></div><div class="desc"><ul id="descList"></ul></div><div class="bottom-bar"><span class="icon-btn" onclick="window.location.href=\'/live-chat\'">&#127911;</span><span class="icon-btn" onclick="window.location.href=\'/wallet\'">&#128722;</span><div class="cart-btn" onclick="addToCart()">Add to Cart</div><div class="buy-btn" onclick="buyNow()">Buy now</div></div><script>var productId = localStorage.getItem("productId");var isFav = false;fetch("https://fakestoreapi.com/products/" + productId).then(function(r){return r.json();}).then(function(p){document.getElementById("mainImg").src = p.image;var thumbs = document.getElementById("thumbs");for(var i=0;i<5;i++){var img = document.createElement("img");img.src = p.image;if(i===0) img.classList.add("active");img.onclick = function(){document.getElementById("mainImg").src = this.src;document.querySelectorAll(".thumbs img").forEach(function(t){t.classList.remove("active");});this.classList.add("active");};thumbs.appendChild(img);}document.getElementById("productTitle").innerText = p.title;document.getElementById("productPrice").innerText = "$" + p.price;var desc = document.getElementById("descList");var points = p.description ? p.description.split(".").filter(function(s){return s.trim();}) : [p.description];points.forEach(function(point){if(point && point.trim()){var li = document.createElement("li");li.innerText = point.trim();desc.appendChild(li);}});});function toggleHeart(){isFav=!isFav;document.getElementById("heartBtn").innerHTML=isFav?"&#10084;&#65039;":"&#129293;";}function addToCart(){var cart=JSON.parse(localStorage.getItem("cart")||"[]");cart.push(productId);localStorage.setItem("cart",JSON.stringify(cart));alert("Added to cart");}function buyNow(){window.location.href="/wallet";}<\/script></body></html>');
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
body{font-family:Arial;background:#f5f5f5;padding-bottom:80px;min-height:100vh;}

/* HEADER */
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:relative;}
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

min-height:100vh;
}

/* HEADER */
.header{
position:relative;
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

<!-- قائمة العمليات -->
<div id="txList" style="padding:0 12px 20px;"></div>

<style>
.tx-card{
  background:white;
  border-radius:16px;
  padding:14px 16px;
  margin-bottom:10px;
  display:flex;
  align-items:center;
  gap:14px;
  box-shadow:0 1px 6px rgba(0,0,0,0.07);
}
.tx-icon{
  width:44px;height:44px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  font-size:20px;flex-shrink:0;
}
.tx-icon.recharge{ background:#e3f2fd; }
.tx-icon.withdraw{ background:#fff3e0; }
.tx-body{ flex:1; }
.tx-type{ font-size:14px;font-weight:bold;color:#222; }
.tx-date{ font-size:12px;color:#aaa;margin-top:2px; }
.tx-right{ text-align:right; }
.tx-amount{ font-size:15px;font-weight:bold; }
.tx-amount.recharge{ color:#1976d2; }
.tx-amount.withdraw{ color:#e65100; }
.tx-badge{
  font-size:11px;font-weight:bold;
  padding:3px 10px;border-radius:20px;
  display:inline-block;margin-top:4px;
}
.tx-badge.pending{ background:#fff8e1;color:#f57c00; }
.tx-badge.approved{ background:#e8f5e9;color:#2e7d32; }
.tx-badge.rejected{ background:#ffebee;color:#c62828; }
.empty-tx{ text-align:center;padding:50px 0;color:#bbb; }
.empty-tx div{ font-size:48px;margin-bottom:10px; }
.empty-tx p{ font-size:14px; }
</style>

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

async function loadTransactions(){
    if(!user) return;
    let res = await fetch("/my-requests/" + encodeURIComponent(user.email));
    let list = await res.json();
    let container = document.getElementById("txList");

    if(!list || list.length === 0){
        container.innerHTML = \`<div class="empty-tx"><div>📄</div><p>No transactions yet</p></div>\`;
        return;
    }

    container.innerHTML = "";
    list.forEach(function(tx){
        let isRecharge = tx.type === "recharge";
        let typeLabel  = isRecharge ? "Recharge" : "Withdrawal";
        let icon       = isRecharge ? "💰" : "📤";
        let amountSign = isRecharge ? "+" : "-";

        // تنسيق التاريخ
        let dateStr = "";
        if(tx.createdAt){
            let d = new Date(tx.createdAt);
            dateStr = d.toLocaleDateString("en-GB", {day:"2-digit",month:"short",year:"numeric"})
                    + " " + d.toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"});
        } else {
            dateStr = new Date(tx.id).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"});
        }

        let statusClass = tx.status === "approved" ? "approved" : tx.status === "rejected" ? "rejected" : "pending";
        let statusLabel = tx.status === "approved" ? "✅ Approved" : tx.status === "rejected" ? "❌ Rejected" : "⏳ Pending";

        let card = document.createElement("div");
        card.className = "tx-card";
        card.innerHTML = \`
          <div class="tx-icon \${isRecharge ? 'recharge' : 'withdraw'}">\${icon}</div>
          <div class="tx-body">
            <div class="tx-type">\${typeLabel}</div>
            <div class="tx-date">\${dateStr}</div>
          </div>
          <div class="tx-right">
            <div class="tx-amount \${isRecharge ? 'recharge' : 'withdraw'}">\${amountSign}$\${Number(tx.amount).toFixed(2)}</div>
            <span class="tx-badge \${statusClass}">\${statusLabel}</span>
          </div>
        \`;
        container.appendChild(card);
    });
}

loadRealBalance();
loadTransactions();
// تحديث كل 5 ثواني لتعكس تغييرات الأدمن
setInterval(loadTransactions, 5000);

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
position:relative;
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
    window.location.href = "/wallet";
})
.catch(err => {
    console.log(err);
    alert("Sent but with issue ⚠️");
    window.location.href = "/wallet";
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
position:relative;
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
window.location.href = "/wallet";
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
body{margin:0;font-family:Arial;background:#f5f5f5;min-height:100vh;}
.header{position:relative;background:#1976d2;color:white;padding:15px;display:flex;align-items:center;gap:10px;}
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

min-height:100vh;
}

/* HEADER */
.header{
position:relative;
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

min-height:100vh;
}

/* HEADER */
.header{
position:relative;
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

<div class="header" style="position:relative;background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;">
  <div style="display:flex;align-items:center;gap:10px;">
    <span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
    <span style="font-size:16px;font-weight:bold;"></span>
  </div>
  <div style="display:flex;align-items:center;gap:15px;">
    <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
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

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 164920, "t": "Free People Womens Carter Pullover", "p": 48.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/7.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "164920_Free People Womens Carter Pullover", "cat": "Clothing & Accessories"})'>
<img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164920_Free People Womens Carter Pullover/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(1)">🤍</div>
<p>Free People Womens Carter Pullover</p>
<div class="price">US$48.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 164915, "t": "POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt Flowy Tank Top for Leggings Cas", "p": 22.75, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/7.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/8.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F", "cat": "Clothing & Accessories"})'>
<img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/17_Clothing_and_Accessories/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(2)">🤍</div>
<p>POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt Flowy Tank Top for Leggings Cas</p>
<div class="price">US$22.75</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165021, "t": "Tricex Automatic Moissanite Diamond Watch – Premium Luxury Hanuman Edition | Sel", "p": 1189.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/7.jpg"], "rating": 5.0, "sales": 1, "description": "", "colors": [], "sizes": [], "folder": "165021_Tricex Automatic Moissanite Diamond Watch  Premium", "cat": "Watches"})'>
<img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165021_Tricex Automatic Moissanite Diamond Watch  Premium/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(3)">🤍</div>
<p>Tricex Automatic Moissanite Diamond Watch – Premium Luxury Hanuman Edition | Sel</p>
<div class="price">US$1189.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165019, "t": "Lucky Harvey Rabbit Automatic Men Watch 925 Silver Rabbit Dial Dome Sapphire Cry", "p": 1399.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/7.jpg"], "rating": 5.0, "sales": 2, "description": "", "colors": [], "sizes": [], "folder": "165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver", "cat": "Watches"})'>
<img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/21_Watches/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(4)">🤍</div>
<p>Lucky Harvey Rabbit Automatic Men Watch 925 Silver Rabbit Dial Dome Sapphire Cry</p>
<div class="price">US$1399.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165133, "t": "14K Real Gold Pendant Necklaces - Elegant and Shiny Cultured Pearl – Jewelry Gif", "p": 160.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/6.jpg"], "rating": 5.0, "sales": 10, "description": "", "colors": [], "sizes": [], "folder": "165133_14K Real Gold Pendant Necklaces - Elegant and Shin", "cat": "Jewelry"})'>
<img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(5)">🤍</div>
<p>14K Real Gold Pendant Necklaces - Elegant and Shiny Cultured Pearl – Jewelry Gif</p>
<div class="price">US$160.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165131, "t": "14k Solid Gold Turquoise Evil Eye Necklace | 14k Yellow Gold Opal Nazar Necklace", "p": 105.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/5.jpg"], "rating": 5.0, "sales": 12, "description": "", "colors": [], "sizes": [], "folder": "165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye", "cat": "Jewelry"})'>
<img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/22_Jewelry/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(6)">🤍</div>
<p>14k Solid Gold Turquoise Evil Eye Necklace | 14k Yellow Gold Opal Nazar Necklace</p>
<div class="price">US$105.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165007, "t": "Dell Touchscreen Laptop, 15.6 FHD Intel CPU, 64GB RAM 128GB SSD WiFi 6 Win 11 Co", "p": 1099.99, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/6.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/7.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/8.jpg"], "rating": 5.0, "sales": 2, "description": "", "colors": [], "sizes": [], "folder": "165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM", "cat": "Electronics"})'>
<img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(7)">🤍</div>
<p>Dell Touchscreen Laptop, 15.6 FHD Intel CPU, 64GB RAM 128GB SSD WiFi 6 Win 11 Co</p>
<div class="price">US$1099.99</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165006, "t": "HP 15-FC000 15.6 FHD (1920x1080) IPS Touchscreen Laptop 2025 New | AMD Ryzen 7 7", "p": 1009.0, "img": "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/1.jpg", "imgs": ["https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/1.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/2.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/3.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/4.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/5.jpg", "https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/6.jpg"], "rating": 5.0, "sales": 3, "description": "", "colors": [], "sizes": [], "folder": "165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt", "cat": "Electronics"})'>
<img src="https://res.cloudinary.com/doabtbdsh/image/upload/products/27_Electronics/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(8)">🤍</div>
<p>HP 15-FC000 15.6 FHD (1920x1080) IPS Touchscreen Laptop 2025 New | AMD Ryzen 7 7</p>
<div class="price">US$1009.00</div>
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

function openRealProduct(prod){
  localStorage.setItem("catProduct", JSON.stringify(prod));
  window.location.href = "/cat-product-detail";
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

min-height:100vh;
}

/* HEADER */
.header{
background:#1976d2;
color:white;
padding:12px 15px;
display:flex;
align-items:center;
justify-content:space-between;
position:fixed;
top:0;left:0;right:0;
z-index:200;
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

<div class="header" style="display:flex;justify-content:space-between;align-items:center;padding:12px 15px;">
  <div style="display:flex;align-items:center;gap:10px;">
    <span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  </div>
  <div style="display:flex;align-items:center;gap:15px;">
    <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
</div>

<div style="background:#1976d2;color:white;text-align:center;padding:10px;font-size:17px;font-weight:bold;position:fixed;top:46px;left:0;right:0;z-index:199;">Customer Service</div>

<div style="height:40px;"></div>

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
position:relative;
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

}

/* HEADER */
.header{
position:relative;
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
<div class="value" id="numberOfOrders">0</div>
</div>

<div>
<p>Turnover</p>
<div class="value" id="turnoverVal">0.00</div>
</div>

<div>
<p>Credential rating</p>
<div class="value" id="credentialRating">0</div>
</div>
</div>
</div>

<!-- ORDER STATUS -->
<div class="card">
<div class="grid4">
<div onclick="window.location.href='/manage-orders?tab=waiting_payment'" style="cursor:pointer;"><span id="waitingPayment">0</span><br><small>Waiting for payment</small></div>
<div onclick="window.location.href='/manage-orders?tab=waiting_shipping'" style="cursor:pointer;"><span id="waitingShipping">0</span><br><small>Waiting for shipping</small></div>
<div onclick="window.location.href='/manage-orders?tab=in_delivery'" style="cursor:pointer;"><span id="waitingDelivery">0</span><br><small>Waiting for delivery</small></div>
<div onclick="window.location.href='/manage-orders?tab=waiting_refund'" style="cursor:pointer;"><span id="waitingRefund">0</span><br><small>Waiting for refund</small></div>
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
    <p id="profitOfDay">0.00</p>
    <small>Profit of the day</small>
</div>

<div onclick="window.location.href='/wallet'" style="cursor:pointer;">
    <p id="totalProfitCredited">0.00</p>
    <small>Total profit credited</small>
</div>
</div>
</div>

<!-- TOOLS -->
<div class="card">
<b>Basic tools</b>

<div class="tools">
<div class="tool" onclick="window.location.href='/listings'" style="cursor:pointer;">
<img src="https://cdn-icons-png.flaticon.com/512/891/891462.png">
<p>Listings</p>
</div>

<div class="tool" onclick="window.location.href='/manage-product'" style="cursor:pointer;">
<img src="https://cdn-icons-png.flaticon.com/512/2921/2921222.png">
<p>Manage product</p>
</div>

<div class="tool" onclick="window.location.href='/manage-orders'" style="cursor:pointer;">
<img src="https://cdn-icons-png.flaticon.com/512/3144/3144456.png">
<p>Manage Order</p>
</div>

<div class="tool" onclick="window.location.href='/store-setting'" style="cursor:pointer;">
<img src="https://cdn-icons-png.flaticon.com/512/2099/2099058.png">
<p>Store setting</p>
</div>

<div class="tool" onclick="window.location.href='/vip-upgrade'" style="cursor:pointer;">
<img src="https://cdn-icons-png.flaticon.com/512/2331/2331949.png">
<p>Store Operating fund</p>
</div>

<div class="tool" onclick="window.location.href='/instructions'" style="cursor:pointer;">
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

    // شعار المتجر - السيرفر هو المصدر الرئيسي، ثم المحلي كـ fallback
    let serverLogo = data.found ? data.storeLogo : "";
    let localLogo  = localStorage.getItem("merchant_storeLogo_" + (user ? user.email : ""))
                     || localStorage.getItem("storeLogo") || "";
    let logo = serverLogo || localLogo;
    if(logo && logo.length > 10){
        document.getElementById("storeLogo").src = logo;
        // مزامنة المحلي مع السيرفر
        if(serverLogo && serverLogo.length > 10){
            localStorage.setItem("merchant_storeLogo_" + (user ? user.email : ""), serverLogo);
        }
    }

    // VIP Level - جلب من السيرفر
    try {
      let token2 = localStorage.getItem("token") || "";
      let vipRes = await fetch("/my-vip-info", { headers:{"Authorization":"Bearer " + token2} });
      let vipData = await vipRes.json();
      if(vipData.success){
        document.getElementById("vipBadge").innerText = "VIP " + (vipData.vipLevel || 0);
      }
    } catch(e){
      document.getElementById("vipBadge").innerText = "VIP 0";
    }
}

// تغيير شعار المتجر
function changeStoreLogo(input){
    if(!input.files || !input.files[0]) return;
    let user = JSON.parse(localStorage.getItem("user"));
    let reader = new FileReader();
    reader.onload = function(e){
        let dataUrl = e.target.result;
        // حفظ محلي فوري
        localStorage.setItem("merchant_storeLogo_" + (user ? user.email : ""), dataUrl);
        document.getElementById("storeLogo").src = dataUrl;
        // رفع الصورة للسيرفر حتى تظهر لجميع المستخدمين
        let token = localStorage.getItem("token") || "";
        fetch("/update-store-logo", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
            body: JSON.stringify({ storeLogo: dataUrl })
        })
        .then(function(r){ return r.json(); })
        .then(function(d){
            if(d.success){ console.log("Logo saved to server"); }
            else { console.warn("Logo server save failed:", d.message); }
        })
        .catch(function(err){ console.warn("Logo upload error:", err); });
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

  // جدول الزوار حسب VIP
  const VIP_VISITORS = [50, 600, 1000, 3000, 10000, 30000];
  let vipLevel = user.vipLevel || 0;
  const DAILY_TARGET = VIP_VISITORS[vipLevel] || 50;
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

  // إضافة زوار بسرعة حسب VIP - كل 30 ثانية إلى دقيقتين
  // VIP 4 = 10000 زائر يومياً = ~7 زوار كل دقيقة
  function scheduleNext(){
    let d = getData();
    if((d.todayAdded || 0) >= DAILY_TARGET) return;

    // حساب عدد الزوار المضافين في كل دفعة حسب VIP
    let batchSize = Math.max(1, Math.floor(DAILY_TARGET / 500));
    
    // delay بين 30 ثانية و90 ثانية
    let delay = 30000 + Math.random() * 60000;

    setTimeout(function(){
      let d = getData();
      let remaining = DAILY_TARGET - (d.todayAdded || 0);
      let toAdd = Math.min(batchSize, remaining);
      if(toAdd > 0){
        d.todayAdded = (d.todayAdded || 0) + toAdd;
        saveData(d);
        showCount(d);
      }
      scheduleNext();
    }, delay);
  }

  // أول إضافة بعد 3 ثوانٍ
  setTimeout(function(){
    let d = getData();
    let batchSize = Math.max(1, Math.floor(DAILY_TARGET / 500));
    let toAdd = Math.min(batchSize, DAILY_TARGET - (d.todayAdded || 0));
    if(toAdd > 0){
      d.todayAdded = (d.todayAdded || 0) + toAdd;
      saveData(d);
      showCount(d);
    }
    scheduleNext();
  }, 3000);
}

// جلب كل إحصائيات الداشبورد
async function loadDashboardStats(){
  try {
    let token = localStorage.getItem("token") || "";
    let r = await fetch("/seller-dashboard-stats", { headers: {"Authorization": "Bearer " + token} });
    let d = await r.json();
    if(!d.success) return;

    // Stats
    let pEl = document.getElementById("productsForSaleCount");
    if(pEl) pEl.innerText = d.productsForSale || 0;
    let noEl = document.getElementById("numberOfOrders");
    if(noEl) noEl.innerText = d.numberOfOrders || 0;
    let tvEl = document.getElementById("turnoverVal");
    if(tvEl) tvEl.innerText = parseFloat(d.turnover||0).toFixed(2);
    let crEl = document.getElementById("credentialRating");
    if(crEl) crEl.innerText = parseFloat(d.credentialRating||0).toFixed(1);

    // Order status
    let wpEl = document.getElementById("waitingPayment");
    if(wpEl) wpEl.innerText = d.waitingPayment || 0;
    let wsEl = document.getElementById("waitingShipping");
    if(wsEl) wsEl.innerText = d.waitingShipping || 0;
    let wdEl = document.getElementById("waitingDelivery");
    if(wdEl) wdEl.innerText = d.waitingDelivery || 0;
    let wrEl = document.getElementById("waitingRefund");
    if(wrEl) wrEl.innerText = d.waitingRefund || 0;

    // Balance
    let balEl = document.getElementById("merchantBalance");
    if(balEl) balEl.innerText = parseFloat(d.availableBalance||0).toFixed(2);
    let capEl = document.getElementById("merchantTotalCapital");
    if(capEl) capEl.innerText = parseFloat(d.totalWorkingCapital||0).toFixed(2);
    let podEl = document.getElementById("profitOfDay");
    if(podEl) podEl.innerText = parseFloat(d.profitOfDay||0).toFixed(2);
    let tpcEl = document.getElementById("totalProfitCredited");
    if(tpcEl) tpcEl.innerText = parseFloat(d.totalProfitCredited||0).toFixed(2);
  } catch(e){ console.error(e); }
}

async function loadMerchantBalance(){
  await loadDashboardStats();
}

function loadProductsCount(){ /* handled by loadDashboardStats */ }

loadStoreInfo();
loadMerchantBalance();
loadVisitorCounter();
loadProductsCount();
setInterval(loadMerchantBalance, 5000);
</script>
</html>`);
});

// ================= VIP UPGRADE API =================
const VIP_PLANS = [
    { level: 0, capital: 0,       visitors: 50,    products: 20,  commission: 15 },
    { level: 1, capital: 500,     visitors: 600,   products: 35,  commission: 17 },
    { level: 2, capital: 5000,    visitors: 1000,  products: 80,  commission: 20 },
    { level: 3, capital: 20000,   visitors: 3000,  products: 120, commission: 22 },
    { level: 4, capital: 50000,   visitors: 10000, products: 300, commission: 25 },
    { level: 5, capital: 200000,  visitors: 30000, products: 1000,commission: 40 }
];

app.post("/upgrade-vip", authMiddleware, (req, res) => {
    const { targetLevel } = req.body;
    const email = req.userEmail;

    const user = users.find(u => u.email === email);
    if (!user) return res.json({ success: false, message: "User not found" });

    const currentLevel = user.vipLevel || 0;
    const nextLevel = parseInt(targetLevel);

    if (isNaN(nextLevel) || nextLevel <= currentLevel || nextLevel > 5) {
        return res.json({ success: false, message: "Invalid level" });
    }

    const plan = VIP_PLANS.find(p => p.level === nextLevel);
    if (!plan) return res.json({ success: false, message: "Plan not found" });

    const balance = parseFloat(user.balance || 0);
    if (balance < plan.capital) {
        return res.json({ success: false, message: "Insufficient balance. You need $" + plan.capital.toLocaleString() + " to upgrade." });
    }

    user.vipLevel = nextLevel;
    // الرصيد يبقى كما هو - الترقية تعتمد على الرصيد كشرط فقط
    user.vipCapital = plan.capital;
    user.vipVisitors = plan.visitors;
    user.vipProducts = plan.products;
    user.vipCommission = plan.commission;
    user.vipUpgradedAt = new Date().toISOString();

    saveUsers();
    addLog("vip_upgrade", "Upgraded to VIP " + nextLevel + " | Capital: $" + plan.capital, email);

    res.json({ success: true, vipLevel: nextLevel, newBalance: user.balance });
});

app.get("/my-vip-info", authMiddleware, (req, res) => {
    const user = users.find(u => u.email === req.userEmail);
    if (!user) return res.json({ success: false });
    res.json({
        success: true,
        vipLevel: user.vipLevel || 0,
        balance: parseFloat(user.balance || 0).toFixed(2)
    });
});

// endpoint عام لجلب VIP مستخدم معين (للمتاجر العامة)
app.get("/store-vip/:email", (req, res) => {
    const user = users.find(u => u.email === req.params.email);
    res.json({ vipLevel: user ? (user.vipLevel || 0) : 0 });
});

// ================= VIP UPGRADE PAGE =================
app.get("/vip-upgrade", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Store Operating Fund</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
  background:#f4f6fb;
  min-height:100vh;
  padding-bottom:30px;
}

/* STICKY TOP = HEADER + BANNER ثابتان معاً */
.sticky-top{
  position:relative;
}

/* HEADER */
.header{
  background:linear-gradient(135deg,#1565c0,#1976d2);
  color:white;
  padding:14px 16px;
  display:flex;align-items:center;gap:12px;
}
.header h2{margin:0;font-size:17px;font-weight:600;}

/* BALANCE BANNER — ملتصق بالهيدر */
.balance-banner{
  background:linear-gradient(135deg,#1565c0,#0d47a1);
  padding:14px 18px 16px;
  color:white;
  display:flex;justify-content:space-between;align-items:center;
}
.balance-banner .label{font-size:12px;opacity:0.85;margin-bottom:3px;}
.balance-banner .amount{font-size:26px;font-weight:700;}
.balance-banner .vip-tag{
  background:rgba(255,255,255,0.2);
  border-radius:20px;padding:6px 16px;
  font-size:13px;font-weight:600;
  border:1px solid rgba(255,255,255,0.35);
}

/* CONTENT — يبدأ بعد الـ sticky */
.content{
  padding-top: 110px; /* ارتفاع header+banner تقريباً */
}

/* SECTION TITLE */
.section-title{
  margin:16px 14px 10px;
  font-size:15px;font-weight:600;color:#333;
}

/* VIP CARD */
.vip-card{
  background:white;
  margin:0 14px 14px;
  border-radius:16px;
  overflow:hidden;
  box-shadow:0 2px 10px rgba(0,0,0,0.07);
  border:2px solid transparent;
}
.vip-card.current{ border-color:#1976d2; }
.vip-card.vip5{ border-color:#ffd700; background:linear-gradient(135deg,#fffdf0,white); }

/* CARD TOP HALF — VIP badge */
.card-top{
  padding:14px 18px 10px;
  display:flex;align-items:center;gap:8px;
}
.vip-badge{
  background:linear-gradient(135deg,#f5a623,#e8791d);
  color:white;
  padding:5px 16px;
  border-radius:20px;
  font-size:15px;
  font-weight:700;
  display:inline-block;
}
.vip-badge.vip5-b{
  background:linear-gradient(135deg,#ffd700,#ffb300);
  color:#5d3a00;
}
.best-badge{
  background:linear-gradient(135deg,#ff6b00,#ff9800);
  color:white;
  font-size:11px;font-weight:700;
  padding:3px 10px;border-radius:20px;
  display:inline-block;
}

/* CARD INFO — قائمة البنود */
.card-info{
  padding:0 18px 14px;
  border-bottom:1px solid #f0f0f0;
}
.info-row{
  display:flex;align-items:center;
  padding:7px 0;
  font-size:14px;
  color:#444;
  border-bottom:1px solid #f7f7f7;
}
.info-row:last-child{ border-bottom:none; }
.info-row .dot{
  width:7px;height:7px;border-radius:50%;
  background:#1976d2;margin-right:10px;flex-shrink:0;
}
.info-row .ikey{ color:#888;min-width:180px; }
.info-row .ival{ font-weight:700;color:#1a1a2e;margin-left:auto; }
.info-row .ival.comm{ color:#1976d2; }

/* CARD BOTTOM — زر */
.card-btn{
  padding:12px 18px;
  display:flex;justify-content:center;
}
.upgrade-btn{
  width:60%;
  padding:12px;
  border:none;
  border-radius:24px;
  background:linear-gradient(135deg,#1976d2,#1565c0);
  color:white;
  font-size:15px;
  font-weight:600;
  cursor:pointer;
  transition:all 0.2s;
  text-align:center;
}
.upgrade-btn:active{ transform:scale(0.97); }
.current-btn{
  width:60%;
  padding:12px;
  border:2px solid #ccc;
  border-radius:24px;
  background:#f0f0f0;
  color:#aaa;
  font-size:15px;
  font-weight:600;
  cursor:default;
  text-align:center;
}
.upgraded-btn{
  width:60%;
  padding:12px;
  border:2px solid #a5d6a7;
  border-radius:24px;
  background:#e8f5e9;
  color:#2e7d32;
  font-size:15px;
  font-weight:600;
  cursor:default;
  text-align:center;
}
.locked-btn{
  width:60%;
  padding:12px;
  border:2px solid #e0e0e0;
  border-radius:24px;
  background:#f5f5f5;
  color:#bbb;
  font-size:15px;
  font-weight:600;
  cursor:default;
  text-align:center;
}

/* TOAST */
.toast{
  position:fixed;bottom:30px;left:50%;
  transform:translateX(-50%) translateY(100px);
  background:#333;color:white;
  padding:12px 24px;border-radius:30px;
  font-size:14px;z-index:999;
  transition:transform 0.3s;
  white-space:nowrap;max-width:90%;text-align:center;
}
.toast.show{transform:translateX(-50%) translateY(0);}
.toast.success{background:#2e7d32;}
.toast.error{background:#c62828;}
</style>
</head>
<body>

<!-- STICKY: HEADER + BALANCE BANNER -->
<div class="sticky-top">
  <div class="header">
    <span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <h2>Store Operating Fund</h2>
  </div>
  <div class="balance-banner">
    <div>
      <div class="label">Available Balance</div>
      <div class="amount">$<span id="bannerBalance">0.00</span></div>
    </div>
    <div class="vip-tag" id="currentVipTag">VIP 0</div>
  </div>
</div>

<!-- SCROLLABLE CONTENT -->
<div class="content">
  <div class="section-title">Select your plan</div>
  <div id="vipCards"></div>
</div>

<!-- TOAST -->
<div class="toast" id="toast"></div>

<script>
const PLANS = [
  { level:0, capital:0,      visitors:50,    products:20,  commission:15, label:"VIP 0" },
  { level:1, capital:500,    visitors:600,   products:35,  commission:17, label:"VIP 1" },
  { level:2, capital:5000,   visitors:1000,  products:80,  commission:20, label:"VIP 2" },
  { level:3, capital:20000,  visitors:3000,  products:120, commission:22, label:"VIP 3" },
  { level:4, capital:50000,  visitors:10000, products:300, commission:25, label:"VIP 4" },
  { level:5, capital:200000, visitors:30000, products:1000,commission:40, label:"VIP 5", best:true }
];

let currentVip = 0;
let currentBalance = 0;

function fmt(n){ return n.toLocaleString(); }

function showToast(msg, type=""){
  let t = document.getElementById("toast");
  t.className = "toast " + type;
  t.innerText = msg;
  t.classList.add("show");
  setTimeout(()=>{ t.classList.remove("show"); }, 3500);
}

function adjustContentPadding(){
  let sticky = document.querySelector(".sticky-top");
  if(sticky){
    document.querySelector(".content").style.paddingTop = (sticky.offsetHeight + 8) + "px";
  }
}

function renderCards(){
  let container = document.getElementById("vipCards");
  container.innerHTML = "";

  PLANS.forEach(function(plan){
    let isCurrent  = plan.level === currentVip;
    let isUpgraded = plan.level < currentVip;
    let canUpgrade = plan.level === currentVip + 1;

    let card = document.createElement("div");
    let cls = "vip-card";
    if(isCurrent) cls += " current";
    if(plan.level === 5) cls += " vip5";
    card.className = cls;

    let badgeCls = plan.level === 5 ? "vip-badge vip5-b" : "vip-badge";
    let capitalTxt = plan.capital === 0 ? "Free" : "$" + fmt(plan.capital);
    let crownHtml  = plan.level === 5 ? "👑 " : "";
    let bestHtml   = plan.best ? ' <span class="best-badge">⭐ Best Value</span>' : "";

    let btnHtml = "";
    if(isCurrent){
      btnHtml = '<div class="current-btn">🔘 Current Plan</div>';
    } else if(isUpgraded){
      btnHtml = '<div class="upgraded-btn">✅ Upgraded</div>';
    } else if(canUpgrade){
      btnHtml = '<div class="upgrade-btn" onclick="doUpgrade(' + plan.level + ')">🔘 Upgrade</div>';
    } else {
      btnHtml = '<div class="locked-btn">🔒 Locked</div>';
    }

    card.innerHTML =
      '<div class="card-top">' +
        '<span class="' + badgeCls + '">' + crownHtml + plan.label + '</span>' +
        bestHtml +
      '</div>' +
      '<div class="card-info">' +
        '<div class="info-row"><span class="dot"></span><span class="ikey">Capital</span><span class="ival">' + capitalTxt + '</span></div>' +
        '<div class="info-row"><span class="dot"></span><span class="ikey">Daily Traffic Provided</span><span class="ival">' + fmt(plan.visitors) + ' Visitors</span></div>' +
        '<div class="info-row"><span class="dot"></span><span class="ikey">Product Limit</span><span class="ival">' + fmt(plan.products) + ' Products</span></div>' +
        '<div class="info-row"><span class="dot"></span><span class="ikey">Sales Commission</span><span class="ival comm">' + plan.commission + '%</span></div>' +
      '</div>' +
      '<div class="card-btn">' + btnHtml + '</div>';

    container.appendChild(card);
  });

  adjustContentPadding();
}

async function loadInfo(){
  try {
    let token = localStorage.getItem("token") || "";
    let res = await fetch("/my-vip-info", { headers:{ "Authorization":"Bearer " + token } });
    let data = await res.json();
    if(data.success){
      currentVip     = data.vipLevel || 0;
      currentBalance = parseFloat(data.balance || 0);
      document.getElementById("bannerBalance").innerText = currentBalance.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2});
      document.getElementById("currentVipTag").innerText = "VIP " + currentVip;
      renderCards();
    }
  } catch(e){
    let user = JSON.parse(localStorage.getItem("user") || "{}");
    currentBalance = parseFloat(user.balance || 0);
    currentVip     = user.vipLevel || 0;
    document.getElementById("bannerBalance").innerText = currentBalance.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2});
    document.getElementById("currentVipTag").innerText = "VIP " + currentVip;
    renderCards();
  }
}

async function doUpgrade(level){
  let plan = PLANS.find(p => p.level === level);
  if(!plan) return;

  if(currentBalance < plan.capital){
    showToast("❌ Insufficient balance. Need $" + fmt(plan.capital), "error");
    return;
  }

  if(!confirm("Upgrade to VIP " + level + "?\\nConfirm upgrade to VIP " + level + ".")){
    return;
  }

  try {
    let token = localStorage.getItem("token") || "";
    let res = await fetch("/upgrade-vip", {
      method:"POST",
      headers:{ "Content-Type":"application/json", "Authorization":"Bearer " + token },
      body: JSON.stringify({ targetLevel: level })
    });
    let data = await res.json();
    if(data.success){
      currentVip     = data.vipLevel;
      currentBalance = parseFloat(data.newBalance);
      document.getElementById("bannerBalance").innerText = currentBalance.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2});
      document.getElementById("currentVipTag").innerText = "VIP " + currentVip;
      let user = JSON.parse(localStorage.getItem("user") || "{}");
      user.vipLevel = currentVip;
      user.balance  = data.newBalance;
      localStorage.setItem("user", JSON.stringify(user));
      renderCards();
      showToast("🎉 Successfully upgraded to VIP " + currentVip + "!", "success");
    } else {
      showToast("❌ " + (data.message || "Upgrade failed"), "error");
    }
  } catch(e){
    showToast("❌ Connection error", "error");
  }
}

window.addEventListener("resize", adjustContentPadding);
loadInfo();
</script>

</body>
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

min-height:100vh;
}

/* HEADER */
.header{
position:relative;
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

min-height:100vh;
}

/* HEADER */
.header{
position:relative;
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

min-height:100vh;
}

/* HEADER */
.header{
position:relative;
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

min-height:100vh;
}

.header{
position:relative;
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

<!-- شاشة البيانات قبل المحادثة -->
<div id="infoScreen" style="flex:1;display:flex;flex-direction:column;justify-content:center;align-items:center;padding:30px;background:#f5f5f5;">
  <div style="background:white;border-radius:16px;padding:25px;width:100%;max-width:360px;box-shadow:0 2px 10px rgba(0,0,0,0.08);">
    <p style="text-align:center;font-size:15px;color:#333;margin:0 0 20px;font-weight:bold;">Please fill in your details before starting</p>
    <label style="font-size:13px;color:#555;">Store Name</label>
    <input id="inputStoreName" placeholder="Enter your store name" style="width:100%;padding:10px;border:1px solid #ccc;border-radius:10px;margin:6px 0 15px;box-sizing:border-box;font-size:14px;">
    <label style="font-size:13px;color:#555;">Mobile Number</label>
    <input id="inputMobile" placeholder="Enter your mobile number" type="tel" style="width:100%;padding:10px;border:1px solid #ccc;border-radius:10px;margin:6px 0 20px;box-sizing:border-box;font-size:14px;">
    <button onclick="startChat()" style="width:100%;padding:12px;background:#1976d2;color:white;border:none;border-radius:10px;font-size:15px;cursor:pointer;">Start Chat →</button>
  </div>
</div>

<!-- شاشة المحادثة (مخفية في البداية) -->
<div id="chatScreen" style="flex:1;display:none;flex-direction:column;overflow:hidden;">
  <div class="chat" id="chat"></div>
  <div class="inputBox">
    <input id="msg" placeholder="Type message...">
    <button onclick="send()">Send</button>
  </div>
</div>

<script>
let user = JSON.parse(localStorage.getItem("user"));

function goBack(){
window.location.href = "/support";
}

function startChat(){
  let storeName = document.getElementById("inputStoreName").value.trim();
  let mobile = document.getElementById("inputMobile").value.trim();
  if(!storeName || !mobile){
    alert("Please fill in all fields");
    return;
  }
  // حفظ البيانات
  localStorage.setItem("livechat_storeName", storeName);
  localStorage.setItem("livechat_mobile", mobile);
  // إخفاء شاشة البيانات وإظهار المحادثة
  document.getElementById("infoScreen").style.display = "none";
  document.getElementById("chatScreen").style.display = "flex";
  // إرسال رسالة تعريفية تلقائية
  fetch("/send-message", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({
      email: user.email,
      text: "Store Name: " + storeName + " | Mobile: " + mobile,
      sender: "user"
    })
  }).then(()=>{ loadMessages(); });
  setInterval(loadMessages, 2000);
  loadMessages();
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

/* STICKY HEADER */
.sticky-top{
  position:relative;
}

/* HEADER */
.header{
  background:#1976d2;
  padding:12px 15px;
  display:flex;
  align-items:center;
  justify-content:space-between;
}
.store-name-title{font-weight:bold;font-size:15px;flex:1;text-align:center;color:white;}
.back-btn{display:inline-flex;align-items:center;cursor:pointer;padding:4px;}
.heart-top{font-size:24px;cursor:pointer;padding:4px;transition:transform 0.2s;line-height:1;color:white;}

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
         fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
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

  // الشعار المحدّث - السيرفر هو المصدر الرئيسي
  var serverLogo = store.storeLogo || "";
  var localLogo  = localStorage.getItem("merchant_storeLogo_" + sEmail) || "";
  var updatedLogo = serverLogo || localLogo;
  if(updatedLogo && updatedLogo.length > 10){
    document.getElementById("storeLogo").src = updatedLogo;
    // مزامنة المحلي مع السيرفر
    if(serverLogo && serverLogo.length > 10){
      localStorage.setItem("merchant_storeLogo_" + sEmail, serverLogo);
    }
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
\n// جلب مستوى VIP الحقيقي من السيرفر
if(sEmail){
  fetch("/store-vip/" + encodeURIComponent(sEmail))
    .then(function(r){ return r.json(); })
    .then(function(d){
      document.getElementById("vipLevel").innerText = d.vipLevel || 0;
    }).catch(function(){});
}

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

// ======= تحميل المنتجات الحقيقية من متجر البائع =======
var CLOUD_SP = "https://res.cloudinary.com/doabtbdsh/image/upload/products";
var CAT_MAP_SP = {17:"17_Clothing_and_Accessories",19:"19_Medical_Bags_and_Sunglasses",20:"20_Shoes",21:"21_Watches",22:"22_Jewelry",27:"27_Electronics",28:"28_Smart_Home",31:"31_Luxury_Brands",32:"32_Beauty_and_Personal_Care",34:"34_Mens_Fashion",35:"35_Health_and_Household",36:"36_Home_and_Kitchen"};

function getStoreImg(p){
  var cat = CAT_MAP_SP[p.category_id]||"27_Electronics";
  var img = (p.images&&p.images.length>0)?p.images[0]:"1.jpg";
  return CLOUD_SP+"/"+cat+"/"+p.folder+"/"+img;
}

function loadStoreProducts(){
  if(!sEmail){ document.getElementById("productGrid").innerHTML="<div class='loading'>No store selected</div>"; return; }
  fetch("/store-products/"+encodeURIComponent(sEmail))
  .then(function(r){ return r.json(); })
  .then(function(d){
    var products = d.products||[];
    document.getElementById("productCount").innerText = products.length;

    var grid = document.getElementById("productGrid");
    if(products.length===0){
      grid.innerHTML="<div class='loading'>No products yet</div>";
      return;
    }
    grid.innerHTML="";
    products.forEach(function(p){
      var card = document.createElement("div");
      card.className = "pcard";

      var img = document.createElement("img");
      img.src = getStoreImg(p);
      img.alt = p.title;
      img.onerror = function(){ this.src="https://via.placeholder.com/150x150?text=Product"; };
      img.loading = "lazy";

      var info = document.createElement("div");
      info.className = "pcard-info";
      info.innerHTML =
        "<p class='pcard-name'>"+(p.title||"")+"</p>"+
        "<p class='pcard-price'>US$"+parseFloat(p.price).toFixed(2)+"</p>";

      card.appendChild(img);
      card.appendChild(info);

      card.onclick = function(){
        localStorage.setItem("storeProduct", JSON.stringify(p));
        localStorage.setItem("storeOwnerEmail", sEmail);
        localStorage.setItem("storeOwnerName", sName);
        window.location.href = "/store-product-detail";
      };
      grid.appendChild(card);
    });
  })
  .catch(function(){
    document.getElementById("productGrid").innerHTML="<div class='loading'>Could not load products</div>";
  });
}
loadStoreProducts();
<\/script>

</body>
</html>`);
});

// ================= STORE PRODUCT DETAIL PAGE =================
app.get("/store-product-detail", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta charset="UTF-8">
<title>Product - TikTok Mall</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;padding-bottom:90px;}

/* HEADER */
.header{background:#1976d2;padding:11px 15px;display:flex;justify-content:space-between;align-items:center;}
.h-left{display:flex;align-items:center;gap:14px;}
.h-right{display:flex;align-items:center;gap:14px;}
.h-icon{cursor:pointer;display:inline-flex;align-items:center;}

/* SLIDER */
.slider-wrap{background:white;position:relative;overflow:hidden;height:310px;}
.slider-imgs{display:flex;height:100%;transition:transform 0.4s ease;}
.slider-img{min-width:100%;height:310px;object-fit:contain;display:block;background:white;}
.slide-arrow{position:absolute;top:50%;transform:translateY(-50%);background:rgba(0,0,0,0.18);color:white;border:none;width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:10;font-size:18px;}
.slide-arrow.left{left:8px;}.slide-arrow.right{right:8px;}

/* HEART & SHARE overlay on slider */
.slider-overlay{position:relative;}
.heart-btn{position:absolute;top:10px;left:12px;z-index:20;background:none;border:none;cursor:pointer;font-size:22px;line-height:1;}
.share-btn{position:absolute;top:10px;right:12px;z-index:20;background:none;border:none;cursor:pointer;font-size:20px;color:#555;}

/* THUMBS */
.thumbs{display:flex;gap:7px;padding:8px 14px;background:white;overflow-x:auto;border-bottom:1px solid #f0f0f0;}
.thumb{width:54px;height:54px;object-fit:cover;border-radius:8px;border:2px solid #eee;cursor:pointer;flex-shrink:0;}
.thumb.active{border-color:#1976d2;}
.slider-dots{display:flex;justify-content:center;gap:5px;padding:6px 0 4px;background:white;}
.dot{width:6px;height:6px;border-radius:50%;background:#ddd;cursor:pointer;transition:all 0.2s;}
.dot.active{background:#1976d2;transform:scale(1.3);}

/* PRICE & INFO */
.info-card{background:white;margin:8px 0 0;padding:14px 15px 14px;}
.product-price{color:#e53935;font-size:26px;font-weight:800;margin-bottom:8px;}
.product-title{font-size:14px;color:#333;line-height:1.55;margin-bottom:10px;}
.badges{display:flex;gap:7px;flex-wrap:wrap;}
.badge{font-size:11px;padding:4px 10px;border-radius:20px;font-weight:600;}
.badge.green{background:#f0faf4;color:#2e7d32;border:1px solid #c8e6c9;}
.badge.star{background:#fffde7;color:#f57f17;border:1px solid #fff9c4;display:flex;align-items:center;gap:3px;}

/* STORE CARD */
.store-card{background:white;margin-top:8px;padding:14px 15px;display:flex;align-items:center;gap:12px;cursor:pointer;}
.store-logo{width:50px;height:50px;border-radius:12px;object-fit:cover;border:1px solid #eee;flex-shrink:0;}
.store-info{flex:1;min-width:0;}
.store-name{font-size:14px;font-weight:700;color:#1a1a1a;}
.store-meta{font-size:12px;color:#888;margin-top:1px;}
.store-vip{background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;display:inline-flex;align-items:center;gap:3px;margin-top:4px;}
.store-tags{display:flex;gap:8px;margin-top:4px;flex-wrap:wrap;}
.store-tag{background:#f5f5f5;font-size:11px;color:#555;padding:2px 8px;border-radius:8px;}
.store-arrow{color:#bbb;font-size:20px;flex-shrink:0;}

/* SPECS */
.specs-card{background:white;margin-top:8px;}
.spec-row{display:flex;justify-content:space-between;padding:12px 15px;border-bottom:1px solid #f5f5f5;font-size:13px;}
.spec-key{color:#999;}
.spec-val{color:#333;font-weight:600;}

/* BOTTOM BAR */
.bottom-bar{position:fixed;bottom:0;left:0;right:0;background:white;padding:10px 14px 14px;border-top:1px solid #eee;display:flex;align-items:center;gap:8px;box-shadow:0 -2px 12px rgba(0,0,0,0.07);}
.bar-icon{width:36px;height:36px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;color:#555;}
.cart-btn{flex:1;padding:13px;border:1.5px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;font-weight:700;cursor:pointer;}
.buy-btn{flex:2;padding:13px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;font-weight:700;cursor:pointer;}
.buy-btn:active,.cart-btn:active{opacity:0.85;}

/* BUY SHEET */
.sheet-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:400;}
.sheet-overlay.open{display:block;}
.buy-sheet{position:fixed;bottom:0;left:0;right:0;background:white;border-radius:20px 20px 0 0;z-index:500;padding:0 0 24px;transform:translateY(100%);transition:transform 0.35s cubic-bezier(0.4,0,0.2,1);max-height:80vh;overflow-y:auto;}
.buy-sheet.open{transform:translateY(0);}
.sheet-handle{width:36px;height:4px;background:#e0e0e0;border-radius:2px;margin:14px auto 0;}
.sheet-product-row{display:flex;gap:12px;padding:16px 16px 12px;border-bottom:1px solid #f5f5f5;}
.sheet-img{width:80px;height:80px;border-radius:10px;object-fit:cover;border:1px solid #eee;flex-shrink:0;}
.sheet-product-info{flex:1;}
.sheet-price{color:#e53935;font-size:20px;font-weight:800;margin-bottom:4px;}
.sheet-title{font-size:12px;color:#666;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}
.sheet-stock{font-size:11px;color:#999;margin-top:4px;}

/* QTY */
.qty-row{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid #f5f5f5;}
.qty-label{font-size:14px;color:#333;font-weight:600;}
.qty-controls{display:flex;align-items:center;gap:0;}
.qty-btn{width:34px;height:34px;border:1.5px solid #e0e0e0;background:white;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;color:#333;font-weight:300;}
.qty-btn:first-child{border-radius:8px 0 0 8px;}
.qty-btn:last-child{border-radius:0 8px 8px 0;}
.qty-num{width:44px;height:34px;border-top:1.5px solid #e0e0e0;border-bottom:1.5px solid #e0e0e0;border-left:none;border-right:none;text-align:center;font-size:15px;font-weight:700;color:#1a1a1a;display:flex;align-items:center;justify-content:center;}

/* SHEET BUTTONS */
.sheet-btns{display:flex;gap:10px;padding:16px 16px 0;}
.sheet-cart{flex:1;padding:14px;border:1.5px solid #1976d2;border-radius:12px;background:white;color:#1976d2;font-size:14px;font-weight:700;cursor:pointer;}
.sheet-buy{flex:2;padding:14px;border:none;border-radius:12px;background:#1976d2;color:white;font-size:14px;font-weight:700;cursor:pointer;}

/* TOAST */
.toast{position:fixed;bottom:110px;left:50%;transform:translateX(-50%);background:#323232;color:white;padding:10px 22px;border-radius:25px;font-size:13px;font-weight:600;z-index:1000;display:none;white-space:nowrap;}
.toast.show{display:block;animation:fadeUp 0.3s ease;}
@keyframes fadeUp{from{opacity:0;transform:translate(-50%,15px);}to{opacity:1;transform:translate(-50%,0);}}
</style>
</head>
<body>

<div class="header">
  <div class="h-left">
    <span class="h-icon" onclick="history.back()"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span class="h-icon" onclick="window.location.href='/dashboard'"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  </div>
  <div class="h-right">
    <span class="h-icon" onclick="window.location.href='/dashboard?search=1'"><svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span class="h-icon" onclick="window.location.href='/dashboard?messages=1'"><svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span class="h-icon" onclick="window.location.href='/dashboard?account=1'"><svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
  </div>
</div>

<!-- SLIDER + HEART + SHARE -->
<div class="slider-overlay">
  <button class="heart-btn" id="heartBtn" onclick="toggleHeart()">🤍</button>
  <button class="share-btn" onclick="shareProduct()">
    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
  </button>
  <div class="slider-wrap">
    <div class="slider-imgs" id="sliderImgs"></div>
    <button class="slide-arrow left" onclick="slide(-1)">&#8249;</button>
    <button class="slide-arrow right" onclick="slide(1)">&#8250;</button>
  </div>
</div>
<div class="thumbs" id="thumbsRow"></div>
<div class="slider-dots" id="sliderDots"></div>

<!-- INFO -->
<div class="info-card">
  <div class="product-price" id="productPrice">—</div>
  <div class="product-title" id="productTitle">Loading...</div>
  <div class="badges">
    <span class="badge green">Free Shipping</span>
    <span class="badge green">Free Return</span>
    <span class="badge star">⭐ 5.0</span>
  </div>
</div>

<!-- STORE CARD -->
<div class="store-card" onclick="window.location.href='/store-page'">
  <img class="store-logo" id="storeLogo" src="https://cdn-icons-png.flaticon.com/512/149/149071.png" onerror="this.src='https://cdn-icons-png.flaticon.com/512/149/149071.png'">
  <div class="store-info">
    <div class="store-name" id="storeName">Store</div>
    <div class="store-meta" id="storeMeta">Official Store</div>
    <span class="store-vip" id="storeVip">✓ VIP 0</span>
    <div class="store-tags" id="storeTags"></div>
  </div>
  <span class="store-arrow">›</span>
</div>

<!-- SPECS -->
<div class="specs-card">
  <div class="spec-row"><span class="spec-key">Shipping</span><span class="spec-val">Free</span></div>
  <div class="spec-row"><span class="spec-key">Guarantee</span><span class="spec-val">Free return</span></div>
  <div class="spec-row"><span class="spec-key">Sales</span><span class="spec-val" id="specSales">0</span></div>
</div>

<!-- BOTTOM BAR -->
<div class="bottom-bar">
  <div class="bar-icon" onclick="window.location.href='/live-chat'">
    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3z"/><path d="M3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/></svg>
  </div>
  <div class="bar-icon" onclick="openSheet('cart')">
    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/></svg>
  </div>
  <button class="cart-btn" onclick="openSheet('cart')">Add to Cart</button>
  <button class="buy-btn" onclick="openSheet('buy')">Buy Now</button>
</div>

<!-- BUY/CART SHEET -->
<div class="sheet-overlay" id="sheetOverlay" onclick="closeSheet()"></div>
<div class="buy-sheet" id="buySheet">
  <div class="sheet-handle"></div>
  <div class="sheet-product-row">
    <img class="sheet-img" id="sheetImg" src="">
    <div class="sheet-product-info">
      <div class="sheet-price" id="sheetPrice">—</div>
      <div class="sheet-title" id="sheetTitle">—</div>
      <div class="sheet-stock">In Stock</div>
    </div>
  </div>
  <div class="qty-row">
    <span class="qty-label">Quantity</span>
    <div style="display:flex;align-items:center;gap:12px;">
      <span class="sheet-total-price" id="sheetTotalPrice" style="color:#e65100;font-size:15px;font-weight:700;"></span>
      <div class="qty-controls">
        <button class="qty-btn" onclick="changeQty(-1)">−</button>
        <div class="qty-num" id="qtyNum">1</div>
        <button class="qty-btn" onclick="changeQty(1)">+</button>
      </div>
    </div>
  </div>
  <div class="sheet-btns">
    <button class="sheet-cart" id="sheetCartBtn" onclick="doCart()">Add to Cart</button>
    <button class="sheet-buy" id="sheetBuyBtn" onclick="doBuy()">Buy Now</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
var p = JSON.parse(localStorage.getItem("storeProduct")||"null");
var sEmail = localStorage.getItem("storeOwnerEmail")||"";
var sName  = localStorage.getItem("storeOwnerName")||"Store";
var currentSlide = 0, imgs = [], qty = 1, sheetMode = "buy";
var CLOUD = "https://res.cloudinary.com/doabtbdsh/image/upload/products";
var CAT_MAP = {17:"17_Clothing_and_Accessories",19:"19_Medical_Bags_and_Sunglasses",20:"20_Shoes",21:"21_Watches",22:"22_Jewelry",27:"27_Electronics",28:"28_Smart_Home",31:"31_Luxury_Brands",32:"32_Beauty_and_Personal_Care",34:"34_Mens_Fashion",35:"35_Health_and_Household",36:"36_Home_and_Kitchen"};

async function init(){
    if(!p){ document.getElementById("productTitle").innerText="Product not found"; return; }

    // Build images from Cloudinary
    var catF = CAT_MAP[p.category_id]||"27_Electronics";
    imgs = (p.images&&p.images.length>0)
        ? p.images.map(function(i){ return CLOUD+"/"+catF+"/"+p.folder+"/"+i; })
        : [CLOUD+"/"+catF+"/"+(p.folder||"")+"/1.jpg"];

    buildSlider();

    document.getElementById("productTitle").innerText = p.title||"";
    document.getElementById("productPrice").innerText = "US$"+parseFloat(p.price).toFixed(2);
    document.getElementById("specSales").innerText = p.sales||0;

    // Store info
    document.getElementById("storeName").innerText = sName||"Store";
    document.getElementById("storeMeta").innerText = (p.category_name||"")+" · Official Store";

    // Load store logo & VIP
    try {
        var apps = await fetch("/all-store-applications").then(function(r){return r.json();});
        var store = null;
        for(var i=0;i<apps.length;i++){ if(apps[i].email===sEmail&&apps[i].status==="approved"){store=apps[i];break;} }
        if(store){
            if(store.storeName) document.getElementById("storeName").innerText = store.storeName;
            if(store.storeLogo&&store.storeLogo.length>10) document.getElementById("storeLogo").src = store.storeLogo;
        }
    }catch(e){}

    try {
        var vd = await fetch("/store-vip/"+encodeURIComponent(sEmail)).then(function(r){return r.json();});
        document.getElementById("storeVip").innerText = "✓ VIP "+(vd.vipLevel||0);
        var prods = await fetch("/store-products/"+encodeURIComponent(sEmail)).then(function(r){return r.json();});
        var prodCount = (prods.products||[]).length;
        var followers = Math.floor(Math.abs(sEmail.split("").reduce(function(h,c){return Math.imul(31,h)+c.charCodeAt(0)|0;},0)) % 9800) + 100;
        var tagsEl = document.getElementById("storeTags");
        if(tagsEl){
            tagsEl.innerHTML = '<span class="store-tag">Products '+prodCount+'</span><span class="store-tag">Followers '+followers.toLocaleString()+'</span>';
        }
    }catch(e){}

    // Sheet info

    document.getElementById("sheetImg").src = imgs[0];
    document.getElementById("sheetPrice").innerText = "US$"+parseFloat(p.price).toFixed(2);
    document.getElementById("sheetTitle").innerText = p.title||"";

    setInterval(function(){ slide(1); }, 3500);
}

function buildSlider(){
    var c=document.getElementById("sliderImgs"),th=document.getElementById("thumbsRow"),dt=document.getElementById("sliderDots");
    c.innerHTML=""; th.innerHTML=""; dt.innerHTML="";
    imgs.forEach(function(src,i){
        var img=document.createElement("img"); img.className="slider-img"; img.src=src;
        img.onerror=function(){this.src="https://via.placeholder.com/310x310?text=Product";};
        c.appendChild(img);
        var t=document.createElement("img"); t.className="thumb"+(i===0?" active":""); t.src=src;
        t.onerror=function(){this.src="https://via.placeholder.com/54x54";};
        t.onclick=(function(idx){return function(){goTo(idx);};})(i); th.appendChild(t);
        var d=document.createElement("span"); d.className="dot"+(i===0?" active":"");
        d.onclick=(function(idx){return function(){goTo(idx);};})(i); dt.appendChild(d);
    });
}

var isFav = false;
function toggleHeart(){
    isFav = !isFav;
    document.getElementById("heartBtn").innerText = isFav ? "❤️" : "🤍";
}
function shareProduct(){
    var url = window.location.href;
    if(navigator.clipboard){ navigator.clipboard.writeText(url).catch(function(){}); }
    showToast("✓ Link copied successfully");
}
function slide(dir){ goTo((currentSlide+dir+imgs.length)%imgs.length); }
function goTo(idx){
    currentSlide=idx;
    document.getElementById("sliderImgs").style.transform="translateX(-"+(idx*100)+"%)";
    document.querySelectorAll(".thumb").forEach(function(t,i){t.classList.toggle("active",i===idx);});
    document.querySelectorAll(".dot").forEach(function(d,i){d.classList.toggle("active",i===idx);});
}

function openSheet(mode){
    sheetMode = mode;
    qty = 1; document.getElementById("qtyNum").innerText = 1;
    updateTotalPrice();
    document.getElementById("sheetImg").src = imgs[currentSlide]||imgs[0];
    document.getElementById("buySheet").classList.add("open");
    document.getElementById("sheetOverlay").classList.add("open");
}
function closeSheet(){
    document.getElementById("buySheet").classList.remove("open");
    document.getElementById("sheetOverlay").classList.remove("open");
}
function changeQty(d){ 
    qty = Math.max(1, qty+d); 
    document.getElementById("qtyNum").innerText = qty;
    updateTotalPrice();
}
function updateTotalPrice(){
    var price = p ? (parseFloat(p.p) || parseFloat(p.price) || 0) : 0;
    var total = (price * qty).toFixed(2);
    var el = document.getElementById("sheetTotalPrice");
    if(el) el.innerText = "US$" + total;
}

async function doCart(){
    var cart = JSON.parse(localStorage.getItem("cart")||"[]");
    cart.push({ product:p, qty:qty, sellerEmail:sEmail, addedAt:new Date().toISOString() });
    localStorage.setItem("cart", JSON.stringify(cart));
    closeSheet();
    showToast("🛒 Added to cart (×"+qty+")");
}

async function doBuy(){
    closeSheet();
    var token = localStorage.getItem("token")||"";
    if(!token){ showToast("⚠️ Please login first"); return; }
    var btn = document.getElementById("sheetBuyBtn");
    btn.disabled = true;
    try {
        var r = await fetch("/create-store-order",{
            method:"POST",
            headers:{"Content-Type":"application/json","Authorization":"Bearer "+token},
            body: JSON.stringify({ product:p, sellerEmail:sEmail, quantity:qty })
        });
        var d = await r.json();
        if(d.success){
            showToast("✅ Order placed! (×"+qty+")");
        } else {
            showToast("⚠️ "+(d.message||"Failed"));
        }
    }catch(e){ showToast("⚠️ Network error"); }
    btn.disabled = false;
}

function showToast(msg){
    var t=document.getElementById("toast"); t.innerText=msg;
    t.classList.add("show"); setTimeout(function(){t.classList.remove("show");},3000);
}

init();
</script>
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
body{font-family:Arial;background:#f5f5f5;padding-bottom:80px;min-height:100vh;}
/* HEADER */
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:relative;}
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
var sProducts    = 20 + (sid % 480);
var sFollowers   = (sid * 7) % 9800;
document.getElementById("storeName").innerText     = sName;
document.getElementById("storeLogo").src           = sAvatar;
document.getElementById("storeProducts").innerText   = "Products " + sProducts;
document.getElementById("storeFollowers").innerText  = "Followers " + sFollowers.toLocaleString();

// جلب VIP الحقيقي من السيرفر إذا كان المتجر معروفاً
(function(){
  var storeEmail = localStorage.getItem("viewStoreEmail") || "";
  if(storeEmail){
    fetch("/store-vip/" + encodeURIComponent(storeEmail))
      .then(function(r){ return r.json(); })
      .then(function(d){
        document.getElementById("storeVip").innerHTML = "&#10004; VIP " + (d.vipLevel || 0);
      })
      .catch(function(){ document.getElementById("storeVip").innerHTML = "&#10004; VIP 0"; });
  } else {
    document.getElementById("storeVip").innerHTML = "&#10004; VIP 0";
  }
})();
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


// =====================================================================
// =================== LISTINGS & STORE SYSTEM =========================
// =====================================================================

// ---- بيانات منتجات البائعين (في الذاكرة) ----
let sellerProducts = {}; // { email: [ {productId, categoryId, addedAt, ...}, ... ] }
let storeOrders = [];    // طلبات المتجر

try {
    const sp = fs.readFileSync("sellerProducts.json");
    sellerProducts = JSON.parse(sp);
} catch(e){ sellerProducts = {}; }

try {
    const so = fs.readFileSync("storeOrders.json");
    storeOrders = JSON.parse(so);
} catch(e){ storeOrders = []; }

function saveSellerProducts(){
    try { fs.writeFileSync("sellerProducts.json", JSON.stringify(sellerProducts, null, 2)); } catch(e){}
    if(db) {
        Object.entries(sellerProducts).forEach(([email, prods]) => {
            db.collection("sellerProducts").updateOne({ email }, { $set: { email, products: prods } }, { upsert: true })
              .catch(()=>{});
        });
    }
}

function saveStoreOrders(){
    try { fs.writeFileSync("storeOrders.json", JSON.stringify(storeOrders, null, 2)); } catch(e){}
    if(db){
        storeOrders.forEach(o => {
            db.collection("storeOrders").updateOne({ id: o.id }, { $set: o }, { upsert: true }).catch(()=>{});
        });
    }
}

// ---- نسب العمولة حسب VIP ----
const VIP_COMMISSION = [15, 17, 20, 22, 25, 40];
const VIP_PRODUCTS   = [20, 35, 80, 120, 300, 1000];

// ---- API: جلب منتجات البائع ----
app.get("/my-seller-products", authMiddleware, (req, res) => {
    const email = req.userEmail;
    const prods = sellerProducts[email] || [];
    res.json({ success: true, products: prods });
});

// ---- API: إضافة منتج للمتجر ----
app.post("/add-seller-product", authMiddleware, (req, res) => {
    const email = req.userEmail;
    const { product } = req.body;
    if(!product || !product.id) return res.json({ success: false, message: "Invalid product" });

    const user = users.find(u => u.email === email);
    const vipLevel = user ? (user.vipLevel || 0) : 0;
    const maxProducts = VIP_PRODUCTS[vipLevel] || 20;

    if(!sellerProducts[email]) sellerProducts[email] = [];
    const current = sellerProducts[email];

    // تحقق من التكرار
    if(current.find(p => p.id === product.id)){
        return res.json({ success: false, message: "Product already in your store" });
    }

    // تحقق من الحد الأقصى
    if(current.length >= maxProducts){
        return res.json({ success: false, message: `VIP ${vipLevel} limit is ${maxProducts} products` });
    }

    current.push({ ...product, addedAt: new Date().toISOString() });
    saveSellerProducts();
    res.json({ success: true, count: current.length });
});

// ---- API: حذف منتج من المتجر ----
app.post("/remove-seller-product", authMiddleware, (req, res) => {
    const email = req.userEmail;
    const { productId } = req.body;
    if(!sellerProducts[email]) return res.json({ success: false });
    sellerProducts[email] = sellerProducts[email].filter(p => p.id != productId);
    saveSellerProducts();
    res.json({ success: true });
});

// ---- API: جلب منتجات متجر معين (للزوار) ----
app.get("/store-products/:email", (req, res) => {
    const prods = sellerProducts[req.params.email] || [];
    res.json({ success: true, products: prods });
});

// ---- API: إنشاء طلب جديد ----
app.post("/create-store-order", authMiddleware, (req, res) => {
    const buyerEmail = req.userEmail;
    const { product, sellerEmail, quantity } = req.body;
    if(!product || !sellerEmail) return res.json({ success: false, message: "Missing data" });

    const buyer = users.find(u => u.email === buyerEmail);
    if(!buyer) return res.json({ success: false, message: "User not found" });

    const price = parseFloat(product.price) || 0;
    const total = price * (parseInt(quantity) || 1);

    if((parseFloat(buyer.balance) || 0) < total){
        return res.json({ success: false, message: "Insufficient balance" });
    }

    // خصم الرصيد من المشتري
    buyer.balance = ((parseFloat(buyer.balance) || 0) - total).toFixed(2);
    saveUsers();

    const seller = users.find(u => u.email === sellerEmail);
    const vipLevel = seller ? (seller.vipLevel || 0) : 0;
    const commissionPct = VIP_COMMISSION[vipLevel] || 15;
    const supplierPrice = parseFloat((price * (1 - commissionPct / 100)).toFixed(2));
    const profit = parseFloat((price - supplierPrice).toFixed(2));

    // طلب واحد فقط بالكمية المطلوبة
    const qty = parseInt(quantity) || 1;
    const order = {
        id: String(Date.now()).slice(-11).padStart(11,'0'),
        buyerEmail,
        sellerEmail,
        product: {
            id: product.id,
            title: product.title,
            price: price,
            image: product.images ? product.images[0] : "",
            folder: product.folder || "",
            category_id: product.category_id || 0
        },
        quantity: qty,
        total: parseFloat((price * qty).toFixed(2)),
        supplierPrice: parseFloat((supplierPrice * qty).toFixed(2)),
        profit: parseFloat((profit * qty).toFixed(2)),
        status: "waiting_shipping",
        createdAt: new Date().toISOString(),
        shippedAt: null,
        deliveryStart: null,
        completedAt: null,
        shippingCountdown: 48 * 60 * 60 * 1000,
        trackingPath: generateTrackingPath()
    };
    storeOrders.push(order);
    saveStoreOrders();
    res.json({ success: true, order: order, orders: [order] });
});

function generateTrackingPath(){
    const origins = [
        { name: "Shanghai", lat: 31.2304, lng: 121.4737 },
        { name: "Shenzhen", lat: 22.5431, lng: 114.0579 },
        { name: "Guangzhou", lat: 23.1291, lng: 113.2644 },
        { name: "Beijing", lat: 39.9042, lng: 116.4074 },
        { name: "Hong Kong", lat: 22.3193, lng: 114.1694 }
    ];
    const destinations = [
        { name: "New York", lat: 40.7128, lng: -74.0060 },
        { name: "London", lat: 51.5074, lng: -0.1278 },
        { name: "Dubai", lat: 25.2048, lng: 55.2708 },
        { name: "Paris", lat: 48.8566, lng: 2.3522 },
        { name: "Sydney", lat: -33.8688, lng: 151.2093 },
        { name: "Toronto", lat: 43.6532, lng: -79.3832 },
        { name: "Singapore", lat: 1.3521, lng: 103.8198 },
        { name: "Cairo", lat: 30.0444, lng: 31.2357 },
        { name: "Riyadh", lat: 24.7136, lng: 46.6753 },
        { name: "Istanbul", lat: 41.0082, lng: 28.9784 }
    ];
    const origin = origins[Math.floor(Math.random() * origins.length)];
    const dest   = destinations[Math.floor(Math.random() * destinations.length)];
    // نقطة وسيطة عشوائية
    const midLat = (origin.lat + dest.lat) / 2 + (Math.random() - 0.5) * 20;
    const midLng = (origin.lng + dest.lng) / 2 + (Math.random() - 0.5) * 30;
    return { origin, destination: dest, midpoint: { lat: midLat, lng: midLng } };
}

// ---- API: شحن طلب ----
app.post("/ship-store-order", authMiddleware, (req, res) => {
    const email = req.userEmail;
    const { orderId } = req.body;
    const order = storeOrders.find(o => o.id === orderId && o.sellerEmail === email);
    if(!order) return res.json({ success: false, message: "Order not found" });
    if(order.status !== "waiting_shipping") return res.json({ success: false, message: "Already shipped" });

    const seller = users.find(u => u.email === email);
    if(!seller) return res.json({ success: false, message: "Seller not found" });

    // خصم سعر المورد من رصيد البائع
    const supplierCost = order.supplierPrice * order.quantity;
    if((parseFloat(seller.balance) || 0) < supplierCost){
        return res.json({ success: false, message: "Insufficient balance to ship" });
    }
    seller.balance = ((parseFloat(seller.balance) || 0) - supplierCost).toFixed(2);
    saveUsers();

    order.status = "in_delivery";
    order.shippedAt = new Date().toISOString();
    order.deliveryStart = Date.now();
    saveStoreOrders();
    res.json({ success: true, order });
});

// ---- API: تأكيد استلام (أدمن فقط) ----
app.post("/confirm-store-delivery", adminMiddleware, (req, res) => {
    const { orderId } = req.body;
    const order = storeOrders.find(o => o.id === orderId);
    if(!order) return res.json({ success: false, message: "Order not found" });
    if(order.status !== "waiting_refund") return res.json({ success: false, message: "Not ready for confirmation" });

    const seller = users.find(u => u.email === order.sellerEmail);
    if(seller){
        const refund = (order.supplierPrice * order.quantity) + (order.profit * order.quantity);
        seller.balance = ((parseFloat(seller.balance) || 0) + refund).toFixed(2);
        // Total working capital: أضف الربح فقط
        if(!seller.totalCapital) seller.totalCapital = parseFloat(seller.balance) || 0;
        seller.totalCapital = ((parseFloat(seller.totalCapital) || 0) + (order.profit * order.quantity)).toFixed(2);
        // profit today
        const today = new Date().toDateString();
        if(!seller.profitToday || seller.profitTodayDate !== today){
            seller.profitToday = 0;
            seller.profitTodayDate = today;
        }
        seller.profitToday = ((parseFloat(seller.profitToday) || 0) + (order.profit * order.quantity)).toFixed(2);
        // total profit credited
        seller.totalProfitCredited = ((parseFloat(seller.totalProfitCredited) || 0) + (order.profit * order.quantity)).toFixed(2);
        // turnover
        seller.turnover = ((parseFloat(seller.turnover) || 0) + order.total).toFixed(2);
        // number of orders
        seller.orderCount = (parseInt(seller.orderCount) || 0) + 1;
        // credential rating (عشوائي بين 3-5 نجوم)
        if(!seller.credentialRating) seller.credentialRating = 0;
        const ratingDelta = (Math.random() * 0.5).toFixed(1);
        seller.credentialRating = Math.min(5, ((parseFloat(seller.credentialRating) || 0) + parseFloat(ratingDelta))).toFixed(1);
        saveUsers();
    }

    order.status = "completed";
    order.completedAt = new Date().toISOString();
    saveStoreOrders();
    res.json({ success: true });
});

// ---- API: إنشاء طلب يدوياً من الأدمن في نظام storeOrders ----
app.post("/admin-create-store-order", adminMiddleware, (req, res) => {
    const order = req.body;
    if(!order || !order.sellerEmail || !order.id){
        return res.json({ success: false, message: "Missing data" });
    }
    // تأكد من وجود trackingPath
    if(!order.trackingPath) order.trackingPath = generateTrackingPath();
    storeOrders.push(order);
    saveStoreOrders();
    res.json({ success: true, order });
});

// ---- API: تحديث حالة الطلبات تلقائياً (cron-like) ----
// كل دقيقة نتحقق هل انتهت مدة التوصيل (3 أيام = 72 ساعة)
setInterval(() => {
    const now = Date.now();
    let changed = false;
    storeOrders.forEach(order => {
        if(order.status === "in_delivery" && order.deliveryStart){
            const elapsed = now - order.deliveryStart;
            if(elapsed >= 72 * 60 * 60 * 1000){ // 3 days
                order.status = "waiting_refund";
                changed = true;
            }
        }
    });
    if(changed) saveStoreOrders();
}, 60 * 1000);

// ---- API: جلب طلبات البائع ----
app.get("/my-store-orders", authMiddleware, async (req, res) => {
    const email = req.userEmail;

    // أولاً: ابحث في الذاكرة
    let orders = storeOrders.filter(o => o.sellerEmail === email);

    // إذا الذاكرة فارغة، اقرأ من MongoDB مباشرة
    if(orders.length === 0 && db){
        try {
            const fromDB = await db.collection("storeOrders").find({ sellerEmail: email }).toArray();
            if(fromDB.length > 0){
                orders = fromDB.map(o => { delete o._id; return o; });
                // حدّث الذاكرة
                orders.forEach(o => {
                    if(!storeOrders.find(x => x.id === o.id)){
                        storeOrders.push(o);
                    }
                });
            }
        } catch(e){ console.error("DB query error:", e.message); }
    }

    res.json({ success: true, orders });
});

// ---- API: جلب طلبات البائع بالإيميل مباشرة (fallback) ----
app.get("/store-orders-by-email/:email", async (req, res) => {
    const email = decodeURIComponent(req.params.email);
    if(!email) return res.json({ success: false, orders: [] });

    // أولاً: ابحث في الذاكرة
    let orders = storeOrders.filter(o => o.sellerEmail === email);

    // إذا الذاكرة فارغة، اقرأ من MongoDB مباشرة
    if(orders.length === 0 && db){
        try {
            const fromDB = await db.collection("storeOrders").find({ sellerEmail: email }).toArray();
            if(fromDB.length > 0){
                orders = fromDB.map(o => { delete o._id; return o; });
                // حدّث الذاكرة
                fromDB.forEach(o => {
                    delete o._id;
                    if(!storeOrders.find(x => x.id === o.id)){
                        storeOrders.push(o);
                    }
                });
            }
        } catch(e){ console.error("DB query error:", e.message); }
    }

    res.json({ success: true, orders });
});

// ---- API: جلب طلبات المشتري ----
app.get("/my-purchases", authMiddleware, (req, res) => {
    const email = req.userEmail;
    const orders = storeOrders.filter(o => o.buyerEmail === email);
    res.json({ success: true, orders });
});

// ---- API: إضافة للسلة ----
// السلة محلية في localStorage - لا نحتاج API

// ---- API: معلومات داشبورد البائع ----
app.get("/seller-dashboard-stats", authMiddleware, async (req, res) => {
    const email = req.userEmail;
    const user = users.find(u => u.email === email);
    if(!user) return res.json({ success: false });

    // أولاً: ابحث في الذاكرة
    let myOrders = storeOrders.filter(o => o.sellerEmail === email);

    // إذا الذاكرة فارغة، اقرأ من MongoDB مباشرة
    if(myOrders.length === 0 && db){
        try {
            const fromDB = await db.collection("storeOrders").find({ sellerEmail: email }).toArray();
            if(fromDB.length > 0){
                myOrders = fromDB.map(o => { delete o._id; return o; });
                myOrders.forEach(o => {
                    if(!storeOrders.find(x => x.id === o.id)){
                        storeOrders.push(o);
                    }
                });
            }
        } catch(e){}
    }

    const today = new Date().toDateString();

    // إعادة تعيين profitToday إذا تغير اليوم
    if(user.profitTodayDate !== today){
        user.profitToday = 0;
        user.profitTodayDate = today;
        saveUsers();
    }

    res.json({
        success: true,
        productsForSale: (sellerProducts[email] || []).length,
        numberOfOrders: myOrders.length,
        turnover: parseFloat(user.turnover) || 0,
        credentialRating: parseFloat(user.credentialRating) || 0,
        waitingShipping: myOrders.filter(o => o.status === "waiting_shipping").length,
        waitingDelivery: myOrders.filter(o => o.status === "in_delivery").length,
        waitingRefund: myOrders.filter(o => o.status === "waiting_refund").length,
        waitingPayment: 0,
        availableBalance: parseFloat(user.balance) || 0,
        totalWorkingCapital: parseFloat(user.totalCapital) || parseFloat(user.balance) || 0,
        profitOfDay: parseFloat(user.profitToday) || 0,
        totalProfitCredited: parseFloat(user.totalProfitCredited) || 0,
        vipLevel: user.vipLevel || 0
    });
});

// ---- API: تحديث إعدادات المتجر (اسم + صورة) ----
app.post("/update-store-settings", authMiddleware, (req, res) => {
    const email = req.userEmail;
    const { storeName, storeLogo } = req.body;
    const appl = storeApplications.find(a => a.email === email && a.status === "approved");
    if(!appl) return res.json({ success: false, message: "Store not found" });
    if(storeName) appl.storeName = storeName;
    if(storeLogo) appl.storeLogo = storeLogo;
    saveStoreApplications();
    res.json({ success: true });
});

// ---- API: تحديث حالة طلب يدوياً من الأدمن ----
app.post("/admin-update-order-status", adminMiddleware, (req, res) => {
    const { orderId, status } = req.body;
    const order = storeOrders.find(o => o.id === orderId);
    if(!order) return res.json({ success: false, message: "Order not found" });

    const oldStatus = order.status;
    order.status = status;

    // إذا انتقل الطلب إلى completed → أعِد المبلغ + الربح للبائع
    if(status === "completed" && oldStatus !== "completed"){
        const seller = users.find(u => u.email === order.sellerEmail);
        if(seller){
            const refund = (order.supplierPrice * order.quantity) + (order.profit * order.quantity);
            seller.balance = ((parseFloat(seller.balance) || 0) + refund).toFixed(2);
            const today = new Date().toDateString();
            if(!seller.profitToday || seller.profitTodayDate !== today){
                seller.profitToday = 0;
                seller.profitTodayDate = today;
            }
            seller.profitToday = ((parseFloat(seller.profitToday) || 0) + (order.profit * order.quantity)).toFixed(2);
            seller.totalProfitCredited = ((parseFloat(seller.totalProfitCredited) || 0) + (order.profit * order.quantity)).toFixed(2);
            seller.turnover = ((parseFloat(seller.turnover) || 0) + order.total).toFixed(2);
            seller.orderCount = (parseInt(seller.orderCount) || 0) + 1;
            if(!seller.totalCapital) seller.totalCapital = parseFloat(seller.balance) || 0;
            seller.totalCapital = ((parseFloat(seller.totalCapital) || 0) + (order.profit * order.quantity)).toFixed(2);
            saveUsers();
        }
        order.completedAt = new Date().toISOString();
    }

    if(status === "in_delivery" && !order.deliveryStart){
        order.deliveryStart = Date.now();
        order.shippedAt = new Date().toISOString();
    }

    saveStoreOrders();
    res.json({ success: true, order });
});

// ---- API: جلب كل الطلبات للأدمن ----
app.get("/admin-store-orders", adminMiddleware, (req, res) => {
    res.json({ success: true, orders: storeOrders });
});



// =================== LISTINGS PAGE ===================
app.get("/listings", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta charset="UTF-8">
<title>Listings - TikTok Mall</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fb;min-height:100vh;}

/* HEADER */
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:relative;}
.header-left{display:flex;align-items:center;gap:12px;}
.header-right{display:flex;align-items:center;gap:14px;}
.header h2{font-size:16px;font-weight:700;letter-spacing:0.3px;}
.h-icon{cursor:pointer;display:inline-flex;align-items:center;}

/* SORT & FILTER BAR */
.top-bar{display:flex;background:white;border-bottom:1px solid #eee;position:relative;}
.sort-btn,.filter-btn{flex:1;padding:13px;display:flex;align-items:center;justify-content:center;gap:6px;font-size:14px;font-weight:600;color:#333;cursor:pointer;border:none;background:transparent;transition:color 0.2s;}
.sort-btn{border-right:1px solid #eee;}
.sort-btn:hover,.filter-btn:hover{color:#1976d2;}
.sort-arrow{font-size:11px;transition:transform 0.2s;}

/* ITEMS COUNT */
.items-count{text-align:center;padding:10px;font-size:13px;color:#888;background:white;border-bottom:1px solid #f0f0f0;}

/* SORT DROPDOWN */
.sort-dropdown{display:none;position:absolute;top:50px;left:0;right:50%;background:white;box-shadow:0 4px 20px rgba(0,0,0,0.12);z-index:400;border-radius:0 0 12px 12px;overflow:hidden;}
.sort-dropdown.open{display:block;}
.sort-option{padding:16px 20px;font-size:14px;color:#333;cursor:pointer;border-bottom:1px solid #f5f5f5;display:flex;justify-content:space-between;align-items:center;transition:background 0.15s;}
.sort-option:hover{background:#f5f9ff;}
.sort-option.active{color:#1976d2;font-weight:600;}
.price-arrows{display:flex;flex-direction:column;gap:0px;line-height:1;}
.price-arrow{font-size:10px;color:#aaa;cursor:pointer;padding:1px 3px;}
.price-arrow.active-arrow{color:#1976d2;}

/* FILTER PANEL */
.filter-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:500;}
.filter-overlay.open{display:block;}
.filter-panel{position:fixed;top:0;right:0;bottom:0;width:75%;max-width:300px;background:white;z-index:600;overflow-y:auto;transform:translateX(100%);transition:transform 0.3s ease;box-shadow:-4px 0 20px rgba(0,0,0,0.15);}
.filter-panel.open{transform:translateX(0);}
.filter-header{padding:16px;border-bottom:1px solid #eee;font-weight:700;font-size:15px;color:#222;}
.price-range-section{padding:16px;}
.price-range-title{font-size:13px;font-weight:700;color:#333;margin-bottom:12px;}
.price-inputs{display:flex;align-items:center;gap:8px;margin-bottom:12px;}
.price-input{flex:1;border:1px solid #ddd;border-radius:8px;padding:9px 10px;font-size:13px;outline:none;color:#333;}
.price-input:focus{border-color:#1976d2;}
.price-dash{color:#aaa;font-size:16px;}
.price-btns{display:flex;gap:8px;}
.price-clear-btn{flex:1;padding:10px;border:1px solid #ddd;border-radius:8px;background:white;color:#666;font-size:13px;cursor:pointer;font-weight:600;}
.price-confirm-btn{flex:1;padding:10px;border:none;border-radius:8px;background:#1976d2;color:white;font-size:13px;cursor:pointer;font-weight:600;}
.filter-divider{height:8px;background:#f5f5f5;}
.cat-list{padding:0;}
.cat-item{padding:15px 16px;font-size:14px;color:#333;cursor:pointer;border-bottom:1px solid #f5f5f5;display:flex;justify-content:space-between;align-items:center;transition:background 0.15s;}
.cat-item:hover{background:#f5f9ff;}
.cat-item.active{color:#1976d2;font-weight:600;background:#f0f7ff;}

/* PRODUCT GRID */
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:10px 10px 80px;}
.pcard{background:white;border-radius:14px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,0.07);cursor:pointer;transition:transform 0.15s,box-shadow 0.15s;position:relative;}
.pcard:active{transform:scale(0.97);}
.pcard:hover{box-shadow:0 4px 16px rgba(0,0,0,0.12);}
.pcard-img{width:100%;height:150px;object-fit:cover;display:block;background:#f5f5f5;}
.pcard-info{padding:9px 10px 10px;}
.pcard-name{font-size:12px;color:#333;margin:0 0 6px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;min-height:33px;}
.pcard-price{color:#1976d2;font-weight:700;font-size:14px;margin:0 0 8px;}
.sell-now-btn{width:100%;padding:7px;border:none;border-radius:8px;background:#1976d2;color:white;font-size:12px;font-weight:700;cursor:pointer;transition:opacity 0.2s;letter-spacing:0.3px;}
.sell-now-btn:hover{opacity:0.88;}

/* LOADING */
.loading-wrap{text-align:center;padding:60px 20px;grid-column:1/-1;}
@keyframes spin{to{transform:rotate(360deg);}}
.sun-spinner{width:42px;height:42px;margin:0 auto 12px;position:relative;animation:spin 0.8s linear infinite;}
.sun-spinner::before{content:'';display:block;width:100%;height:100%;background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 40 40'%3E%3Ccircle cx='20' cy='20' r='7' fill='%231976d2'/%3E%3Cg stroke='%231976d2' stroke-width='3' stroke-linecap='round'%3E%3Cline x1='20' y1='2' x2='20' y2='8' opacity='1'/%3E%3Cline x1='20' y1='32' x2='20' y2='38' opacity='0.2'/%3E%3Cline x1='2' y1='20' x2='8' y2='20' opacity='0.55'/%3E%3Cline x1='32' y1='20' x2='38' y2='20' opacity='0.35'/%3E%3Cline x1='6.1' y1='6.1' x2='10.4' y2='10.4' opacity='0.9'/%3E%3Cline x1='29.6' y1='29.6' x2='33.9' y2='33.9' opacity='0.15'/%3E%3Cline x1='33.9' y1='6.1' x2='29.6' y2='10.4' opacity='0.7'/%3E%3Cline x1='10.4' y1='29.6' x2='6.1' y2='33.9' opacity='0.45'/%3E%3C/g%3E%3C/svg%3E") no-repeat center/contain;}
.no-results{grid-column:1/-1;text-align:center;padding:60px 20px;color:#aaa;font-size:14px;}

/* SELL NOW POPUP */
.popup-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:700;align-items:flex-end;justify-content:center;}
.popup-overlay.open{display:flex;}
.popup-box{background:white;border-radius:20px 20px 0 0;width:100%;max-width:480px;overflow:hidden;box-shadow:0 -4px 30px rgba(0,0,0,0.15);animation:slideUp 0.3s ease;}
@keyframes slideUp{from{transform:translateY(100%);}to{transform:translateY(0);}}
.popup-handle{width:40px;height:4px;background:#e0e0e0;border-radius:2px;margin:12px auto 0;}
.popup-header{background:white;color:#222;padding:14px 20px 8px;text-align:left;}
.popup-header h3{font-size:15px;font-weight:700;margin:0 0 3px;color:#111;}
.popup-header p{font-size:12px;color:#888;margin:0;}
.popup-body{padding:8px 20px 16px;}
.profit-row{display:flex;justify-content:space-between;align-items:center;padding:14px 0;border-bottom:1px solid #f0f0f0;}
.profit-row:last-child{border-bottom:none;}
.profit-row.supplier{background:transparent;}
.profit-row.retail{background:transparent;}
.profit-row.earn{background:transparent;}
.profit-label{font-size:14px;color:#333;font-weight:400;}
.profit-value{font-size:14px;font-weight:700;}
.profit-row.supplier .profit-value{color:#e65100;}
.profit-row.retail .profit-value{color:#1976d2;}
.profit-row.earn .profit-value{color:#2e7d32;}
.popup-footer{display:flex;gap:10px;padding:0 20px 28px;}
.popup-cancel{flex:1;padding:14px;border:1.5px solid #ddd;border-radius:50px;background:white;color:#333;font-size:14px;cursor:pointer;font-weight:600;}
.popup-ok{flex:2;padding:14px;border:none;border-radius:50px;background:#1976d2;color:white;font-size:14px;cursor:pointer;font-weight:700;}
.popup-ok:active{opacity:0.88;}

/* SUCCESS TOAST */
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#2e7d32;color:white;padding:12px 24px;border-radius:25px;font-size:13px;font-weight:600;z-index:1000;display:none;white-space:nowrap;box-shadow:0 4px 16px rgba(0,0,0,0.2);}
.toast.show{display:block;animation:fadeInUp 0.3s ease;}
@keyframes fadeInUp{from{opacity:0;transform:translate(-50%,20px);}to{opacity:1;transform:translate(-50%,0);}}

/* INFINITE SCROLL */
.load-more{display:none;}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-left">
    <span class="h-icon" onclick="history.back()">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span class="h-icon" onclick="window.location.href='/dashboard'"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  </div>
  <div class="header-right">
    <span class="h-icon" onclick="window.location.href='/dashboard?search=1'">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    </span>
    <span class="h-icon" onclick="window.location.href='/dashboard?messages=1'" style="position:relative;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
    </span>
    <span class="h-icon" onclick="window.location.href='/dashboard?account=1'">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    </span>
    <span class="h-icon" onclick="window.location.href='/dashboard?lang=1'">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
    </span>
  </div>
</div>

<!-- SORT & FILTER BAR -->
<div class="top-bar" style="position:relative;">
  <button class="sort-btn" id="sortBtn" onclick="toggleSort()">
    Sort <span class="sort-arrow" id="sortArrow">▼</span>
  </button>
  <button class="filter-btn" onclick="openFilter()">Filter</button>

  <!-- SORT DROPDOWN -->
  <div class="sort-dropdown" id="sortDropdown">
    <div class="sort-option active" id="sortRec" onclick="setSort('recommendation')">
      Recommendation
    </div>
    <div class="sort-option" id="sortSales" onclick="setSort('sales')">
      Sales
    </div>
    <div class="sort-option" id="sortPrice" onclick="togglePriceSort()">
      Price
      <div class="price-arrows">
        <span class="price-arrow" id="priceUp" onclick="event.stopPropagation();setPriceSort('asc')">▲</span>
        <span class="price-arrow" id="priceDown" onclick="event.stopPropagation();setPriceSort('desc')">▼</span>
      </div>
    </div>
  </div>
</div>

<!-- ITEMS COUNT -->
<div class="items-count" id="itemsCount">Loading...</div>

<!-- PRODUCT GRID -->
<div class="grid" id="productGrid">
  <div class="loading-wrap">
    <div class="sun-spinner"></div>
    <p style="color:#aaa;font-size:13px;">Loading products...</p>
  </div>
</div>

<!-- FILTER OVERLAY & PANEL -->
<div class="filter-overlay" id="filterOverlay" onclick="closeFilter()"></div>
<div class="filter-panel" id="filterPanel">
  <div class="filter-header">Price range</div>
  <div class="price-range-section">
    <div class="price-inputs">
      <input class="price-input" id="priceMin" type="number" placeholder="Lowest p" min="0">
      <span class="price-dash">—</span>
      <input class="price-input" id="priceMax" type="number" placeholder="Highest p" min="0">
    </div>
    <div class="price-btns">
      <button class="price-clear-btn" onclick="clearPriceFilter()">Clear</button>
      <button class="price-confirm-btn" onclick="applyPriceFilter()">Confirm</button>
    </div>
  </div>
  <div class="filter-divider"></div>
  <div class="cat-list" id="catList">
    <div class="cat-item active" data-cat="all" onclick="selectCat(this,'all')">All Categories</div>
    <div class="cat-item" data-cat="28" onclick="selectCat(this,'28')">Smart Home</div>
    <div class="cat-item" data-cat="31" onclick="selectCat(this,'31')">Luxury Brands</div>
    <div class="cat-item" data-cat="32" onclick="selectCat(this,'32')">Beauty and Personal Care</div>
    <div class="cat-item" data-cat="34" onclick="selectCat(this,'34')">Men's Fashion</div>
    <div class="cat-item" data-cat="35" onclick="selectCat(this,'35')">Health and Household</div>
    <div class="cat-item" data-cat="36" onclick="selectCat(this,'36')">Home and Kitchen</div>
    <div class="cat-item" data-cat="17" onclick="selectCat(this,'17')">Clothing & Accessories</div>
    <div class="cat-item" data-cat="19" onclick="selectCat(this,'19')">Medical Bags and Sunglasses</div>
    <div class="cat-item" data-cat="20" onclick="selectCat(this,'20')">Shoes</div>
    <div class="cat-item" data-cat="21" onclick="selectCat(this,'21')">Watches</div>
    <div class="cat-item" data-cat="22" onclick="selectCat(this,'22')">Jewelry</div>
    <div class="cat-item" data-cat="27" onclick="selectCat(this,'27')">Electronics</div>
  </div>
</div>

<!-- SELL NOW POPUP -->
<div class="popup-overlay" id="sellPopup">
  <div class="popup-box">
    <div class="popup-handle"></div>
    <div class="popup-header">
      <h3 id="popupTitle">Add to your store</h3>
      <p id="popupSubtitle">VIP 0 — 15% supplier discount</p>
    </div>
    <div class="popup-body">
      <div class="profit-row supplier">
        <span class="profit-label">Supplier price</span>
        <span class="profit-value" id="popupSupplier">—</span>
      </div>
      <div class="profit-row retail">
        <span class="profit-label">Sell price</span>
        <span class="profit-value" id="popupRetail">—</span>
      </div>
      <div class="profit-row earn">
        <span class="profit-label">Your profit</span>
        <span class="profit-value" id="popupProfit">—</span>
      </div>
    </div>
    <div class="popup-footer">
      <button class="popup-cancel" onclick="closePopup()">Cancel</button>
      <button class="popup-ok" onclick="confirmAddProduct()">OK - Add to Store</button>
    </div>
  </div>
</div>

<!-- TOAST -->
<div class="toast" id="toast"></div>

<script>
// ====== DATA ======
var ALL_PRODUCTS = [];
var FILTERED = [];
var PAGE_SIZE = 20;
var currentPage = 0;
var sortMode = 'recommendation';
var priceSortDir = null; // 'asc' or 'desc'
var activeCat = 'all';
var priceMin = null;
var priceMax = null;
var selectedProduct = null;
var VIP_COMMISSION = [15,17,20,22,25,40];
var myVipLevel = 0;
var myToken = localStorage.getItem("token") || "";

// ====== LOAD ALL PRODUCTS ======
var CATEGORIES = [17,19,20,21,22,27,28,31,32,34,35,36];
var loadedCount = 0;

async function loadAllProducts(){
    var promises = CATEGORIES.map(function(catId){
        return fetch("/products-by-cat/" + catId)
            .then(function(r){ return r.json(); })
            .then(function(data){ return data.products || []; })
            .catch(function(){ return []; });
    });
    var results = await Promise.all(promises);
    ALL_PRODUCTS = [];
    results.forEach(function(prods){ ALL_PRODUCTS = ALL_PRODUCTS.concat(prods); });
    applyFiltersAndRender(true);
}

// Load VIP level
async function loadVip(){
    try {
        var r = await fetch("/my-vip-info", { headers: { "Authorization": "Bearer " + myToken } });
        var d = await r.json();
        if(d.success) myVipLevel = d.vipLevel || 0;
    } catch(e){}
}

// ====== FILTER & SORT ======
function applyFiltersAndRender(reset){
    if(reset) currentPage = 0;
    var list = ALL_PRODUCTS.slice();

    // Category filter
    if(activeCat !== 'all'){
        list = list.filter(function(p){ return String(p.category_id) === String(activeCat); });
    }

    // Price filter
    if(priceMin !== null){ list = list.filter(function(p){ return parseFloat(p.price) >= priceMin; }); }
    if(priceMax !== null){ list = list.filter(function(p){ return parseFloat(p.price) <= priceMax; }); }

    // Sort
    if(sortMode === 'sales'){
        list.sort(function(a,b){ return (b.sales||0)-(a.sales||0); });
    } else if(sortMode === 'price'){
        if(priceSortDir === 'asc') list.sort(function(a,b){ return parseFloat(a.price)-parseFloat(b.price); });
        else list.sort(function(a,b){ return parseFloat(b.price)-parseFloat(a.price); });
    } else {
        // recommendation: shuffle-ish by rating then sales
        list.sort(function(a,b){ return ((b.rating||0)+(b.sales||0))-((a.rating||0)+(a.sales||0)); });
    }

    FILTERED = list;
    document.getElementById("itemsCount").innerText = list.length.toLocaleString() + " Items";
    renderPage(true);
}

function renderPage(reset){
    var grid = document.getElementById("productGrid");
    if(reset){ grid.innerHTML = ""; currentPage = 0; }
    if(FILTERED.length === 0){
        grid.innerHTML = '<div class="no-results">No products found</div>';
        return;
    }
    var start = currentPage * PAGE_SIZE;
    var end = Math.min(start + PAGE_SIZE, FILTERED.length);
    var fragment = document.createDocumentFragment();

    for(var i = start; i < end; i++){
        var p = FILTERED[i];
        var card = buildCard(p);
        fragment.appendChild(card);
    }

    // Infinite scroll sentinel
    if(end < FILTERED.length){
        var sentinel = document.createElement("div");
        sentinel.id = "infiniteSentinel";
        sentinel.style.cssText = "height:1px;grid-column:1/-1;";
        fragment.appendChild(sentinel);
    }

    grid.appendChild(fragment);
    currentPage++;

    // Observe sentinel for infinite scroll
    var newSentinel = document.getElementById("infiniteSentinel");
    if(newSentinel){
        if(window.__infiniteObserver) window.__infiniteObserver.disconnect();
        window.__infiniteObserver = new IntersectionObserver(function(entries){
            if(entries[0].isIntersecting){
                window.__infiniteObserver.disconnect();
                var s = document.getElementById("infiniteSentinel");
                if(s) s.remove();
                renderPage(false);
            }
        }, { rootMargin: "200px" });
        window.__infiniteObserver.observe(newSentinel);
    }
}


// ====== Cloudinary Image Helper ======
var CLOUD_BASE = 'https://res.cloudinary.com/doabtbdsh/image/upload/products';
var CLOUDINARY_CAT = {17:'17_Clothing_and_Accessories',19:'19_Medical_Bags_and_Sunglasses',20:'20_Shoes',21:'21_Watches',22:'22_Jewelry',27:'27_Electronics',28:'28_Smart_Home',31:'31_Luxury_Brands',32:'32_Beauty_and_Personal_Care',34:'34_Mens_Fashion',35:'35_Health_and_Household',36:'36_Home_and_Kitchen'};

function getCloudImg(p, imgName) {
    imgName = imgName || '1.jpg';
    var catFolder = CLOUDINARY_CAT[p.category_id] || '27_Electronics';
    return CLOUD_BASE + '/' + catFolder + '/' + (p.folder||'') + '/' + imgName;
}

function getProductImg(p){
    return getCloudImg(p, '1.jpg');
}

function buildCard(p){
    var imgSrc = getProductImg(p);

    var card = document.createElement("div");
    card.className = "pcard";

    var img = document.createElement("img");
    img.className = "pcard-img";
    img.src = imgSrc;
    img.alt = p.title;
    img.onerror = function(){
        this.src = getCloudImg(p, '1.jpg');
        this.onerror = null;
    };
    img.loading = "lazy";
    img.onclick = function(e){ openProductDetail(p); };

    var info = document.createElement("div");
    info.className = "pcard-info";
    info.innerHTML =
        '<p class="pcard-name">' + escHtml(p.title) + '</p>' +
        '<p class="pcard-price">US$' + parseFloat(p.price).toFixed(2) + '</p>';

    var sellBtn = document.createElement("button");
    sellBtn.className = "sell-now-btn";
    sellBtn.innerText = "Sell Now";
    sellBtn.onclick = function(e){
        e.stopPropagation();
        openSellPopup(p);
    };
    info.appendChild(sellBtn);

    card.appendChild(img);
    card.appendChild(info);
    return card;
}

function escHtml(t){ return (t||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

// ====== SORT ======
function toggleSort(){
    var dd = document.getElementById("sortDropdown");
    var arrow = document.getElementById("sortArrow");
    dd.classList.toggle("open");
    arrow.style.transform = dd.classList.contains("open") ? "rotate(180deg)" : "";
}

function setSort(mode){
    sortMode = mode;
    priceSortDir = null;
    document.querySelectorAll(".sort-option").forEach(function(el){ el.classList.remove("active"); });
    if(mode === 'recommendation') document.getElementById("sortRec").classList.add("active");
    else if(mode === 'sales') document.getElementById("sortSales").classList.add("active");
    document.getElementById("sortDropdown").classList.remove("open");
    document.getElementById("sortArrow").style.transform = "";
    applyFiltersAndRender(true);
}

function togglePriceSort(){
    sortMode = 'price';
    if(!priceSortDir) priceSortDir = 'asc';
    document.querySelectorAll(".sort-option").forEach(function(el){ el.classList.remove("active"); });
    document.getElementById("sortPrice").classList.add("active");
    updatePriceArrows();
    document.getElementById("sortDropdown").classList.remove("open");
    document.getElementById("sortArrow").style.transform = "";
    applyFiltersAndRender(true);
}

function setPriceSort(dir){
    sortMode = 'price';
    priceSortDir = dir;
    document.querySelectorAll(".sort-option").forEach(function(el){ el.classList.remove("active"); });
    document.getElementById("sortPrice").classList.add("active");
    updatePriceArrows();
    document.getElementById("sortDropdown").classList.remove("open");
    document.getElementById("sortArrow").style.transform = "";
    applyFiltersAndRender(true);
}

function updatePriceArrows(){
    document.getElementById("priceUp").className = "price-arrow" + (priceSortDir==="asc" ? " active-arrow" : "");
    document.getElementById("priceDown").className = "price-arrow" + (priceSortDir==="desc" ? " active-arrow" : "");
}

// ====== FILTER ======
function openFilter(){
    document.getElementById("filterOverlay").classList.add("open");
    document.getElementById("filterPanel").classList.add("open");
}
function closeFilter(){
    document.getElementById("filterOverlay").classList.remove("open");
    document.getElementById("filterPanel").classList.remove("open");
}
function selectCat(el, cat){
    activeCat = cat;
    document.querySelectorAll(".cat-item").forEach(function(i){ i.classList.remove("active"); });
    el.classList.add("active");
    closeFilter();
    applyFiltersAndRender(true);
}
function clearPriceFilter(){
    priceMin = null; priceMax = null;
    document.getElementById("priceMin").value = "";
    document.getElementById("priceMax").value = "";
}
function applyPriceFilter(){
    var mn = parseFloat(document.getElementById("priceMin").value);
    var mx = parseFloat(document.getElementById("priceMax").value);
    priceMin = isNaN(mn) ? null : mn;
    priceMax = isNaN(mx) ? null : mx;
    closeFilter();
    applyFiltersAndRender(true);
}

// ====== SELL NOW POPUP ======
function openSellPopup(productOrJson){
    var p = (typeof productOrJson === 'string') ? JSON.parse(productOrJson) : productOrJson;
    selectedProduct = p;
    var price = parseFloat(p.price);
    var commPct = VIP_COMMISSION[myVipLevel] || 15;
    var supplierPrice = price * (1 - commPct/100);
    var profit = price - supplierPrice;

    document.getElementById("popupTitle").innerText = p.title.substring(0,40) + (p.title.length>40?"...":"");
    document.getElementById("popupSubtitle").innerText = "VIP " + myVipLevel + " — " + commPct + "% discount from supplier";
    document.getElementById("popupSupplier").innerText = "US$" + supplierPrice.toFixed(2);
    document.getElementById("popupRetail").innerText = "US$" + price.toFixed(2);
    document.getElementById("popupProfit").innerText = "US$" + profit.toFixed(2);
    document.getElementById("sellPopup").classList.add("open");
}
function closePopup(){
    document.getElementById("sellPopup").classList.remove("open");
    selectedProduct = null;
}
async function confirmAddProduct(){
    if(!selectedProduct) return;
    var btn = document.querySelector(".popup-ok");
    btn.disabled = true;
    btn.innerText = "Adding...";
    try {
        var r = await fetch("/add-seller-product", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": "Bearer " + myToken },
            body: JSON.stringify({ product: selectedProduct })
        });
        var d = await r.json();
        closePopup();
        if(d.success){
            showToast("✅ Added to your store!");
        } else {
            showToast("⚠️ " + (d.message || "Failed to add"));
        }
    } catch(e){
        closePopup();
        showToast("⚠️ Network error");
    }
    btn.disabled = false;
    btn.innerText = "OK - Add to Store";
}

// ====== PRODUCT DETAIL ======
function openProductDetail(p){
    localStorage.setItem("listingProduct", JSON.stringify(p));
    window.location.href = "/listing-product-detail";
}

// ====== TOAST ======
function showToast(msg){
    var t = document.getElementById("toast");
    t.innerText = msg;
    t.classList.add("show");
    setTimeout(function(){ t.classList.remove("show"); }, 3000);
}

// ====== CLOSE SORT ON OUTSIDE CLICK ======
document.addEventListener("click", function(e){
    if(!e.target.closest(".sort-btn") && !e.target.closest(".sort-dropdown")){
        document.getElementById("sortDropdown").classList.remove("open");
        document.getElementById("sortArrow").style.transform = "";
    }
});

// ====== INIT ======
(async function(){
    await loadVip();
    await loadAllProducts();
})();
</script>
</body>
</html>`);
});

// ---- Serve products by category ----
app.get("/products-by-cat/:catId", (req, res) => {
    const catId = parseInt(req.params.catId);
    const catFiles = {
        17: "products_17_clothing.json",
        19: "products_19_medical.json",
        20: "products_20_shoes.json",
        21: "products_21_watches.json",
        22: "products_22_jewelry.json",
        27: "products_27_electronics.json",
        28: "products_28_smarthome.json",
        31: "products_31_luxury.json",
        32: "products_32_beauty.json",
        34: "products_34_mens.json",
        35: "products_35_health.json",
        36: "products_36_home.json"
    };
    const file = catFiles[catId];
    if(!file) return res.json({ products: [] });
    try {
        const data = JSON.parse(fs.readFileSync(path.join(__dirname, file)));
        res.json({ products: data });
    } catch(e){
        res.json({ products: [] });
    }
});

// ---- Serve product images ----
app.get("/product-image/:folder/:img", (req, res) => {
    const folder = req.params.folder;
    const img = req.params.img;
    const base = path.join(__dirname, "product_images");
    const fp = path.join(base, folder, img);
    if(fs.existsSync(fp)){
        res.sendFile(fp);
    } else {
        // Return placeholder
        res.redirect("https://via.placeholder.com/300x300?text=Product");
    }
});



// =================== LISTING PRODUCT DETAIL PAGE ===================
app.get("/listing-product-detail", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta charset="UTF-8">
<title>Product - TikTok Mall</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;padding-bottom:90px;}

/* HEADER - clean icons only */
.header{background:#1976d2;padding:11px 15px;display:flex;justify-content:space-between;align-items:center;position:relative;}
.h-left{display:flex;align-items:center;gap:14px;}
.h-right{display:flex;align-items:center;gap:14px;}
.h-icon{cursor:pointer;display:inline-flex;align-items:center;}

/* SLIDER */
.slider-wrap{background:white;position:relative;overflow:hidden;height:310px;}
.slider-imgs{display:flex;height:100%;transition:transform 0.4s ease;}
.slider-img{min-width:100%;height:310px;object-fit:cover;display:block;background:#f0f0f0;}
.slide-arrow{position:absolute;top:50%;transform:translateY(-50%);background:rgba(0,0,0,0.22);color:white;border:none;width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:10;font-size:16px;}
.slide-arrow.left{left:8px;}.slide-arrow.right{right:8px;}
.slider-dots{display:flex;justify-content:center;gap:5px;padding:8px;background:white;}
.dot{width:6px;height:6px;border-radius:50%;background:#ddd;cursor:pointer;transition:all 0.2s;}
.dot.active{background:#1976d2;transform:scale(1.3);}
.thumbs{display:flex;gap:7px;padding:8px 14px;background:white;overflow-x:auto;border-bottom:1px solid #f0f0f0;}
.thumb{width:54px;height:54px;object-fit:cover;border-radius:8px;border:2px solid #eee;cursor:pointer;flex-shrink:0;}
.thumb.active{border-color:#1976d2;}

/* INFO CARD */
.info-card{background:white;margin:8px 0 0;padding:14px 15px 12px;}
.product-title{font-size:15px;font-weight:700;color:#1a1a1a;line-height:1.55;margin-bottom:10px;}
.product-price{color:#1976d2;font-size:26px;font-weight:800;letter-spacing:-0.5px;}
.badge-row{display:flex;gap:7px;margin-top:10px;flex-wrap:wrap;}
.badge{font-size:11px;padding:4px 10px;border-radius:20px;font-weight:600;border:1px solid;}
.badge.green{background:#f0faf4;color:#2e7d32;border-color:#c8e6c9;}
.badge.orange{background:#fffde7;color:#f57f17;border-color:#fff176;}

/* SUPPLIER CARD - replaces specs */
.supplier-card{background:white;margin-top:8px;padding:14px 15px;display:flex;align-items:center;gap:12px;cursor:pointer;}
.supplier-logo{width:48px;height:48px;border-radius:10px;object-fit:cover;background:#f0f0f0;border:1px solid #eee;flex-shrink:0;}
.supplier-info{flex:1;min-width:0;}
.supplier-name{font-size:14px;font-weight:700;color:#1a1a1a;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.supplier-meta{font-size:12px;color:#888;margin-top:2px;}
.supplier-badge{background:#fff8e1;color:#f57f17;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;display:inline-block;margin-top:3px;}
.supplier-arrow{color:#bbb;font-size:18px;flex-shrink:0;}

/* PROFIT BOTTOM SHEET */
.bottom-sheet{position:fixed;bottom:0;left:0;right:0;background:white;border-radius:20px 20px 0 0;box-shadow:0 -4px 24px rgba(0,0,0,0.1);z-index:300;padding:16px 16px 20px;transform:translateY(100%);transition:transform 0.35s cubic-bezier(0.4,0,0.2,1);}
.bottom-sheet.open{transform:translateY(0);}
.sheet-handle{width:36px;height:4px;background:#e0e0e0;border-radius:2px;margin:0 auto 14px;}
.sheet-title{font-size:14px;font-weight:700;color:#1a1a1a;margin-bottom:4px;}
.sheet-sub{font-size:12px;color:#888;margin-bottom:14px;}
.profit-rows{}
.profit-item{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #f5f5f5;}
.profit-item:last-child{border-bottom:none;}
.pi-label{font-size:13px;color:#555;}
.pi-value{font-size:14px;font-weight:700;}
.pi-value.s{color:#e65100;}
.pi-value.r{color:#1976d2;}
.pi-value.g{color:#2e7d32;}
.sheet-btn-row{display:flex;gap:10px;margin-top:16px;}
.sheet-cancel{flex:1;padding:13px;border:1.5px solid #e0e0e0;border-radius:12px;background:white;color:#555;font-size:14px;font-weight:600;cursor:pointer;}
.sheet-ok{flex:2;padding:13px;border:none;border-radius:12px;background:#1976d2;color:white;font-size:14px;font-weight:700;cursor:pointer;}
.sheet-ok:active{opacity:0.88;}
.sheet-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.35);z-index:299;}
.sheet-overlay.open{display:block;}

/* BOTTOM BAR */
.bottom-bar{position:fixed;bottom:0;left:0;right:0;background:white;padding:10px 15px 14px;border-top:1px solid #eeeeee;}
.add-btn{width:100%;padding:14px;border:none;border-radius:14px;background:#1976d2;color:white;font-size:15px;font-weight:700;cursor:pointer;letter-spacing:0.3px;}
.add-btn:active{opacity:0.88;}

.toast{position:fixed;bottom:110px;left:50%;transform:translateX(-50%);background:#323232;color:white;padding:10px 22px;border-radius:25px;font-size:13px;font-weight:600;z-index:1000;display:none;white-space:nowrap;}
.toast.show{display:block;animation:fadeUp 0.3s ease;}
@keyframes fadeUp{from{opacity:0;transform:translate(-50%,15px);}to{opacity:1;transform:translate(-50%,0);}}
</style>
</head>
<body>

<!-- HEADER: icons only, no text -->
<div class="header">
  <div class="h-left">
    <span class="h-icon" onclick="history.back()">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span class="h-icon" onclick="window.location.href='/dashboard'">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
    </span>
  </div>
  <div class="h-right">
    <span class="h-icon" onclick="window.location.href='/dashboard?search=1'">
      <svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    </span>
    <span class="h-icon" onclick="window.location.href='/dashboard?messages=1'">
      <svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
    </span>
    <span class="h-icon" onclick="window.location.href='/dashboard?account=1'">
      <svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    </span>
    <span class="h-icon" onclick="window.location.href='/dashboard?lang=1'">
      <svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
    </span>
  </div>
</div>

<!-- SLIDER -->
<div class="slider-wrap">
  <div class="slider-imgs" id="sliderImgs"></div>
  <button class="slide-arrow left" onclick="slide(-1)">&#8249;</button>
  <button class="slide-arrow right" onclick="slide(1)">&#8250;</button>
</div>
<div class="thumbs" id="thumbsRow"></div>
<div class="slider-dots" id="sliderDots"></div>

<!-- INFO -->
<div class="info-card">
  <div class="product-title" id="productTitle">Loading...</div>
  <div class="product-price" id="productPrice"></div>
  <div class="badge-row">
    <span class="badge green">Free Shipping</span>
    <span class="badge green">Free Return</span>
    <span class="badge orange">⭐ 5.0</span>
  </div>
</div>

<!-- SUPPLIER CARD (replaces specs + profit sections) -->
<div class="supplier-card" id="supplierCard">
  <img class="supplier-logo" id="supplierLogo" src="https://cdn-icons-png.flaticon.com/512/149/149071.png" onerror="this.src='https://cdn-icons-png.flaticon.com/512/149/149071.png'">
  <div class="supplier-info">
    <div class="supplier-name" id="supplierName">Loading supplier...</div>
    <div class="supplier-meta" id="supplierMeta">Official Store</div>
    <span class="supplier-badge" id="supplierVip">✓ VIP 0</span>
  </div>
  <span class="supplier-arrow">›</span>
</div>

<!-- BOTTOM BAR -->
<div class="bottom-bar">
  <button class="add-btn" onclick="openSheet()">＋ Add to My Store</button>
</div>

<!-- SHEET OVERLAY -->
<div class="sheet-overlay" id="sheetOverlay" onclick="closeSheet()"></div>

<!-- BOTTOM SHEET (profit details) -->
<div class="bottom-sheet" id="bottomSheet">
  <div class="sheet-handle"></div>
  <div class="sheet-title">Add to your store</div>
  <div class="sheet-sub" id="sheetSub">VIP 0 — 15% supplier discount</div>
  <div class="profit-rows">
    <div class="profit-item">
      <span class="pi-label">Supplier price</span>
      <span class="pi-value s" id="sheetSupplier">—</span>
    </div>
    <div class="profit-item">
      <span class="pi-label">Sell price</span>
      <span class="pi-value r" id="sheetRetail">—</span>
    </div>
    <div class="profit-item">
      <span class="pi-label">Your profit</span>
      <span class="pi-value g" id="sheetProfit">—</span>
    </div>
  </div>
  <div class="sheet-btn-row">
    <button class="sheet-cancel" onclick="closeSheet()">Cancel</button>
    <button class="sheet-ok" id="sheetOkBtn" onclick="confirmAdd()">OK - Add to Store</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
var p = JSON.parse(localStorage.getItem("listingProduct") || "null");
var VIP_COMMISSION = [15,17,20,22,25,40];
var myVipLevel = 0;
var myToken = localStorage.getItem("token") || "";
var currentSlide = 0;
var imgs = [];

// Supplier names pool (realistic store names)
var SUPPLIER_NAMES = ["Global Trade Co.","Prime Wholesale Hub","ShopDirect Store","TikTok Official Supplier","TopBrand Wholesale","Elite Products Store","FastShip Supplier","ProMall Wholesale","DirectBuy Store","CertifiedSeller Pro"];
var SUPPLIER_LOGOS = ["https://cdn-icons-png.flaticon.com/512/3081/3081648.png","https://cdn-icons-png.flaticon.com/512/2331/2331949.png","https://cdn-icons-png.flaticon.com/512/891/891462.png","https://cdn-icons-png.flaticon.com/512/3144/3144456.png","https://cdn-icons-png.flaticon.com/512/2921/2921222.png"];

var CLOUD_D = "https://res.cloudinary.com/doabtbdsh/image/upload/products";
var CAT_MAP_D = {17:"17_Clothing_and_Accessories",19:"19_Medical_Bags_and_Sunglasses",20:"20_Shoes",21:"21_Watches",22:"22_Jewelry",27:"27_Electronics",28:"28_Smart_Home",31:"31_Luxury_Brands",32:"32_Beauty_and_Personal_Care",34:"34_Mens_Fashion",35:"35_Health_and_Household",36:"36_Home_and_Kitchen"};

async function init(){
    try{
        var r = await fetch("/my-vip-info",{headers:{"Authorization":"Bearer "+myToken}});
        var d = await r.json();
        if(d.success) myVipLevel = d.vipLevel||0;
    }catch(e){}

    if(!p){ document.getElementById("productTitle").innerText="Product not found"; return; }

    // Build Cloudinary images
    var catFolder = CAT_MAP_D[p.category_id] || "27_Electronics";
    imgs = (p.images && p.images.length > 0)
        ? p.images.map(function(img){ return CLOUD_D+"/"+catFolder+"/"+p.folder+"/"+img; })
        : [CLOUD_D+"/"+catFolder+"/"+(p.folder||"")+"/1.jpg"];

    buildSlider();

    document.getElementById("productTitle").innerText = p.title;
    document.getElementById("productPrice").innerText = "US$" + parseFloat(p.price).toFixed(2);

    // Supplier info — deterministic from product id
    var idx = (p.id||0) % SUPPLIER_NAMES.length;
    var logoIdx = (p.id||0) % SUPPLIER_LOGOS.length;
    var supplierVip = Math.min(5, Math.floor(((p.id||0) % 6)));
    document.getElementById("supplierName").innerText = SUPPLIER_NAMES[idx];
    document.getElementById("supplierLogo").src = SUPPLIER_LOGOS[logoIdx];
    document.getElementById("supplierMeta").innerText = (p.category_name||"") + " · Official Store";
    document.getElementById("supplierVip").innerText = "✓ VIP " + supplierVip;

    setInterval(function(){ slide(1); }, 3500);
}

function buildSlider(){
    var c=document.getElementById("sliderImgs"),th=document.getElementById("thumbsRow"),dt=document.getElementById("sliderDots");
    c.innerHTML=""; th.innerHTML=""; dt.innerHTML="";
    imgs.forEach(function(src,i){
        var img=document.createElement("img"); img.className="slider-img"; img.src=src;
        img.onerror=function(){this.src="https://via.placeholder.com/300x300?text=No+Image";};
        c.appendChild(img);
        var t=document.createElement("img"); t.className="thumb"+(i===0?" active":""); t.src=src;
        t.onerror=function(){this.src="https://via.placeholder.com/60x60";};
        t.onclick=(function(idx){return function(){goTo(idx);};})(i); th.appendChild(t);
        var d=document.createElement("span"); d.className="dot"+(i===0?" active":"");
        d.onclick=(function(idx){return function(){goTo(idx);};})(i); dt.appendChild(d);
    });
}

function slide(dir){ goTo((currentSlide+dir+imgs.length)%imgs.length); }
function goTo(idx){
    currentSlide=idx;
    document.getElementById("sliderImgs").style.transform="translateX(-"+(idx*100)+"%)";
    document.querySelectorAll(".thumb").forEach(function(t,i){t.classList.toggle("active",i===idx);});
    document.querySelectorAll(".dot").forEach(function(d,i){d.classList.toggle("active",i===idx);});
}

function openSheet(){
    var price=parseFloat(p.price);
    var commPct=VIP_COMMISSION[myVipLevel]||15;
    var supplier=price*(1-commPct/100), profit=price-supplier;
    document.getElementById("sheetSub").innerText="VIP "+myVipLevel+" — "+commPct+"% supplier discount";
    document.getElementById("sheetSupplier").innerText="US$"+supplier.toFixed(2);
    document.getElementById("sheetRetail").innerText="US$"+price.toFixed(2);
    document.getElementById("sheetProfit").innerText="US$"+profit.toFixed(2);
    document.getElementById("bottomSheet").classList.add("open");
    document.getElementById("sheetOverlay").classList.add("open");
}
function closeSheet(){
    document.getElementById("bottomSheet").classList.remove("open");
    document.getElementById("sheetOverlay").classList.remove("open");
}

async function confirmAdd(){
    var btn=document.getElementById("sheetOkBtn");
    btn.disabled=true; btn.innerText="Adding...";
    try{
        var r=await fetch("/add-seller-product",{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+myToken},body:JSON.stringify({product:p})});
        var d=await r.json();
        closeSheet();
        showToast(d.success?"✅ Added to your store!":"⚠️ "+(d.message||"Failed"));
    }catch(e){ closeSheet(); showToast("⚠️ Network error"); }
    btn.disabled=false; btn.innerText="OK - Add to Store";
}

function showToast(msg){
    var t=document.getElementById("toast"); t.innerText=msg;
    t.classList.add("show"); setTimeout(function(){t.classList.remove("show");},3000);
}

init();
</script>
</body>
</html>`);
});


// =================== MANAGE PRODUCT PAGE ===================
app.get("/manage-product", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta charset="UTF-8">
<title>Manage Products</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fb;min-height:100vh;padding-bottom:30px;}
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100;box-shadow:0 2px 8px rgba(25,118,210,0.3);}
.header h2{font-size:16px;font-weight:700;flex:1;}
.limit-bar{background:white;margin:12px 12px 0;border-radius:12px;padding:14px 15px;box-shadow:0 1px 6px rgba(0,0,0,0.07);}
.limit-text{font-size:13px;color:#555;margin-bottom:8px;}
.limit-progress{height:6px;background:#e0e0e0;border-radius:3px;overflow:hidden;}
.limit-fill{height:100%;background:linear-gradient(90deg,#1976d2,#42a5f5);border-radius:3px;transition:width 0.5s;}
.limit-nums{display:flex;justify-content:space-between;margin-top:5px;font-size:11px;color:#aaa;}
.list{padding:12px;}
.pitem{background:white;border-radius:14px;display:flex;align-items:center;gap:12px;padding:11px 13px;margin-bottom:10px;box-shadow:0 2px 8px rgba(0,0,0,0.07);cursor:pointer;transition:transform 0.15s;}
.pitem:active{transform:scale(0.98);}
.pitem-img{width:60px;height:60px;border-radius:10px;object-fit:cover;flex-shrink:0;background:#f0f0f0;}
.pitem-info{flex:1;min-width:0;}
.pitem-name{font-size:13px;color:#222;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:4px;}
.pitem-cat{font-size:11px;color:#888;}
.pitem-price{font-size:13px;color:#1976d2;font-weight:700;margin-top:3px;}
.delete-btn{background:#fff5f5;border:1px solid #ffcccc;color:#e53935;width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;font-size:16px;font-weight:700;transition:background 0.2s;}
.delete-btn:hover{background:#ffebee;}
.empty{text-align:center;padding:60px 20px;color:#aaa;}
.empty-icon{font-size:48px;margin-bottom:12px;}
.empty p{font-size:14px;}
.empty a{color:#1976d2;text-decoration:none;font-weight:600;}
.loading-wrap{text-align:center;padding:50px;color:#aaa;}
.loading-spinner{width:32px;height:32px;border:3px solid #e0e0e0;border-top-color:#1976d2;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 10px;}
@keyframes spin{to{transform:rotate(360deg);}}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#e53935;color:white;padding:11px 22px;border-radius:25px;font-size:13px;font-weight:600;z-index:1000;display:none;}
.toast.show{display:block;animation:fadeUp 0.3s ease;}
@keyframes fadeUp{from{opacity:0;transform:translate(-50%,15px);}to{opacity:1;transform:translate(-50%,0);}}
</style>
</head>
<body>
<div class="header">
  <span onclick="history.back()" style="cursor:pointer;display:inline-flex;">
    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
  </span>
  <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  <span style="flex:1"></span>
  <span style="font-size:13px;background:rgba(255,255,255,0.2);padding:4px 10px;border-radius:12px;" id="countBadge">0 / 20</span>
</div>

<div class="limit-bar">
  <div class="limit-text">Products in your store <span id="limitText" style="font-weight:700;color:#1976d2;"></span></div>
  <div class="limit-progress"><div class="limit-fill" id="limitFill" style="width:0%"></div></div>
  <div class="limit-nums"><span>0</span><span id="maxText">20</span></div>
</div>

<div class="list" id="productList">
  <div class="loading-wrap"><div class="loading-spinner"></div><p>Loading...</p></div>
</div>

<div class="toast" id="toast"></div>

<script>
var myToken = localStorage.getItem("token") || "";
var VIP_PRODUCTS = [20,35,80,120,300,1000];
var myVipLevel = 0;

async function load(){
    try {
        var r1 = await fetch("/my-vip-info", { headers: {"Authorization":"Bearer "+myToken} });
        var d1 = await r1.json();
        if(d1.success) myVipLevel = d1.vipLevel || 0;
    } catch(e){}

    var maxP = VIP_PRODUCTS[myVipLevel] || 20;

    try {
        var r = await fetch("/my-seller-products", { headers: {"Authorization":"Bearer "+myToken} });
        var d = await r.json();
        var prods = d.products || [];

        document.getElementById("countBadge").innerText = prods.length + " / " + maxP;
        document.getElementById("limitText").innerText = prods.length + " of " + maxP;
        document.getElementById("limitFill").style.width = Math.min(100, (prods.length/maxP)*100) + "%";
        document.getElementById("maxText").innerText = maxP;

        var list = document.getElementById("productList");
        if(prods.length === 0){
            list.innerHTML = '<div class="empty"><div class="empty-icon">🛍️</div><p>No products yet.<br><a href="/listings">Browse Listings</a> to add products.</p></div>';
            return;
        }
        list.innerHTML = "";
        prods.forEach(function(p){
            var catImgMap = {17:'17_Clothing_and_Accessories',19:'19_Medical_Bags_and_Sunglasses',20:'20_Shoes',21:'21_Watches',22:'22_Jewelry',27:'27_Electronics',28:'28_Smart_Home',31:'31_Luxury_Brands',32:'32_Beauty_and_Personal_Care',34:'34_Mens_Fashion',35:'35_Health_and_Household',36:'36_Home_and_Kitchen'};
            var imgSrc = 'https://res.cloudinary.com/doabtbdsh/image/upload/products/' + (catImgMap[p.category_id]||'27_Electronics') + '/' + p.folder + '/1.jpg';
            var item = document.createElement("div");
            item.className = "pitem";
            item.innerHTML =
                '<img class="pitem-img" src="' + imgSrc + '" onerror="this.src=\\'https://via.placeholder.com/60x60\\'" loading="lazy">' +
                '<div class="pitem-info">' +
                  '<div class="pitem-name">' + escHtml(p.title) + '</div>' +
                  '<div class="pitem-cat">' + (p.category_name||"") + '</div>' +
                  '<div class="pitem-price">US$' + parseFloat(p.price).toFixed(2) + '</div>' +
                '</div>' +
                '<div class="delete-btn" onclick="event.stopPropagation();deleteProduct(' + p.id + ')">✕</div>';
            item.onclick = function(){
                localStorage.setItem("listingProduct", JSON.stringify(p));
                window.location.href = "/listing-product-detail";
            };
            list.appendChild(item);
        });
    } catch(e){
        document.getElementById("productList").innerHTML = '<div class="empty"><p>Error loading products</p></div>';
    }
}

async function deleteProduct(productId){
    if(!confirm("Remove this product from your store?")) return;
    try {
        var r = await fetch("/remove-seller-product", {
            method:"POST",
            headers:{"Content-Type":"application/json","Authorization":"Bearer "+myToken},
            body: JSON.stringify({ productId })
        });
        var d = await r.json();
        if(d.success){ showToast("🗑️ Product removed"); load(); }
        else showToast("⚠️ Failed to remove");
    } catch(e){ showToast("⚠️ Error"); }
}

function escHtml(t){ return (t||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function showToast(msg){ var t=document.getElementById("toast"); t.innerText=msg; t.classList.add("show"); setTimeout(function(){ t.classList.remove("show"); },2500); }

load();
</script>
</body>
</html>`);
});


// =================== MANAGE ORDERS PAGE ===================
app.get("/manage-orders", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta charset="UTF-8">
<title>Manage Orders</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fb;min-height:100vh;padding-bottom:30px;}
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;align-items:center;justify-content:space-between;}
.tabs{display:flex;background:white;border-bottom:2px solid #f0f0f0;}
.tab{flex:1;padding:12px 4px;text-align:center;font-size:11px;font-weight:600;color:#999;cursor:pointer;border-bottom:3px solid transparent;}
.tab.active{color:#1976d2;border-bottom-color:#1976d2;}
.tab .cnt{background:#ff3b30;color:white;font-size:9px;padding:1px 5px;border-radius:8px;margin-left:3px;}
.orders-list{padding:12px;}
.ocard{background:white;border-radius:14px;padding:14px;margin-bottom:10px;box-shadow:0 2px 10px rgba(0,0,0,0.07);cursor:pointer;}
.ocard-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
.order-id{font-size:11px;color:#aaa;font-family:monospace;}
.sbadge{font-size:11px;padding:4px 10px;border-radius:12px;font-weight:700;}
.sbadge.ship{background:#fff3e0;color:#e65100;}
.sbadge.del{background:#e3f2fd;color:#1976d2;}
.sbadge.ref{background:#fff3e0;color:#e65100;}
.sbadge.done{background:#e8f5e9;color:#2e7d32;}
.ocard-mid{display:flex;gap:12px;align-items:flex-start;margin-bottom:10px;}
.ocard-img{width:65px;height:65px;border-radius:10px;object-fit:cover;background:#f0f0f0;flex-shrink:0;}
.ocard-title{font-size:13px;font-weight:600;color:#222;margin-bottom:5px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}
.ocard-price{font-size:13px;color:#1976d2;font-weight:700;}
.ocard-profit{font-size:11px;color:#2e7d32;margin-top:2px;}
.countdown{display:flex;align-items:center;gap:6px;background:#fff8e1;border-radius:8px;padding:7px 10px;margin-bottom:10px;font-size:12px;color:#e65100;font-weight:600;}
.ship-btn{width:100%;padding:12px;border:none;border-radius:10px;background:linear-gradient(135deg,#1976d2,#1565c0);color:white;font-size:14px;font-weight:700;cursor:pointer;}
.map-wrap{border-radius:12px;overflow:hidden;height:160px;background:#e8f4fd;margin-bottom:10px;position:relative;}
.map-canvas{width:100%;height:100%;}
.map-label{position:absolute;bottom:6px;right:8px;font-size:10px;color:#1976d2;background:rgba(255,255,255,0.9);padding:2px 7px;border-radius:8px;}
.empty{text-align:center;padding:60px 20px;color:#aaa;}
.empty-icon{font-size:48px;margin-bottom:12px;}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#2e7d32;color:white;padding:11px 22px;border-radius:25px;font-size:13px;font-weight:600;z-index:1000;display:none;}
.toast.show{display:block;}
@keyframes spin{to{transform:rotate(360deg);}}

/* SHIP POPUP */
.popup-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:700;align-items:flex-end;justify-content:center;}
.popup-overlay.open{display:flex;}
.popup-box{background:white;border-radius:20px 20px 0 0;width:100%;max-width:480px;padding:0 0 24px;animation:slideUp 0.3s ease;}
@keyframes slideUp{from{transform:translateY(100%);}to{transform:translateY(0);}}
.popup-handle{width:40px;height:4px;background:#e0e0e0;border-radius:2px;margin:12px auto 0;}
.popup-row{display:flex;justify-content:space-between;padding:12px 20px;border-bottom:1px solid #f0f0f0;}
.popup-row:last-of-type{border-bottom:none;}

/* PASSWORD POPUP - bottom sheet */
.pwd-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:800;align-items:flex-end;justify-content:center;}
.pwd-overlay.open{display:flex;}
.pwd-box{background:white;border-radius:20px 20px 0 0;width:100%;max-width:480px;padding:0 0 28px;animation:slideUp 0.3s ease;}
.pwd-input{width:100%;border:1.5px solid #ddd;border-radius:12px;padding:12px 16px;font-size:15px;text-align:center;letter-spacing:3px;outline:none;margin-bottom:14px;}
.pwd-input:focus{border-color:#1976d2;}

/* TRACKING MODAL */
.track-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:800;align-items:flex-end;justify-content:center;}
.track-overlay.open{display:flex;}
.track-box{background:white;border-radius:20px 20px 0 0;width:100%;max-width:480px;max-height:90vh;overflow-y:auto;animation:slideUp 0.3s ease;}

/* PRODUCT MODAL */
.prod-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:800;align-items:flex-end;justify-content:center;}
.prod-overlay.open{display:flex;}
.prod-box{background:white;border-radius:20px 20px 0 0;width:100%;max-width:480px;max-height:88vh;overflow-y:auto;animation:slideUp 0.3s ease;position:relative;}
.slider-wrap{position:relative;width:100%;height:260px;overflow:hidden;background:#f0f0f0;}
.slider-track{display:flex;transition:transform 0.4s ease;height:100%;}
.slide{min-width:100%;height:100%;object-fit:cover;}
.slider-btn{position:absolute;top:50%;transform:translateY(-50%);background:rgba(0,0,0,0.35);color:white;border:none;width:32px;height:32px;border-radius:50%;font-size:16px;cursor:pointer;}
.slider-btn.prev{left:10px;}
.slider-btn.next{right:10px;}
.dots{position:absolute;bottom:10px;left:50%;transform:translateX(-50%);display:flex;gap:6px;}
.dot{width:8px;height:8px;border-radius:50%;background:rgba(255,255,255,0.5);cursor:pointer;}
.dot.active{background:white;}
</style>
</head>
<body>

<div class="header">
  <div style="display:flex;align-items:center;gap:12px;">
    <span onclick="history.back()" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
    </span>
  </div>
  <div style="display:flex;align-items:center;gap:14px;">
    <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    </span>
    <span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
    </span>
    <span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    </span>
    <span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
    </span>
  </div>
</div>

<div class="tabs">
  <div class="tab active" id="tab-ship" onclick="switchTab('waiting_shipping')">Shipping<span class="cnt" id="cnt-ship" style="display:none;">0</span></div>
  <div class="tab" id="tab-del" onclick="switchTab('in_delivery')">Delivery<span class="cnt" id="cnt-del" style="display:none;">0</span></div>
  <div class="tab" id="tab-ref" onclick="switchTab('waiting_refund')">Refund<span class="cnt" id="cnt-ref" style="display:none;">0</span></div>
  <div class="tab" id="tab-done" onclick="switchTab('completed')">Done<span class="cnt" id="cnt-done" style="display:none;">0</span></div>
</div>

<div class="orders-list" id="ordersList">
  <div class="empty"><div class="empty-icon">📦</div><p>Loading...</p></div>
</div>

<div class="toast" id="toast"></div>

<!-- SHIP CONFIRM POPUP -->
<div id="shipPopup" class="popup-overlay">
  <div class="popup-box">
    <div class="popup-handle"></div>
    <div style="font-size:15px;font-weight:700;color:#111;padding:14px 20px 4px;">🚚 Confirm Shipment</div>
    <div style="font-size:12px;color:#888;padding:0 20px 10px;">Supplier cost will be deducted from your balance</div>
    <div class="popup-row"><span style="font-size:13px;color:#555;">Order Number</span><span style="font-size:13px;font-weight:700;font-family:monospace;" id="sp-num">-</span></div>
    <div class="popup-row"><span style="font-size:13px;color:#555;">Supplier Price</span><span style="font-size:14px;font-weight:700;color:#e65100;" id="sp-sup">$0.00</span></div>
    <div class="popup-row"><span style="font-size:13px;color:#555;">Retail Price</span><span style="font-size:14px;font-weight:700;color:#1976d2;" id="sp-ret">$0.00</span></div>
    <div class="popup-row"><span style="font-size:13px;color:#555;">Your Profit</span><span style="font-size:14px;font-weight:700;color:#2e7d32;" id="sp-pro">$0.00</span></div>
    <div style="display:flex;gap:10px;padding:14px 20px 0;">
      <button onclick="closeShipPopup()" style="flex:1;padding:13px;border:1.5px solid #ddd;border-radius:12px;background:white;color:#555;font-size:14px;font-weight:600;cursor:pointer;">Cancel</button>
      <button onclick="openPwdPopup()" style="flex:2;padding:13px;border:none;border-radius:12px;background:#1976d2;color:white;font-size:14px;font-weight:700;cursor:pointer;">✅ OK Ship Now</button>
    </div>
  </div>
</div>

<!-- PASSWORD POPUP - bottom sheet -->
<div id="pwdPopup" class="pwd-overlay">
  <div class="pwd-box">
    <div style="width:40px;height:4px;background:#e0e0e0;border-radius:2px;margin:12px auto 0;"></div>
    <div style="font-size:15px;font-weight:700;color:#111;padding:14px 20px 4px;">🔐 Enter Your Password</div>
    <div style="font-size:12px;color:#888;padding:0 20px 14px;">Enter your account password to confirm shipment</div>
    <div style="padding:0 20px 8px;">
      <input class="pwd-input" type="password" id="pwdInput" placeholder="••••••••">
    </div>
    <div style="display:flex;gap:10px;padding:4px 20px 0;">
      <button onclick="closePwdPopup()" style="flex:1;padding:13px;border:1.5px solid #ddd;border-radius:12px;background:white;color:#555;font-size:14px;font-weight:600;cursor:pointer;">Cancel</button>
      <button onclick="doShip()" style="flex:2;padding:13px;border:none;border-radius:12px;background:linear-gradient(135deg,#1976d2,#1565c0);color:white;font-size:14px;font-weight:700;cursor:pointer;">🚚 Ship Now</button>
    </div>
  </div>
</div>

<!-- TRACKING MODAL -->
<div id="trackModal" class="track-overlay">
  <div class="track-box">
    <div class="popup-handle"></div>
    <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px;">
      <span style="font-size:15px;font-weight:700;">📦 Order Tracking</span>
      <button onclick="closeTrackModal()" style="border:none;background:#f0f0f0;border-radius:50%;width:30px;height:30px;font-size:16px;cursor:pointer;">✕</button>
    </div>
    <div id="track-num" style="padding:0 16px 6px;font-size:12px;color:#888;font-family:monospace;"></div>
    <div id="track-title" style="padding:0 16px 10px;font-size:13px;font-weight:600;color:#222;"></div>
    <div style="margin:0 16px 10px;border-radius:12px;overflow:hidden;height:200px;position:relative;background:#e8f4fd;">
      <canvas id="track-canvas" style="width:100%;height:100%;"></canvas>
    </div>
    <div id="track-route" style="padding:0 16px 20px;font-size:13px;color:#555;line-height:1.7;"></div>
  </div>
</div>

<!-- PRODUCT DETAIL MODAL -->
<div id="prodModal" class="prod-overlay">
  <div class="prod-box">
    <div class="popup-handle"></div>
    <button onclick="closeProdModal()" style="position:absolute;top:14px;right:16px;border:none;background:#f0f0f0;border-radius:50%;width:30px;height:30px;font-size:16px;cursor:pointer;">✕</button>
    <div class="slider-wrap" id="sliderWrap">
      <div class="slider-track" id="sliderTrack"></div>
      <button class="slider-btn prev" onclick="slideMove(-1)">‹</button>
      <button class="slider-btn next" onclick="slideMove(1)">›</button>
      <div class="dots" id="sliderDots"></div>
    </div>
    <div style="padding:14px 16px 6px;">
      <div id="pm-title" style="font-size:14px;font-weight:700;color:#222;line-height:1.5;margin-bottom:6px;"></div>
      <div id="pm-price" style="font-size:16px;font-weight:800;color:#1976d2;margin-bottom:3px;"></div>
      <div id="pm-profit" style="font-size:12px;color:#2e7d32;font-weight:600;margin-bottom:10px;"></div>
    </div>
    <div id="pm-countdown" style="margin:0 16px 10px;background:#fff8e1;border-radius:10px;padding:10px 14px;font-size:13px;color:#e65100;font-weight:600;display:flex;align-items:center;gap:8px;">
      ⏱ Ship within: <b id="pm-cd">--:--:--</b>
    </div>
    <div style="padding:0 16px 20px;">
      <button class="ship-btn" onclick="shipFromModal()">🚚 Ship Now</button>
    </div>
  </div>
</div>

<script>
var user = JSON.parse(localStorage.getItem("user") || "{}");
var token = localStorage.getItem("token") || user.token || "";
var allOrders = [];
var currentTab = "waiting_shipping";
var pendingOrderId = null;
var slideIdx = 0;
var slideImgs = [];
var modalCdTimer = null;

// Auto-switch tab from URL
(function(){
    var p = new URLSearchParams(window.location.search);
    var t = p.get("tab");
    if(t){
        if(t === "waiting_payment") t = "waiting_shipping";
        if(["waiting_shipping","in_delivery","waiting_refund","completed"].includes(t)){
            currentTab = t;
            var k = {"waiting_shipping":"ship","in_delivery":"del","waiting_refund":"ref","completed":"done"}[t];
            document.querySelectorAll(".tab").forEach(function(x){ x.classList.remove("active"); });
            var el = document.getElementById("tab-"+k);
            if(el) el.classList.add("active");
        }
    }
})();

// ===== LOAD ORDERS =====
async function load(){
    var el = document.getElementById("ordersList");
    var orders = null;

    // Try token first
    if(token){
        try {
            var r = await fetch("/my-store-orders", {
                headers: {"Authorization": "Bearer " + token},
                credentials: "include"
            });
            if(r.ok){ var d = await r.json(); if(d.success) orders = d.orders; }
        } catch(e){}
    }

    // Fallback: use email
    if(orders === null && user.email){
        try {
            var r2 = await fetch("/store-orders-by-email/" + encodeURIComponent(user.email), { credentials:"include" });
            if(r2.ok){ var d2 = await r2.json(); if(d2.success) orders = d2.orders; }
        } catch(e){}
    }

    if(orders === null){
        el.innerHTML = '<div class="empty"><div class="empty-icon">🔐</div><p>Please <a href="/login-page" style="color:#1976d2;">login again</a></p></div>';
        return;
    }

    allOrders = orders;
    // Update counts
    ["waiting_shipping","in_delivery","waiting_refund","completed"].forEach(function(s){
        var k = {"waiting_shipping":"ship","in_delivery":"del","waiting_refund":"ref","completed":"done"}[s];
        var n = allOrders.filter(function(o){ return o.status===s; }).length;
        var ce = document.getElementById("cnt-"+k);
        if(ce){ ce.innerText = n; ce.style.display = n>0?"":"none"; }
    });
    render();
}

function render(){
    var list = allOrders.filter(function(o){ return o.status===currentTab; });
    var el = document.getElementById("ordersList");
    if(list.length === 0){
        el.innerHTML = '<div class="empty"><div class="empty-icon">📦</div><p>No orders here</p></div>';
        return;
    }
    el.innerHTML = "";
    list.forEach(function(o){ el.appendChild(buildCard(o)); });
}

function switchTab(t){
    currentTab = t;
    document.querySelectorAll(".tab").forEach(function(x){ x.classList.remove("active"); });
    var k = {"waiting_shipping":"ship","in_delivery":"del","waiting_refund":"ref","completed":"done"}[t];
    var el = document.getElementById("tab-"+k);
    if(el) el.classList.add("active");
    render();
}

function orderNum(id){
    var s = String(id).replace(/\\D/g,"");
    if(s.length>=11) return s.slice(-11);
    while(s.length<11) s="0"+s;
    return s;
}

var catMap = {17:"17_Clothing_and_Accessories",19:"19_Medical_Bags_and_Sunglasses",20:"20_Shoes",21:"21_Watches",22:"22_Jewelry",27:"27_Electronics",28:"28_Smart_Home",31:"31_Luxury_Brands",32:"32_Beauty_and_Personal_Care",34:"34_Mens_Fashion",35:"35_Health_and_Household",36:"36_Home_and_Kitchen"};

function imgUrl(o){
    var cat = catMap[(o.product&&o.product.category_id)] || "27_Electronics";
    var folder = o.product&&o.product.folder ? o.product.folder : "";
    if(!folder) return "https://via.placeholder.com/65x65?text=No+Image";
    return "https://res.cloudinary.com/doabtbdsh/image/upload/products/"+cat+"/"+folder+"/1.jpg";
}

function buildCard(o){
    var card = document.createElement("div");
    card.className = "ocard";
    var labels = {waiting_shipping:"Waiting to Ship",in_delivery:"In Delivery",waiting_refund:"Pending Confirmation",completed:"Delivered"};
    var cls = {waiting_shipping:"ship",in_delivery:"del",waiting_refund:"ref",completed:"done"};
    var num = orderNum(o.id);
    var img = imgUrl(o);
    var qty = parseInt(o.quantity||1);
    var retailPrice = parseFloat(o.total||0);
    var supplierPrice = parseFloat(o.supplierPrice||0)*qty;
    var profit = parseFloat(o.profit||0)*qty;
    var createdDate = o.createdAt ? new Date(o.createdAt).toLocaleString() : "-";
    var shippedDate = o.shippedAt ? new Date(o.shippedAt).toLocaleString() : "-";
    var deliveredDate = o.deliveredAt ? new Date(o.deliveredAt).toLocaleString() : "-";

    // --- TOP ROW: order number + status badge (no colored border) ---
    var html = '<div class="ocard-top">' +
        '<span class="order-id">#'+num+'</span>' +
        '<span class="sbadge '+cls[o.status]+'" style="background:transparent;border:none;color:'+(o.status==="waiting_shipping"?"#1976d2":o.status==="in_delivery"?"#1976d2":o.status==="waiting_refund"?"#e65100":"#2e7d32")+';font-weight:700;">'+labels[o.status]+'</span>' +
        '</div>';

    // --- PRODUCT ROW ---
    html += '<div class="ocard-mid">' +
        '<img class="ocard-img" src="'+img+'" onerror="this.src=\\'https://via.placeholder.com/65x65\\'">' +
        '<div style="flex:1;">' +
        '<div class="ocard-title">'+(o.product?o.product.title:"Product")+'</div>' +
        '<div style="font-size:12px;color:#555;margin-top:2px;">Qty: '+qty+'</div>' +
        '<div class="ocard-price">US$'+parseFloat(o.product&&o.product.price||0).toFixed(2)+' &times; '+qty+' = US$'+retailPrice.toFixed(2)+'</div>' +
        '</div></div>';

    // --- ORDER DETAILS ---
    html += '<div style="margin:8px 0;padding:8px 10px;background:#f9f9f9;border-radius:8px;font-size:12px;color:#555;line-height:1.9;">' +
        '<div style="display:flex;justify-content:space-between;"><span>Supplier Cost</span><span style="color:#e65100;font-weight:600;">US$'+supplierPrice.toFixed(2)+'</span></div>' +
        '<div style="display:flex;justify-content:space-between;"><span>Retail Price</span><span style="color:#1976d2;font-weight:600;">US$'+retailPrice.toFixed(2)+'</span></div>' +
        '<div style="display:flex;justify-content:space-between;"><span>Profit</span><span style="color:#2e7d32;font-weight:700;">+US$'+profit.toFixed(2)+'</span></div>' +
        '<div style="display:flex;justify-content:space-between;border-top:1px solid #eee;margin-top:4px;padding-top:4px;"><span>Order Date</span><span>'+createdDate+'</span></div>' +
        (o.status==="in_delivery"||o.status==="waiting_refund"||o.status==="completed" ? '<div style="display:flex;justify-content:space-between;"><span>Shipped Date</span><span>'+shippedDate+'</span></div>' : '') +
        (o.status==="waiting_refund"||o.status==="completed" ? '<div style="display:flex;justify-content:space-between;"><span>Delivered Date</span><span>'+deliveredDate+'</span></div>' : '') +
        '</div>';

    if(o.status === "waiting_shipping"){
        var created = new Date(o.createdAt).getTime();
        var remaining = Math.max(0, created + 48*60*60*1000 - Date.now());
        var isTO = remaining === 0;
        html += '<div class="countdown" id="cd-'+o.id+'" style="'+(isTO?"background:#fce4ec;color:#c62828;":"")+'">' +
            '⏱ '+(isTO?'<b>⏰ TIME OUT</b>':'Ship within: <b id="cdt-'+o.id+'">'+fmtTime(remaining)+'</b>')+'</div>';
        html += '<button class="ship-btn" onclick="event.stopPropagation();openShipPopup(\\''+ o.id +'\\')">Ship Now</button>';
    }

    if(o.status === "in_delivery"){
        html += '<div class="map-wrap"><canvas class="map-canvas" id="map-'+o.id+'"></canvas><span class="map-label">📍 In transit</span></div>';
    }

    if(o.status === "waiting_refund"){
        html += '<div class="map-wrap"><canvas class="map-canvas" id="map-ref-'+o.id+'"></canvas><span class="map-label">📍 Arrived Now</span></div>';
        html += '<div style="background:white;border-radius:10px;padding:10px;font-size:13px;color:#e65100;font-weight:600;text-align:center;border:1px solid #eee;">⏳ Pending Confirmation</div>';
    }

    if(o.status === "completed"){
        html += '<div style="background:white;border-radius:10px;padding:10px;font-size:13px;color:#2e7d32;font-weight:600;text-align:center;border:1px solid #eee;">✅ Profit added to wallet</div>';
    }

    card.innerHTML = html;

    if(o.status === "waiting_shipping"){
        card.onclick = function(e){ if(e.target.tagName==="BUTTON") return; openProdModal(o); };
        startCd(o.id, o.createdAt);
    }
    if(o.status === "in_delivery"){
        card.onclick = function(){ openTrackModal(o); };
        setTimeout(function(){ drawMap("map-"+o.id, o.trackingPath, o.deliveryStart); }, 100);
    }
    if(o.status === "waiting_refund"){
        card.onclick = function(){ showToast("⏳ Order is pending delivery confirmation"); };
        setTimeout(function(){ drawMap("map-ref-"+o.id, o.trackingPath, o.deliveryStart); }, 100);
    }
    if(o.status === "completed"){
        card.onclick = function(){ showToast("✅ Profit has been credited to your wallet"); };
    }
    return card;
}

function startCd(id, createdAt){
    var deadline = new Date(createdAt).getTime() + 48*60*60*1000;
    var t = setInterval(function(){
        var r = Math.max(0, deadline - Date.now());
        var el = document.getElementById("cdt-"+id);
        var wrap = document.getElementById("cd-"+id);
        if(r === 0){
            clearInterval(t);
            if(wrap){ wrap.style.background="#fce4ec"; wrap.style.color="#c62828"; wrap.innerHTML="⏱ <b>⏰ TIME OUT</b>"; }
        } else {
            if(el) el.innerText = fmtTime(r);
        }
    }, 1000);
}

function fmtTime(ms){
    var s=Math.floor(ms/1000), h=Math.floor(s/3600), m=Math.floor((s%3600)/60), sec=s%60;
    return pad(h)+":"+pad(m)+":"+pad(sec);
}
function pad(n){ return n<10?"0"+n:""+n; }

// ===== SHIP POPUP =====
function openShipPopup(id){
    var o = allOrders.find(function(x){ return x.id===id; });
    if(!o) return;
    pendingOrderId = id;
    var sup = parseFloat(o.supplierPrice||0)*parseInt(o.quantity||1);
    var ret = parseFloat(o.total||0);
    var pro = parseFloat(o.profit||0)*parseInt(o.quantity||1);
    document.getElementById("sp-num").innerText = orderNum(o.id);
    document.getElementById("sp-sup").innerText = "US$"+sup.toFixed(2);
    document.getElementById("sp-ret").innerText = "US$"+ret.toFixed(2);
    document.getElementById("sp-pro").innerText = "US$"+pro.toFixed(2);
    document.getElementById("shipPopup").classList.add("open");
    closeProdModal();
}
function closeShipPopup(){
    document.getElementById("shipPopup").classList.remove("open");
}
function openPwdPopup(){
    if(!pendingOrderId) return;
    document.getElementById("shipPopup").classList.remove("open");
    document.getElementById("pwdInput").value = "";
    document.getElementById("pwdPopup").classList.add("open");
}
function closePwdPopup(){
    document.getElementById("pwdPopup").classList.remove("open");
}

async function doShip(){
    var pwd = document.getElementById("pwdInput").value;
    if(!pwd){ showToast("⚠️ Enter your password"); return; }
    if(!pendingOrderId){ closePwdPopup(); return; }

    // Verify password
    try {
        var vr = await fetch("/login", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify({ email: user.email, password: pwd })
        });
        var vd = await vr.json();
        if(vd.error){ showToast("❌ Wrong password"); document.getElementById("pwdInput").value=""; return; }
    } catch(e){ showToast("⚠️ Error"); return; }

    var id = pendingOrderId;
    closePwdPopup();
    pendingOrderId = null;

    try {
        var r = await fetch("/ship-store-order", {
            method:"POST",
            headers:{"Content-Type":"application/json","Authorization":"Bearer "+token},
            credentials:"include",
            body: JSON.stringify({ orderId: id })
        });
        var d = await r.json();
        if(d.success){ showToast("✅ Shipped successfully!"); load(); }
        else showToast("⚠️ " + (d.message||"Failed"));
    } catch(e){ showToast("⚠️ Network error"); }
}

// ===== PRODUCT MODAL =====
function openProdModal(o){
    var cat = catMap[(o.product&&o.product.category_id)] || "27_Electronics";
    var folder = o.product&&o.product.folder ? o.product.folder : "";
    var base = "https://res.cloudinary.com/doabtbdsh/image/upload/products/";
    slideImgs = folder ? [1,2,3,4,5,6,7,8].map(function(i){ return base+cat+"/"+folder+"/"+i+".jpg"; }) : ["https://via.placeholder.com/400x260?text=No+Image"];
    slideIdx = 0;

    var track = document.getElementById("sliderTrack");
    var dots = document.getElementById("sliderDots");
    track.innerHTML = "";
    dots.innerHTML = "";
    slideImgs.forEach(function(src,i){
        var img = document.createElement("img");
        img.className = "slide"; img.src = src;
        track.appendChild(img);
        var dot = document.createElement("div");
        dot.className = "dot"+(i===0?" active":"");
        dot.onclick = (function(idx){ return function(){ goSlide(idx); }; })(i);
        dots.appendChild(dot);
    });
    updateSlider();

    document.getElementById("pm-title").innerText = o.product ? o.product.title : "Product";
    document.getElementById("pm-price").innerText = "US$"+parseFloat(o.total||0).toFixed(2);
    document.getElementById("pm-profit").innerText = "+US$"+parseFloat(o.profit*(o.quantity||1)||0).toFixed(2)+" profit";

    // Countdown
    if(modalCdTimer) clearInterval(modalCdTimer);
    var deadline = new Date(o.createdAt).getTime() + 48*60*60*1000;
    function tick(){
        var r = Math.max(0, deadline - Date.now());
        var el = document.getElementById("pm-cd");
        var wrap = document.getElementById("pm-countdown");
        if(r===0){ clearInterval(modalCdTimer); if(wrap){ wrap.style.background="#fce4ec"; wrap.style.color="#c62828"; wrap.innerHTML="⏰ TIME OUT"; } }
        else { if(el) el.innerText = fmtTime(r); }
    }
    tick();
    modalCdTimer = setInterval(tick, 1000);

    // Store current order id for shipFromModal
    document.getElementById("prodModal").dataset.orderId = o.id;
    document.getElementById("prodModal").classList.add("open");
}
function closeProdModal(){
    document.getElementById("prodModal").classList.remove("open");
    if(modalCdTimer){ clearInterval(modalCdTimer); modalCdTimer=null; }
}
function shipFromModal(){
    var id = document.getElementById("prodModal").dataset.orderId;
    if(id) openShipPopup(id);
}
function slideMove(d){ goSlide(slideIdx+d); }
function goSlide(i){ slideIdx=(i+slideImgs.length)%slideImgs.length; updateSlider(); }
function updateSlider(){
    document.getElementById("sliderTrack").style.transform="translateX(-"+slideIdx*100+"%)";
    var ds=document.getElementById("sliderDots").children;
    for(var i=0;i<ds.length;i++) ds[i].classList.toggle("active",i===slideIdx);
}

// ===== TRACKING MODAL =====
function openTrackModal(o){
    document.getElementById("track-num").innerText = "#"+orderNum(o.id);
    document.getElementById("track-title").innerText = o.product ? o.product.title : "";
    var tp = o.trackingPath;
    if(tp){
        document.getElementById("track-route").innerHTML =
            "<b>📍 Route:</b> "+(tp.origin?tp.origin.name:"?")+" → "+(tp.destination?tp.destination.name:"?")+
            "<br><span style='color:#1976d2;font-weight:600;'>✈ Package is on the way</span>";
    }
    document.getElementById("trackModal").classList.add("open");
    setTimeout(function(){
        var c = document.getElementById("track-canvas");
        if(!c) return;
        c.width = c.offsetWidth||400; c.height = c.offsetHeight||200;
        drawMap2(c, o.trackingPath, o.deliveryStart);
    }, 100);
}
function closeTrackModal(){ document.getElementById("trackModal").classList.remove("open"); }

function drawMap(canvasId, tp, ds){
    var c = document.getElementById(canvasId);
    if(!c) return;
    c.width=c.offsetWidth; c.height=c.offsetHeight;
    drawMap2(c, tp, ds);
}
function drawMap2(c, tp, ds){
    if(!tp||!c) return;
    var ctx=c.getContext("2d"), W=c.width, H=c.height;
    var g=ctx.createLinearGradient(0,0,W,H); g.addColorStop(0,"#e3f2fd"); g.addColorStop(1,"#bbdefb");
    ctx.fillStyle=g; ctx.fillRect(0,0,W,H);
    ctx.fillStyle="rgba(25,118,210,0.08)";
    [[0.15,0.35,60],[0.5,0.4,80],[0.75,0.55,55],[0.85,0.45,45]].forEach(function(c2){
        ctx.beginPath(); ctx.arc(c2[0]*W,c2[1]*H,c2[2],0,Math.PI*2); ctx.fill();
    });
    function tc(lat,lng){ return {x:((lng+180)/360)*W, y:((90-lat)/180)*H}; }
    var p0=tc(tp.origin.lat,tp.origin.lng), p1=tc(tp.midpoint.lat,tp.midpoint.lng), p2=tc(tp.destination.lat,tp.destination.lng);
    var elapsed=ds?Date.now()-ds:0, prog=Math.min(1,elapsed/(72*60*60*1000));
    ctx.setLineDash([5,4]); ctx.strokeStyle="rgba(25,118,210,0.3)"; ctx.lineWidth=2;
    ctx.beginPath(); ctx.moveTo(p0.x,p0.y); ctx.quadraticCurveTo(p1.x,p1.y,p2.x,p2.y); ctx.stroke();
    ctx.setLineDash([]); ctx.strokeStyle="#1976d2"; ctx.lineWidth=2.5; ctx.beginPath(); ctx.moveTo(p0.x,p0.y);
    for(var t=0;t<=prog;t+=1/60){ var bx=(1-t)*(1-t)*p0.x+2*(1-t)*t*p1.x+t*t*p2.x, by=(1-t)*(1-t)*p0.y+2*(1-t)*t*p1.y+t*t*p2.y; ctx.lineTo(bx,by); }
    ctx.stroke();
    var pt=prog, px=(1-pt)*(1-pt)*p0.x+2*(1-pt)*pt*p1.x+pt*pt*p2.x, py=(1-pt)*(1-pt)*p0.y+2*(1-pt)*pt*p1.y+pt*pt*p2.y;
    ctx.fillStyle="#1976d2"; ctx.beginPath(); ctx.arc(px,py,7,0,Math.PI*2); ctx.fill();
    ctx.fillStyle="white"; ctx.font="10px Arial"; ctx.textAlign="center"; ctx.textBaseline="middle"; ctx.fillText("✈",px,py);
    [[p0,"🏭"],[p2,"📍"]].forEach(function(item){
        ctx.fillStyle="#ff6b35"; ctx.beginPath(); ctx.arc(item[0].x,item[0].y,5,0,Math.PI*2); ctx.fill();
        ctx.fillStyle="#333"; ctx.font="11px Arial"; ctx.textAlign="center"; ctx.textBaseline="middle"; ctx.fillText(item[1],item[0].x,item[0].y-12);
    });
    ctx.fillStyle="#1976d2"; ctx.font="bold 9px Arial"; ctx.textAlign="left"; ctx.fillText(tp.origin.name,Math.max(2,p0.x-20),p0.y+14);
    ctx.textAlign="right"; ctx.fillText(tp.destination.name,Math.min(W-2,p2.x+20),p2.y+14);
}

function showToast(msg){ var t=document.getElementById("toast"); t.innerText=msg; t.classList.add("show"); setTimeout(function(){ t.classList.remove("show"); },2500); }

// Start loading immediately
load();
setInterval(load, 30000);
</script>
</body>
</html>`);
});



// =================== STORE SETTING PAGE ===================
app.get("/store-setting", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta charset="UTF-8">
<title>Store Setting</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fb;min-height:100vh;padding-bottom:30px;}
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100;box-shadow:0 2px 8px rgba(25,118,210,0.3);}
.header h2{font-size:16px;font-weight:700;}
.section{background:white;margin:12px;border-radius:16px;padding:18px;box-shadow:0 2px 10px rgba(0,0,0,0.07);}
.section h3{font-size:14px;font-weight:700;color:#333;margin-bottom:16px;}

/* Logo Upload */
.logo-wrap{display:flex;flex-direction:column;align-items:center;gap:12px;}
.logo-preview{width:90px;height:90px;border-radius:50%;object-fit:cover;border:3px solid #e0e0e0;cursor:pointer;transition:opacity 0.2s;}
.logo-preview:hover{opacity:0.8;}
.logo-hint{font-size:12px;color:#aaa;text-align:center;}
.change-logo-btn{padding:9px 22px;border:1.5px solid #1976d2;border-radius:10px;background:white;color:#1976d2;font-size:13px;font-weight:600;cursor:pointer;}

/* Name Input */
.input-group{margin-bottom:14px;}
.input-label{font-size:12px;color:#888;font-weight:600;margin-bottom:6px;display:block;}
.text-input{width:100%;border:1.5px solid #e0e0e0;border-radius:10px;padding:11px 13px;font-size:14px;outline:none;color:#222;transition:border-color 0.2s;}
.text-input:focus{border-color:#1976d2;}

/* Save button */
.save-btn{width:100%;padding:14px;border:none;border-radius:12px;background:linear-gradient(135deg,#1976d2,#1565c0);color:white;font-size:15px;font-weight:700;cursor:pointer;transition:opacity 0.2s;margin-top:4px;}
.save-btn:active{opacity:0.88;}

.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#2e7d32;color:white;padding:11px 22px;border-radius:25px;font-size:13px;font-weight:600;z-index:1000;display:none;white-space:nowrap;}
.toast.show{display:block;animation:fadeUp 0.3s ease;}
@keyframes fadeUp{from{opacity:0;transform:translate(-50%,15px);}to{opacity:1;transform:translate(-50%,0);}}
</style>
</head>
<body>
<div class="header">
  <span onclick="history.back()" style="cursor:pointer;display:inline-flex;">
    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
  </span>
  <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
</div>

<div class="section">
  <h3>🖼️ Store Logo</h3>
  <div class="logo-wrap">
    <img id="logoPreview" class="logo-preview" src="https://cdn-icons-png.flaticon.com/512/149/149071.png" onclick="document.getElementById('logoInput').click()">
    <p class="logo-hint">Tap to change your store logo</p>
    <button class="change-logo-btn" onclick="document.getElementById('logoInput').click()">Change Logo</button>
    <input type="file" id="logoInput" accept="image/*" style="display:none" onchange="previewLogo(this)">
  </div>
</div>

<div class="section">
  <h3>✏️ Store Name</h3>
  <div class="input-group">
    <label class="input-label">Store Name</label>
    <input class="text-input" id="storeNameInput" type="text" placeholder="Enter your store name" maxlength="40">
  </div>
  <button class="save-btn" onclick="saveSettings()">Save Changes</button>
</div>

<div class="toast" id="toast"></div>

<script>
var myToken = localStorage.getItem("token") || "";
var newLogoData = null;

async function init(){
    try {
        var user = JSON.parse(localStorage.getItem("user") || "{}");
        if(!user.email) return;
        var r = await fetch("/store-status/" + encodeURIComponent(user.email));
        var d = await r.json();
        if(d.found){
            document.getElementById("storeNameInput").value = d.storeName || "";
            if(d.storeLogo && d.storeLogo.length > 10){
                document.getElementById("logoPreview").src = d.storeLogo;
            }
        }
    } catch(e){}
}

function previewLogo(input){
    if(!input.files || !input.files[0]) return;
    var reader = new FileReader();
    reader.onload = function(e){
        newLogoData = e.target.result;
        document.getElementById("logoPreview").src = newLogoData;
    };
    reader.readAsDataURL(input.files[0]);
}

async function saveSettings(){
    var name = document.getElementById("storeNameInput").value.trim();
    if(!name){ showToast("⚠️ Please enter a store name"); return; }

    var body = { storeName: name };
    if(newLogoData) body.storeLogo = newLogoData;

    try {
        var r = await fetch("/update-store-settings", {
            method:"POST",
            headers:{"Content-Type":"application/json","Authorization":"Bearer "+myToken},
            body: JSON.stringify(body)
        });
        var d = await r.json();
        if(d.success){
            // Update localStorage
            var user = JSON.parse(localStorage.getItem("user") || "{}");
            if(user.email){
                localStorage.setItem("merchant_storeName_" + user.email, name);
                if(newLogoData) localStorage.setItem("merchant_storeLogo_" + user.email, newLogoData);
            }
            showToast("✅ Settings saved!");
        } else showToast("⚠️ " + (d.message||"Failed to save"));
    } catch(e){ showToast("⚠️ Network error"); }
}

function showToast(msg){ var t=document.getElementById("toast"); t.innerText=msg; t.classList.add("show"); setTimeout(function(){ t.classList.remove("show"); },2500); }
init();
</script>
</body>
</html>`);
});

// =================== INSTRUCTIONS FOR OPERATION PAGE ===================
app.get("/instructions", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta charset="UTF-8">
<title>Instructions - TikTok Mall</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fb;min-height:100vh;padding-bottom:40px;}
.header{background:#010101;color:white;padding:12px 15px;display:flex;align-items:center;gap:12px;box-shadow:0 2px 8px rgba(0,0,0,0.4);}
.header h2{font-size:16px;font-weight:700;color:white;}

/* HERO */
.hero{background:#010101;padding:28px 20px 36px;text-align:center;color:white;position:relative;overflow:hidden;}
.hero::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 30% 50%,rgba(105,201,208,0.15) 0%,transparent 60%),radial-gradient(ellipse at 70% 50%,rgba(255,0,80,0.12) 0%,transparent 60%);}
.tiktok-logo{display:inline-flex;align-items:center;justify-content:center;margin-bottom:14px;position:relative;z-index:1;}
.tiktok-logo svg{width:64px;height:64px;}
.hero h1{font-size:26px;font-weight:900;margin-bottom:10px;letter-spacing:0.5px;position:relative;z-index:1;}
.hero h1 span.tt1{color:#69c9d0;}
.hero h1 span.tt2{color:#ee1d52;}
.hero p{font-size:13px;opacity:0.85;line-height:1.8;max-width:340px;margin:0 auto;position:relative;z-index:1;}

/* STATS BAR */
.stats-bar{display:flex;background:#111;color:white;padding:14px 0;}
.stat-item{flex:1;text-align:center;border-right:1px solid #333;}
.stat-item:last-child{border-right:none;}
.stat-num{font-size:18px;font-weight:800;color:#69c9d0;}
.stat-label{font-size:10px;color:#888;margin-top:2px;}

/* SECTION */
.section{background:white;margin:12px;border-radius:16px;padding:18px;box-shadow:0 2px 10px rgba(0,0,0,0.07);}
.section h3{font-size:15px;font-weight:700;color:#010101;margin-bottom:14px;display:flex;align-items:center;gap:8px;}

/* STEP */
.step{display:flex;gap:12px;align-items:flex-start;margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid #f5f5f5;}
.step:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0;}
.step-num{width:34px;height:34px;border-radius:50%;background:#010101;color:white;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:800;flex-shrink:0;border:2px solid #ee1d52;}
.step-text h4{font-size:13px;font-weight:700;color:#111;margin-bottom:5px;}
.step-text p{font-size:12px;color:#666;line-height:1.7;}
.step-text .badge{display:inline-block;background:#f0f0f0;border-radius:6px;font-size:11px;padding:2px 8px;margin-top:5px;color:#333;}

/* VIP */
.vip-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
.vip-card{border:1.5px solid #e0e0e0;border-radius:14px;padding:14px 12px;text-align:center;transition:transform 0.15s;}
.vip-card:active{transform:scale(0.97);}
.vip-card .vip-name{font-size:14px;font-weight:800;color:#111;margin-bottom:5px;}
.vip-card .vip-pcts{font-size:11px;color:#666;line-height:1.8;}
.vip-card .vip-disc{font-size:13px;font-weight:700;color:#2e7d32;}
.vip-card.top{border-color:#ee1d52;background:linear-gradient(135deg,#fff5f5,white);}
.vip-card.top .vip-name{color:#ee1d52;}
.vip-card.top .vip-disc{color:#ee1d52;}

/* HIGHLIGHT */
.highlight{background:#f9f9f9;border-left:4px solid #010101;border-radius:0 10px 10px 0;padding:14px 16px;font-size:13px;color:#222;line-height:1.8;margin-top:4px;}

/* FAQ */
.faq-item{border-bottom:1px solid #f0f0f0;padding:14px 0;}
.faq-item:last-child{border-bottom:none;}
.faq-q{font-size:13px;font-weight:700;color:#111;cursor:pointer;display:flex;justify-content:space-between;align-items:center;}
.faq-a{font-size:12px;color:#666;line-height:1.7;margin-top:8px;display:none;}
.faq-item.open .faq-a{display:block;}
.faq-item.open .faq-arr{transform:rotate(180deg);}
.faq-arr{transition:transform 0.2s;color:#aaa;}

/* EARNING TABLE */
.earn-table{width:100%;border-collapse:collapse;font-size:12px;}
.earn-table th{background:#010101;color:white;padding:9px 8px;text-align:center;}
.earn-table td{padding:9px 8px;text-align:center;border-bottom:1px solid #f0f0f0;}
.earn-table tr:last-child td{border-bottom:none;}
.earn-table tr:nth-child(even) td{background:#fafafa;}
</style>
</head>
<body>

<div class="header">
  <span onclick="history.back()" style="cursor:pointer;display:inline-flex;">
    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
  </span>
  <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
  <h2>Instructions for Operation</h2>
</div>

<!-- HERO -->
<div class="hero">
  <div class="tiktok-logo">
    <!-- TikTok official logo SVG -->
    <svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" fill="none">
      <rect width="48" height="48" rx="10" fill="#010101"/>
      <path d="M34.2 14.6c-1.7-1.1-3-2.8-3.5-4.8H27v20.4c0 2-1.6 3.6-3.6 3.6s-3.6-1.6-3.6-3.6 1.6-3.6 3.6-3.6c.4 0 .7.1 1.1.2v-4.1c-.4-.1-.7-.1-1.1-.1-4.3 0-7.8 3.5-7.8 7.8s3.5 7.8 7.8 7.8 7.8-3.5 7.8-7.8V20.3c1.5 1.1 3.4 1.7 5.3 1.7v-4.1c-1 0-2-.3-2.3-.3z" fill="white"/>
      <path d="M34.2 14.6c-1.7-1.1-3-2.8-3.5-4.8H27v20.4c0 2-1.6 3.6-3.6 3.6s-3.6-1.6-3.6-3.6 1.6-3.6 3.6-3.6c.4 0 .7.1 1.1.2v-4.1c-.4-.1-.7-.1-1.1-.1-4.3 0-7.8 3.5-7.8 7.8s3.5 7.8 7.8 7.8 7.8-3.5 7.8-7.8V20.3c1.5 1.1 3.4 1.7 5.3 1.7v-4.1c-1 0-2-.3-2.3-.3z" fill="#ee1d52" opacity="0.6"/>
      <path d="M31.7 15.2c1.7 1.1 3.6 1.7 5.6 1.7v-4.1c-1.1 0-2.2-.4-3.1-1c-.8-.6-1.4-1.4-1.7-2.3H28v20.7c-.1 1.9-1.7 3.4-3.6 3.4s-3.6-1.6-3.6-3.6 1.6-3.6 3.6-3.6c.4 0 .7.1 1.1.2v-4.1c-4.1.1-7.4 3.4-7.4 7.5s3.4 7.5 7.5 7.5 7.5-3.4 7.5-7.5l.1-14.8z" fill="#69c9d0" opacity="0.7"/>
    </svg>
  </div>
  <h1><span class="tt1">TikTok</span> <span class="tt2">Mall</span></h1>
  <p>The world's #1 social commerce platform — powering millions of merchants to build profitable online stores and earn real income from home.</p>
</div>

<!-- STATS BAR -->
<div class="stats-bar">
  <div class="stat-item"><div class="stat-num">50K+</div><div class="stat-label">Products</div></div>
  <div class="stat-item"><div class="stat-num">12</div><div class="stat-label">Categories</div></div>
  <div class="stat-item"><div class="stat-num">40%</div><div class="stat-label">Max Profit</div></div>
  <div class="stat-item"><div class="stat-num">3-Day</div><div class="stat-label">Delivery</div></div>
</div>

<!-- HOW IT WORKS -->
<div class="section">
  <h3>🚀 How It Works</h3>
  <div class="step">
    <div class="step-num">1</div>
    <div class="step-text">
      <h4>Register & Open Your Store</h4>
      <p>Sign up with an invite code and apply for a merchant account. Once approved, your personalized TikTok Mall store is instantly live and accessible to customers worldwide. Customize your store name and logo to build your brand identity.</p>
      <span class="badge">⏱ Takes under 5 minutes</span>
    </div>
  </div>
  <div class="step">
    <div class="step-num">2</div>
    <div class="step-text">
      <h4>Browse & Add Products to Your Store</h4>
      <p>Access 50,000+ premium products from verified global suppliers across 12 categories — Electronics, Watches, Luxury Brands, Beauty, Shoes, Jewelry, and more. Add any product to your store with a single tap. No inventory needed — you never hold stock.</p>
      <span class="badge">📦 0 inventory required</span>
    </div>
  </div>
  <div class="step">
    <div class="step-num">3</div>
    <div class="step-text">
      <h4>Customers Buy From Your Store</h4>
      <p>When a customer purchases from your store, the full retail price is credited to your account. Your working capital is only used to pay the discounted supplier price at the moment you confirm shipment — meaning you earn the difference as pure profit.</p>
      <span class="badge">💰 Pay supplier only when you ship</span>
    </div>
  </div>
  <div class="step">
    <div class="step-num">4</div>
    <div class="step-text">
      <h4>Confirm Shipment Within 48 Hours</h4>
      <p>After receiving an order, you have 48 hours to confirm shipment. A countdown timer is shown for every pending order. Use your account password to authorize the shipment — this deducts the supplier cost from your balance and triggers the delivery process.</p>
      <span class="badge">⏰ 48-hour shipping window</span>
    </div>
  </div>
  <div class="step">
    <div class="step-num">5</div>
    <div class="step-text">
      <h4>Track & Collect Your Profits</h4>
      <p>Every order includes real-time tracking with a live map showing the shipment route from origin warehouse to the customer. After the 3-day delivery window, your profit is automatically credited to your wallet — ready to withdraw anytime.</p>
      <span class="badge">🗺 Live tracking map per order</span>
    </div>
  </div>
</div>

<!-- VIP LEVELS -->
<div class="section">
  <h3>💎 VIP Commission Levels</h3>
  <p style="font-size:12px;color:#888;margin-bottom:12px;line-height:1.6;">Your VIP level determines how many products you can list and how large your supplier discount is. Upgrade by maintaining a sufficient working capital balance.</p>
  <div class="vip-grid">
    <div class="vip-card"><div class="vip-name">VIP 0</div><div class="vip-pcts">Up to 20 products<br>50 daily visitors<br><span class="vip-disc">15% supplier discount</span></div></div>
    <div class="vip-card"><div class="vip-name">VIP 1</div><div class="vip-pcts">Up to 35 products<br>600 daily visitors<br><span class="vip-disc">17% supplier discount</span></div></div>
    <div class="vip-card"><div class="vip-name">VIP 2</div><div class="vip-pcts">Up to 80 products<br>1,000 daily visitors<br><span class="vip-disc">20% supplier discount</span></div></div>
    <div class="vip-card"><div class="vip-name">VIP 3</div><div class="vip-pcts">Up to 120 products<br>3,000 daily visitors<br><span class="vip-disc">22% supplier discount</span></div></div>
    <div class="vip-card"><div class="vip-name">VIP 4</div><div class="vip-pcts">Up to 300 products<br>10,000 daily visitors<br><span class="vip-disc">25% supplier discount</span></div></div>
    <div class="vip-card top"><div class="vip-name">VIP 5 ⭐</div><div class="vip-pcts">Up to 1,000 products<br>30,000 daily visitors<br><span class="vip-disc">40% supplier discount</span></div></div>
  </div>
</div>

<!-- EARNINGS TABLE -->
<div class="section">
  <h3>📊 Estimated Earnings Example</h3>
  <p style="font-size:12px;color:#888;margin-bottom:12px;">Based on a $100 product sold at retail price:</p>
  <table class="earn-table">
    <tr><th>VIP Level</th><th>Supplier Price</th><th>Your Profit</th><th>Profit %</th></tr>
    <tr><td>VIP 0</td><td>$85.00</td><td>$15.00</td><td>15%</td></tr>
    <tr><td>VIP 1</td><td>$83.00</td><td>$17.00</td><td>17%</td></tr>
    <tr><td>VIP 2</td><td>$80.00</td><td>$20.00</td><td>20%</td></tr>
    <tr><td>VIP 3</td><td>$78.00</td><td>$22.00</td><td>22%</td></tr>
    <tr><td>VIP 4</td><td>$75.00</td><td>$25.00</td><td>25%</td></tr>
    <tr><td style="color:#ee1d52;font-weight:700;">VIP 5</td><td style="color:#ee1d52;font-weight:700;">$60.00</td><td style="color:#ee1d52;font-weight:700;">$40.00</td><td style="color:#ee1d52;font-weight:700;">40%</td></tr>
  </table>
</div>

<!-- KEY RULES -->
<div class="section">
  <h3>📋 Platform Rules</h3>
  <div class="step">
    <div class="step-num">✓</div>
    <div class="step-text">
      <h4>48-Hour Shipping Commitment</h4>
      <p>You must confirm shipment within 48 hours of receiving an order. Failure to do so results in a TIME OUT status, which may affect your store's credibility rating. Always monitor your pending orders.</p>
    </div>
  </div>
  <div class="step">
    <div class="step-num">✓</div>
    <div class="step-text">
      <h4>Password-Protected Shipments</h4>
      <p>To authorize a shipment, you must enter your account password. This security step ensures only you can trigger payments and shipments from your store.</p>
    </div>
  </div>
  <div class="step">
    <div class="step-num">✓</div>
    <div class="step-text">
      <h4>3-Day Delivery Window</h4>
      <p>Every order is tracked in real-time on a live map. The delivery simulation runs over 72 hours. Once complete, the order moves to "Waiting for Refund" and your profit is released upon admin confirmation.</p>
    </div>
  </div>
  <div class="step">
    <div class="step-num">✓</div>
    <div class="step-text">
      <h4>Maintain Sufficient Working Capital</h4>
      <p>Your balance must cover the supplier cost at the time of shipment. If your balance is insufficient, you will not be able to confirm the shipment. Recharge your wallet regularly to keep your store operational.</p>
    </div>
  </div>
  <div class="step">
    <div class="step-num">✓</div>
    <div class="step-text">
      <h4>Store Credibility Rating</h4>
      <p>Your credibility rating increases with every completed order. A higher rating builds customer trust and is factored into your store's visibility and ranking on the platform.</p>
    </div>
  </div>
</div>

<!-- FAQ -->
<div class="section">
  <h3>❓ Frequently Asked Questions</h3>
  <div class="faq-item" onclick="this.classList.toggle('open')">
    <div class="faq-q">How do I receive payments from customers? <span class="faq-arr">▼</span></div>
    <div class="faq-a">Customer payments are collected by TikTok Mall and added to your available balance. You can withdraw your earnings at any time through the Wallet section using your registered USDT address.</div>
  </div>
  <div class="faq-item" onclick="this.classList.toggle('open')">
    <div class="faq-q">Do I need to handle shipping myself? <span class="faq-arr">▼</span></div>
    <div class="faq-a">No. TikTok Mall handles all logistics. When you confirm shipment, our supplier network dispatches the product directly to the customer. You simply authorize the transaction from your dashboard.</div>
  </div>
  <div class="faq-item" onclick="this.classList.toggle('open')">
    <div class="faq-q">When is my profit credited to my wallet? <span class="faq-arr">▼</span></div>
    <div class="faq-a">After the 3-day delivery window, the order moves to "Waiting for Refund" status. Once the platform admin confirms delivery, your profit (retail price minus supplier price) is instantly added to your Available Balance.</div>
  </div>
  <div class="faq-item" onclick="this.classList.toggle('open')">
    <div class="faq-q">How do I upgrade my VIP level? <span class="faq-arr">▼</span></div>
    <div class="faq-a">Go to Store Operating Fund in your merchant dashboard. Each VIP level requires a minimum working capital balance. Your balance must meet or exceed the required capital for the target level. Upgrading is free — no deduction is made.</div>
  </div>
  <div class="faq-item" onclick="this.classList.toggle('open')">
    <div class="faq-q">What happens if I miss the 48-hour shipping window? <span class="faq-arr">▼</span></div>
    <div class="faq-a">The order timer will show "TIME OUT". You can still ship the order, but it may negatively impact your credibility rating. We strongly recommend shipping all orders promptly to maintain a high rating.</div>
  </div>
</div>

<div class="section">
  <div class="highlight">
    💡 <strong>Pro Tip:</strong> Upgrade to VIP 5 to unlock the maximum 40% profit margin. A merchant selling 10 products per day at an average price of $200 can earn up to <strong>$800/day</strong> in pure profit at VIP 5 level.
  </div>
</div>

</body>
</html>`);
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
