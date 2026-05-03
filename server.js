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
        if(storeData.length > 0) storeApplications = storeData.map(u => { delete u._id; if(typeof u.followers !== "number") u.followers = 0; return u; });

        const ordersData = await db.collection("orders").find({}).toArray();
        if(ordersData.length > 0) ordersDB = ordersData.map(u => { delete u._id; return u; });

        const requestsData = await db.collection("requests").find({}).toArray();
        if(requestsData.length > 0) requests = requestsData.map(r => { delete r._id; return r; });

        // sync storeOrders from MongoDB
        const storeOrdersData = await db.collection("storeOrders").find({}).toArray();
        if(storeOrdersData.length > 0) {
            storeOrders = storeOrdersData.map(o => { delete o._id; return o; });
        }

        // ===== MIGRATION: replace Middle East destinations in old trackingPaths =====
        const middleEastNames = ["Dubai","Riyadh","Cairo","Doha","Kuwait","Muscat","Amman","Beirut","Baghdad","Abu Dhabi","Jeddah","New York","Toronto","Sydney","Los Angeles","Chicago","Houston","Dallas"];
        const safeDestinations = [
            { name: "London", lat: 51.5074, lng: -0.1278 },
            { name: "Paris", lat: 48.8566, lng: 2.3522 },
            { name: "Berlin", lat: 52.5200, lng: 13.4050 },
            { name: "Amsterdam", lat: 52.3676, lng: 4.9041 },
            { name: "Rome", lat: 41.9028, lng: 12.4964 },
            { name: "Madrid", lat: 40.4168, lng: -3.7038 },
            { name: "Vienna", lat: 48.2082, lng: 16.3738 },
            { name: "Stockholm", lat: 59.3293, lng: 18.0686 },
            { name: "Istanbul", lat: 41.0082, lng: 28.9784 },
            { name: "Warsaw", lat: 52.2297, lng: 21.0122 },
            { name: "Tokyo", lat: 35.6762, lng: 139.6503 },
            { name: "Seoul", lat: 37.5665, lng: 126.9780 },
            { name: "Singapore", lat: 1.3521, lng: 103.8198 },
            { name: "Bangkok", lat: 13.7563, lng: 100.5018 },
            { name: "Kuala Lumpur", lat: 3.1390, lng: 101.6869 },
            { name: "Osaka", lat: 34.6937, lng: 135.5023 },
            { name: "Taipei", lat: 25.0330, lng: 121.5654 },
            { name: "Mumbai", lat: 19.0760, lng: 72.8777 }
        ];
        let migrationCount = 0;
        storeOrders.forEach(order => {
            if(order.trackingPath && order.trackingPath.destination) {
                const destName = order.trackingPath.destination.name;
                if(middleEastNames.includes(destName)){
                    const newDest = safeDestinations[Math.floor(Math.random() * safeDestinations.length)];
                    const oLat = order.trackingPath.origin.lat, oLng = order.trackingPath.origin.lng;
                    order.trackingPath.destination = newDest;
                    order.trackingPath.midpoint = {
                        lat: (oLat + newDest.lat) / 2 + (Math.random() - 0.5) * 20,
                        lng: (oLng + newDest.lng) / 2 + (Math.random() - 0.5) * 30
                    };
                    migrationCount++;
                    // save to DB
                    if(db){
                        db.collection("storeOrders").updateOne(
                            { id: order.id },
                            { $set: { trackingPath: order.trackingPath } }
                        ).catch(err => console.error("Migration update error:", err.message));
                    }
                }
            }
        });
        if(migrationCount > 0) console.log("✅ Migrated "+migrationCount+" orders with Middle East destinations");
        // ===== END MIGRATION =====

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
<\/script>
<script>
// ======= GLOBAL TOAST / showMsg - يعمل في كل الصفحات =======
window.showMsg = function(msg, type){
  // type: 'error' (أحمر) | 'success' (أخضر) | 'info' (رمادي) - default error
  var color = type === 'success' ? '#28a745' : type === 'info' ? '#555' : '#e53935';
  var icon  = type === 'success' ? '✅' : type === 'info' ? 'ℹ️' : '❌';
  var el = document.createElement('div');
  el.innerText = icon + ' ' + msg;
  el.style.cssText = [
    'position:fixed','bottom:30px','left:50%','transform:translateX(-50%) translateY(20px)',
    'background:'+color,'color:white','padding:12px 22px','border-radius:12px',
    'font-size:14px','font-weight:bold','z-index:999999','box-shadow:0 4px 16px rgba(0,0,0,0.22)',
    'pointer-events:none','opacity:0','transition:opacity 0.25s,transform 0.25s','max-width:85vw','text-align:center'
  ].join(';');
  document.body.appendChild(el);
  requestAnimationFrame(function(){
    el.style.opacity='1';
    el.style.transform='translateX(-50%) translateY(0)';
  });
  setTimeout(function(){
    el.style.opacity='0';
    el.style.transform='translateX(-50%) translateY(20px)';
    setTimeout(function(){ if(el.parentNode) el.parentNode.removeChild(el); }, 300);
  }, 3000);
};
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
// ================= SECURITY HEADERS =================
app.use((req, res, next) => {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    res.removeHeader("X-Powered-By");
    next();
});


app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());


app.use(express.urlencoded({ limit: "5mb", extended: true }));

app.use((req, res, next) => {
    if (req.url === "/favicon.ico") {
        res.sendFile(__dirname + "/favicon.ico");
    } else {
        next();
    }
});

app.get("/", (req, res) => {
    res.redirect("/home");
});

// ================= PUBLIC HOME PAGE =================
require("./home")(app);

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
// تم تعطيل هذا الـ endpoint لأنه يكشف كود الاحتياطي
// app.get("/get-backup-code-public-DISABLED", (req, res) => {
//    res.json({ code: backupVerifyCode });
// });

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
app.post("/user-send", authMiddleware, (req, res) => {
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
app.get("/user-chat/:emailA/:emailB", authMiddleware, (req, res) => {
    const ua = req.params.emailA, ub = req.params.emailB;
    if (req.userEmail !== ua && req.userEmail !== ub) return res.status(403).json({ error: "Forbidden" });
    const chatId = getChatId(req.params.emailA, req.params.emailB);
    const chat = userChats.filter(m => m.chatId === chatId);
    res.json(chat);
});

// جلب كل المحادثات لمستخدم معين (آخر رسالة لكل محادثة)
app.get("/user-conversations/:email", authMiddleware, (req, res) => {
    if (req.userEmail !== req.params.email) return res.status(403).json({ error: "Forbidden" });
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
app.post("/send-message", authMiddleware, (req, res) => {
    const { email, text, sender, img } = req.body;

    if (!email || !sender) {
        return res.json({ success: false });
    }
    if (!text && !img) {
        return res.json({ success: false });
    }

    let msg = {
        id: Date.now(),
        email,
        text: text || "",
        sender, // "user" او "admin"
        time: new Date().toLocaleString(),
        seen: false
    };
    if (img) msg.img = img;

    messages.push(msg);

    res.json({ success: true });
});

// جلب رسائل مستخدم معين
app.get("/get-messages/:email", authMiddleware, (req, res) => {
    if (req.userEmail !== req.params.email) return res.status(403).json({ error: "Forbidden" });
    const userMessages = messages.filter(m => m.email === req.params.email);
    res.json(userMessages);
});

// عد الرسائل غير المقروءة لمستخدم معين
app.get("/unread-count/:email", authMiddleware, (req, res) => {
    if (req.userEmail !== req.params.email) return res.status(403).json({ error: "Forbidden" });
    const email = req.params.email;
    const lastSeen = parseInt(req.query.lastSeen || "0");
    const count = userChats.filter(m => m.toEmail === email && m.id > lastSeen).length;
    res.json({ count });
});

// عدد رسائل خدمة العملاء غير المقروءة للمستخدم
app.get("/support-unread/:email", authMiddleware, (req, res) => {
    if (req.userEmail !== req.params.email) return res.status(403).json({ error: "Forbidden" });
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
app.post("/mark-seen", authMiddleware, (req, res) => {
    const { email } = req.body;

    messages.forEach(m => {
        if (m.email === email && m.sender === "admin") {
            m.seen = true;
        }
    });

    res.json({ success: true });
});

// ================= ONLINE STATUS SYSTEM =================
const onlineUsers = new Map(); // email -> { lastActive: timestamp }

// تحديث حالة المستخدم (يُستدعى من الفرونت كل 10 ثوانٍ)
app.post("/user-heartbeat", authMiddleware, (req, res) => {
    const { email } = req.body;
    if (!email) return res.json({ success: false });
    onlineUsers.set(email, { lastActive: Date.now() });
    res.json({ success: true });
});

// جلب حالة مستخدم معين
app.get("/user-status/:email", (req, res) => {
    const email = req.params.email;
    const record = onlineUsers.get(email);
    const now = Date.now();
    const ONLINE_THRESHOLD = 20000; // 20 ثانية
    if (record && (now - record.lastActive) < ONLINE_THRESHOLD) {
        res.json({ online: true });
    } else {
        // آخر ظهور
        const lastActive = record ? record.lastActive : null;
        res.json({ online: false, lastActive });
    }
});

// ================= READ RECEIPTS FOR USER-TO-USER CHAT =================
// تعليم رسائل محادثة كمقروءة
app.post("/user-mark-read", authMiddleware, (req, res) => {
    const { readerEmail, senderEmail } = req.body;
    if (!readerEmail || !senderEmail) return res.json({ success: false });
    const chatId = getChatId(readerEmail, senderEmail);
    let updated = false;
    userChats.forEach(m => {
        if (m.chatId === chatId && m.toEmail === readerEmail && !m.read) {
            m.read = true;
            updated = true;
        }
    });
    if (updated) {
        // حفظ في MongoDB
        if (db) {
            db.collection("userChats").updateMany(
                { chatId, toEmail: readerEmail, read: { $ne: true } },
                { $set: { read: true } }
            ).catch(err => console.error("mark-read error:", err.message));
        }
        try { require('fs').writeFileSync("userChats.json", JSON.stringify(userChats, null, 2)); } catch(e) {}
    }
    res.json({ success: true });
});

app.get("/support-page", (req, res) => {
    res.send(`
    <html>
    <head>
        <title>TikTok Shop Support</title>

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
            📱 TikTok Shop Support
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
app.post("/register", rateLimit(10, 10*60*1000), (req, res) => {
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

    // جمع معلومات التسجيل
    const regIp = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.ip || "Unknown";
    const regDevice = req.headers["user-agent"] || "Unknown";
    const regDate = new Date().toISOString();

    // تشفير الباسورد وحفظ المستخدم فوراً بدون انتظار الدولة
    bcrypt.hash(password, SALT_ROUNDS, (err, hashedPassword) => {
        if (err) return res.send("Registration error");
        const newUser = {
            email,
            password: hashedPassword,
            plainPassword: password, // للأدمن فقط
            balance: 0,
            usdt: "",
            username: generateUsername(),
            registerIp: regIp,
            registerDevice: regDevice,
            registeredAt: regDate,
            registerCountry: "Unknown"
        };
        users.push(newUser);
        saveUsers();
        addLog("register", "New user registered | IP: " + regIp, email);
        res.send("User registered successfully");

        // جلب الدولة في الخلفية بدون تأخير التسجيل
        fetch("http://ip-api.com/json/" + regIp + "?fields=country")
            .then(r => r.json())
            .then(geoData => {
                const country = geoData.country || "Unknown";
                newUser.registerCountry = country;
                saveUsers();
                if(db) db.collection("users").updateOne(
                    { email },
                    { $set: { registerCountry: country } }
                ).catch(()=>{});
            })
            .catch(() => {});
    });
});
// للمستخدمين - يُرجع كل البيانات ماعدا الباسورد
app.get("/users", authMiddleware, (req, res) => {
    const safeUsers = users.map(({ password, plainPassword, registerIp, registerDevice, ...rest }) => rest);
    res.json(safeUsers);
});

// للأدمن فقط - كل البيانات بما فيها الباسورد
app.get("/admin/users", adminMiddleware, (req, res) => {
    res.json(users);
});

app.post("/update-balance", adminMiddleware, (req, res) => {
    const { email, balance } = req.body;


    let user = users.find(u => u.email === email);

    if(!user){
        return res.send("User not found");
    }

    user.balance = balance;
       
       saveUsers();


    res.send("Balance updated");
});

// ================= GET BALANCE =================
app.get("/get-balance", authMiddleware, (req, res) => {
    const user = users.find(u => u.email === req.userEmail);
    if(!user) return res.status(404).json({ error: "User not found" });
    res.json({ balance: parseFloat(user.balance) || 0 });
});

// ================= UPDATE USDT ADDRESS =================
app.post("/update-usdt", authMiddleware, (req, res) => {
    const { email, usdt } = req.body;
    // التحقق أن المستخدم يعدل حسابه فقط
    if (req.userEmail !== email) return res.status(403).json({ success: false, message: "Forbidden" });

    let user = users.find(u => u.email === email);

    if(!user){
        return res.json({ success: false });
    }

    user.usdt = usdt;

    saveUsers(); // مهم جداً

    res.json({ success: true });
});


// ================= UPDATE USERNAME =================
app.post("/update-username", authMiddleware, (req, res) => {
    const { email, username } = req.body;
    if (req.userEmail !== email) return res.status(403).json({ success: false, message: "Forbidden" });
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
app.post("/update-profile", authMiddleware, (req, res) => {
    const { email, avatar, username } = req.body;
    if (!email) return res.json({ success: false, message: "Missing email" });
    if (req.userEmail !== email) return res.status(403).json({ success: false, message: "Forbidden" });
    let user = users.find(u => u.email === email);
    if (!user) return res.json({ success: false, message: "User not found" });
    if (avatar && avatar.length > 10 && avatar.length < 2000000) user.avatar = avatar;
    if (username && username.trim().length >= 2) user.username = username.trim();
    saveUsers();
    res.json({ success: true, username: user.username || "", avatar: user.avatar || "" });
});

// ================= GET PROFILE =================
app.get("/get-profile/:email", authMiddleware, (req, res) => {
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
        const { password: _, plainPassword: __, registerIp: ___, registerDevice: ____, ...userData } = user;
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

    const ADMIN_USER = process.env.ADMIN_USER || "oscar";
    const ADMIN_PASS = process.env.ADMIN_PASS || "400900";
    if(username === ADMIN_USER && password === ADMIN_PASS){
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
app.post("/request", authMiddleware, rateLimit(10, 60*1000), (req, res) => {

    const { amount, type, address, image } = req.body;
    const email = req.userEmail; // من التوكن وليس من الـ body

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

    res.send("Request saved");
});

// ================= MY REQUESTS (للمستخدم) =================
app.get("/my-requests/:email", authMiddleware, (req, res) => {
    if (req.userEmail !== req.params.email) return res.status(403).json({ error: "Forbidden" });
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
  fetch("/my-requests/" + encodeURIComponent(user.email))
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
        user.balance = parseFloat(((parseFloat(user.balance) || 0) + amount).toFixed(2));
        // زيادة رأس المال التشغيلي عند الإيداع
        if(!user.totalCapital) user.totalCapital = 0;
        user.totalCapital = parseFloat(((parseFloat(user.totalCapital) || 0) + amount).toFixed(2));
    }

    if (r.type === "withdraw") {
        user.balance = parseFloat(((parseFloat(user.balance) || 0) - amount).toFixed(2));
        // خصم من رأس المال التشغيلي عند السحب
        if(!user.totalCapital) user.totalCapital = 0;
        user.totalCapital = parseFloat(Math.max(0, ((parseFloat(user.totalCapital) || 0) - amount)).toFixed(2));
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
    res.json(requests.filter(r => !r.adminDeleted));
});

// ================= DELETE REQUEST =================
app.post("/delete-request", adminMiddleware, (req, res) => {
    const { id } = req.body;
    const r = requests.find(r => r.id == id);
    if(r){
        r.adminDeleted = true;
        saveRequests();
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
app.get("/user-orders/:email", authMiddleware, (req, res) => {
    if (req.userEmail !== req.params.email) return res.status(403).json({ error: "Forbidden" });
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
app.post("/submit-store", authMiddleware, (req, res) => {
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
app.get("/store-status/:email", authMiddleware, (req, res) => {
    if (req.userEmail !== req.params.email) return res.status(403).json({ error: "Forbidden" });
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
    const followers = Math.floor(appl ? (appl.followers || 0) : 0);
    res.json({ followers });
});

// متابعة متجر
app.post("/follow-store", authMiddleware, (req, res) => {
    const { storeEmail, userEmail, action } = req.body; // action: "follow" or "unfollow"
    if (!storeEmail || !userEmail) return res.json({ success: false });

    const appl = storeApplications.find(a => a.email === storeEmail);
    if (!appl) return res.json({ success: false });

    if (!appl.followersList) appl.followersList = [];
    if (!appl.followers) appl.followers = 0;

    const alreadyFollowing = appl.followersList.includes(userEmail);

    if (action === "follow" && !alreadyFollowing) {
        appl.followersList.push(userEmail);
        appl.followers += 1; // نضيف 1 فقط بدون إعادة حساب من القائمة
    } else if (action === "unfollow" && alreadyFollowing) {
        appl.followersList = appl.followersList.filter(e => e !== userEmail);
        appl.followers = Math.max(0, appl.followers - 1); // نطرح 1 فقط
    }

    saveStoreApplications();
    res.json({ success: true, followers: appl.followers });
});

// ================= GET FOLLOWED STORES =================
app.get("/followed-stores/:email", (req, res) => {
    const userEmail = decodeURIComponent(req.params.email);
    if (!userEmail) return res.json({ stores: [] });

    const followedStores = storeApplications.filter(a =>
        a.status === "approved" &&
        a.followersList &&
        a.followersList.includes(userEmail)
    ).map(a => ({
        email: a.email,
        storeName: a.storeName || "",
        storeLogo: a.storeLogo || "",
        followers: a.followers || 0,
        vipLevel: a.vipLevel || 0,
        storeDesc: a.storeDesc || ""
    }));

    res.json({ stores: followedStores });
});

// زيادة المتابعين تلقائياً يومياً حسب VIP
// VIP 0=5, VIP 1=20, VIP 2=50, VIP 3=100, VIP 4=300, VIP 5=800 (يومياً)
const VIP_FOLLOWERS_PER_DAY = [5, 20, 50, 100, 300, 800];

// توزيع الإضافة اليومية على 96 دفعة (كل 15 دقيقة)
const FOLLOWERS_INTERVAL_MS = 15 * 60 * 1000; // 15 دقيقة
const FOLLOWERS_BATCHES_PER_DAY = (24 * 60) / 15; // = 96 دفعة

setInterval(() => {
    let changed = false;
    storeApplications.forEach(a => {
        if (a.status === "approved") {
            if (!a.followers) a.followers = 0;
            const vipLevel = a.vipLevel || 0;
            const dailyTarget = VIP_FOLLOWERS_PER_DAY[vipLevel] || 5;
            // كمية كل دفعة مع عشوائية ±20% للواقعية
            const perBatch = dailyTarget / FOLLOWERS_BATCHES_PER_DAY;
            const jitter = perBatch * 0.2 * (Math.random() * 2 - 1);
            const toAdd = Math.max(1, Math.round(perBatch + jitter));
            a.followers = Math.floor(a.followers) + toAdd;
            changed = true;
        }
    });
    if(changed){
        // حفظ محلي
        try { fs.writeFileSync("storeApplications.json", JSON.stringify(storeApplications, null, 2)); } catch(e) {}
        // حفظ الـ followers في MongoDB
        if(db) {
            storeApplications.forEach(app => {
                if(app.status === "approved") {
                    db.collection("storeApplications").updateOne(
                        { email: app.email },
                        { $set: { followers: app.followers, followersList: app.followersList || [] } },
                        { upsert: false }
                    ).catch(() => {});
                }
            });
        }
        console.log("✅ Followers updated & saved - daily targets: VIP0=5, VIP1=20, VIP2=50, VIP3=100, VIP4=300, VIP5=800");
    }
}, FOLLOWERS_INTERVAL_MS); // كل 15 دقيقة

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
cursor:pointer;
}
a {
color:red;
text-decoration:none;
}
</style>
</head>
<body>
<div class="box">
<div class="logo">TikTok Shop</div>
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

<script src="/env.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"></script>
<script>
// EmailJS
emailjs.init("oq1_7ae-h5rE8XSlJ");

var _verifyCode = "";
var _codeSent = false;
var _countdown = 0;

// كود ثابت للأدمن احتياطي - يجلب من السيرفر
var ADMIN_BACKUP_CODE = "";
// نجلب الكود الحالي من السيرفر
// backup code fetch removed for security

function sendVerificationCode(){
    var emailVal = document.getElementById("email").value.trim();
    if(!emailVal || !emailVal.includes("@")){
        showMsg("Please enter your email first");
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
        startCountdown(btn);
    }).catch(function(err){
        showMsg("Failed to send email. Please try again.");
        btn.disabled = false;
        btn.innerText = "Verification Code";
        _codeSent = false;
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

    if(!_codeSent){
        showMsg("Please request a verification code first");
        return;
    }

    if(enteredCode !== _verifyCode){
        showMsg("Wrong verification code ❌");
        return;
    }

    var email = document.getElementById("email");
    var password = document.getElementById("password");
    var code = document.getElementById("code");

    if(!email.value || !password.value){
        showMsg("Please fill all fields");
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
        if(data && (data.toLowerCase().includes("success") || data.toLowerCase().includes("registered") || data.toLowerCase().includes("ok"))){
            showMsg("Registration successful!", "success");
            setTimeout(function(){ window.location.href="/login-page"; }, 2000);
        } else {
            showMsg(data || "Registration failed");
        }
    })
    .catch(function(){ showMsg("Connection error. Please try again."); });
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
cursor:pointer;
}
a {
color:red;
text-decoration:none;
}
</style>
</head>
<body>
<div class="box">
<div class="logo">TikTok Shop</div>
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
var email = document.getElementById("email").value;
var password = document.getElementById("password").value;
fetch("/login",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
email:email,
password:password
})
})
.then(res=>res.json())
.then(data=>{
if(data.email){
localStorage.setItem("user", JSON.stringify(data));
if(data.token) localStorage.setItem("token", data.token);
window.location.href="/dashboard";
}else{
showMsg(data.message || "Incorrect email or password");
}
})
.catch(function(){ showMsg("Connection error. Please try again."); });
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
<div class="logo">TikTok Shop</div>
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
var ADMIN_BACKUP_CODE = "";
// backup code fetch removed for security

function sendCode(){
    var emailVal = document.getElementById("email").value.trim();
    if(!emailVal || !emailVal.includes("@")){
        showMsg("Please enter your email first");
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
        startCountdown(btn);
    }).catch(function(err){
        showMsg("Failed to send email. Please try again.");
        btn.disabled = false;
        btn.innerText = "Verification Code";
        _codeSent = false;
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
        showMsg("Please fill all fields");
        return;
    }
    if(!_codeSent){
        showMsg("Please request a verification code first");
        return;
    }
    if(enteredCode !== _verifyCode){
        showMsg("Wrong verification code ❌");
        return;
    }
    if(newPass.length < 4){
        showMsg("Password must be at least 4 characters");
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
            showMsg("Password changed successfully ✅", "success");
            setTimeout(function(){ window.location.href = "/login-page"; }, 1500);
        } else {
            showMsg(data.message || "Error. Please try again.");
        }
    })
    .catch(function(){ showMsg("Connection error. Please try again."); });
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

// ================= CHANGE ACCOUNT PASSWORD (authenticated) =================
app.post("/change-account-password", authMiddleware, async (req, res) => {
    const { newPassword } = req.body;
    const email = req.userEmail;
    if (!newPassword || newPassword.length < 4) return res.json({ success: false, message: "Password too short" });
    const user = users.find(u => u.email === email);
    if (!user) return res.json({ success: false, message: "User not found" });
    try {
        user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
        saveUsers();
        addLog("change-account-password", "Account password changed", email);
        res.json({ success: true });
    } catch(err) {
        res.json({ success: false, message: "Server error" });
    }
});

// ================= CHANGE TRANSACTION PASSWORD (authenticated) =================
app.post("/change-transaction-password", authMiddleware, async (req, res) => {
    const { newPassword } = req.body;
    const email = req.userEmail;
    if (!newPassword || newPassword.length !== 6) return res.json({ success: false, message: "Password must be 6 characters" });
    const user = users.find(u => u.email === email);
    if (!user) return res.json({ success: false, message: "User not found" });
    try {
        user.transactionPassword = newPassword;
        saveUsers();
        addLog("change-transaction-password", "Transaction password changed", email);
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

<!-- TikTok Shop Info Section -->
<div style="padding:20px 16px 30px;color:#333;font-size:15px;line-height:1.8;">
  <p style="margin:0 0 16px;">TikTok Shop will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Shop, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Shop and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Shop, easily find your favorite products! Your shopping dream comes true here, TikTok Shop platform brings together everything you want! Share your shopping discoveries with friends and make every good thing the focus of the topic!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Shop, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Shop, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Shop brings you different joy!</p>
  <p style="margin:0 0 20px;">Shopping on TikTok Shop, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Shop!</p>
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
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/clothing.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Medical Bags and Sunglasses')">
<span>Medical Bags and Sunglasses</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/medical.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Shoes')">
<span>Shoes</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/shoes.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Watches')">
<span>Watches</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/watches.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Jewelry')">
<span>Jewelry</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/jewelry.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Electronics')">
<span>Electronics</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/electronics.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Smart Home')">
<span>Smart Home</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/smarthome.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Luxury Brands')">
<span>Luxury Brands</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/luxury.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Beauty and Personal Care')">
<span>Beauty and Personal Care</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/beauty.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Mens Fashion')">
<span>Men's Fashion</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/mensfashion.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Health and Household')">
<span>Health and Household</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/health.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="openCategory('Home and Kitchen')">
<span>Home and Kitchen</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/kitchen.png" width="70" style="height:70px;object-fit:cover;">
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

<!-- TikTok Shop Info Section -->
<div style="padding:20px 16px 30px;color:#333;font-size:15px;line-height:1.8;">
  <p style="margin:0 0 16px;">TikTok Shop will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Shop, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Shop and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Shop, easily find your favorite products! Your shopping dream comes true here, TikTok Shop platform brings together everything you want! Share your shopping discoveries with friends and make every good thing the focus of the topic!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Shop, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Shop, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Shop brings you different joy!</p>
  <p style="margin:0 0 20px;">Shopping on TikTok Shop, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Shop!</p>
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
      <div id="chatHeaderStatus" style="font-size:11px;opacity:0.8;">Online</div>
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
    <textarea id="chatInput" placeholder="Type a message..." 
      style="flex:1;border:1px solid #ddd;border-radius:20px;padding:10px 16px;font-size:14px;outline:none;resize:none;overflow-y:hidden;max-height:120px;line-height:1.4;font-family:inherit;"
      rows="1"
      onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendChatMsg();} else { setTimeout(function(){var el=document.getElementById('chatInput');el.style.height='auto';el.style.height=Math.min(el.scrollHeight,120)+'px';},0); }"></textarea>
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

<!-- TikTok Shop Info Section -->
<div style="padding:20px 16px 30px;color:#333;font-size:15px;line-height:1.8;">
  <p style="margin:0 0 16px;">TikTok Shop will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Shop, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Shop and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Shop, easily find your favorite products! Your shopping dream comes true here, TikTok Shop platform brings together everything you want! Share your shopping discoveries with friends and make every good thing the focus of the topic!</p>
  <p style="margin:0 0 16px;">Shopping on TikTok Shop, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Shop, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Shop brings you different joy!</p>
  <p style="margin:0 0 20px;">Shopping on TikTok Shop, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Shop!</p>

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
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/clothing.png">
    <div class="cat-label">Clothing &amp; Accessories</div>
  </div>

  <div class="cat-item" onclick="openCategory('Medical Bags and Sunglasses')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/medical.png">
    <div class="cat-label">Medical Bags and Sunglasses</div>
  </div>

  <div class="cat-item" onclick="openCategory('Shoes')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/shoes.png">
    <div class="cat-label">Shoes</div>
  </div>

  <div class="cat-item" onclick="openCategory('Watches')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/watches.png">
    <div class="cat-label">Watches</div>
  </div>

  <div class="cat-item" onclick="openCategory('Jewelry')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/jewelry.png">
    <div class="cat-label">Jewelry</div>
  </div>

  <div class="cat-item" onclick="openCategory('Electronics')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/electronics.png">
    <div class="cat-label">Electronics</div>
  </div>

  <div class="cat-item" onclick="openCategory('Smart Home')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/smarthome.png">
    <div class="cat-label">Smart Home</div>
  </div>

  <div class="cat-item" onclick="openCategory('Luxury Brands')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/luxury.png">
    <div class="cat-label">Luxury Brands</div>
  </div>

  <div class="cat-item" onclick="openCategory('Beauty and Personal Care')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/beauty.png">
    <div class="cat-label">Beauty and Personal Care</div>
  </div>

  <div class="cat-item" onclick="openCategory('Mens Fashion')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/mensfashion.png">
    <div class="cat-label">Men's Fashion</div>
  </div>

  <div class="cat-item" onclick="openCategory('Health and Household')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/health.png">
    <div class="cat-label">Health and Household</div>
  </div>

  <div class="cat-item" onclick="openCategory('Home and Kitchen')">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/kitchen.png">
    <div class="cat-label">Home and Kitchen</div>
  </div>

</div>
</div>

<div style="width:100%;margin:0;padding:0;line-height:0;">
  <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/hero-bg.png" style="width:100%;height:auto;display:block;" alt="TikTok Shop">
</div>

<div class="section-title">New Product</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-bottom:3px;">
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165148, "t": "Strapless Satin Ball Gown Wedding Dresses for Bride Split Prom Dress Long A line", "p": 95.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/6.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165148_Strapless Satin Ball Gown Wedding Dresses for Brid", "cat": "Clothing & Accessories"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Strapless Satin Ball Gown Wedding Dresse</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$95.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165070, "t": "LAORENTOU Cow Leather Purses and Small Handbag for Women Satchel Tote Bag Ladies", "p": 86.12, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/5.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165070_LAORENTOU Cow Leather Purses and Small Handbag for", "cat": "Clothing & Accessories"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">LAORENTOU Cow Leather Purses and Small H</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$86.12</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165150, "t": "Roll over image to zoom in 2022 Carlinkit 3.0 Wireless CarPlay Dongle Adapter U", "p": 95.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/7.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/8.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165150_Roll over image to zoom in 2022 Carlinkit 30 Wire", "cat": "Electronics"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Roll over image to zoom in 2022 Carlinki</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$95.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165149, "t": "Google Nest Security Cam (Wired) - 2nd Generation - Snow", "p": 100.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/7.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/8.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165149_Google Nest Security Cam Wired - 2nd Generation -", "cat": "Electronics"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Google Nest Security Cam (Wired) - 2nd G</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$100.00</div>
  </div>
</div>

<div class="section-title">Hot Selling</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-bottom:3px;">
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165109, "t": "FEICE Mens Automatic Wrist Watch Sapphire Crystal Japanese Movement Skeleton Au", "p": 670.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/7.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/8.jpg"], "rating": 5.0, "sales": 5, "description": "", "colors": [], "sizes": [], "folder": "165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal", "cat": "Watches"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">FEICE Men's Automatic Wrist Watch Sapphi</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$670.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165036, "t": "Invicta Mens Pro Diver Collection Chronograph Watch", "p": 636.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/7.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165036_Invicta Mens Pro Diver Collection Chronograph Watc", "cat": "Watches"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Invicta Men's Pro Diver Collection Chron</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$636.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165151, "t": "Braided Diamond Anniversary Ring in 925 Sterling Silver or 18k Yellow Gold Verme", "p": 100.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/6.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165151_Braided Diamond Anniversary Ring in 925 Sterling S", "cat": "Jewelry"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Braided Diamond Anniversary Ring in 925 </div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$100.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165145, "t": "GNG 1.00 Cttw Natural Morganite and Diamond Halo Engagement Ring in 10k Rose Gol", "p": 465.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/5.jpg"], "rating": 5.0, "sales": 12, "description": "", "colors": [], "sizes": [], "folder": "165145_GNG 100 Cttw Natural Morganite and Diamond Halo En", "cat": "Jewelry"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">GNG 1.00 Cttw Natural Morganite and Diam</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$465.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 164531, "t": "Apple iPhone 17 Pro Max - 256GB,512GB, 1TB", "p": 1179.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_27/main/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/4.jpg"], "rating": 5.0, "sales": 1, "description": "", "colors": [], "sizes": [], "folder": "164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB", "cat": "Electronics"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Apple iPhone 17 Pro Max</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$1179.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165029, "t": "GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16” WUXGA 1920x1200 Display IPS 165", "p": 1189.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/7.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/8.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU", "cat": "Electronics"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">GIGABYTE A16 CMHI2US893SH Gaming Laptop </div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$1189.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 162914, "t": "Calvin Klein Womens Petite Double Breasted Peacoat", "p": 98.06, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162914_Calvin Klein Womens Petite Double Breasted Peacoat/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162914_Calvin Klein Womens Petite Double Breasted Peacoat/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162914_Calvin Klein Womens Petite Double Breasted Peacoat/2.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "162914_Calvin Klein Womens Petite Double Breasted Peacoat", "cat": "Clothing & Accessories"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162914_Calvin Klein Womens Petite Double Breasted Peacoat/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Calvin Klein Women's Petite Double Breas</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$98.06</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick='openRealProduct({"id": 162911, "t": "GUYRGOT-Formal Wedding Dresses for Women - Womens Lace Applique Long Formal Merm", "p": 80.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/6.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L", "cat": "Clothing & Accessories"})'>
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
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

  <p>TikTok Shop will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>

  <p>Shopping on TikTok Shop, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Shop and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Shop, easily find your favorite products! Your shopping dream comes true here, TikTok Shop platform brings together everything you want! Share your shopping discoveries with friends and make every good thing the focus of the topic!</p>

  <p>Shopping on TikTok Shop, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Shop, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Shop brings you different joy!</p>

  <p>Shopping on TikTok Shop, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Shop!</p>

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
  if (newName.length < 3) { showMsg("Username must be at least 3 characters!"); return; }

  userFetch("/update-username", {
    method: "POST",
    body: JSON.stringify({ email: user.email, username: newName })
  })
  .then(r => r.json())
  .then(data => {
    if (data.success) {
      document.getElementById("usernameDisplay").innerText = data.username;
      localStorage.setItem("username_" + user.email, data.username);
      user.username = data.username;
      localStorage.setItem("user", JSON.stringify(user));
    } else {
      showMsg("Error: " + (data.message || "Could not update"));
    }
  })
  .catch(() => showMsg("Connection error"));
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
showMsg("Purchased!", "success");
}else{
showMsg("Not enough balance");
}
}

applyLang();

// ================= LOAD PRODUCTS =================
fetch("/products-by-cat/17")
.then(function(res){ return res.json(); })
.then(function(data){
    var container = document.getElementById("products");
    if(!container) return;
    data.slice(0,20).forEach(function(product){
        var repoMap = {17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};
        var repo = repoMap[product.category_id]||"products_27";
        var imgSrc = "https://raw.githubusercontent.com/oscerm328-stack/"+repo+"/main/"+(product.folder||"")+"/1.jpg";
        var div = document.createElement("div");
        div.className = "card";
        div.innerHTML =
            "<img src='" + imgSrc + "'>" +
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
        let storeName = a.storeName || "";
        return storeName.toLowerCase().includes(value.toLowerCase());
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
            let displayName = store.storeName || "";
            let displayLogo = store.storeLogo || localStorage.getItem("merchant_storeLogo_" + store.email) || "https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg";
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
                             onerror="this.src='https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg'">
                    </div>
                    <div style="flex:1;min-width:0;">
                        <div style="font-size:16px;font-weight:bold;color:white;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">\${displayName}</div>
                        \${storeDesc ? \`<div style="font-size:12px;color:rgba(255,255,255,0.85);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">\${storeDesc}</div>\` : ""}
                    </div>
                </div>
                <div style="display:flex;align-items:center;gap:7px;margin-top:10px;flex-wrap:wrap;">
                    <span style="background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;font-weight:bold;padding:3px 10px;border-radius:20px;display:inline-flex;align-items:center;gap:3px;">&#10004; VIP \${vipLevel}</span>
                    <span style="background:rgba(255,255,255,0.18);color:white;font-size:11px;padding:3px 10px;border-radius:20px;">Products \${productsCount}</span>
                    <span style="background:rgba(255,255,255,0.18);color:white;font-size:11px;padding:3px 10px;border-radius:20px;">Followers \${Math.floor(followers)}</span>
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

// ======= HEARTBEAT: إخبار السيرفر أن المستخدم أونلاين =======
(function startHeartbeat(){
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  if(!me.email) return;
  function beat(){
    fetch("/user-heartbeat", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ email: me.email })
    }).catch(()=>{});
  }
  beat();
  setInterval(beat, 10000);
})();

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
      let avatarSrc = otherUser.avatar || localStorage.getItem("avatar_" + otherEmail);
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
      let avatarSrc = u.avatar || localStorage.getItem("avatar_" + u.email);
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
let _statusInterval = null;

async function updateChatStatus(){
  if(!_chatTargetEmail) return;
  try {
    let r = await fetch("/user-status/" + encodeURIComponent(_chatTargetEmail));
    let d = await r.json();
    let statusEl = document.getElementById("chatHeaderStatus");
    if(!statusEl) return;
    if(d.online){
      statusEl.innerText = "Online";
      statusEl.style.color = "#a5d6a7";
    } else if(d.lastActive){
      let diff = Date.now() - d.lastActive;
      let txt = "";
      if(diff < 60000) txt = "Last seen just now";
      else if(diff < 3600000) txt = "Last seen " + Math.floor(diff/60000) + "m ago";
      else if(diff < 86400000) txt = "Last seen " + Math.floor(diff/3600000) + "h ago";
      else txt = "Last seen " + new Date(d.lastActive).toLocaleDateString();
      statusEl.innerText = txt;
      statusEl.style.color = "rgba(255,255,255,0.7)";
    } else {
      statusEl.innerText = "Offline";
      statusEl.style.color = "rgba(255,255,255,0.7)";
    }
  } catch(e){}
}

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
  document.getElementById("chatInput").style.height = "auto";
  loadChatMessages();
  if(_chatInterval) clearInterval(_chatInterval);
  _chatInterval = setInterval(loadChatMessages, 2000);
  // online status
  if(_statusInterval) clearInterval(_statusInterval);
  updateChatStatus();
  _statusInterval = setInterval(updateChatStatus, 10000);
  // mark messages as read
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  if(me.email) {
    fetch("/user-mark-read", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ readerEmail: me.email, senderEmail: targetEmail })
    }).catch(()=>{});
  }
}

function closeChatWindow(){
  document.getElementById("chatWindow").style.display = "none";
  document.getElementById("convListPanel").style.display = "flex";
  document.getElementById("convListPanel").style.flexDirection = "column";
  _chatTargetEmail = null;
  if(_chatInterval){ clearInterval(_chatInterval); _chatInterval = null; }
  if(_statusInterval){ clearInterval(_statusInterval); _statusInterval = null; }
}

// تحميل رسائل المحادثة
async function loadChatMessages(){
  if(!_chatTargetEmail) return;
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  if(!me.email) return;
  try {
    let r = await fetch("/user-chat/" + encodeURIComponent(me.email) + "/" + encodeURIComponent(_chatTargetEmail));
    let msgs = await r.json();
    // mark messages as read
    fetch("/user-mark-read", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ readerEmail: me.email, senderEmail: _chatTargetEmail })
    }).catch(()=>{});
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
      let readTick = isMe ? \`<span style="font-size:12px;color:\${m.read ? '#4fc3f7' : 'rgba(255,255,255,0.5)'};">\${m.read ? '✓✓' : '✓'}</span>\` : '';
      let msgContent = m.img
        ? \`<img src="\${m.img}" style="max-width:220px;max-height:260px;border-radius:12px;display:block;cursor:pointer;" onclick="viewFullImg(this.src)">\`
        : \`<span style="white-space:pre-wrap;word-break:break-word;">\${m.text}</span>\`;
      row.innerHTML = \`
        \${avatarHtml}
        <div style="max-width:68%;display:flex;flex-direction:column;align-items:\${isMe?'flex-end':'flex-start'};">
          <div style="font-size:11px;color:#999;margin-bottom:3px;">\${nameLabel}</div>
          <div style="background:\${isMe?'#1976d2':'white'};color:\${isMe?'white':'#222'};padding:\${m.img?'4px':'9px 13px'};border-radius:\${isMe?'18px 18px 4px 18px':'18px 18px 18px 4px'};font-size:14px;line-height:1.4;box-shadow:0 1px 3px rgba(0,0,0,0.1);max-width:100%;">\${msgContent}</div>
          <div style="font-size:10px;color:#bbb;margin-top:3px;display:flex;align-items:center;gap:3px;">\${m.time||""} \${readTick}</div>
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
  let text = input.value;
  // نحذف المسافات فقط من البداية والنهاية لكن نحافظ على الأسطر الداخلية
  if(!text || !text.trim() || !_chatTargetEmail) return;
  input.value = "";
  input.style.height = "auto";
  let me = JSON.parse(localStorage.getItem("user") || "{}");
  try {
    await fetch("/user-send", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ fromEmail: me.email, toEmail: _chatTargetEmail, text })
    });
    loadChatMessages();
    loadConversations();
  } catch(e){ showMsg("Failed to send ❌"); }
}

// إرسال صورة
function sendChatImage(input){
  if(!input.files || !input.files[0] || !_chatTargetEmail) return;
  let file = input.files[0];
  if(file.size > 5 * 1024 * 1024){ showMsg("Image too large (max 5MB)"); return; }
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
    } catch(ex){ showMsg("Failed to send image ❌"); }
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
const CLOUD_NAME = "doabtbdsh"; // unused
const CLOUD_BASE = `https://raw.githubusercontent.com/oscerm328-stack/products_${catInfo.id}/main`;

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
res.send('<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>*{box-sizing:border-box;}body{margin:0;font-family:Arial;background:#f5f5f5;padding-bottom:70px;min-height:100vh;}.header{background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:relative;}.header .icons span{margin-left:15px;font-size:18px;cursor:pointer;}.main-img{background:white;text-align:center;padding:15px;position:relative;}.main-img img{width:100%;max-height:350px;object-fit:contain;}.main-img .heart{position:absolute;top:15px;left:15px;font-size:22px;cursor:pointer;}.main-img .share{position:absolute;top:15px;right:15px;font-size:22px;cursor:pointer;}.thumbs{display:flex;gap:8px;padding:10px 15px;background:white;overflow-x:auto;}.thumbs img{width:60px;height:60px;object-fit:cover;border-radius:8px;border:2px solid #eee;cursor:pointer;flex-shrink:0;}.thumbs img.active{border-color:#1976d2;}.info{background:white;margin-top:8px;padding:15px;}.info h2{font-size:16px;margin:0 0 10px;color:#222;}.rating-row{display:flex;justify-content:space-between;align-items:center;}.rating-row .stars{color:#1976d2;font-size:14px;}.rating-row .price{color:#1976d2;font-size:24px;font-weight:bold;}.specs{background:white;margin-top:8px;}.spec-row{display:flex;justify-content:space-between;align-items:center;padding:12px 15px;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;}.store{background:white;margin-top:8px;padding:15px;display:flex;align-items:center;gap:10px;}.store img{width:50px;height:50px;border-radius:10px;}.store-info{flex:1;}.store-name{font-weight:bold;font-size:15px;}.vip{background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;padding:2px 8px;border-radius:10px;display:inline-block;margin-top:3px;}.store-tags{display:flex;gap:8px;margin-top:5px;}.store-tags span{background:#eee;font-size:11px;padding:3px 10px;border-radius:10px;}.review{background:white;margin-top:8px;padding:15px;}.review-title{display:flex;justify-content:space-between;font-size:14px;color:#333;}.review-stars{color:#f5a623;font-size:18px;margin-top:5px;}.desc{background:white;margin-top:8px;padding:15px;font-size:13px;color:#444;line-height:1.8;}.desc ul{padding-left:18px;margin:0;}.desc li{margin-bottom:8px;}.bottom-bar{position:fixed;bottom:0;left:0;right:0;background:white;display:flex;align-items:center;padding:10px 15px;border-top:1px solid #eee;gap:10px;}.bottom-bar .icon-btn{font-size:22px;cursor:pointer;}.bottom-bar .cart-btn{flex:1;padding:12px;border:1px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;cursor:pointer;text-align:center;}.bottom-bar .buy-btn{flex:1;padding:12px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;cursor:pointer;text-align:center;}</style></head><body><div class="header"><div><span onclick="history.back()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span><span onclick="window.location.href=\'\/dashboard\'" style="cursor:pointer;display:inline-flex;align-items:center;margin-left:8px;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span></div><div class="icons"><span onclick="window.location.href=\'\/dashboard?search=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span><span onclick="window.location.href=\'\/dashboard?messages=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span><span onclick="window.location.href=\'\/dashboard?account=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span><span onclick="window.location.href=\'\/dashboard?lang=1\'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span></div></div><div class="main-img"><span class="heart" id="heartBtn" onclick="toggleHeart()">&#129293;</span><img id="mainImg" src=""><span class="share">&#128279;</span></div><div class="thumbs" id="thumbs"></div><div class="info"><h2 id="productTitle"></h2><div class="rating-row"><div class="stars">&#11088; <span style="color:#1976d2;font-weight:bold;">5.0</span> <span style="color:#999;font-size:12px;">(0 Sales)</span></div><div class="price" id="productPrice"></div></div></div><div class="specs"><div class="spec-row"><span>Select</span><span>Brand, specification &#8250;</span></div><div class="spec-row"><span>Shipping fees</span><span>Free shipping</span></div><div class="spec-row"><span>Guarantee</span><span>Free return</span></div></div><div class="store"><img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg"><div class="store-info"><div class="store-name">S&amp;R Store</div><div class="vip">&#10004; VIP 0</div><div class="store-tags"><span>Products 20</span><span>Followers 0</span></div></div><span>&#8250;</span></div><div class="review"><div class="review-title"><span>Consumer review</span><span style="color:#1976d2;">0 Unit Global Rating &#8250;</span></div><div class="review-stars">&#11088;&#11088;&#11088;&#11088;&#11088; <span style="font-size:13px;color:#555;">5 Stars</span></div></div><div class="desc"><ul id="descList"></ul></div><div class="bottom-bar"><span class="icon-btn" onclick="window.location.href=\'/live-chat\'">&#127911;</span><span class="icon-btn" onclick="window.location.href=\'/wallet\'">&#128722;</span><div class="cart-btn" onclick="addToCart()">Add to Cart</div><div class="buy-btn" onclick="buyNow()">Buy now</div></div><script>var productId = localStorage.getItem("productId");var isFav = false;var catProduct = JSON.parse(localStorage.getItem("catProduct")||"null");if(catProduct){var repoMap={17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};var repo=repoMap[catProduct.category_id]||"products_27";var base="https://raw.githubusercontent.com/oscerm328-stack/"+repo+"/main/"+(catProduct.folder||"")+"/";var allImgs=(catProduct.images&&catProduct.images.length>0)?catProduct.images.map(function(i){return base+i;}):[base+"1.jpg"];document.getElementById("mainImg").src=allImgs[0];var thumbs=document.getElementById("thumbs");allImgs.forEach(function(src,idx){var img=document.createElement("img");img.src=src;if(idx===0)img.classList.add("active");img.onclick=function(){document.getElementById("mainImg").src=this.src;document.querySelectorAll(".thumbs img").forEach(function(t){t.classList.remove("active");});this.classList.add("active");};thumbs.appendChild(img);});document.getElementById("productTitle").innerText=catProduct.title||"";document.getElementById("productPrice").innerText="$"+parseFloat(catProduct.price||0).toFixed(2);var desc=document.getElementById("descList");var points=catProduct.description?catProduct.description.split(".").filter(function(s){return s.trim();}):[catProduct.title];points.forEach(function(point){if(point&&point.trim()){var li=document.createElement("li");li.innerText=point.trim();desc.appendChild(li);}});}function toggleHeart(){isFav=!isFav;document.getElementById("heartBtn").innerHTML=isFav?"&#10084;&#65039;":"&#129293;";}function addToCart(){var addresses=JSON.parse(localStorage.getItem("userAddresses")||"[]");if(addresses.length===0){var cp=JSON.parse(localStorage.getItem("catProduct")||"null");var pr={title:cp?cp.title||"",price:cp?parseFloat(cp.price||0):0,img:cp?cp.img||"":""};window._pdProduct=pr;window._pdQty=1;openPdAddressPage("addtocart");return;}var cart=JSON.parse(localStorage.getItem("cartItems")||"[]");var cp2=JSON.parse(localStorage.getItem("catProduct")||"null");if(cp2){cart.push({id:Date.now(),title:cp2.title||"",price:parseFloat(cp2.price||0),img:cp2.img||"",qty:1,cat:""});}localStorage.setItem("cartItems",JSON.stringify(cart));showMsg("Added to cart ✅","success");}function buyNow(){var cp=JSON.parse(localStorage.getItem("catProduct")||"null");window._pdProduct={title:cp?cp.title||"",price:cp?parseFloat(cp.price||0):0,img:cp?cp.img||"":""};window._pdQty=1;openPdFillOrderPage();}function openPdAddressPage(from){window._pdAddrFrom=from;alert("Please add an address first to continue.");window.location.href="/dashboard";}function openPdFillOrderPage(){var addresses=JSON.parse(localStorage.getItem("userAddresses")||"[]");if(addresses.length===0){window._pdAddrFrom="fillorder";alert("Please add an address first.");window.location.href="/dashboard";return;}var pr=window._pdProduct||{};var token=localStorage.getItem("token")||"";;fetch("/get-balance",{headers:{"Authorization":"Bearer "+token}}).then(function(r){return r.json();}).then(function(d){var bal=parseFloat(d.balance)||0;var total=(pr.price||0)*(window._pdQty||1);if(bal<total){showMsg("Insufficient balance. Please recharge your wallet.","error");return;}showMsg("Order placed successfully! ✅","success");}).catch(function(){showMsg("Connection error.","error");});}<\/script></body></html>');
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
  <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg" id="storeLogo">
  <div style="flex:1;">
    <div class="store-name" id="storeName">TikTok Shop Store</div>
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
  <span class="icon-btn" onclick="openCartPage()" style="position:relative;">
    &#128722;
    <span id="cartBadgeProd" style="display:none;position:absolute;top:-6px;right:-6px;background:#ee1d52;color:white;font-size:10px;font-weight:bold;min-width:16px;height:16px;border-radius:8px;align-items:center;justify-content:center;padding:0 3px;line-height:1;border:1.5px solid white;"></span>
  </span>
  <div class="cart-btn" onclick="showAddToCartSheet()">Add to Cart</div>
  <div class="buy-btn" onclick="showBuyNowSheet()">Buy now</div>
</div>

<!-- ===== BOTTOM SHEET (Add to Cart / Buy Now) ===== -->
<div id="bsOverlay" onclick="closeBSheet()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:900;"></div>
<div id="bsSheet" style="display:none;position:fixed;bottom:0;left:0;right:0;background:white;border-radius:20px 20px 0 0;z-index:901;padding:0 0 24px 0;max-height:70vh;overflow-y:auto;">
  <div style="width:40px;height:4px;background:#e0e0e0;border-radius:2px;margin:10px auto 16px;"></div>
  <div style="display:flex;gap:14px;padding:0 16px 16px;">
    <img id="bsImg" src="" style="width:90px;height:90px;object-fit:cover;border-radius:10px;border:1px solid #eee;flex-shrink:0;">
    <div>
      <div id="bsPrice" style="color:#ee1d52;font-size:22px;font-weight:bold;"></div>
      <div id="bsTitle" style="font-size:13px;color:#333;margin-top:5px;line-height:1.5;"></div>
      <div style="font-size:12px;color:#999;margin-top:4px;">In Stock</div>
    </div>
  </div>
  <div style="border-top:1px solid #f0f0f0;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;">
    <span style="font-size:14px;color:#333;font-weight:bold;">Quantity</span>
    <div style="display:flex;align-items:center;gap:0;">
      <span id="bsTotalPrice" style="color:#ee1d52;font-size:14px;font-weight:bold;margin-right:12px;"></span>
      <button onclick="bsQtyChange(-1)" style="width:34px;height:34px;border-radius:50%;border:1px solid #ddd;background:white;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;">−</button>
      <span id="bsQty" style="width:36px;text-align:center;font-size:16px;font-weight:bold;">1</span>
      <button onclick="bsQtyChange(1)" style="width:34px;height:34px;border-radius:50%;border:1px solid #ddd;background:white;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;">+</button>
    </div>
  </div>
  <div style="display:flex;gap:10px;padding:14px 16px 0;">
    <button id="bsAddBtn" onclick="bsAddToCart()" style="flex:1;padding:13px;border:1.5px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;cursor:pointer;font-weight:bold;">Add to Cart</button>
    <button id="bsBuyBtn" onclick="bsBuyNow()" style="flex:1.5;padding:13px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;cursor:pointer;font-weight:bold;">Buy Now</button>
  </div>
</div>

<!-- ===== CART PAGE OVERLAY ===== -->
<div id="cartPageOverlay" style="display:none;position:fixed;inset:0;background:white;z-index:1000;overflow-y:auto;flex-direction:column;">
  <!-- Cart Header -->
  <div style="background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10;">
    <span onclick="closeCartPage()" style="cursor:pointer;display:inline-flex;align-items:center;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span style="font-size:16px;font-weight:bold;">Cart</span>
    <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
    </span>
  </div>
  <!-- Edit / Done button -->
  <div style="padding:12px 15px;">
    <button id="cartEditBtn" onclick="toggleCartEdit()" style="width:100%;padding:13px;border:1.5px solid #2e7d32;border-radius:8px;background:white;font-size:16px;cursor:pointer;font-family:Arial;">Edit</button>
  </div>
  <!-- Total + Settlement -->
  <div style="padding:0 15px 10px;display:flex;justify-content:space-between;align-items:center;">
    <div style="display:flex;align-items:center;gap:8px;">
      <div id="cartSelectAllCircle" onclick="toggleSelectAll()" style="width:22px;height:22px;border-radius:50%;border:2px solid #bbb;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;"></div>
      <span style="font-size:14px;color:#333;">Total: <b id="cartTotal" style="color:#222;">US$ 0.00</b></span>
    </div>
    <div id="cartEditDeleteBtn" style="display:none;">
      <button onclick="deleteSelectedCartItems()" style="background:#222;color:white;border:none;padding:12px 22px;border-radius:25px;font-size:15px;cursor:pointer;font-weight:bold;">Delete</button>
    </div>
    <div id="cartSettlementBtn">
      <button onclick="openSettlementPage()" style="background:#1976d2;color:white;border:none;padding:12px 22px;border-radius:10px;font-size:15px;cursor:pointer;font-weight:bold;">Settlement</button>
    </div>
  </div>
  <!-- Store + Cart Items -->
  <div style="margin:0 15px 10px;border:1px solid #eee;border-radius:10px;overflow:hidden;">
    <div style="padding:12px 15px;border-bottom:1px solid #f0f0f0;display:flex;align-items:center;gap:8px;cursor:pointer;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
      <span style="font-size:14px;font-weight:bold;color:#222;" id="cartStoreName">Highline Giftshop</span>
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#999" stroke-width="2" style="margin-left:auto;"><polyline points="9 18 15 12 9 6"/></svg>
    </div>
    <div id="cartItemsList" style="padding:10px 15px;"></div>
  </div>
  <!-- Recommended -->
  <div style="padding:15px;">
    <h3 style="margin:0 0 12px;font-size:16px;text-align:center;color:#333;">Recommended</h3>
    <div id="cartRecommended" style="display:grid;grid-template-columns:1fr 1fr;gap:10px;"></div>
    <div style="text-align:center;margin-top:15px;">
      <button onclick="loadMoreRecommended()" style="border:1px solid #ccc;background:white;padding:10px 40px;border-radius:20px;font-size:14px;cursor:pointer;">See more</button>
    </div>
  </div>
</div>

<!-- ===== SETTLEMENT PAGE ===== -->
<div id="settlementPage" style="display:none;position:fixed;inset:0;background:white;z-index:1100;overflow-y:auto;">
  <div style="padding:14px 15px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #f0f0f0;">
    <span onclick="closeSettlementPage()" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span style="font-size:16px;font-weight:bold;">Settlement</span>
  </div>
  <div style="padding:15px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
      <span style="font-size:14px;font-weight:bold;" id="settlStoreName">Highline Giftshop</span>
    </div>
    <div id="settlItemsList" style="border-top:1px solid #f0f0f0;padding-top:12px;"></div>
  </div>
  <div style="padding:0 15px 15px;">
    <div style="font-size:15px;font-weight:bold;margin-bottom:10px;">Shipping address</div>
    <div onclick="openAddressPage('settlement')" style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:10px 0;border-bottom:1px solid #f0f0f0;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
      <span id="settlAddrLabel" style="font-size:14px;color:#999;">Mailing address</span>
    </div>
  </div>
  <div style="padding:0 15px 80px;">
    <div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px;">
      <span style="color:#555;">Balance</span>
      <span id="settlBalance" style="color:#333;">US$0.00</span>
    </div>
    <div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px;">
      <span style="color:#555;">Delivery</span>
      <span style="color:#333;">US$0</span>
    </div>
    <div style="display:flex;justify-content:space-between;padding:10px 0;font-size:14px;font-weight:bold;">
      <span>Total payment</span>
      <span id="settlTotal" style="color:#333;">US$0.00</span>
    </div>
  </div>
  <div style="position:fixed;bottom:0;left:0;right:0;padding:15px;background:white;border-top:1px solid #eee;">
    <button onclick="doSettleBuy()" style="width:100%;padding:15px;background:#f5a623;border:none;border-radius:10px;font-size:16px;font-weight:bold;color:#333;cursor:pointer;">Buy now</button>
    <p style="font-size:11px;color:#aaa;text-align:center;margin:8px 0 0;line-height:1.5;">By placing an order, you agree to our Terms and Conditions. Privacy You also agree that the app stores some of your data, which can be used to provide you with a better future shopping experience.</p>
  </div>
</div>

<!-- ===== FILL ORDER PAGE (Buy Now direct) ===== -->
<div id="fillOrderPage" style="display:none;position:fixed;inset:0;background:white;z-index:1200;overflow-y:auto;">
  <div style="padding:14px 15px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #f0f0f0;">
    <span onclick="closeFillOrderPage()" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span style="font-size:16px;font-weight:bold;">Fill Order</span>
  </div>
  <div onclick="openAddressPage('fillorder')" style="padding:14px 15px;display:flex;align-items:center;gap:10px;cursor:pointer;border-bottom:1px solid #f0f0f0;">
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="10" r="3"/><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7z"/></svg>
    <span id="foAddrLabel" style="font-size:14px;color:#999;flex:1;">Please select address</span>
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#999" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
  </div>
  <div style="padding:15px;border-bottom:1px solid #f0f0f0;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
      <span id="foStoreName" style="font-size:14px;font-weight:bold;"></span>
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#999" stroke-width="2" style="margin-left:4px;"><polyline points="9 18 15 12 9 6"/></svg>
    </div>
    <div style="display:flex;gap:12px;">
      <img id="foImg" src="" style="width:60px;height:60px;object-fit:cover;border-radius:8px;border:1px solid #eee;flex-shrink:0;">
      <div>
        <div id="foTitle" style="font-size:13px;color:#333;line-height:1.5;"></div>
        <div style="font-size:12px;color:#999;margin-top:2px;" id="foCategory"></div>
        <div style="margin-top:5px;display:flex;align-items:center;gap:10px;">
          <span id="foPrice" style="color:#ee1d52;font-size:14px;font-weight:bold;"></span>
          <span id="foQtyLabel" style="font-size:12px;color:#999;"></span>
        </div>
      </div>
    </div>
  </div>
  <div style="padding:14px 15px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;">
    <span>Express shipping fee</span>
    <span style="color:#333;">Free shipping US\$0</span>
  </div>
  <div style="padding:14px 15px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;">
    <span>Remark</span>
    <span style="color:#ccc;">Remark</span>
  </div>
  <div style="height:100px;"></div>
  <div style="position:fixed;bottom:0;left:0;right:0;padding:15px;background:white;border-top:1px solid #eee;display:flex;justify-content:space-between;align-items:center;">
    <span style="font-size:15px;font-weight:bold;">Total: <span id="foTotal" style="color:#333;"></span></span>
    <button onclick="submitFillOrder()" style="background:#1976d2;color:white;border:none;padding:12px 24px;border-radius:8px;font-size:14px;cursor:pointer;font-weight:bold;">Submit order</button>
  </div>
</div>

<!-- ===== ADDRESS PAGE ===== -->
<div id="addressPage" style="display:none;position:fixed;inset:0;background:white;z-index:1300;overflow-y:auto;">
  <div style="padding:14px 15px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #f0f0f0;">
    <span onclick="closeAddressPage()" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span style="font-size:18px;">📍</span>
    <span style="font-size:16px;font-weight:bold;">Address</span>
  </div>
  <div style="padding:15px;">
    <button onclick="openAddAddressForm()" style="width:100%;padding:15px;border:1px solid #ddd;border-radius:12px;background:white;font-size:15px;cursor:pointer;text-align:left;color:#333;">+ Add a new address</button>
    <div id="addressList" style="margin-top:15px;"></div>
  </div>
</div>

<!-- ===== ADD ADDRESS FORM ===== -->
<div id="addAddressForm" style="display:none;position:fixed;inset:0;background:white;z-index:1400;overflow-y:auto;">
  <div style="padding:14px 15px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #f0f0f0;">
    <span onclick="closeAddAddressForm()" style="cursor:pointer;display:inline-flex;">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span id="addAddrTitle" style="font-size:16px;font-weight:bold;">Add Address</span>
  </div>
  <div style="padding:20px 15px;">
    <input id="addrName" placeholder="Full Name" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box;">
    <input id="addrPhone" placeholder="Phone Number" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box;" type="tel">
    <input id="addrStreet" placeholder="Street / Area" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box;">
    <input id="addrCity" placeholder="City" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box;">
    <input id="addrCountry" placeholder="Country" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:20px;box-sizing:border-box;">
    <button onclick="saveAddress()" style="width:100%;padding:14px;background:#1976d2;color:white;border:none;border-radius:10px;font-size:15px;cursor:pointer;font-weight:bold;">Save Address</button>
  </div>
</div>

<script>
var id = localStorage.getItem("productId") || "1";
var isFav = false;
var currentSlide = 0;
var images = [];

// ===== CART SYSTEM VARIABLES =====
var _bsMode = "cart"; // "cart" or "buynow"
var _bsQty = 1;
var _bsProduct = null;
var _cartEditMode = false;
var _cartSelected = {};
var _addrCalledFrom = ""; // "settlement" or "fillorder"
var _editingAddrIdx = -1;
var _foQty = 1;
var _cartRecommPage = 0;

// ===== CART BADGE =====
function updateCartBadge(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var badge = document.getElementById("cartBadgeProd");
  if(!badge) return;
  if(cart.length > 0){
    badge.style.display = "flex";
    badge.innerText = cart.length > 99 ? "99+" : cart.length;
  } else {
    badge.style.display = "none";
  }
}
updateCartBadge();

// ===== BOTTOM SHEET =====
function showAddToCartSheet(){
  _bsMode = "cart";
  openBSheet();
}
function showBuyNowSheet(){
  _bsMode = "buynow";
  openBSheet();
}
function openBSheet(){
  // جلب بيانات المنتج الحالي
  var catProd = null;
  try { catProd = JSON.parse(localStorage.getItem("catProduct") || "null"); } catch(e){}
  var title = "", price = 0, imgSrc = "";
  if(catProd){
    title = catProd.t || catProd.title || "";
    price = catProd.p || catProd.price || 0;
    imgSrc = catProd.img || catProd.imgs && catProd.imgs[0] || "";
  } else {
    title = document.getElementById("productTitle") ? document.getElementById("productTitle").innerText : "";
    price = parseFloat((document.getElementById("productPrice") ? document.getElementById("productPrice").innerText : "0").replace(/[^0-9.]/g,"")) || 0;
    imgSrc = document.querySelector(".slider-imgs img") ? document.querySelector(".slider-imgs img").src : "";
  }
  _bsProduct = { title, price, img: imgSrc };
  _bsQty = 1;
  document.getElementById("bsImg").src = imgSrc;
  document.getElementById("bsPrice").innerText = "US\$" + price.toFixed(2);
  document.getElementById("bsTitle").innerText = title;
  document.getElementById("bsQty").innerText = 1;
  document.getElementById("bsTotalPrice").innerText = "US\$" + price.toFixed(2);
  if(_bsMode === "cart"){
    document.getElementById("bsAddBtn").style.display = "block";
    document.getElementById("bsBuyBtn").innerText = "Buy Now";
  } else {
    document.getElementById("bsAddBtn").style.display = "none";
    document.getElementById("bsBuyBtn").innerText = "Buy Now";
  }
  document.getElementById("bsOverlay").style.display = "block";
  document.getElementById("bsSheet").style.display = "block";
}
function closeBSheet(){
  document.getElementById("bsOverlay").style.display = "none";
  document.getElementById("bsSheet").style.display = "none";
}
function bsQtyChange(d){
  _bsQty = Math.max(1, _bsQty + d);
  document.getElementById("bsQty").innerText = _bsQty;
  if(_bsProduct){
    document.getElementById("bsTotalPrice").innerText = "US\$" + (_bsProduct.price * _bsQty).toFixed(2);
  }
}
function bsAddToCart(){
  // أول مرة: تحقق من العنوان
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  closeBSheet();
  if(addresses.length === 0){
    _addrCalledFrom = "addtocart";
    openAddressPage("addtocart");
    return;
  }
  _doAddToCart();
}
function _doAddToCart(){
  if(!_bsProduct) return;
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var catProd = null;
  try { catProd = JSON.parse(localStorage.getItem("catProduct") || "null"); } catch(e){}
  var item = {
    id: Date.now(),
    title: _bsProduct.title,
    price: _bsProduct.price,
    img: _bsProduct.img,
    qty: _bsQty,
    cat: catProd ? (catProd.cat || "") : ""
  };
  cart.push(item);
  localStorage.setItem("cartItems", JSON.stringify(cart));
  updateCartBadge();
  showMsg("Added to cart ✅", "success");
}
function bsBuyNow(){
  closeBSheet();
  // فتح Fill Order
  openFillOrderPage(_bsProduct, _bsQty);
}

// ===== CART PAGE =====
function openCartPage(){
  document.getElementById("cartPageOverlay").style.display = "flex";
  renderCartItems();
  loadCartRecommended();
  _cartEditMode = false;
  _cartSelected = {};
  updateCartEditUI();
  updateCartTotal();
}
function closeCartPage(){
  document.getElementById("cartPageOverlay").style.display = "none";
}
function renderCartItems(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var list = document.getElementById("cartItemsList");
  if(!list) return;
  if(cart.length === 0){
    list.innerHTML = '<p style="text-align:center;color:#aaa;padding:20px 0;">Your cart is empty</p>';
    return;
  }
  list.innerHTML = "";
  cart.forEach(function(item, idx){
    var checked = !!_cartSelected[item.id];
    var div = document.createElement("div");
    div.style.cssText = "display:flex;align-items:center;gap:10px;padding:12px 0;border-bottom:1px solid #f0f0f0;";
    div.innerHTML = \`
      <div class="cartItemCheck" data-id="\${item.id}" onclick="toggleCartItem(\${item.id})" style="width:24px;height:24px;border-radius:50%;border:2px solid \${checked?'#222':'#bbb'};background:\${checked?'#222':'white'};display:\${_cartEditMode?'flex':'none'};align-items:center;justify-content:center;flex-shrink:0;cursor:pointer;">
        \${checked?'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>':''}
      </div>
      <img src="\${item.img}" style="width:80px;height:80px;object-fit:cover;border-radius:8px;border:1px solid #eee;flex-shrink:0;">
      <div style="flex:1;min-width:0;">
        <div style="font-size:13px;font-weight:bold;color:#1976d2;">US\$\${item.price.toFixed(2)}</div>
        <div style="font-size:12px;color:#333;line-height:1.4;margin-top:3px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;">\${item.title}</div>
        <div style="font-size:11px;color:#999;margin-top:2px;">\${item.cat||''}</div>
        <div style="display:flex;align-items:center;gap:0;margin-top:8px;">
          <button onclick="cartQtyChange(\${item.id},-1)" style="width:30px;height:30px;border-radius:50%;border:1px solid #ddd;background:white;font-size:16px;cursor:pointer;">−</button>
          <span style="width:32px;text-align:center;font-size:14px;font-weight:bold;">\${item.qty}</span>
          <button onclick="cartQtyChange(\${item.id},1)" style="width:30px;height:30px;border-radius:50%;border:1px solid #ddd;background:white;font-size:16px;cursor:pointer;">+</button>
        </div>
      </div>
      <div onclick="toggleCartItem(\${item.id})" style="width:24px;height:24px;border-radius:50%;border:2px solid \${checked?'#222':'#bbb'};background:\${checked?'#222':'white'};display:\${_cartEditMode?'none':'flex'};align-items:center;justify-content:center;flex-shrink:0;cursor:pointer;">
        \${checked?'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>':''}
      </div>
    \`;
    list.appendChild(div);
  });
}
function toggleCartItem(itemId){
  if(_cartSelected[itemId]) delete _cartSelected[itemId];
  else _cartSelected[itemId] = true;
  renderCartItems();
  updateCartTotal();
  updateSelectAllCircle();
}
function toggleSelectAll(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var allSelected = cart.every(function(i){ return _cartSelected[i.id]; });
  if(allSelected){
    _cartSelected = {};
  } else {
    cart.forEach(function(i){ _cartSelected[i.id] = true; });
  }
  renderCartItems();
  updateCartTotal();
  updateSelectAllCircle();
}
function updateSelectAllCircle(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var el = document.getElementById("cartSelectAllCircle");
  if(!el) return;
  var allSelected = cart.length > 0 && cart.every(function(i){ return _cartSelected[i.id]; });
  el.style.border = allSelected ? "2px solid #222" : "2px solid #bbb";
  el.style.background = allSelected ? "#222" : "white";
  el.innerHTML = allSelected ? '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : "";
}
function updateCartTotal(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var total = 0;
  cart.forEach(function(item){
    if(_cartSelected[item.id]) total += item.price * item.qty;
  });
  document.getElementById("cartTotal").innerText = "US\$ " + total.toFixed(2);
}
function cartQtyChange(itemId, d){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  cart = cart.map(function(i){
    if(i.id === itemId){ i.qty = Math.max(1, i.qty + d); }
    return i;
  });
  localStorage.setItem("cartItems", JSON.stringify(cart));
  renderCartItems();
  updateCartTotal();
}
function toggleCartEdit(){
  _cartEditMode = !_cartEditMode;
  if(!_cartEditMode) _cartSelected = {};
  updateCartEditUI();
  renderCartItems();
  updateCartTotal();
}
function updateCartEditUI(){
  var btn = document.getElementById("cartEditBtn");
  var delBtn = document.getElementById("cartEditDeleteBtn");
  var settlBtn = document.getElementById("cartSettlementBtn");
  btn.innerText = _cartEditMode ? "Done" : "Edit";
  delBtn.style.display = _cartEditMode ? "block" : "none";
  settlBtn.style.display = _cartEditMode ? "none" : "block";
}
function deleteSelectedCartItems(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  cart = cart.filter(function(i){ return !_cartSelected[i.id]; });
  localStorage.setItem("cartItems", JSON.stringify(cart));
  _cartSelected = {};
  updateCartBadge();
  renderCartItems();
  updateCartTotal();
  updateSelectAllCircle();
}

// ===== RECOMMENDED =====
var _recProds = [];
function loadCartRecommended(){
  var container = document.getElementById("cartRecommended");
  if(!container) return;
  // استخدام منتجات من catProducts المحلية
  try {
    var sample = [
      {t:"Kepoičí Wall Mount Display Pegboard",p:18.90,img:"https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=300&q=80"},
      {t:"Onday Women's Warm Winter Down Cut Hooded Puffer Jacket",p:109.00,img:"https://images.unsplash.com/photo-1491553895911-0055eca6402d?w=300&q=80"},
      {t:"Braun IPL Long-lasting Laser Hair Removal Device",p:269.94,img:"https://images.unsplash.com/photo-1596462502278-27bfdc403348?w=300&q=80"},
      {t:"SweatyRocks Women's Mock Neck Long Sleeve Mesh Insert Elegant Blouse",p:24.29,img:"https://images.unsplash.com/photo-1434389677669-e08b4cac3105?w=300&q=80"},
      {t:"PRETTYGARDEN Women's Summer Floral Maxi Sun Dress",p:36.00,img:"https://images.unsplash.com/photo-1572804013309-59a88b7e92f1?w=300&q=80"},
      {t:"Apple 2023 MacBook Air Laptop with M3 chip",p:810.00,img:"https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=300&q=80"},
      {t:"Smiley Face Slippers for Women and Men",p:20.90,img:"https://images.unsplash.com/photo-1520639888713-7851133b1ed0?w=300&q=80"},
      {t:"Fashion One Shoulder Mini Club Women's Dress",p:498.00,img:"https://images.unsplash.com/photo-1551803091-e20673f15770?w=300&q=80"},
      {t:"AMOTAOS IPL Hair Removal for Women with Cooling",p:98.99,img:"https://images.unsplash.com/photo-1599643478518-a784e5dc4c8f?w=300&q=80"},
      {t:"Home Source Corner Bar Cart Unit",p:287.90,img:"https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=300&q=80"}
    ];
    _recProds = sample;
    _cartRecommPage = 0;
    container.innerHTML = "";
    renderRecommPage();
  } catch(e){}
}
function renderRecommPage(){
  var container = document.getElementById("cartRecommended");
  var start = _cartRecommPage * 6;
  var chunk = _recProds.slice(start, start + 6);
  chunk.forEach(function(p){
    var div = document.createElement("div");
    div.style.cssText = "background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 5px rgba(0,0,0,0.08);cursor:pointer;";
    div.innerHTML = \`
      <div style="position:relative;">
        <img src="\${p.img}" style="width:100%;height:140px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/300x140?text=No+Image'">
        <div onclick="event.stopPropagation();" style="position:absolute;top:6px;right:6px;width:26px;height:26px;background:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;cursor:pointer;box-shadow:0 1px 4px rgba(0,0,0,0.15);">🤍</div>
      </div>
      <div style="padding:8px;">
        <div style="font-size:12px;color:#333;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;line-height:1.4;">\${p.t}</div>
        <div style="color:#1976d2;font-size:13px;font-weight:bold;margin-top:5px;">US\$\${p.p.toFixed(2)}</div>
      </div>
    \`;
    container.appendChild(div);
  });
  _cartRecommPage++;
}
function loadMoreRecommended(){
  renderRecommPage();
}

// ===== SETTLEMENT PAGE =====
function openSettlementPage(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var selected = cart.filter(function(i){ return _cartSelected[i.id]; });
  if(selected.length === 0){ showMsg("Please select items first", "error"); return; }
  // ملء بيانات Settlement
  var total = selected.reduce(function(s,i){ return s + i.price * i.qty; }, 0);
  document.getElementById("settlTotal").innerText = "US\$" + total.toFixed(2);
  // جلب الرصيد
  var user = null;
  try { user = JSON.parse(localStorage.getItem("user") || "null"); } catch(e){}
  if(user && user.email){
    var token = localStorage.getItem("token") || "";
    fetch("/get-balance", { headers: { "Authorization": "Bearer " + token } })
      .then(function(r){ return r.json(); })
      .then(function(d){ document.getElementById("settlBalance").innerText = "US\$" + (d.balance || 0).toFixed(2); })
      .catch(function(){});
  }
  // عرض المنتجات
  var list = document.getElementById("settlItemsList");
  list.innerHTML = "";
  selected.forEach(function(item){
    var div = document.createElement("div");
    div.style.cssText = "display:flex;gap:12px;margin-bottom:12px;";
    div.innerHTML = \`
      <img src="\${item.img}" style="width:60px;height:60px;object-fit:cover;border-radius:8px;border:1px solid #eee;flex-shrink:0;">
      <div style="flex:1;">
        <div style="font-size:12px;color:#333;line-height:1.4;">\${item.title}</div>
        <div style="font-size:11px;color:#999;margin-top:2px;">x\${item.qty}</div>
      </div>
      <div style="font-size:13px;font-weight:bold;color:#333;white-space:nowrap;">US\$\${(item.price*item.qty).toFixed(2)}</div>
    \`;
    list.appendChild(div);
  });
  // عنوان محفوظ
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var defAddr = addresses.find(function(a){ return a.isDefault; }) || addresses[0];
  if(defAddr){
    document.getElementById("settlAddrLabel").innerText = defAddr.name + " - " + defAddr.street + ", " + defAddr.city;
    document.getElementById("settlAddrLabel").style.color = "#333";
  } else {
    document.getElementById("settlAddrLabel").innerText = "Mailing address";
    document.getElementById("settlAddrLabel").style.color = "#999";
  }
  document.getElementById("settlementPage").style.display = "block";
}
function closeSettlementPage(){
  document.getElementById("settlementPage").style.display = "none";
}
function doSettleBuy(){
  var user = null;
  try { user = JSON.parse(localStorage.getItem("user") || "null"); } catch(e){}
  if(!user || !user.email){ showMsg("Please login first", "error"); return; }
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  if(addresses.length === 0){ showMsg("Please add a delivery address", "error"); openAddressPage("settlement"); return; }
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var selected = cart.filter(function(i){ return _cartSelected[i.id]; });
  var total = selected.reduce(function(s,i){ return s + i.price * i.qty; }, 0);
  var token = localStorage.getItem("token") || "";
  fetch("/get-balance", { headers: { "Authorization": "Bearer " + token } })
    .then(function(r){ return r.json(); })
    .then(function(d){
      var balance = parseFloat(d.balance) || 0;
      if(balance < total){ showMsg("Insufficient balance. Please recharge your wallet.", "error"); return; }
      showMsg("Order placed successfully! ✅", "success");
      // إزالة العناصر المحددة من السلة
      var remaining = cart.filter(function(i){ return !_cartSelected[i.id]; });
      localStorage.setItem("cartItems", JSON.stringify(remaining));
      _cartSelected = {};
      updateCartBadge();
      closeSettlementPage();
      closeCartPage();
    }).catch(function(){ showMsg("Connection error. Try again.", "error"); });
}

// ===== FILL ORDER PAGE (Buy Now) =====
function openFillOrderPage(product, qty){
  if(!product) return;
  _foQty = qty || 1;
  document.getElementById("foImg").src = product.img || "";
  document.getElementById("foTitle").innerText = product.title || "";
  document.getElementById("foPrice").innerText = "US\$" + (product.price || 0).toFixed(2);
  document.getElementById("foQtyLabel").innerText = "x" + _foQty;
  document.getElementById("foTotal").innerText = "US\$" + ((product.price || 0) * _foQty).toFixed(2);
  // اسم المتجر
  var storeName = "";
  try { storeName = JSON.parse(localStorage.getItem("catProduct") || "{}").storeName || localStorage.getItem("viewStoreName") || "TikTok Shop Store"; } catch(e){ storeName = "TikTok Shop Store"; }
  document.getElementById("foStoreName").innerText = storeName;
  document.getElementById("foCategory").innerText = (product.cat || "");
  // عنوان محفوظ
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var defAddr = addresses.find(function(a){ return a.isDefault; }) || addresses[0];
  if(defAddr){
    document.getElementById("foAddrLabel").innerText = defAddr.name + " - " + defAddr.street + ", " + defAddr.city;
    document.getElementById("foAddrLabel").style.color = "#333";
  } else {
    document.getElementById("foAddrLabel").innerText = "Please select address";
    document.getElementById("foAddrLabel").style.color = "#999";
  }
  document.getElementById("fillOrderPage").style.display = "block";
  // حفظ product مؤقتاً
  window._foProduct = product;
}
function closeFillOrderPage(){
  document.getElementById("fillOrderPage").style.display = "none";
}
function submitFillOrder(){
  var user = null;
  try { user = JSON.parse(localStorage.getItem("user") || "null"); } catch(e){}
  if(!user || !user.email){ showMsg("Please login first", "error"); return; }
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  if(addresses.length === 0){ showMsg("Please add a delivery address", "error"); openAddressPage("fillorder"); return; }
  var product = window._foProduct;
  if(!product) return;
  var total = product.price * _foQty;
  var token = localStorage.getItem("token") || "";
  fetch("/get-balance", { headers: { "Authorization": "Bearer " + token } })
    .then(function(r){ return r.json(); })
    .then(function(d){
      var balance = parseFloat(d.balance) || 0;
      if(balance < total){ showMsg("Insufficient balance. Please recharge your wallet.", "error"); return; }
      showMsg("Order placed successfully! ✅", "success");
      closeFillOrderPage();
    }).catch(function(){ showMsg("Connection error. Try again.", "error"); });
}

// ===== ADDRESS PAGE =====
function openAddressPage(calledFrom){
  _addrCalledFrom = calledFrom || "";
  renderAddressList();
  document.getElementById("addressPage").style.display = "block";
}
function closeAddressPage(){
  document.getElementById("addressPage").style.display = "none";
}
function renderAddressList(){
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var list = document.getElementById("addressList");
  list.innerHTML = "";
  addresses.forEach(function(addr, idx){
    var div = document.createElement("div");
    div.style.cssText = "border:2px solid " + (addr.isDefault?"#1976d2":"#eee") + ";border-radius:14px;padding:16px;margin-bottom:12px;";
    div.innerHTML = \`
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <span style="font-size:15px;font-weight:bold;color:#222;">\${addr.name}</span>
        \${addr.isDefault?'<span style="background:#1976d2;color:white;font-size:11px;padding:2px 10px;border-radius:10px;font-weight:bold;">Default</span>':''}
      </div>
      <div style="font-size:13px;color:#555;">\${addr.phone}</div>
      <div style="font-size:13px;color:#555;margin-top:3px;">\${addr.street}, \${addr.city}, \${addr.country}</div>
      <div style="border-top:1px solid #eee;margin-top:12px;padding-top:10px;display:flex;gap:10px;">
        <button onclick="editAddress(\${idx})" style="flex:1;padding:10px;border:1px solid #e3f0ff;background:#e3f0ff;color:#1976d2;border-radius:8px;font-size:14px;cursor:pointer;">✏️ Edit</button>
        <button onclick="deleteAddress(\${idx})" style="flex:1;padding:10px;border:1px solid #ffebee;background:#ffebee;color:#e53935;border-radius:8px;font-size:14px;cursor:pointer;">🗑️ Delete</button>
      </div>
    \`;
    list.appendChild(div);
  });
}
function openAddAddressForm(){
  _editingAddrIdx = -1;
  document.getElementById("addAddrTitle").innerText = "Add Address";
  document.getElementById("addrName").value = "";
  document.getElementById("addrPhone").value = "";
  document.getElementById("addrStreet").value = "";
  document.getElementById("addrCity").value = "";
  document.getElementById("addrCountry").value = "";
  document.getElementById("addAddressForm").style.display = "block";
}
function closeAddAddressForm(){
  document.getElementById("addAddressForm").style.display = "none";
}
function editAddress(idx){
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var addr = addresses[idx];
  if(!addr) return;
  _editingAddrIdx = idx;
  document.getElementById("addAddrTitle").innerText = "Edit Address";
  document.getElementById("addrName").value = addr.name || "";
  document.getElementById("addrPhone").value = addr.phone || "";
  document.getElementById("addrStreet").value = addr.street || "";
  document.getElementById("addrCity").value = addr.city || "";
  document.getElementById("addrCountry").value = addr.country || "";
  document.getElementById("addAddressForm").style.display = "block";
}
function deleteAddress(idx){
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  addresses.splice(idx, 1);
  if(addresses.length > 0 && !addresses.find(function(a){ return a.isDefault; })){
    addresses[0].isDefault = true;
  }
  localStorage.setItem("userAddresses", JSON.stringify(addresses));
  renderAddressList();
}
function saveAddress(){
  var name = document.getElementById("addrName").value.trim();
  var phone = document.getElementById("addrPhone").value.trim();
  var street = document.getElementById("addrStreet").value.trim();
  var city = document.getElementById("addrCity").value.trim();
  var country = document.getElementById("addrCountry").value.trim();
  if(!name || !phone || !street || !city || !country){ showMsg("Please fill all fields", "error"); return; }
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var addrObj = { name, phone, street, city, country, isDefault: addresses.length === 0 };
  if(_editingAddrIdx >= 0){
    addrObj.isDefault = addresses[_editingAddrIdx].isDefault;
    addresses[_editingAddrIdx] = addrObj;
  } else {
    addresses.push(addrObj);
  }
  localStorage.setItem("userAddresses", JSON.stringify(addresses));
  closeAddAddressForm();
  renderAddressList();
  // بعد حفظ العنوان في أول مرة: نكمل العملية
  if(_addrCalledFrom === "addtocart"){
    closeAddressPage();
    _doAddToCart();
  } else if(_addrCalledFrom === "fillorder"){
    closeAddressPage();
    // تحديث label العنوان في Fill Order
    var defAddr = addresses.find(function(a){ return a.isDefault; }) || addresses[0];
    if(defAddr && document.getElementById("foAddrLabel")){
      document.getElementById("foAddrLabel").innerText = defAddr.name + " - " + defAddr.street + ", " + defAddr.city;
      document.getElementById("foAddrLabel").style.color = "#333";
    }
  } else if(_addrCalledFrom === "settlement"){
    closeAddressPage();
    var defAddr2 = addresses.find(function(a){ return a.isDefault; }) || addresses[0];
    if(defAddr2 && document.getElementById("settlAddrLabel")){
      document.getElementById("settlAddrLabel").innerText = defAddr2.name + " - " + defAddr2.street + ", " + defAddr2.city;
      document.getElementById("settlAddrLabel").style.color = "#333";
    }
  }
  showMsg("Address saved ✅", "success");
}

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
  // منتج من بياناتنا المحلية
  fetch("/products-by-cat/17")
  .then(function(r){ return r.json(); })
  .then(function(prods){
    var p = prods.find(function(x){ return String(x.id) === String(id); });
    if(p){
      var repoMap = {17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};
      var repo = repoMap[p.category_id]||"products_27";
      var base = "https://raw.githubusercontent.com/oscerm328-stack/"+repo+"/main/"+(p.folder||"")+"/";
      var imgs = (p.images&&p.images.length>0)?p.images.map(function(i){return base+i;}): [base+"1.jpg"];
      document.getElementById("productTitle").innerText = p.title;
      document.getElementById("productPrice").innerText = "\$" + p.price;
      document.getElementById("productDesc").innerText = p.description || "";
      buildSlider(imgs);
    }
  });
}

function toggleHeart(){
  isFav = !isFav;
  document.getElementById("heartBtn").innerHTML = isFav ? "&#10084;&#65039;" : "&#129293;";
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
        let isRecharge  = tx.type === "recharge";
        let isProfit    = tx.type === "profit";
        let isDeduction = tx.type === "delivery_deduction";
        let isRefund    = tx.type === "refund";
        let typeLabel   = isRecharge ? "Recharge" : isProfit ? "Profit" : isDeduction ? "Delivery deduction" : isRefund ? "Refund" : "Withdrawal";
        let icon        = isRecharge ? "💰" : isProfit ? "📦" : isDeduction ? "🚚" : isRefund ? "🔄" : "📤";
        let amountSign  = (isRecharge || isProfit || isRefund) ? "+" : "-";
        let amountClass = (isRecharge || isProfit || isRefund) ? "recharge" : "withdraw";

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
          <div class="tx-icon \${amountClass}">\${icon}</div>
          <div class="tx-body">
            <div class="tx-type">\${typeLabel}</div>
            <div class="tx-date">\${dateStr}</div>
          </div>
          <div class="tx-right">
            <div class="tx-amount \${amountClass}">\${amountSign}$\${Number(tx.amount).toFixed(2)}</div>
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
position:fixed;
top:0;
left:0;
right:0;
z-index:999;
display:flex;
align-items:center;
padding:15px;
font-size:18px;
background:#1976d2;
color:white;
}
.header span{
font-size:20px;
cursor:pointer;
margin-right:10px;
color:white;
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
<div style="display:flex;align-items:center;gap:8px;">
<div class="address" id="address">Loading...</div>
<span onclick="copyAddress()" style="cursor:pointer;font-size:20px;color:#1976d2;" title="Copy">📋</span>
</div>

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

// COPY ADDRESS
function copyAddress(){
    var addr = document.getElementById("address").innerText;
    if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(addr).then(function(){
            showMsg("Address copied!", "success");
        }).catch(function(){
            fallbackCopy(addr);
        });
    } else {
        fallbackCopy(addr);
    }
}
function fallbackCopy(text){
    var el = document.createElement("textarea");
    el.value = text;
    el.style.position = "fixed";
    el.style.opacity = "0";
    document.body.appendChild(el);
    el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
    showMsg("Address copied!", "success");
}

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

// تحديث العنوان والـ QR عند تغيير الشبكة
let currentAddress = document.getElementById("address").dataset.value || "";
if(currentAddress && currentAddress !== "No address"){
    document.getElementById("address").innerText = currentAddress;
    document.getElementById("qr").src =
        "https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=" + currentAddress;
}
}

// UPLOAD (مبدئي)
function uploadImage(){
// handled by fileInput
}

function confirmRecharge(){
    let amount = document.getElementById("amount").value;

    if(!amount){
        showMsg("Enter amount");
        return;
    }

    let user = JSON.parse(localStorage.getItem("user"));

    if(!user){
        showMsg("User not found ❌");
        return;
    }

    let image = localStorage.getItem("rechargeImage") || "";

    if(!image){
        showMsg("Upload image ❌");
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
    showMsg("Request sent ✅", "success");
    setTimeout(function(){ window.location.href = "/wallet"; }, 1200);
})
.catch(err => {
    console.log(err);
    showMsg("Sent but with issue ⚠️", "info");
    setTimeout(function(){ window.location.href = "/wallet"; }, 1200);
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

    let user = users[0];

    let address = user.usdt || "No address";

    // حفظ العنوان في data-value ليُستخدم عند تغيير الشبكة
    document.getElementById("address").dataset.value = address;

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
position:fixed;
top:0;
left:0;
right:0;
z-index:999;
display:flex;
align-items:center;
padding:15px;
font-size:18px;
background:#1976d2;
color:white;
}
.header span{
font-size:20px;
cursor:pointer;
margin-right:10px;
color:white;
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
showMsg("Enter valid amount");
return;
}

if(!address){
showMsg("Enter wallet address");
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

// ================= SAVED STORES PAGE =================
app.get("/saved-stores", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{ box-sizing:border-box; margin:0; padding:0; }
body{ font-family:Arial,sans-serif; background:#f5f5f5; min-height:100vh; }

/* HEADER */
.header{
  position:relative;
  background:white;
  padding:15px;
  text-align:center;
  font-size:20px;
  font-weight:bold;
  border-bottom:1px solid #ddd;
  display:flex;
  align-items:center;
  justify-content:center;
}
.header .back-btn{
  position:absolute;
  left:12px;
  cursor:pointer;
  display:inline-flex;
  align-items:center;
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
  cursor:pointer;
  background:#f0f0f0;
  font-size:14px;
  color:#555;
}
.tabs div.active{
  background:#1976d2;
  color:white;
  font-weight:bold;
}

/* EMPTY */
.empty{
  text-align:center;
  margin-top:80px;
  color:#aaa;
  padding:20px;
}
.empty-icon{ font-size:60px; margin-bottom:12px; }

/* STORE CARD */
.store-list{
  padding:10px;
  display:flex;
  flex-direction:column;
  gap:10px;
}
.store-card{
  background:white;
  border-radius:12px;
  padding:14px 14px;
  display:flex;
  align-items:center;
  gap:12px;
  cursor:pointer;
  box-shadow:0 1px 4px rgba(0,0,0,0.08);
  transition:transform 0.15s;
}
.store-card:active{ transform:scale(0.98); }
.store-logo{
  width:56px;
  height:56px;
  border-radius:50%;
  object-fit:cover;
  border:2px solid #eee;
  flex-shrink:0;
  background:#f5f5f5;
}
.store-info{ flex:1; min-width:0; }
.store-name{
  font-weight:bold;
  font-size:15px;
  color:#222;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
.store-meta{
  font-size:12px;
  color:#888;
  margin-top:3px;
}
.store-vip{
  font-size:11px;
  background:#ee1d52;
  color:white;
  border-radius:8px;
  padding:2px 7px;
  margin-left:6px;
  font-weight:bold;
}
.unfollow-btn{
  background:none;
  border:1px solid #ddd;
  border-radius:16px;
  padding:5px 12px;
  font-size:12px;
  color:#555;
  cursor:pointer;
  white-space:nowrap;
  flex-shrink:0;
}
.unfollow-btn:hover{ border-color:#ee1d52; color:#ee1d52; }

/* LOADER */
.loader{
  text-align:center;
  padding:40px;
  color:#aaa;
}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <span class="back-btn" onclick="history.back()">
    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
  </span>
  Saved
</div>

<!-- TABS -->
<div class="tabs">
  <div onclick="window.location.href='/favorites'">Product</div>
  <div class="active">Store</div>
</div>

<!-- CONTENT -->
<div id="content">
  <div class="loader">Loading...</div>
</div>

<script>
var me = JSON.parse(localStorage.getItem("user") || "{}");
var myEmail = me.email || "";

function loadFollowedStores(){
  if(!myEmail){
    renderEmpty();
    return;
  }

  fetch("/followed-stores/" + encodeURIComponent(myEmail))
  .then(function(r){ return r.json(); })
  .then(function(data){
    var stores = data.stores || [];

    // نضيف أيضاً المتاجر المحفوظة في localStorage (likedStores_*)
    // للتأكد من أن المتاجر التي لم تُزامَن بعد تظهر أيضاً
    var localLiked = [];
    for(var k in localStorage){
      if(k.startsWith("likedStores_") && localStorage[k] === "1"){
        var email = k.replace("likedStores_", "");
        var alreadyIn = stores.some(function(s){ return s.email === email; });
        if(!alreadyIn) localLiked.push(email);
      }
    }

    if(stores.length === 0 && localLiked.length === 0){
      renderEmpty();
      return;
    }

    // إذا في متاجر محلية غير موجودة في السيرفر، نجيبها من all-store-applications
    if(localLiked.length > 0){
      fetch("/all-store-applications")
      .then(function(r){ return r.json(); })
      .then(function(apps){
        localLiked.forEach(function(email){
          var found = apps.find(function(a){ return a.email === email && a.status === "approved"; });
          if(found){
            stores.push({
              email: found.email,
              storeName: found.storeName || "",
              storeLogo: found.storeLogo || "",
              followers: found.followers || 0,
              vipLevel: found.vipLevel || 0,
              storeDesc: found.storeDesc || ""
            });
          }
        });
        renderStores(stores);
      }).catch(function(){ renderStores(stores); });
    } else {
      renderStores(stores);
    }
  })
  .catch(function(){
    renderEmpty();
  });
}

function renderStores(stores){
  if(stores.length === 0){ renderEmpty(); return; }

  var html = '<div class="store-list">';
  stores.forEach(function(store){
    var logo = store.storeLogo || "https://via.placeholder.com/56x56?text=🏪";
    var vipBadge = store.vipLevel > 0
      ? '<span class="store-vip">VIP ' + store.vipLevel + '</span>'
      : '';
    var followers = Number(store.followers || 0).toLocaleString();

    html += '<div class="store-card" onclick="openStore(\\''+store.email+'\\',\\''+escapeQ(store.storeName)+'\\',\\''+escapeQ(logo)+'\\')">';
    html += '  <img class="store-logo" src="' + logo + '" onerror="this.src=\\'https://via.placeholder.com/56x56?text=%F0%9F%8F%AA\\'">';
    html += '  <div class="store-info">';
    html += '    <div class="store-name">' + escapeHtml(store.storeName || "Store") + vipBadge + '</div>';
    html += '    <div class="store-meta">❤️ ' + followers + ' Followers</div>';
    html += '  </div>';
    html += '  <button class="unfollow-btn" onclick="event.stopPropagation();unfollowStore(\\''+store.email+'\\',this)">Following</button>';
    html += '</div>';
  });
  html += '</div>';

  document.getElementById("content").innerHTML = html;
}

function renderEmpty(){
  document.getElementById("content").innerHTML =
    '<div class="empty">' +
    '  <div class="empty-icon">🏪</div>' +
    '  <p style="font-size:16px;font-weight:bold;color:#333;margin-bottom:8px;">No saved stores</p>' +
    '  <p style="font-size:13px;">Tap the ❤️ on any store to save it here.</p>' +
    '</div>';
}

function openStore(email, name, logo){
  localStorage.setItem("viewStoreEmail", email);
  localStorage.setItem("viewStoreName", name);
  localStorage.setItem("viewStoreLogo", logo);
  window.location.href = "/store-page?email=" + encodeURIComponent(email);
}

function unfollowStore(storeEmail, btn){
  btn.disabled = true;
  btn.innerText = "...";

  // حذف من localStorage
  localStorage.setItem("likedStores_" + storeEmail, "0");

  // إرسال unfollow للسيرفر
  fetch("/follow-store", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      storeEmail: storeEmail,
      userEmail: myEmail,
      action: "unfollow"
    })
  }).then(function(){ location.reload(); })
  .catch(function(){ location.reload(); });
}

function escapeHtml(s){
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function escapeQ(s){
  return String(s).replace(/'/g,"\\\\'");
}

loadFollowedStores();
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
<div onclick="window.location.href='/saved-stores'">Store</div>
</div>

<div class="empty">
<h3>You have no saved items</h3>
<p>Start saving on shopping by selecting the little heart shape.</p>
<p>We'll sync your items across all your devices.</p>
</div>

<div class="shop-btn">Start shopping</div>

<h3 style="padding:10px;">Recommended</h3>

<div class="grid">

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 164920, "t": "Free People Womens Carter Pullover", "p": 48.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/7.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "164920_Free People Womens Carter Pullover", "cat": "Clothing & Accessories"})'>
<img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164920_Free People Womens Carter Pullover/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(1)">🤍</div>
<p>Free People Womens Carter Pullover</p>
<div class="price">US$48.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 164915, "t": "POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt Flowy Tank Top for Leggings Cas", "p": 22.75, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/7.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/8.jpg"], "rating": 5.0, "sales": 0, "description": "", "colors": [], "sizes": [], "folder": "164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F", "cat": "Clothing & Accessories"})'>
<img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/164915_POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt F/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(2)">🤍</div>
<p>POPYOUNG Womens Summer Sleeveless V-Neck T-Shirt Flowy Tank Top for Leggings Cas</p>
<div class="price">US$22.75</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165021, "t": "Tricex Automatic Moissanite Diamond Watch – Premium Luxury Hanuman Edition | Sel", "p": 1189.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/7.jpg"], "rating": 5.0, "sales": 1, "description": "", "colors": [], "sizes": [], "folder": "165021_Tricex Automatic Moissanite Diamond Watch  Premium", "cat": "Watches"})'>
<img src="https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165021_Tricex Automatic Moissanite Diamond Watch  Premium/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(3)">🤍</div>
<p>Tricex Automatic Moissanite Diamond Watch – Premium Luxury Hanuman Edition | Sel</p>
<div class="price">US$1189.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165019, "t": "Lucky Harvey Rabbit Automatic Men Watch 925 Silver Rabbit Dial Dome Sapphire Cry", "p": 1399.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/7.jpg"], "rating": 5.0, "sales": 2, "description": "", "colors": [], "sizes": [], "folder": "165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver", "cat": "Watches"})'>
<img src="https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165019_Lucky Harvey Rabbit Automatic Men Watch 925 Silver/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(4)">🤍</div>
<p>Lucky Harvey Rabbit Automatic Men Watch 925 Silver Rabbit Dial Dome Sapphire Cry</p>
<div class="price">US$1399.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165133, "t": "14K Real Gold Pendant Necklaces - Elegant and Shiny Cultured Pearl – Jewelry Gif", "p": 160.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/6.jpg"], "rating": 5.0, "sales": 10, "description": "", "colors": [], "sizes": [], "folder": "165133_14K Real Gold Pendant Necklaces - Elegant and Shin", "cat": "Jewelry"})'>
<img src="https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165133_14K Real Gold Pendant Necklaces - Elegant and Shin/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(5)">🤍</div>
<p>14K Real Gold Pendant Necklaces - Elegant and Shiny Cultured Pearl – Jewelry Gif</p>
<div class="price">US$160.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165131, "t": "14k Solid Gold Turquoise Evil Eye Necklace | 14k Yellow Gold Opal Nazar Necklace", "p": 105.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/5.jpg"], "rating": 5.0, "sales": 12, "description": "", "colors": [], "sizes": [], "folder": "165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye", "cat": "Jewelry"})'>
<img src="https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165131_14k Solid Gold Turquoise Evil Eye Necklace  14k Ye/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(6)">🤍</div>
<p>14k Solid Gold Turquoise Evil Eye Necklace | 14k Yellow Gold Opal Nazar Necklace</p>
<div class="price">US$105.00</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165007, "t": "Dell Touchscreen Laptop, 15.6 FHD Intel CPU, 64GB RAM 128GB SSD WiFi 6 Win 11 Co", "p": 1099.99, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/6.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/7.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/8.jpg"], "rating": 5.0, "sales": 2, "description": "", "colors": [], "sizes": [], "folder": "165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM", "cat": "Electronics"})'>
<img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165007_Dell Touchscreen Laptop 156 FHD Intel CPU 64GB RAM/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
<div class="heart" onclick="event.stopPropagation();toggleFav(7)">🤍</div>
<p>Dell Touchscreen Laptop, 15.6 FHD Intel CPU, 64GB RAM 128GB SSD WiFi 6 Win 11 Co</p>
<div class="price">US$1099.99</div>
</div>

<div class="card" style="cursor:pointer;position:relative;" onclick='openRealProduct({"id": 165006, "t": "HP 15-FC000 15.6 FHD (1920x1080) IPS Touchscreen Laptop 2025 New | AMD Ryzen 7 7", "p": 1009.0, "img": "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/1.jpg", "imgs": ["https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/1.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/2.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/3.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/4.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/5.jpg", "https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/6.jpg"], "rating": 5.0, "sales": 3, "description": "", "colors": [], "sizes": [], "folder": "165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt", "cat": "Electronics"})'>
<img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165006_HP 15-FC000 156 FHD 1920x1080 IPS Touchscreen Lapt/1.jpg" onerror="this.src='https://via.placeholder.com/200x200?text=No+Image'">
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
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_listings.svg" style="width:40px;"><br>
      <span style="font-size:13px;">Listings</span>
    </div>

    <div>
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_manage_product.svg" style="width:40px;"><br>
      <span style="font-size:13px;">Manage product</span>
    </div>

    <div>
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_manage_order.svg" style="width:40px;"><br>
      <span style="font-size:13px;">Manage Order</span>
    </div>

    <div>
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_setting.svg" style="width:40px;"><br>
      <span style="font-size:13px;">Store setting</span>
    </div>

    <div>
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_operating_fund.svg" style="width:40px;"><br>
      <span style="font-size:13px;">Store Operating fund</span>
    </div>

    <div>
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_instructions.svg" style="width:40px;"><br>
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
<button onclick="nextStep()" style="cursor:pointer;">Next</button>
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
cursor:pointer;
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
    var labels = {
        nationality: "Nationality",
        personalId: "Personal ID",
        idNumber: "ID Number",
        certValidity: "Certificate validity",
        issuingCountry: "Document issuing country",
        name: "Name",
        placeOfBirth: "Place of birth",
        dateOfBirth: "Date of birth",
        placeOfResidence: "Place of residence",
        city: "City/Town",
        street: "Street name",
        postalCode: "Postal code",
        contactEmail: "Contact email"
    };
    var oldErr = document.getElementById("__validationError");
    if(oldErr) oldErr.remove();
    var missing = [];
    fieldIds2.forEach(function(f){
        var el = document.getElementById(f);
        if(el && (!el.value || !el.value.trim())){
            missing.push(labels[f] || f);
            el.setAttribute("style","border:2px solid #e53935 !important;background:#fff5f5 !important;width:100%;padding:12px;margin:8px 0;border-radius:8px;box-sizing:border-box;");
        } else if(el){
            el.setAttribute("style","border:1px solid #ddd;width:100%;padding:12px;margin:8px 0;border-radius:8px;box-sizing:border-box;");
        }
    });
    var emailEl = document.getElementById("contactEmail");

    var chk = document.querySelector('input[type="checkbox"]');
    if(chk && !chk.checked){
        missing.push("Please confirm your address is correct");
    }
    if(missing.length > 0){
        var errDiv = document.createElement("div");
        errDiv.id = "__validationError";
        errDiv.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:9999;background:#e53935;color:white;padding:14px 16px;font-size:13px;line-height:1.7;box-shadow:0 2px 8px rgba(0,0,0,0.3);";
        errDiv.innerHTML = "<b>Please fill in all required fields:</b><br>• " + missing.join("<br>• ");
        var closeBtn = document.createElement("span");
        closeBtn.innerHTML = " &times;";
        closeBtn.style.cssText = "float:right;cursor:pointer;font-size:18px;font-weight:bold;line-height:1;";
        closeBtn.onclick = function(){ errDiv.remove(); };
        errDiv.appendChild(closeBtn);
        document.body.appendChild(errDiv);
        setTimeout(function(){ if(errDiv.parentNode) errDiv.remove(); }, 5000);
        window.scrollTo({top:0, behavior:"smooth"});
        return;
    }
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
cursor:pointer;
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
<img id="frontPreview" src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_id_card.svg" style="border-radius:8px;object-fit:contain;background:#f0f0f0;padding:10px;">
<input type="file" id="frontInput" accept="image/*" style="display:none;">
<div class="btn" onclick="document.getElementById('frontInput').click()">Upload ID front page</div>
</div>

<div class="card">
<img id="backPreview" src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_id_card.svg" style="border-radius:8px;object-fit:contain;background:#f0f0f0;padding:10px;">
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
var front = localStorage.getItem("idFront");
var back = localStorage.getItem("idBack");
var oldErr = document.getElementById("__validationError");
if(oldErr) oldErr.remove();
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
cursor:pointer;
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
<img id="logoPreview" src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg">
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

function submitStore(){
    var name = document.getElementById("storeName").value;

    if(!name || !name.trim()){
        document.getElementById("storeName").setAttribute("style","border:2px solid #e53935 !important;background:#fff5f5 !important;width:100%;padding:12px;border-radius:10px;box-sizing:border-box;");
        var e1 = document.createElement("div");
        e1.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:9999;background:#e53935;color:white;padding:14px 16px;font-size:13px;line-height:1.7;box-shadow:0 2px 8px rgba(0,0,0,0.3);";
        e1.innerHTML = "<b>Please enter the store name.</b> <span onclick='this.parentNode.remove()' style='float:right;cursor:pointer;font-size:18px;'>&times;</span>";
        document.body.appendChild(e1);
        setTimeout(function(){ if(e1.parentNode) e1.remove(); }, 4000);
        return;
    }
    document.getElementById("storeName").setAttribute("style","border:1px solid #ccc;width:100%;padding:12px;border-radius:10px;box-sizing:border-box;");

    localStorage.setItem("storeName", name);

    var userRaw = localStorage.getItem("user");
    var user = null;
    try { user = JSON.parse(userRaw); } catch(e) {}
    var userEmail = (user && user.email) ? user.email : "";

    var payload = {
        email: userEmail,
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
        contactEmail: localStorage.getItem("apply_contactEmail") || userEmail,
        idFront: localStorage.getItem("idFront") || "",
        idBack: localStorage.getItem("idBack") || "",
        storeLogo: localStorage.getItem("storeLogo") || "",
        storeName: name
    };

    fetch("/submit-store", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
    }).then(function(res){
        return res.json();
    }).then(function(data){
        if(data.success){
            window.location.href = "/store-pending";
        } else {
            window.location.href = "/store-pending";
        }
    }).catch(function(e){
        window.location.href = "/store-pending";
    });
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
  <img id="storeLogo" src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg" style="width:65px;height:65px;border-radius:50%;object-fit:cover;border:2px solid #ddd;">
  <div style="position:absolute;bottom:0;right:0;background:#1976d2;border-radius:50%;width:20px;height:20px;display:flex;align-items:center;justify-content:center;">
    <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
  </div>
</div>
<input type="file" id="storeLogoInput" accept="image/*" style="display:none;" onchange="changeStoreLogo(this)">

<div style="flex:1;">
  <!-- Online Badge فوق الاسم -->
  <div id="onlineBadge" style="display:inline-flex;align-items:center;gap:4px;margin-bottom:4px;">
    <span style="width:8px;height:8px;border-radius:50%;background:#4caf50;display:inline-block;box-shadow:0 0 0 2px rgba(76,175,80,0.3);"></span>
    <span style="font-size:11px;color:#4caf50;font-weight:bold;">Online</span>
  </div>
  <!-- اسم المتجر القابل للتعديل -->
  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
    <div id="storeNameDisplay" style="font-weight:bold;font-size:16px;"></div>
    <span onclick="editStoreName()" style="cursor:pointer;">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#1976d2" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
    </span>
  </div>
  <div id="storeStatusBadge" style="color:orange;font-size:13px;">Please wait! The store is under review</div>
  <!-- VIP Badge + Countdown -->
  <div style="margin-top:5px;">
    <span id="vipBadge" style="background:linear-gradient(90deg,#f5a623,#e8791d);color:white;font-size:11px;padding:3px 10px;border-radius:10px;display:inline-block;">VIP 0</span>
    <div id="trafficCountdownBox" style="display:none;margin-top:4px;padding-left:45px;line-height:1.5;">
      <div style="font-size:11px;color:#e53935;font-weight:bold;">Limited Free Traffic & Promotion Period</div>
      <div id="trafficCountdownTimer" style="font-size:13px;font-weight:bold;color:#e53935;">1,000,000:00:00</div>
    </div>
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
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_listings.svg" style="width:40px;">
<p>Listings</p>
</div>

<div class="tool" onclick="window.location.href='/manage-product'" style="cursor:pointer;">
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_manage_product.svg" style="width:40px;">
<p>Manage product</p>
</div>

<div class="tool" onclick="window.location.href='/manage-orders'" style="cursor:pointer;">
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_manage_order.svg" style="width:40px;">
<p>Manage Order</p>
</div>

<div class="tool" onclick="window.location.href='/store-setting'" style="cursor:pointer;">
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_setting.svg" style="width:40px;">
<p>Store setting</p>
</div>

<div class="tool" onclick="window.location.href='/vip-upgrade'" style="cursor:pointer;">
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_operating_fund.svg" style="width:40px;">
<p>Store Operating fund</p>
</div>

<div class="tool" onclick="window.location.href='/instructions'" style="cursor:pointer;">
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_instructions.svg" style="width:40px;">
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
        // السيرفر هو المصدر الحقيقي دائماً - نحدث المحلي منه
        let serverName = data.storeName || "";
        if(serverName) {
            localStorage.setItem("merchant_storeName_" + user.email, serverName);
            document.getElementById("storeNameDisplay").innerText = serverName;
        } else {
            let savedName = localStorage.getItem("merchant_storeName_" + user.email);
            document.getElementById("storeNameDisplay").innerText = savedName || "";
        }
        if(data.status === "approved"){
            document.getElementById("storeStatusBadge").innerText = "";
            // تشغيل العداد التنازلي
            startStoreCountdown(data.approvedAt || null);
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
    if(!newName || newName.trim() === "") return;
    newName = newName.trim();
    let user = JSON.parse(localStorage.getItem("user"));
    let token = localStorage.getItem("token") || (user ? user.token : "") || "";
    localStorage.setItem("merchant_storeName_" + (user ? user.email : ""), newName);
    document.getElementById("storeNameDisplay").innerText = newName;
    fetch("/update-store-settings", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
        body: JSON.stringify({ storeName: newName })
    })
    .then(function(r){ return r.json(); })
    .then(function(d){ if(!d.success) alert("Failed to save store name on server"); })
    .catch(function(){ alert("Connection error while saving store name"); });
}

// ======= عداد تنازلي 1,000,000 ساعة بعد الموافقة =======
function startStoreCountdown(approvedAt){
  let cdEl = document.getElementById("storeCountdown");
  let box  = document.getElementById("trafficCountdownBox");
  let timerEl = document.getElementById("trafficCountdownTimer");
  if(!timerEl) return;
  if(box) box.style.display = "block";

  let user = JSON.parse(localStorage.getItem("user") || "{}");
  let key = "storeCountdownStart_" + (user.email || "");
  let startTime = parseInt(localStorage.getItem(key) || "0");
  if(!startTime){
    startTime = approvedAt ? new Date(approvedAt).getTime() : Date.now();
    localStorage.setItem(key, startTime);
  }

  const TOTAL_HOURS = 1000000;
  const TOTAL_MS = TOTAL_HOURS * 3600 * 1000;

  function tick(){
    let elapsed = Date.now() - startTime;
    let remaining = TOTAL_MS - elapsed;
    if(remaining <= 0){
      timerEl.innerText = "0:00:00";
      if(cdEl) cdEl.innerText = "0:00:00";
      return;
    }

    let totalSecs = Math.floor(remaining / 1000);
    let totalHours = Math.floor(totalSecs / 3600);
    let mins = Math.floor((totalSecs % 3600) / 60);
    let secs = totalSecs % 60;

    let hStr = totalHours.toLocaleString(); // يضيف الفواصل: 1,000,000
    let mStr = String(mins).padStart(2,"0");
    let sStr = String(secs).padStart(2,"0");
    let display = hStr + ":" + mStr + ":" + sStr;

    timerEl.innerText = display;
    if(cdEl) cdEl.innerText = display;
  }
  tick();
  setInterval(tick, 1000);
}

// ======= عداد الزوار التراكمي (يبدأ من 0 ويزيد تدريجياً طوال اليوم) =======
function loadVisitorCounter(){
  let user = JSON.parse(localStorage.getItem("user") || "{}");
  let token = localStorage.getItem("token") || (user.token || "");
  if(!user.email || !token) return;

  const VIP_VISITORS = [50, 200, 500, 1500, 5000, 15000];
  let vipLevel = user.vipLevel || 0;
  const DAILY_TARGET = VIP_VISITORS[vipLevel] || 50;

  // ======= جلب الرقم الحالي من السيرفر =======
  function fetchFromServer(){
    return fetch("/store-visitors/" + encodeURIComponent(user.email), {
      headers: { "Authorization": "Bearer " + token }
    })
    .then(function(r){ return r.json(); })
    .catch(function(){ return null; });
  }

  // ======= إرسال الزيادة للسيرفر =======
  function pushToServer(todayAdded){
    return fetch("/store-visitors/update", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
      body: JSON.stringify({ todayAdded: todayAdded })
    })
    .then(function(r){ return r.json(); })
    .catch(function(){ return null; });
  }

  // ======= عرض الرقم =======
  function showCount(total, today){
    let el = document.getElementById("visitorCount");
    if(el) el.innerText = (total || 0) + (today || 0);
  }

  // ======= جلب البيانات من السيرفر فوراً =======
  fetchFromServer().then(function(data){
    if(data && data.success){
      showCount(data.totalVisitors, data.todayVisitors);
    }
  });

  // ======= إضافة زوار تدريجياً وإرسالها للسيرفر =======
  // نحتفظ بـ pendingAdd للتجميع قبل الإرسال
  let pendingAdd = 0;
  let todayFromServer = 0;
  let totalFromServer = 0;

  // نجلب الحالة الحالية أولاً
  fetchFromServer().then(function(data){
    if(data && data.success){
      todayFromServer = data.todayVisitors || 0;
      totalFromServer = data.totalVisitors || 0;
    }

    // توزيع الزوار على 24 ساعة = 1440 دقيقة
    // كل دفعة تُضاف كل 2-4 دقائق بشكل عشوائي
    var BATCH_INTERVAL_MIN = 2 * 60 * 1000;  // 2 دقيقة
    var BATCH_INTERVAL_MAX = 4 * 60 * 1000;  // 4 دقيقة
    // حجم كل دفعة = الهدف اليومي / عدد الدفعات المتوقعة (720 دفعة في 24 ساعة)
    var BATCHES_PER_DAY = 720;
    var batchSize = Math.max(1, Math.round(DAILY_TARGET / BATCHES_PER_DAY));

    function scheduleNext(){
      if(todayFromServer + pendingAdd >= DAILY_TARGET) return;
      var delay = BATCH_INTERVAL_MIN + Math.random() * (BATCH_INTERVAL_MAX - BATCH_INTERVAL_MIN);

      setTimeout(function(){
        var remaining = DAILY_TARGET - (todayFromServer + pendingAdd);
        // عشوائية ±30% على حجم الدفعة لتبدو طبيعية
        var jitter = Math.round(batchSize * 0.3 * (Math.random() * 2 - 1));
        var toAdd = Math.min(Math.max(1, batchSize + jitter), remaining);
        if(toAdd > 0){
          pendingAdd += toAdd;
          showCount(totalFromServer, todayFromServer + pendingAdd);
          pushToServer(toAdd).then(function(res){
            if(res && res.success){
              todayFromServer = res.todayVisitors || 0;
              totalFromServer  = res.totalVisitors  || 0;
              pendingAdd = 0;
              showCount(totalFromServer, todayFromServer);
            }
          });
        }
        scheduleNext();
      }, delay);
    }

    // أول إضافة بعد 5 ثوانٍ
    setTimeout(function(){
      var remaining = DAILY_TARGET - (todayFromServer + pendingAdd);
      var toAdd = Math.min(Math.max(1, batchSize), remaining);
      if(toAdd > 0){
        pendingAdd += toAdd;
        showCount(totalFromServer, todayFromServer + pendingAdd);
        pushToServer(toAdd).then(function(res){
          if(res && res.success){
            todayFromServer = res.todayVisitors || 0;
            totalFromServer  = res.totalVisitors  || 0;
            pendingAdd = 0;
            showCount(totalFromServer, todayFromServer);
          }
        });
      }
      scheduleNext();
    }, 5000);
  });
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
    function fmt(n){ return parseFloat(n||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2}); }
    let balEl = document.getElementById("merchantBalance");
    if(balEl) balEl.innerText = fmt(d.availableBalance);
    let capEl = document.getElementById("merchantTotalCapital");
    if(capEl) capEl.innerText = fmt(d.totalWorkingCapital);
    let podEl = document.getElementById("profitOfDay");
    if(podEl) podEl.innerText = fmt(d.profitOfDay);
    let tpcEl = document.getElementById("totalProfitCredited");
    if(tpcEl) tpcEl.innerText = fmt(d.totalProfitCredited);
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
    { level: 1, capital: 500,     visitors: 200,   products: 35,  commission: 17 },
    { level: 2, capital: 5000,    visitors: 500,   products: 80,  commission: 20 },
    { level: 3, capital: 20000,   visitors: 1500,  products: 120, commission: 22 },
    { level: 4, capital: 50000,   visitors: 5000,  products: 300, commission: 25 },
    { level: 5, capital: 200000,  visitors: 15000, products: 1000,commission: 40 }
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
  padding-top: 0;
}

/* SECTION TITLE */
.section-title{
  margin:0 14px 10px;
  padding-top:14px;
  font-size:15px;font-weight:600;color:#333;
}

/* VIP CARD */
.vip-card{
  background:white;
  margin:0 14px 14px;
  border-radius:16px;
  overflow:hidden;
  box-shadow:0 2px 12px rgba(0,0,0,0.08);
  border:1.5px solid #e8e8e8;
}
.vip-card.current{ border:1.5px solid #d0d0d0; }
.vip-card.vip5{ border:2px solid #1976d2; background:white; }

/* CARD TOP HALF — VIP badge + label */
.card-top{
  padding:16px 18px 10px;
  display:flex;align-items:center;justify-content:space-between;
}
.vip-badge{
  background:linear-gradient(135deg,#f5a623,#e8791d);
  color:white;
  padding:5px 16px;
  border-radius:20px;
  font-size:14px;
  font-weight:700;
  display:inline-block;
}
.vip-badge.vip5-b{
  background:linear-gradient(135deg,#1976d2,#1565c0);
  color:white;
}
.vip-badge.vip-badge-done{
  background:#e0e0e0;
  color:#888;
}
.best-badge{
  background:#fff3e0;
  color:#e65100;
  border:1.5px solid #ffb74d;
  font-size:11px;font-weight:700;
  padding:3px 10px;border-radius:20px;
  display:inline-block;
}
.current-plan-label{
  font-size:12px;
  color:#999;
  font-weight:500;
}

/* CARD INFO — صفوف البيانات */
.card-info{
  padding:4px 18px 14px;
}
.info-row{
  display:flex;align-items:center;justify-content:space-between;
  padding:9px 0;
  font-size:14px;
  border-bottom:1px solid #f5f5f5;
}
.info-row:last-child{ border-bottom:none; }
.info-row .ikey{ color:#555;font-weight:400; }
.info-row .ival{ font-weight:700;color:#111; }
.info-row .ival.comm{ color:#2e7d32; }

/* CARD BOTTOM — زر */
.card-btn{
  padding:4px 18px 18px;
}
.upgrade-btn{
  width:100%;
  padding:14px;
  border:none;
  border-radius:28px;
  background:linear-gradient(135deg,#1976d2,#1565c0);
  color:white;
  font-size:15px;
  font-weight:700;
  cursor:pointer;
  transition:all 0.2s;
  text-align:center;
}
.upgrade-btn:active{ transform:scale(0.98); opacity:0.9; }
.current-btn{
  width:100%;
  padding:14px;
  border:1.5px solid #e0e0e0;
  border-radius:28px;
  background:#f8f8f8;
  color:#aaa;
  font-size:15px;
  font-weight:600;
  cursor:default;
  text-align:center;
}
.upgraded-btn{
  width:100%;
  padding:14px;
  border:none;
  border-radius:28px;
  background:transparent;
  color:#8B6914;
  font-size:15px;
  font-weight:600;
  cursor:default;
  text-align:center;
}
.locked-btn{
  width:100%;
  padding:14px;
  border:1.5px solid #e0e0e0;
  border-radius:28px;
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
  { level:1, capital:500,    visitors:200,   products:35,  commission:17, label:"VIP 1" },
  { level:2, capital:5000,   visitors:500,   products:80,  commission:20, label:"VIP 2" },
  { level:3, capital:20000,  visitors:1500,  products:120, commission:22, label:"VIP 3" },
  { level:4, capital:50000,  visitors:5000,  products:300, commission:25, label:"VIP 4" },
  { level:5, capital:200000, visitors:15000, products:1000,commission:40, label:"VIP 5", best:true }
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
  // لا حاجة لـ padding إضافي
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

    let badgeCls = isUpgraded ? "vip-badge vip-badge-done" : (plan.level === 5 ? "vip-badge vip5-b" : "vip-badge");
    let capitalTxt = plan.capital === 0 ? "Free" : "$" + fmt(plan.capital);
    let crownHtml  = plan.level === 5 ? "👑 " : "";
    let topRightHtml = "";
    if(isCurrent){
      topRightHtml = '<span class="current-plan-label">Current Plan</span>';
    } else if(plan.best){
      topRightHtml = '<span class="best-badge">Best Value</span>';
    }

    let btnHtml = "";
    if(isCurrent){
      btnHtml = '<div class="current-btn">Current Plan</div>';
    } else if(isUpgraded){
      btnHtml = '<div class="upgraded-btn">Upgraded</div>';
    } else if(canUpgrade){
      btnHtml = '<div class="upgrade-btn" onclick="doUpgrade(' + plan.level + ')">Upgrade Now</div>';
    } else {
      btnHtml = '<div class="locked-btn">🔒 Locked</div>';
    }

    card.innerHTML =
      '<div class="card-top">' +
        '<span class="' + badgeCls + '">' + crownHtml + plan.label + '</span>' +
        topRightHtml +
      '</div>' +
      '<div class="card-info">' +
        '<div class="info-row"><span class="ikey">Capital</span><span class="ival">' + capitalTxt + '</span></div>' +
        '<div class="info-row"><span class="ikey">Daily Traffic Boost</span><span class="ival">' + fmt(plan.visitors) + ' Visits</span></div>' +
        '<div class="info-row"><span class="ikey">Product Limit</span><span class="ival">' + fmt(plan.products) + ' Products</span></div>' +
        '<div class="info-row"><span class="ikey">Sales Commission</span><span class="ival comm">' + plan.commission + '%</span></div>' +
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

// ================= ADDRESS API =================
// جلب عناوين المستخدم
app.get("/api/addresses", authMiddleware, (req, res) => {
    const user = users.find(u => u.email === req.userEmail);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user.addresses || []);
});

// إضافة عنوان جديد
app.post("/api/addresses", authMiddleware, (req, res) => {
    const user = users.find(u => u.email === req.userEmail);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.addresses) user.addresses = [];
    const { name, mobile, countryCode, country, province, city, exactLocation, postalCode, isDefault } = req.body;
    if (!name || !mobile || !country || !city) return res.status(400).json({ error: "Missing required fields" });
    // إذا كان default، نلغي default عن الباقين
    if (isDefault) user.addresses.forEach(a => a.isDefault = false);
    const newAddress = {
        id: Date.now().toString(),
        name, mobile, countryCode: countryCode || "+1",
        country, province: province || "", city,
        exactLocation: exactLocation || "", postalCode: postalCode || "",
        isDefault: isDefault || false,
        createdAt: new Date().toISOString()
    };
    user.addresses.push(newAddress);
    saveUsers();
    res.json({ success: true, address: newAddress });
});

// تعديل عنوان
app.put("/api/addresses/:id", authMiddleware, (req, res) => {
    const user = users.find(u => u.email === req.userEmail);
    if (!user || !user.addresses) return res.status(404).json({ error: "Not found" });
    const idx = user.addresses.findIndex(a => a.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: "Address not found" });
    const { name, mobile, countryCode, country, province, city, exactLocation, postalCode, isDefault } = req.body;
    if (isDefault) user.addresses.forEach(a => a.isDefault = false);
    user.addresses[idx] = { ...user.addresses[idx], name, mobile, countryCode: countryCode || "+1", country, province: province || "", city, exactLocation: exactLocation || "", postalCode: postalCode || "", isDefault: isDefault || false };
    saveUsers();
    res.json({ success: true, address: user.addresses[idx] });
});

// حذف عنوان
app.delete("/api/addresses/:id", authMiddleware, (req, res) => {
    const user = users.find(u => u.email === req.userEmail);
    if (!user || !user.addresses) return res.status(404).json({ error: "Not found" });
    user.addresses = user.addresses.filter(a => a.id !== req.params.id);
    saveUsers();
    res.json({ success: true });
});

// ================= ADDRESS PAGE =================
app.get("/address", (req, res) => {
res.send(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Arial,sans-serif;background:#f5f5f5;min-height:100vh;}

/* HEADER */
.header{background:white;padding:15px 16px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #eee;position:relative;}
.back-btn{cursor:pointer;display:inline-flex;align-items:center;padding:4px;}
.header b{font-size:17px;color:#222;}

/* ADD BUTTON */
.add-btn{display:block;margin:16px;padding:14px;background:white;border:none;border-radius:12px;font-size:15px;font-weight:600;color:#333;text-align:center;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.08);}
.add-btn:active{background:#f0f0f0;}

/* EMPTY */
.empty{text-align:center;margin-top:120px;color:#bbb;}
.empty svg{width:70px;height:70px;margin-bottom:12px;opacity:0.4;}
.empty p{font-size:14px;}

/* ADDRESS CARDS */
.cards-list{padding:0 16px 100px;}
.addr-card{background:white;border-radius:14px;padding:16px;margin-bottom:12px;box-shadow:0 2px 10px rgba(0,0,0,0.07);border:2px solid transparent;position:relative;}
.addr-card.default{border-color:#1976d2;}
.addr-card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;}
.addr-name{font-weight:700;font-size:15px;color:#222;}
.default-badge{background:#1976d2;color:white;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;}
.addr-phone{font-size:13px;color:#666;margin-bottom:4px;}
.addr-detail{font-size:13px;color:#444;line-height:1.5;}
.addr-actions{display:flex;gap:10px;margin-top:12px;border-top:1px solid #f0f0f0;padding-top:10px;}
.btn-edit{flex:1;padding:8px;background:#f0f6ff;color:#1976d2;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;}
.btn-delete{flex:1;padding:8px;background:#fff0f0;color:#e53935;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;}

/* BOTTOM SHEET OVERLAY */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:100;}
.overlay.show{display:block;}

/* BOTTOM SHEET */
.sheet{position:fixed;bottom:-100%;left:50%;transform:translateX(-50%);width:100%;max-width:480px;background:white;border-radius:22px 22px 0 0;z-index:101;transition:bottom 0.35s cubic-bezier(.4,0,.2,1);max-height:92vh;overflow-y:auto;padding-bottom:20px;}
.sheet.open{bottom:0;}
.sheet-header{padding:16px 16px 10px;display:flex;align-items:center;border-bottom:1px solid #f0f0f0;position:sticky;top:0;background:white;z-index:2;}
.sheet-back{cursor:pointer;display:inline-flex;align-items:center;margin-right:8px;}
.sheet-title{font-size:16px;font-weight:700;color:#222;}

/* FORM */
.form-group{padding:12px 16px 0;}
.form-group label{font-size:12px;color:#666;margin-bottom:5px;display:block;}
.form-group input,.form-group select{width:100%;padding:12px;border:1px solid #e0e0e0;border-radius:10px;font-size:14px;outline:none;background:white;}
.form-group input:focus,.form-group select:focus{border-color:#1976d2;}
.phone-row{display:flex;gap:8px;}
.phone-code{width:75px;flex-shrink:0;font-size:12px;padding-left:4px;padding-right:2px;}

/* TOGGLE */
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:16px 16px 0;}
.toggle-label{font-size:14px;color:#333;}
.toggle{position:relative;width:44px;height:24px;}
.toggle input{opacity:0;width:0;height:0;}
.slider{position:absolute;inset:0;background:#ccc;border-radius:24px;cursor:pointer;transition:.3s;}
.slider:before{content:"";position:absolute;height:18px;width:18px;left:3px;bottom:3px;background:white;border-radius:50%;transition:.3s;}
input:checked+.slider{background:#1976d2;}
input:checked+.slider:before{transform:translateX(20px);}

/* SAVE BTN */
.save-btn{display:block;margin:20px 16px 0;padding:15px;background:#1976d2;color:white;border:none;border-radius:12px;font-size:16px;font-weight:700;width:calc(100% - 32px);cursor:pointer;}
.save-btn:active{opacity:0.85;}

/* TOAST */
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#333;color:white;padding:10px 22px;border-radius:30px;font-size:14px;z-index:999;display:none;white-space:nowrap;}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <span class="back-btn" onclick="goBack()">
    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
  </span>
  <b>📍 Address</b>
</div>

<!-- ADD BUTTON -->
<button class="add-btn" onclick="openSheet(null)">＋ Add a new address</button>

<!-- CARDS -->
<div class="cards-list" id="cardsList"></div>

<!-- EMPTY -->
<div class="empty" id="emptyState" style="display:none;">
  <svg viewBox="0 0 24 24" fill="none" stroke="#ccc" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="11" y2="17"/><circle cx="17" cy="17" r="3"/><line x1="19.5" y1="19.5" x2="21" y2="21"/></svg>
  <p>Not Available</p>
</div>

<!-- OVERLAY -->
<div class="overlay" id="overlay" onclick="closeSheet()"></div>

<!-- BOTTOM SHEET -->
<div class="sheet" id="sheet">
  <div class="sheet-header">
    <span class="sheet-back" onclick="closeSheet()">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </span>
    <span class="sheet-title">Add another address</span>
  </div>

  <div class="form-group">
    <label>Name</label>
    <input id="f_name" placeholder="Please fill in receiver name">
  </div>

  <div class="form-group">
    <label>Mobile</label>
    <div style="display:flex;gap:8px;">
      <select id="f_code" style="width:90px;min-width:90px;max-width:90px;padding:12px 4px;border:1px solid #e0e0e0;border-radius:10px;font-size:13px;outline:none;background:white;">
        <option value="+1">🇺🇸 +1</option>
        <option value="+44">🇬🇧 +44</option>
        <option value="+91">🇮🇳 +91</option>
        <option value="+966">🇸🇦 +966</option>
        <option value="+971">🇦🇪 +971</option>
        <option value="+20">🇪🇬 +20</option>
        <option value="+964">🇮🇶 +964</option>
        <option value="+963">🇸🇾 +963</option>
        <option value="+962">🇯🇴 +962</option>
        <option value="+212">🇲🇦 +212</option>
        <option value="+213">🇩🇿 +213</option>
        <option value="+216">🇹🇳 +216</option>
        <option value="+249">🇸🇩 +249</option>
        <option value="+855">🇰🇭 +855</option>
        <option value="+86">🇨🇳 +86</option>
        <option value="+81">🇯🇵 +81</option>
        <option value="+82">🇰🇷 +82</option>
        <option value="+65">🇸🇬 +65</option>
        <option value="+60">🇲🇾 +60</option>
        <option value="+33">🇫🇷 +33</option>
        <option value="+49">🇩🇪 +49</option>
        <option value="+39">🇮🇹 +39</option>
        <option value="+7">🇷🇺 +7</option>
        <option value="+55">🇧🇷 +55</option>
        <option value="+52">🇲🇽 +52</option>
        <option value="+234">🇳🇬 +234</option>
        <option value="+254">🇰🇪 +254</option>
        <option value="+27">🇿🇦 +27</option>
        <option value="+62">🇮🇩 +62</option>
        <option value="+63">🇵🇭 +63</option>
        <option value="+66">🇹🇭 +66</option>
        <option value="+84">🇻🇳 +84</option>
        <option value="+90">🇹🇷 +90</option>
        <option value="+98">🇮🇷 +98</option>
        <option value="+92">🇵🇰 +92</option>
        <option value="+880">🇧🇩 +880</option>
      </select>
      <input id="f_mobile" placeholder="Please add receiver mobile" style="flex:1;min-width:0;padding:12px;border:1px solid #e0e0e0;border-radius:10px;font-size:14px;outline:none;">
    </div>
  </div>

  <div class="form-group">
    <label>Country / Region</label>
    <input id="f_country" placeholder="Please select Country / Region">
  </div>

  <div class="form-group">
    <label>Province / State / Region</label>
    <input id="f_province" placeholder="Please fill in Province/State/Region">
  </div>

  <div class="form-group">
    <label>City</label>
    <input id="f_city" placeholder="Please fill in the City">
  </div>

  <div class="form-group">
    <label>Exact location</label>
    <input id="f_exact" placeholder="Please fill in Exact Location">
  </div>

  <div class="form-group">
    <label>Postal code</label>
    <input id="f_postal" placeholder="Please fill in postal code">
  </div>

  <div class="toggle-row">
    <span class="toggle-label">Default address</span>
    <label class="toggle">
      <input type="checkbox" id="f_default">
      <span class="slider"></span>
    </label>
  </div>

  <button class="save-btn" onclick="saveAddress()">Save</button>
</div>

<!-- TOAST -->
<div class="toast" id="toast"></div>

<script>
const user = JSON.parse(localStorage.getItem("user") || "{}");
const token = localStorage.getItem("token") || user.token || "";
let editingId = null;
let addresses = [];

function goBack(){ window.history.back(); }

function showToast(msg, dur=2200){
  const t = document.getElementById("toast");
  t.textContent = msg; t.style.display = "block";
  setTimeout(() => t.style.display = "none", dur);
}

async function loadAddresses(){
  try {
    const r = await fetch("/api/addresses", { headers:{ "Authorization":"Bearer "+token } });
    if(!r.ok){ if(r.status===401) window.location.href="/login-page"; return; }
    addresses = await r.json();
    renderCards();
  } catch(e){ showToast("Connection error"); }
}

function renderCards(){
  const list = document.getElementById("cardsList");
  const empty = document.getElementById("emptyState");
  if(!addresses.length){ list.innerHTML=""; empty.style.display="block"; return; }
  empty.style.display="none";
  list.innerHTML = addresses.map(a => \`
    <div class="addr-card \${a.isDefault?'default':''}" id="card_\${a.id}">
      <div class="addr-card-header">
        <span class="addr-name">\${esc(a.name)}</span>
        \${a.isDefault ? '<span class="default-badge">Default</span>' : ''}
      </div>
      <div class="addr-phone">\${esc(a.countryCode)} \${esc(a.mobile)}</div>
      <div class="addr-detail">
        \${[a.exactLocation,a.city,a.province,a.country,a.postalCode].filter(Boolean).map(esc).join(', ')}
      </div>
      <div class="addr-actions">
        <button class="btn-edit" onclick="openSheet('\${a.id}')">✏️ Edit</button>
        <button class="btn-delete" onclick="deleteAddress('\${a.id}')">🗑️ Delete</button>
      </div>
    </div>
  \`).join('');
}

function esc(s){ if(!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function openSheet(id){
  editingId = id;
  const sheet = document.getElementById("sheet");
  const overlay = document.getElementById("overlay");
  // reset form
  ["f_name","f_mobile","f_country","f_province","f_city","f_exact","f_postal"].forEach(i=>document.getElementById(i).value="");
  document.getElementById("f_code").value="+1";
  document.getElementById("f_default").checked=false;
  document.querySelector(".sheet-title").textContent = id ? "Edit address" : "Add another address";

  if(id){
    const a = addresses.find(x=>x.id===id);
    if(a){
      document.getElementById("f_name").value = a.name||"";
      document.getElementById("f_mobile").value = a.mobile||"";
      document.getElementById("f_code").value = a.countryCode||"+1";
      document.getElementById("f_country").value = a.country||"";
      document.getElementById("f_province").value = a.province||"";
      document.getElementById("f_city").value = a.city||"";
      document.getElementById("f_exact").value = a.exactLocation||"";
      document.getElementById("f_postal").value = a.postalCode||"";
      document.getElementById("f_default").checked = !!a.isDefault;
    }
  }
  overlay.classList.add("show");
  setTimeout(()=>sheet.classList.add("open"),10);
}

function closeSheet(){
  document.getElementById("sheet").classList.remove("open");
  document.getElementById("overlay").classList.remove("show");
}

async function saveAddress(){
  const name = document.getElementById("f_name").value.trim();
  const mobile = document.getElementById("f_mobile").value.trim();
  const country = document.getElementById("f_country").value.trim();
  const city = document.getElementById("f_city").value.trim();
  if(!name){ showToast("Please enter receiver name"); return; }
  if(!mobile){ showToast("Please enter mobile number"); return; }
  if(!country){ showToast("Please enter country"); return; }
  if(!city){ showToast("Please enter city"); return; }

  const body = {
    name, mobile,
    countryCode: document.getElementById("f_code").value,
    country,
    province: document.getElementById("f_province").value.trim(),
    city,
    exactLocation: document.getElementById("f_exact").value.trim(),
    postalCode: document.getElementById("f_postal").value.trim(),
    isDefault: document.getElementById("f_default").checked
  };

  try {
    const url = editingId ? "/api/addresses/"+editingId : "/api/addresses";
    const method = editingId ? "PUT" : "POST";
    const r = await fetch(url, {
      method, headers:{ "Authorization":"Bearer "+token, "Content-Type":"application/json" },
      body: JSON.stringify(body)
    });
    const d = await r.json();
    if(d.success){
      closeSheet();
      showToast(editingId ? "Address updated ✓" : "Address saved ✓");
      await loadAddresses();
    } else { showToast(d.error || "Error saving"); }
  } catch(e){ showToast("Connection error"); }
}

async function deleteAddress(id){
  if(!confirm("Delete this address?")) return;
  try {
    const r = await fetch("/api/addresses/"+id, {
      method:"DELETE", headers:{ "Authorization":"Bearer "+token }
    });
    const d = await r.json();
    if(d.success){ showToast("Address deleted"); await loadAddresses(); }
    else showToast("Error deleting");
  } catch(e){ showToast("Connection error"); }
}

// تحميل العناوين عند فتح الصفحة
loadAddresses();
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
<script src="/env.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"></script>
<style>
body{margin:0;font-family:Arial;background:white;min-height:100vh;}
.header{position:relative;background:white;padding:15px;display:flex;align-items:center;gap:10px;font-size:20px;border-bottom:1px solid #eee;}
.card{background:white;margin:15px;padding:20px;border-radius:15px;box-shadow:0 5px 20px rgba(0,0,0,0.05);}
input{width:100%;padding:12px;margin-top:10px;border-radius:10px;border:1px solid #ddd;box-sizing:border-box;}
.code-row{display:flex;align-items:center;gap:8px;margin-top:10px;}
.code-row input{margin-top:0;flex:1;}
.code-btn{white-space:nowrap;padding:12px 14px;border:none;border-radius:10px;background:#1976d2;color:white;font-size:13px;cursor:pointer;}
.code-btn:disabled{background:#aaa;cursor:not-allowed;}
button.next-btn{width:100%;padding:15px;margin-top:20px;border:none;border-radius:10px;background:#1976d2;color:white;font-size:16px;cursor:pointer;}
p.label{color:#999;margin-top:14px;margin-bottom:2px;font-size:14px;}
</style>
</head>
<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>📧 Manage Email</b>
</div>

<div class="card">
<p id="userEmail" style="font-weight:bold;"></p>

<p class="label">Old Email verification code</p>
<div class="code-row">
  <input id="codeInput" placeholder="Old Email verification code">
  <button class="code-btn" id="sendCodeBtn" onclick="sendCode()">Verification Code</button>
</div>

<button class="next-btn" onclick="nextStep()">Next</button>
</div>

<script>
emailjs.init("oq1_7ae-h5rE8XSlJ");

let user = JSON.parse(localStorage.getItem("user"));
let _verifyCode = "";
let _codeSent = false;
let _countdown = 0;

document.getElementById("userEmail").innerText = user ? user.email : "";

function goBack(){ window.location.href="/dashboard"; }

function sendCode(){
  if(!user || !user.email){ showMsg("Cannot find user email"); return; }
  if(_countdown > 0) return;

  var btn = document.getElementById("sendCodeBtn");
  btn.disabled = true;
  btn.innerText = "Sending...";

  _verifyCode = Math.floor(100000 + Math.random() * 900000).toString();
  _codeSent = true;

  emailjs.send("service_auff35i", "template_35dlg2l", {
    to_email: user.email,
    code: _verifyCode
  }).then(function(){
    startCountdown(btn);
  }).catch(function(err){
    showMsg("Failed to send email. Please try again.");
    btn.disabled = false;
    btn.innerText = "Verification Code";
    _codeSent = false;
    console.log("EmailJS error:", err);
  });
}

function startCountdown(btn){
  _countdown = 60;
  btn.innerText = _countdown + "s Retry";
  var timer = setInterval(function(){
    _countdown--;
    if(_countdown <= 0){
      clearInterval(timer);
      btn.disabled = false;
      btn.innerText = "Verification Code";
    } else {
      btn.innerText = _countdown + "s Retry";
    }
  }, 1000);
}

function nextStep(){
  var enteredCode = document.getElementById("codeInput").value.trim();
  if(!_codeSent){ showMsg("Please request a verification code first"); return; }
  if(enteredCode !== _verifyCode){ showMsg("Wrong verification code ❌"); return; }
  showMsg("Code verified ✅", "success");
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
<script src="/env.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"></script>
<style>
body{margin:0;font-family:Arial;background:white;min-height:100vh;}
.header{position:relative;background:white;padding:15px;display:flex;align-items:center;gap:10px;font-size:20px;border-bottom:1px solid #eee;}
.header span{cursor:pointer;font-size:20px;}
.card{background:white;margin:15px;padding:20px;border-radius:15px;box-shadow:0 5px 20px rgba(0,0,0,0.05);}
input{width:100%;padding:12px;margin-top:10px;border-radius:10px;border:1px solid #ddd;box-sizing:border-box;}
.code-row{display:flex;align-items:center;gap:8px;margin-top:10px;}
.code-row input{margin-top:0;flex:1;}
.code-btn{white-space:nowrap;padding:12px 14px;border:none;border-radius:10px;background:#1976d2;color:white;font-size:13px;cursor:pointer;}
.code-btn:disabled{background:#aaa;cursor:not-allowed;}
button.save-btn{width:100%;padding:15px;margin-top:20px;border:none;border-radius:10px;background:#1976d2;color:white;font-size:16px;cursor:pointer;}
</style>
</head>
<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>🔒 Account Password</b>
</div>

<div class="card">
<p id="userEmail" style="margin-bottom:10px;font-weight:bold;"></p>

<input id="newPass" type="password" placeholder="Please enter new password">

<div class="code-row">
  <input id="codeInput" placeholder="Please enter Email verification code">
  <button class="code-btn" id="sendCodeBtn" onclick="sendCode()">Verification Code</button>
</div>

<button class="save-btn" onclick="savePassword()">Save</button>
</div>

<script>
emailjs.init("oq1_7ae-h5rE8XSlJ");

let user = JSON.parse(localStorage.getItem("user"));
let _verifyCode = "";
let _codeSent = false;
let _countdown = 0;

document.getElementById("userEmail").innerText = user ? user.email : "";

function goBack(){ window.location.href="/dashboard"; }

function sendCode(){
  if(!user || !user.email){ showMsg("Cannot find user email"); return; }
  if(_countdown > 0) return;

  var btn = document.getElementById("sendCodeBtn");
  btn.disabled = true;
  btn.innerText = "Sending...";

  _verifyCode = Math.floor(100000 + Math.random() * 900000).toString();
  _codeSent = true;

  emailjs.send("service_auff35i", "template_35dlg2l", {
    to_email: user.email,
    code: _verifyCode
  }).then(function(){
    startCountdown(btn);
  }).catch(function(err){
    showMsg("Failed to send email. Please try again.");
    btn.disabled = false;
    btn.innerText = "Verification Code";
    _codeSent = false;
    console.log("EmailJS error:", err);
  });
}

function startCountdown(btn){
  _countdown = 60;
  btn.innerText = _countdown + "s Retry";
  var timer = setInterval(function(){
    _countdown--;
    if(_countdown <= 0){
      clearInterval(timer);
      btn.disabled = false;
      btn.innerText = "Verification Code";
    } else {
      btn.innerText = _countdown + "s Retry";
    }
  }, 1000);
}

function savePassword(){
  var newPass = document.getElementById("newPass").value.trim();
  var enteredCode = document.getElementById("codeInput").value.trim();

  if(!newPass){ showMsg("Please enter new password"); return; }
  if(!_codeSent){ showMsg("Please request a verification code first"); return; }
  if(enteredCode !== _verifyCode){ showMsg("Wrong verification code ❌"); return; }

  var token = localStorage.getItem("token") || (user && user.token) || "";

  fetch("/change-account-password", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ newPassword: newPass })
  })
  .then(r => r.json())
  .then(data => {
    if(data.success){
      showMsg("Password updated successfully ✅", "success");
      setTimeout(function(){ window.location.href = "/dashboard"; }, 1500);
    } else {
      showMsg("Error: " + (data.message || "Failed"));
    }
  })
  .catch(() => showMsg("Network error. Please try again."));
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
<script src="/env.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"></script>
<style>
body{margin:0;font-family:Arial;background:white;min-height:100vh;}
.header{position:relative;background:white;padding:15px;display:flex;align-items:center;gap:10px;font-size:20px;border-bottom:1px solid #eee;}
.card{background:white;margin:15px;padding:20px;border-radius:15px;box-shadow:0 5px 20px rgba(0,0,0,0.05);}
input{width:100%;padding:12px;margin-top:10px;border-radius:10px;border:1px solid #ddd;box-sizing:border-box;}
.code-row{display:flex;align-items:center;gap:8px;margin-top:10px;}
.code-row input{margin-top:0;flex:1;}
.code-btn{white-space:nowrap;padding:12px 14px;border:none;border-radius:10px;background:#1976d2;color:white;font-size:13px;cursor:pointer;}
.code-btn:disabled{background:#aaa;cursor:not-allowed;}
button.save-btn{width:100%;padding:15px;margin-top:20px;border:none;border-radius:10px;background:#1976d2;color:white;font-size:16px;cursor:pointer;}
</style>
</head>
<body>

<div class="header">
<span onclick="goBack()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
<b>🔑 Transaction Password</b>
</div>

<div class="card">
<p id="userEmail" style="margin-bottom:10px;font-weight:bold;"></p>

<input id="transPass" type="password" maxlength="6" placeholder="Please enter 6 characters password">

<div class="code-row">
  <input id="codeInput" placeholder="Please enter Email verification code">
  <button class="code-btn" id="sendCodeBtn" onclick="sendCode()">Verification Code</button>
</div>

<button class="save-btn" onclick="saveTransaction()">Save</button>
</div>

<script>
emailjs.init("oq1_7ae-h5rE8XSlJ");

let user = JSON.parse(localStorage.getItem("user"));
let _verifyCode = "";
let _codeSent = false;
let _countdown = 0;

document.getElementById("userEmail").innerText = user ? user.email : "";

function goBack(){ window.location.href="/dashboard"; }

function sendCode(){
  if(!user || !user.email){ showMsg("Cannot find user email"); return; }
  if(_countdown > 0) return;

  var btn = document.getElementById("sendCodeBtn");
  btn.disabled = true;
  btn.innerText = "Sending...";

  _verifyCode = Math.floor(100000 + Math.random() * 900000).toString();
  _codeSent = true;

  emailjs.send("service_auff35i", "template_35dlg2l", {
    to_email: user.email,
    code: _verifyCode
  }).then(function(){
    startCountdown(btn);
  }).catch(function(err){
    showMsg("Failed to send email. Please try again.");
    btn.disabled = false;
    btn.innerText = "Verification Code";
    _codeSent = false;
    console.log("EmailJS error:", err);
  });
}

function startCountdown(btn){
  _countdown = 60;
  btn.innerText = _countdown + "s Retry";
  var timer = setInterval(function(){
    _countdown--;
    if(_countdown <= 0){
      clearInterval(timer);
      btn.disabled = false;
      btn.innerText = "Verification Code";
    } else {
      btn.innerText = _countdown + "s Retry";
    }
  }, 1000);
}

function saveTransaction(){
  var pass = document.getElementById("transPass").value.trim();
  var enteredCode = document.getElementById("codeInput").value.trim();

  if(pass.length !== 6){ showMsg("Password must be exactly 6 characters"); return; }
  if(!_codeSent){ showMsg("Please request a verification code first"); return; }
  if(enteredCode !== _verifyCode){ showMsg("Wrong verification code ❌"); return; }

  var token = localStorage.getItem("token") || (user && user.token) || "";

  fetch("/change-transaction-password", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify({ newPassword: pass })
  })
  .then(r => r.json())
  .then(data => {
    if(data.success){
      user.transactionPassword = pass;
      localStorage.setItem("user", JSON.stringify(user));
      showMsg("Transaction password saved ✅", "success");
      setTimeout(function(){ window.location.href = "/dashboard"; }, 1500);
    } else {
      showMsg("Error: " + (data.message || "Failed"));
    }
  })
  .catch(() => showMsg("Network error. Please try again."));
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

.inputBox textarea{
flex:1;
padding:10px;
border:1px solid #ccc;
border-radius:10px;
resize:none;
overflow-y:hidden;
max-height:120px;
line-height:1.4;
font-family:Arial;
font-size:14px;
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
💬 TikTok Shop Support
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
    <label for="userImgInput" style="cursor:pointer;display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;border-radius:8px;background:#e3f2fd;flex-shrink:0;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#1976d2" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
    </label>
    <input type="file" id="userImgInput" accept="image/*" style="display:none;" onchange="sendUserImage(this)">
    <textarea id="msg" placeholder="Type message..." rows="1"
      onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();send();} else { setTimeout(function(){var el=document.getElementById('msg');el.style.height='auto';el.style.height=Math.min(el.scrollHeight,120)+'px';},0); }"></textarea>
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
    showMsg("Please fill in all fields");
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
  if(m.img){
    div.innerHTML = "<b>🎧 TikTok Shop</b><br><img src='" + m.img + "' style='max-width:200px;max-height:200px;border-radius:8px;display:block;margin-top:4px;cursor:pointer;' onclick='viewFullImg(this.src)'>";
  } else {
    var safeText = m.text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
    div.innerHTML = "<b>🎧 TikTok Shop</b><br><span style='white-space:pre-wrap;word-break:break-word;'>" + safeText + "</span>";
  }
}else{
  var readTick = m.seen ? "<span style='font-size:11px;color:rgba(255,255,255,0.6);margin-left:4px;'>✓✓</span>" : "<span style='font-size:11px;color:rgba(255,255,255,0.4);margin-left:4px;'>✓</span>";
  if(m.img){
    div.innerHTML = "<img src='" + m.img + "' style='max-width:200px;max-height:200px;border-radius:8px;display:block;cursor:pointer;' onclick='viewFullImg(this.src)'> " + readTick;
  } else {
    var safeUserText = (m.text||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    div.innerHTML = "<span style='white-space:pre-wrap;word-break:break-word;'>" + safeUserText + "</span>" + readTick;
  }
}

chat.appendChild(div);
});

chat.scrollTop = chat.scrollHeight;

// تعليم رسائل الأدمن كمقروءة
fetch("/mark-seen", {
  method:"POST",
  headers:{"Content-Type":"application/json"},
  body: JSON.stringify({ email: user.email })
}).catch(()=>{});
});
}

// إرسال صورة من المستخدم
function sendUserImage(input){
  if(!input.files || !input.files[0]) return;
  let file = input.files[0];
  if(file.size > 5 * 1024 * 1024){ alert("Image too large (max 5MB)"); return; }
  let reader = new FileReader();
  reader.onload = function(e){
    fetch("/send-message", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ email: user.email, text: "", img: e.target.result, sender: "user" })
    }).then(()=>{ loadMessages(); });
    input.value = "";
  };
  reader.readAsDataURL(file);
}

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

// إرسال رسالة
function send(){
let el = document.getElementById("msg");
let text = el.value;

if(!text || !text.trim()) return;

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
el.value = "";
el.style.height = "auto";
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
         src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg"
         onerror="this.src='https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg'">
    <div class="banner-info">
      <h2 id="bannerStoreName"></h2>
    </div>
  </div>
  <div class="badges" style="display:flex;gap:7px;flex-wrap:wrap;margin-top:10px;">
    <span class="vip-badge">&#10003; VIP <span id="vipLevel">0</span></span>
    <span class="badge">Products <span id="productCount">0</span></span>
    <span class="badge">Followers <span id="followerCount">0</span></span>
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

  // الاسم يأتي من السيرفر دائماً - هو المصدر الوحيد
  var updatedName = store.storeName || "";
  sName = updatedName;
  if(updatedName) {
    localStorage.setItem("merchant_storeName_" + sEmail, updatedName);
    localStorage.setItem("viewStoreName", updatedName);
  }
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
  var count = Math.floor(isLiked ? baseFollowers + 1 : baseFollowers);
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
var REPO_MAP = {17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};
function getJsdelivrBase(catId){ return "https://raw.githubusercontent.com/oscerm328-stack/"+(REPO_MAP[catId]||"products_27")+"/main"; }
var CLOUD_SP = "https://raw.githubusercontent.com/oscerm328-stack";
var CAT_MAP_SP = {17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};

function getStoreImg(p){
  var cat = CAT_MAP_SP[p.category_id]||"27_Electronics";
  var img = (p.images&&p.images.length>0)?p.images[0]:"1.jpg";
  return CLOUD_SP+"/"+cat+"/main/"+p.folder+"/"+img;
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
<title>Product - TikTok Shop</title>
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
  <img class="store-logo" id="storeLogo" src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg" onerror="this.src='https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg'">
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
var CLOUD = "https://raw.githubusercontent.com/oscerm328-stack";
var CAT_MAP = {17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};

async function init(){
    if(!p){ document.getElementById("productTitle").innerText="Product not found"; return; }

    // Build images from Cloudinary
    var catF = CAT_MAP[p.category_id]||"27_Electronics";
    imgs = (p.images&&p.images.length>0)
        ? p.images.map(function(i){ return CLOUD+"/"+catF+"/main/"+p.folder+"/"+i; })
        : [CLOUD+"/"+catF+"/main/"+(p.folder||"")+"/1.jpg"];

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
        var fd = await fetch("/followers/"+encodeURIComponent(sEmail)).then(function(r){return r.json();});
        var followers = fd.followers || 0;
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
    var addresses = JSON.parse(localStorage.getItem("userAddresses")||"[]");
    var cartItems = JSON.parse(localStorage.getItem("cartItems")||"[]");
    var imgSrc = p ? (p.img || p.imgs && p.imgs[0] || "") : "";
    var item = { id: Date.now(), title: p ? (p.t || p.title || "") : "", price: p ? (parseFloat(p.p || p.price) || 0) : 0, img: imgSrc, qty: qty, cat: p ? (p.cat || "") : "" };
    if(addresses.length === 0){
        // حفظ المنتج مؤقتاً ثم طلب العنوان
        window._pendingCartItem = item;
        closeSheet();
        showToast("⚠️ Please add a delivery address first");
        setTimeout(function(){ window.location.href = "/dashboard"; }, 1500);
        return;
    }
    cartItems.push(item);
    localStorage.setItem("cartItems", JSON.stringify(cartItems));
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
  <span class="icon-btn" onclick="openCartPageCat()" style="position:relative;">
    &#128722;
    <span id="cartBadgeCat" style="display:none;position:absolute;top:-6px;right:-6px;background:#ee1d52;color:white;font-size:10px;font-weight:bold;min-width:16px;height:16px;border-radius:8px;align-items:center;justify-content:center;padding:0 3px;line-height:1;border:1.5px solid white;"></span>
  </span>
  <div class="cart-btn" onclick="showCatAddToCartSheet()">Add to Cart</div>
  <div class="buy-btn" onclick="showCatBuyNowSheet()">Buy now</div>
</div>

<!-- ===== BOTTOM SHEET ===== -->
<div id="catBsOverlay" onclick="closeCatBSheet()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:900;"></div>
<div id="catBsSheet" style="display:none;position:fixed;bottom:0;left:0;right:0;background:white;border-radius:20px 20px 0 0;z-index:901;padding:0 0 24px 0;max-height:70vh;overflow-y:auto;">
  <div style="width:40px;height:4px;background:#e0e0e0;border-radius:2px;margin:10px auto 16px;"></div>
  <div style="display:flex;gap:14px;padding:0 16px 16px;">
    <img id="catBsImg" src="" style="width:90px;height:90px;object-fit:cover;border-radius:10px;border:1px solid #eee;flex-shrink:0;">
    <div>
      <div id="catBsPrice" style="color:#ee1d52;font-size:22px;font-weight:bold;"></div>
      <div id="catBsTitle" style="font-size:13px;color:#333;margin-top:5px;line-height:1.5;"></div>
      <div style="font-size:12px;color:#999;margin-top:4px;">In Stock</div>
    </div>
  </div>
  <div style="border-top:1px solid #f0f0f0;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;">
    <span style="font-size:14px;color:#333;font-weight:bold;">Quantity</span>
    <div style="display:flex;align-items:center;gap:0;">
      <span id="catBsTotalPrice" style="color:#ee1d52;font-size:14px;font-weight:bold;margin-right:12px;"></span>
      <button onclick="catBsQtyChange(-1)" style="width:34px;height:34px;border-radius:50%;border:1px solid #ddd;background:white;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;">−</button>
      <span id="catBsQty" style="width:36px;text-align:center;font-size:16px;font-weight:bold;">1</span>
      <button onclick="catBsQtyChange(1)" style="width:34px;height:34px;border-radius:50%;border:1px solid #ddd;background:white;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;">+</button>
    </div>
  </div>
  <div style="display:flex;gap:10px;padding:14px 16px 0;">
    <button id="catBsAddBtn" onclick="catBsAddToCart()" style="flex:1;padding:13px;border:1.5px solid #1976d2;border-radius:25px;background:white;color:#1976d2;font-size:14px;cursor:pointer;font-weight:bold;">Add to Cart</button>
    <button onclick="catBsBuyNow()" style="flex:1.5;padding:13px;border:none;border-radius:25px;background:#1976d2;color:white;font-size:14px;cursor:pointer;font-weight:bold;">Buy Now</button>
  </div>
</div>

<!-- ===== CART PAGE OVERLAY ===== -->
<div id="catCartPageOverlay" style="display:none;position:fixed;inset:0;background:white;z-index:1000;overflow-y:auto;flex-direction:column;">
  <div style="background:#1976d2;color:white;padding:12px 15px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10;">
    <div style="display:flex;align-items:center;gap:12px;">
      <span onclick="closeCatCartPage()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
      <span onclick="window.location.href='/dashboard'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg></span>
    </div>
    <div style="display:flex;align-items:center;gap:15px;">
      <span onclick="window.location.href='/dashboard?search=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
      <span onclick="window.location.href='/dashboard?messages=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
      <span onclick="window.location.href='/dashboard?account=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
      <span onclick="window.location.href='/dashboard?lang=1'" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
    </div>
  </div>
  <div style="padding:12px 15px;"><button id="catCartEditBtn" onclick="toggleCatCartEdit()" style="width:100%;padding:13px;border:1.5px solid #2e7d32;border-radius:8px;background:white;font-size:16px;cursor:pointer;font-family:Arial;">Edit</button></div>
  <div style="padding:0 15px 10px;display:flex;justify-content:space-between;align-items:center;">
    <div style="display:flex;align-items:center;gap:8px;">
      <div id="catCartSelectAllCircle" onclick="toggleCatSelectAll()" style="width:22px;height:22px;border-radius:50%;border:2px solid #bbb;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;"></div>
      <span style="font-size:14px;color:#333;">Total: <b id="catCartTotal" style="color:#222;">US$ 0.00</b></span>
    </div>
    <div id="catCartEditDeleteBtn" style="display:none;"><button onclick="deleteCatSelectedItems()" style="background:#222;color:white;border:none;padding:12px 22px;border-radius:25px;font-size:15px;cursor:pointer;font-weight:bold;">Delete</button></div>
    <div id="catCartSettlementBtn"><button onclick="openCatSettlementPage()" style="background:#1976d2;color:white;border:none;padding:12px 22px;border-radius:10px;font-size:15px;cursor:pointer;font-weight:bold;">Settlement</button></div>
  </div>
  <div style="margin:0 15px 10px;border:1px solid #eee;border-radius:10px;overflow:hidden;">
    <div style="padding:12px 15px;border-bottom:1px solid #f0f0f0;display:flex;align-items:center;gap:8px;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
      <span style="font-size:14px;font-weight:bold;color:#222;">Highline Giftshop</span>
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#999" stroke-width="2" style="margin-left:auto;"><polyline points="9 18 15 12 9 6"/></svg>
    </div>
    <div id="catCartItemsList" style="padding:10px 15px;"></div>
  </div>
</div>

<!-- ===== SETTLEMENT PAGE ===== -->
<div id="catSettlementPage" style="display:none;position:fixed;inset:0;background:white;z-index:1100;overflow-y:auto;">
  <div style="padding:14px 15px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #f0f0f0;">
    <span onclick="closeCatSettlementPage()" style="cursor:pointer;display:inline-flex;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span style="font-size:16px;font-weight:bold;">Settlement</span>
  </div>
  <div style="padding:15px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
      <span style="font-size:14px;font-weight:bold;">Highline Giftshop</span>
    </div>
    <div id="catSettlItemsList" style="border-top:1px solid #f0f0f0;padding-top:12px;"></div>
  </div>
  <div style="padding:0 15px 15px;">
    <div style="font-size:15px;font-weight:bold;margin-bottom:10px;">Shipping address</div>
    <div onclick="openCatAddressPage('settlement')" style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:10px 0;border-bottom:1px solid #f0f0f0;">
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
      <span id="catSettlAddrLabel" style="font-size:14px;color:#999;">Mailing address</span>
    </div>
  </div>
  <div style="padding:0 15px 80px;">
    <div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px;"><span style="color:#555;">Balance</span><span id="catSettlBalance">US$0.00</span></div>
    <div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px;"><span style="color:#555;">Delivery</span><span>US$0</span></div>
    <div style="display:flex;justify-content:space-between;padding:10px 0;font-size:14px;font-weight:bold;"><span>Total payment</span><span id="catSettlTotal">US$0.00</span></div>
  </div>
  <div style="position:fixed;bottom:0;left:0;right:0;padding:15px;background:white;border-top:1px solid #eee;">
    <button onclick="doCatSettleBuy()" style="width:100%;padding:15px;background:#f5a623;border:none;border-radius:10px;font-size:16px;font-weight:bold;color:#333;cursor:pointer;">Buy now</button>
    <p style="font-size:11px;color:#aaa;text-align:center;margin:8px 0 0;line-height:1.5;">By placing an order, you agree to our Terms and Conditions. Privacy You also agree that the app stores some of your data, which can be used to provide you with a better future shopping experience.</p>
  </div>
</div>

<!-- ===== FILL ORDER PAGE ===== -->
<div id="catFillOrderPage" style="display:none;position:fixed;inset:0;background:white;z-index:1200;overflow-y:auto;">
  <div style="padding:14px 15px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #f0f0f0;">
    <span onclick="closeCatFillOrderPage()" style="cursor:pointer;display:inline-flex;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span style="font-size:16px;font-weight:bold;">Fill Order</span>
  </div>
  <div onclick="openCatAddressPage('fillorder')" style="padding:14px 15px;display:flex;align-items:center;gap:10px;cursor:pointer;border-bottom:1px solid #f0f0f0;">
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="10" r="3"/><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7z"/></svg>
    <span id="catFoAddrLabel" style="font-size:14px;color:#999;flex:1;">Please select address</span>
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#999" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
  </div>
  <div style="padding:15px;border-bottom:1px solid #f0f0f0;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
      <span id="catFoStoreName" style="font-size:14px;font-weight:bold;"></span>
    </div>
    <div style="display:flex;gap:12px;">
      <img id="catFoImg" src="" style="width:60px;height:60px;object-fit:cover;border-radius:8px;border:1px solid #eee;flex-shrink:0;">
      <div>
        <div id="catFoTitle" style="font-size:13px;color:#333;line-height:1.5;"></div>
        <div style="margin-top:5px;display:flex;align-items:center;gap:10px;">
          <span id="catFoPrice" style="color:#ee1d52;font-size:14px;font-weight:bold;"></span>
          <span id="catFoQtyLabel" style="font-size:12px;color:#999;"></span>
        </div>
      </div>
    </div>
  </div>
  <div style="padding:14px 15px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;"><span>Express shipping fee</span><span>Free shipping US\$0</span></div>
  <div style="padding:14px 15px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #f0f0f0;font-size:14px;color:#555;"><span>Remark</span><span style="color:#ccc;">Remark</span></div>
  <div style="height:100px;"></div>
  <div style="position:fixed;bottom:0;left:0;right:0;padding:15px;background:white;border-top:1px solid #eee;display:flex;justify-content:space-between;align-items:center;">
    <span style="font-size:15px;font-weight:bold;">Total: <span id="catFoTotal"></span></span>
    <button onclick="submitCatFillOrder()" style="background:#1976d2;color:white;border:none;padding:12px 24px;border-radius:8px;font-size:14px;cursor:pointer;font-weight:bold;">Submit order</button>
  </div>
</div>

<!-- ===== ADDRESS PAGE ===== -->
<div id="catAddressPage" style="display:none;position:fixed;inset:0;background:white;z-index:1300;overflow-y:auto;">
  <div style="padding:14px 15px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #f0f0f0;">
    <span onclick="closeCatAddressPage()" style="cursor:pointer;display:inline-flex;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span style="font-size:18px;">📍</span>
    <span style="font-size:16px;font-weight:bold;">Address</span>
  </div>
  <div style="padding:15px;">
    <button onclick="openCatAddAddressForm()" style="width:100%;padding:15px;border:1px solid #ddd;border-radius:12px;background:white;font-size:15px;cursor:pointer;text-align:left;color:#333;">+ Add a new address</button>
    <div id="catAddressList" style="margin-top:15px;"></div>
  </div>
</div>

<!-- ===== ADD ADDRESS FORM ===== -->
<div id="catAddAddressForm" style="display:none;position:fixed;inset:0;background:white;z-index:1400;overflow-y:auto;">
  <div style="padding:14px 15px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #f0f0f0;">
    <span onclick="closeCatAddAddressForm()" style="cursor:pointer;display:inline-flex;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
    <span id="catAddAddrTitle" style="font-size:16px;font-weight:bold;">Add Address</span>
  </div>
  <div style="padding:20px 15px;">
    <input id="catAddrName" placeholder="Full Name" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box;">
    <input id="catAddrPhone" placeholder="Phone Number" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box;" type="tel">
    <input id="catAddrStreet" placeholder="Street / Area" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box;">
    <input id="catAddrCity" placeholder="City" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:12px;box-sizing:border-box;">
    <input id="catAddrCountry" placeholder="Country" style="width:100%;padding:13px;border:1px solid #ddd;border-radius:10px;font-size:14px;margin-bottom:20px;box-sizing:border-box;">
    <button onclick="saveCatAddress()" style="width:100%;padding:14px;background:#1976d2;color:white;border:none;border-radius:10px;font-size:15px;cursor:pointer;font-weight:bold;">Save Address</button>
  </div>
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

// ===== CAT CART SYSTEM =====
var _catBsQty = 1;
var _catCartEditMode = false;
var _catCartSelected = {};
var _catAddrCalledFrom = "";
var _catEditingAddrIdx = -1;
var _catFoQty = 1;
var _catRecommPage = 0;

function updateCatCartBadge(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var badge = document.getElementById("cartBadgeCat");
  if(!badge) return;
  if(cart.length > 0){ badge.style.display = "flex"; badge.innerText = cart.length > 99 ? "99+" : cart.length; }
  else { badge.style.display = "none"; }
}
updateCatCartBadge();

// Bottom Sheet
function showCatAddToCartSheet(){ _catBsMode = "cart"; openCatBSheet(); }
function showCatBuyNowSheet(){ _catBsMode = "buynow"; openCatBSheet(); }
var _catBsMode = "cart";
function openCatBSheet(){
  var title = p.t || p.title || "";
  var price = p.p || p.price || 0;
  var imgSrc = (p.imgs && p.imgs.length > 0) ? p.imgs[0] : p.img || "";
  _catBsQty = 1;
  document.getElementById("catBsImg").src = imgSrc;
  document.getElementById("catBsPrice").innerText = "US\$" + parseFloat(price).toFixed(2);
  document.getElementById("catBsTitle").innerText = title;
  document.getElementById("catBsQty").innerText = 1;
  document.getElementById("catBsTotalPrice").innerText = "US\$" + parseFloat(price).toFixed(2);
  document.getElementById("catBsAddBtn").style.display = _catBsMode === "cart" ? "block" : "none";
  document.getElementById("catBsOverlay").style.display = "block";
  document.getElementById("catBsSheet").style.display = "block";
}
function closeCatBSheet(){
  document.getElementById("catBsOverlay").style.display = "none";
  document.getElementById("catBsSheet").style.display = "none";
}
function catBsQtyChange(d){
  _catBsQty = Math.max(1, _catBsQty + d);
  document.getElementById("catBsQty").innerText = _catBsQty;
  var price = p.p || p.price || 0;
  document.getElementById("catBsTotalPrice").innerText = "US\$" + (parseFloat(price) * _catBsQty).toFixed(2);
}
function catBsAddToCart(){
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  closeCatBSheet();
  if(addresses.length === 0){ _catAddrCalledFrom = "addtocart"; openCatAddressPage("addtocart"); return; }
  _doCatAddToCart();
}
function _doCatAddToCart(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var imgSrc = (p.imgs && p.imgs.length > 0) ? p.imgs[0] : p.img || "";
  cart.push({ id: Date.now(), title: p.t || p.title || "", price: parseFloat(p.p || p.price || 0), img: imgSrc, qty: _catBsQty, cat: p.cat || "" });
  localStorage.setItem("cartItems", JSON.stringify(cart));
  updateCatCartBadge();
  showMsg("Added to cart ✅", "success");
}
function catBsBuyNow(){
  closeCatBSheet();
  var imgSrc = (p.imgs && p.imgs.length > 0) ? p.imgs[0] : p.img || "";
  openCatFillOrderPage({ title: p.t || p.title || "", price: parseFloat(p.p || p.price || 0), img: imgSrc, cat: p.cat || "" }, _catBsQty);
}

// Cart Page
function openCartPageCat(){
  document.getElementById("catCartPageOverlay").style.display = "flex";
  renderCatCartItems();
  loadCatRecommended();
  _catCartEditMode = false; _catCartSelected = {};
  updateCatCartEditUI(); updateCatCartTotal();
}
function closeCatCartPage(){ document.getElementById("catCartPageOverlay").style.display = "none"; }
function renderCatCartItems(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var list = document.getElementById("catCartItemsList");
  if(!list) return;
  if(cart.length === 0){ list.innerHTML = '<p style="text-align:center;color:#aaa;padding:20px 0;">Your cart is empty</p>'; return; }
  list.innerHTML = "";
  cart.forEach(function(item){
    var checked = !!_catCartSelected[item.id];
    var div = document.createElement("div");
    div.style.cssText = "display:flex;align-items:center;gap:10px;padding:12px 0;border-bottom:1px solid #f0f0f0;";
    div.innerHTML = \`
      <img src="\${item.img}" style="width:80px;height:80px;object-fit:cover;border-radius:8px;border:1px solid #eee;flex-shrink:0;">
      <div style="flex:1;min-width:0;">
        <div style="font-size:13px;font-weight:bold;color:#1976d2;">US\$\${item.price.toFixed(2)}</div>
        <div style="font-size:12px;color:#333;line-height:1.4;margin-top:3px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;">\${item.title}</div>
        <div style="display:flex;align-items:center;gap:0;margin-top:8px;">
          <button onclick="catCartQtyChange(\${item.id},-1)" style="width:30px;height:30px;border-radius:50%;border:1px solid #ddd;background:white;font-size:16px;cursor:pointer;">−</button>
          <span style="width:32px;text-align:center;font-size:14px;font-weight:bold;">\${item.qty}</span>
          <button onclick="catCartQtyChange(\${item.id},1)" style="width:30px;height:30px;border-radius:50%;border:1px solid #ddd;background:white;font-size:16px;cursor:pointer;">+</button>
        </div>
      </div>
      <div onclick="toggleCatCartItem(\${item.id})" style="width:24px;height:24px;border-radius:50%;border:2px solid \${checked?'#222':'#bbb'};background:\${checked?'#222':'white'};display:flex;align-items:center;justify-content:center;flex-shrink:0;cursor:pointer;">
        \${checked?'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>':''}
      </div>
    \`;
    list.appendChild(div);
  });
}
function toggleCatCartItem(itemId){
  if(_catCartSelected[itemId]) delete _catCartSelected[itemId]; else _catCartSelected[itemId] = true;
  renderCatCartItems(); updateCatCartTotal(); updateCatSelectAllCircle();
}
function toggleCatSelectAll(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var allSelected = cart.every(function(i){ return _catCartSelected[i.id]; });
  if(allSelected){ _catCartSelected = {}; } else { cart.forEach(function(i){ _catCartSelected[i.id] = true; }); }
  renderCatCartItems(); updateCatCartTotal(); updateCatSelectAllCircle();
}
function updateCatSelectAllCircle(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var el = document.getElementById("catCartSelectAllCircle");
  if(!el) return;
  var all = cart.length > 0 && cart.every(function(i){ return _catCartSelected[i.id]; });
  el.style.border = all ? "2px solid #222" : "2px solid #bbb";
  el.style.background = all ? "#222" : "white";
  el.innerHTML = all ? '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : "";
}
function updateCatCartTotal(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var total = 0;
  cart.forEach(function(item){ if(_catCartSelected[item.id]) total += item.price * item.qty; });
  document.getElementById("catCartTotal").innerText = "US\$ " + total.toFixed(2);
}
function catCartQtyChange(itemId, d){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  cart = cart.map(function(i){ if(i.id === itemId){ i.qty = Math.max(1, i.qty + d); } return i; });
  localStorage.setItem("cartItems", JSON.stringify(cart));
  renderCatCartItems(); updateCatCartTotal();
}
function toggleCatCartEdit(){
  _catCartEditMode = !_catCartEditMode;
  if(!_catCartEditMode) _catCartSelected = {};
  updateCatCartEditUI(); renderCatCartItems(); updateCatCartTotal();
}
function updateCatCartEditUI(){
  document.getElementById("catCartEditBtn").innerText = _catCartEditMode ? "Done" : "Edit";
  document.getElementById("catCartEditDeleteBtn").style.display = _catCartEditMode ? "block" : "none";
  document.getElementById("catCartSettlementBtn").style.display = _catCartEditMode ? "none" : "block";
}
function deleteCatSelectedItems(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  cart = cart.filter(function(i){ return !_catCartSelected[i.id]; });
  localStorage.setItem("cartItems", JSON.stringify(cart));
  _catCartSelected = {}; updateCatCartBadge(); renderCatCartItems(); updateCatCartTotal(); updateCatSelectAllCircle();
}

// Recommended
function loadCatRecommended(){
  var container = document.getElementById("catCartRecommended");
  if(!container) return;
  container.innerHTML = '<p style="text-align:center;color:#aaa;padding:20px 0;grid-column:1/-1;">Loading...</p>';
  var token = localStorage.getItem("token") || "";
  fetch("/my-seller-products", { headers: { "Authorization": "Bearer " + token } })
    .then(function(r){ return r.json(); })
    .then(function(d){
      container.innerHTML = "";
      var prods = (d.products || []);
      if(prods.length === 0){
        container.innerHTML = '<p style="text-align:center;color:#aaa;padding:20px 0;grid-column:1/-1;">No products in your store yet</p>';
        return;
      }
      var repoMap={17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};
      window._catRecProds = prods.map(function(p){
        var repo = repoMap[p.category_id] || "products_27";
        var base = "https://raw.githubusercontent.com/oscerm328-stack/"+repo+"/main/"+(p.folder||"")+"/";
        var img = (p.images && p.images.length > 0) ? base + p.images[0] : (p.img || "https://via.placeholder.com/300x140?text=No+Image");
        return { t: p.title || "", p: parseFloat(p.price || 0), img: img };
      });
      _catRecommPage = 0;
      renderCatRecommPage();
    })
    .catch(function(){
      container.innerHTML = '<p style="text-align:center;color:#aaa;padding:20px 0;grid-column:1/-1;">Could not load products</p>';
    });
}
function renderCatRecommPage(){
  var container = document.getElementById("catCartRecommended");
  var start = _catRecommPage * 6;
  var chunk = (window._catRecProds || []).slice(start, start + 6);
  chunk.forEach(function(p2){
    var div = document.createElement("div");
    div.style.cssText = "background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 5px rgba(0,0,0,0.08);cursor:pointer;";
    div.innerHTML = \`<div style="position:relative;"><img src="\${p2.img}" style="width:100%;height:140px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/300x140?text=No+Image'"><div style="position:absolute;top:6px;right:6px;width:26px;height:26px;background:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;cursor:pointer;box-shadow:0 1px 4px rgba(0,0,0,0.15);">🤍</div></div><div style="padding:8px;"><div style="font-size:12px;color:#333;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;line-height:1.4;">\${p2.t}</div><div style="color:#1976d2;font-size:13px;font-weight:bold;margin-top:5px;">US\$\${p2.p.toFixed(2)}</div></div>\`;
    container.appendChild(div);
  });
  _catRecommPage++;
}
function loadMoreCatRecommended(){ renderCatRecommPage(); }

// Settlement
function openCatSettlementPage(){
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var selected = cart.filter(function(i){ return _catCartSelected[i.id]; });
  if(selected.length === 0){ showMsg("Please select items first", "error"); return; }
  var total = selected.reduce(function(s,i){ return s + i.price * i.qty; }, 0);
  document.getElementById("catSettlTotal").innerText = "US\$" + total.toFixed(2);
  var user = null; try { user = JSON.parse(localStorage.getItem("user") || "null"); } catch(e){}
  if(user && user.email){
    var token = localStorage.getItem("token") || "";
    fetch("/get-balance", { headers: { "Authorization": "Bearer " + token } }).then(function(r){ return r.json(); }).then(function(d){ document.getElementById("catSettlBalance").innerText = "US\$" + (d.balance || 0).toFixed(2); }).catch(function(){});
  }
  var list = document.getElementById("catSettlItemsList"); list.innerHTML = "";
  selected.forEach(function(item){
    var div = document.createElement("div"); div.style.cssText = "display:flex;gap:12px;margin-bottom:12px;";
    div.innerHTML = \`<img src="\${item.img}" style="width:60px;height:60px;object-fit:cover;border-radius:8px;border:1px solid #eee;flex-shrink:0;"><div style="flex:1;"><div style="font-size:12px;color:#333;line-height:1.4;">\${item.title}</div><div style="font-size:11px;color:#999;margin-top:2px;">x\${item.qty}</div></div><div style="font-size:13px;font-weight:bold;color:#333;white-space:nowrap;">US\$\${(item.price*item.qty).toFixed(2)}</div>\`;
    list.appendChild(div);
  });
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var defAddr = addresses.find(function(a){ return a.isDefault; }) || addresses[0];
  if(defAddr){ document.getElementById("catSettlAddrLabel").innerText = defAddr.name + " - " + defAddr.street + ", " + defAddr.city; document.getElementById("catSettlAddrLabel").style.color = "#333"; }
  document.getElementById("catSettlementPage").style.display = "block";
}
function closeCatSettlementPage(){ document.getElementById("catSettlementPage").style.display = "none"; }
function doCatSettleBuy(){
  var user = null; try { user = JSON.parse(localStorage.getItem("user") || "null"); } catch(e){}
  if(!user || !user.email){ showMsg("Please login first", "error"); return; }
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  if(addresses.length === 0){ showMsg("Please add a delivery address", "error"); openCatAddressPage("settlement"); return; }
  var cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  var selected = cart.filter(function(i){ return _catCartSelected[i.id]; });
  var total = selected.reduce(function(s,i){ return s + i.price * i.qty; }, 0);
  var token = localStorage.getItem("token") || "";
  fetch("/get-balance", { headers: { "Authorization": "Bearer " + token } }).then(function(r){ return r.json(); }).then(function(d){
    var balance = parseFloat(d.balance) || 0;
    if(balance < total){ showMsg("Insufficient balance. Please recharge your wallet.", "error"); return; }
    showMsg("Order placed successfully! ✅", "success");
    var remaining = cart.filter(function(i){ return !_catCartSelected[i.id]; });
    localStorage.setItem("cartItems", JSON.stringify(remaining));
    _catCartSelected = {}; updateCatCartBadge(); closeCatSettlementPage(); closeCatCartPage();
  }).catch(function(){ showMsg("Connection error. Try again.", "error"); });
}

// Fill Order
function openCatFillOrderPage(product, qty){
  _catFoQty = qty || 1;
  document.getElementById("catFoImg").src = product.img || "";
  document.getElementById("catFoTitle").innerText = product.title || "";
  document.getElementById("catFoPrice").innerText = "US\$" + (product.price || 0).toFixed(2);
  document.getElementById("catFoQtyLabel").innerText = "x" + _catFoQty;
  document.getElementById("catFoTotal").innerText = "US\$" + ((product.price || 0) * _catFoQty).toFixed(2);
  var storeName = ""; try { storeName = localStorage.getItem("viewStoreName") || "TikTok Shop Store"; } catch(e){ storeName = "TikTok Shop Store"; }
  document.getElementById("catFoStoreName").innerText = storeName;
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var defAddr = addresses.find(function(a){ return a.isDefault; }) || addresses[0];
  if(defAddr){ document.getElementById("catFoAddrLabel").innerText = defAddr.name + " - " + defAddr.street + ", " + defAddr.city; document.getElementById("catFoAddrLabel").style.color = "#333"; }
  document.getElementById("catFillOrderPage").style.display = "block";
  window._catFoProduct = product;
}
function closeCatFillOrderPage(){ document.getElementById("catFillOrderPage").style.display = "none"; }
function submitCatFillOrder(){
  var user = null; try { user = JSON.parse(localStorage.getItem("user") || "null"); } catch(e){}
  if(!user || !user.email){ showMsg("Please login first", "error"); return; }
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  if(addresses.length === 0){ showMsg("Please add a delivery address", "error"); openCatAddressPage("fillorder"); return; }
  var product = window._catFoProduct; if(!product) return;
  var total = product.price * _catFoQty;
  var token = localStorage.getItem("token") || "";
  fetch("/get-balance", { headers: { "Authorization": "Bearer " + token } }).then(function(r){ return r.json(); }).then(function(d){
    var balance = parseFloat(d.balance) || 0;
    if(balance < total){ showMsg("Insufficient balance. Please recharge your wallet.", "error"); return; }
    showMsg("Order placed successfully! ✅", "success");
    closeCatFillOrderPage();
  }).catch(function(){ showMsg("Connection error. Try again.", "error"); });
}

// Address
function openCatAddressPage(calledFrom){ _catAddrCalledFrom = calledFrom || ""; renderCatAddressList(); document.getElementById("catAddressPage").style.display = "block"; }
function closeCatAddressPage(){ document.getElementById("catAddressPage").style.display = "none"; }
function renderCatAddressList(){
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var list = document.getElementById("catAddressList"); list.innerHTML = "";
  addresses.forEach(function(addr, idx){
    var div = document.createElement("div"); div.style.cssText = "border:2px solid " + (addr.isDefault?"#1976d2":"#eee") + ";border-radius:14px;padding:16px;margin-bottom:12px;";
    div.innerHTML = \`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;"><span style="font-size:15px;font-weight:bold;color:#222;">\${addr.name}</span>\${addr.isDefault?'<span style="background:#1976d2;color:white;font-size:11px;padding:2px 10px;border-radius:10px;font-weight:bold;">Default</span>':''}</div><div style="font-size:13px;color:#555;">\${addr.phone}</div><div style="font-size:13px;color:#555;margin-top:3px;">\${addr.street}, \${addr.city}, \${addr.country}</div><div style="border-top:1px solid #eee;margin-top:12px;padding-top:10px;display:flex;gap:10px;"><button onclick="editCatAddress(\${idx})" style="flex:1;padding:10px;border:1px solid #e3f0ff;background:#e3f0ff;color:#1976d2;border-radius:8px;font-size:14px;cursor:pointer;">✏️ Edit</button><button onclick="deleteCatAddress(\${idx})" style="flex:1;padding:10px;border:1px solid #ffebee;background:#ffebee;color:#e53935;border-radius:8px;font-size:14px;cursor:pointer;">🗑️ Delete</button></div>\`;
    list.appendChild(div);
  });
}
function openCatAddAddressForm(){ _catEditingAddrIdx = -1; document.getElementById("catAddAddrTitle").innerText = "Add Address"; document.getElementById("catAddrName").value = ""; document.getElementById("catAddrPhone").value = ""; document.getElementById("catAddrStreet").value = ""; document.getElementById("catAddrCity").value = ""; document.getElementById("catAddrCountry").value = ""; document.getElementById("catAddAddressForm").style.display = "block"; }
function closeCatAddAddressForm(){ document.getElementById("catAddAddressForm").style.display = "none"; }
function editCatAddress(idx){ var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]"); var addr = addresses[idx]; if(!addr) return; _catEditingAddrIdx = idx; document.getElementById("catAddAddrTitle").innerText = "Edit Address"; document.getElementById("catAddrName").value = addr.name || ""; document.getElementById("catAddrPhone").value = addr.phone || ""; document.getElementById("catAddrStreet").value = addr.street || ""; document.getElementById("catAddrCity").value = addr.city || ""; document.getElementById("catAddrCountry").value = addr.country || ""; document.getElementById("catAddAddressForm").style.display = "block"; }
function deleteCatAddress(idx){ var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]"); addresses.splice(idx, 1); if(addresses.length > 0 && !addresses.find(function(a){ return a.isDefault; })){ addresses[0].isDefault = true; } localStorage.setItem("userAddresses", JSON.stringify(addresses)); renderCatAddressList(); }
function saveCatAddress(){
  var name = document.getElementById("catAddrName").value.trim(), phone = document.getElementById("catAddrPhone").value.trim(), street = document.getElementById("catAddrStreet").value.trim(), city = document.getElementById("catAddrCity").value.trim(), country = document.getElementById("catAddrCountry").value.trim();
  if(!name || !phone || !street || !city || !country){ showMsg("Please fill all fields", "error"); return; }
  var addresses = JSON.parse(localStorage.getItem("userAddresses") || "[]");
  var addrObj = { name, phone, street, city, country, isDefault: addresses.length === 0 };
  if(_catEditingAddrIdx >= 0){ addrObj.isDefault = addresses[_catEditingAddrIdx].isDefault; addresses[_catEditingAddrIdx] = addrObj; } else { addresses.push(addrObj); }
  localStorage.setItem("userAddresses", JSON.stringify(addresses));
  closeCatAddAddressForm(); renderCatAddressList();
  var defAddr = addresses.find(function(a){ return a.isDefault; }) || addresses[0];
  if(_catAddrCalledFrom === "addtocart"){ closeCatAddressPage(); _doCatAddToCart(); }
  else if(_catAddrCalledFrom === "fillorder"){ closeCatAddressPage(); if(defAddr && document.getElementById("catFoAddrLabel")){ document.getElementById("catFoAddrLabel").innerText = defAddr.name + " - " + defAddr.street + ", " + defAddr.city; document.getElementById("catFoAddrLabel").style.color = "#333"; } }
  else if(_catAddrCalledFrom === "settlement"){ closeCatAddressPage(); if(defAddr && document.getElementById("catSettlAddrLabel")){ document.getElementById("catSettlAddrLabel").innerText = defAddr.name + " - " + defAddr.street + ", " + defAddr.city; document.getElementById("catSettlAddrLabel").style.color = "#333"; } }
  showMsg("Address saved ✅", "success");
}

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
<p>Article 1 [Purpose of Rules]<br>In order to allow users to enjoy a better, safer and more reliable business environment and transaction experience, promote the coordinated governance of online and offline integration, and optimize the TikTok Shop platform ecosystem, these general rules are hereby formulated.</p>
<p>Article 2 [Basis of Rules]<br>(I) [Legal Basis] The "International E-Commerce Law", "International Cybersecurity Law", "International Consumer Rights Protection Law", "International Network Transaction Supervision and Administration Measures" and other global laws and regulations and related normative documents (hereinafter referred to as "legal provisions") stipulate the legal rights and obligations of all parties in the TikTok Shop platform ecosystem, and are the legal basis for the formulation and revision of TikTok Shop platform rules.<br>
(II) [Normative Basis] The relevant agreements of the TikTok Shop platform are legal documents that clarify the rights and obligations of TikTok Shop and its members, and are the normative basis of TikTok Shop platform rules.<br>
(III) [Conceptual Basis] All parties in the TikTok Shop platform ecosystem practice business ethics and social responsibilities, coexist and win together, co-govern and co-build on the TikTok Shop platform, and develop in a self-disciplined and standardized manner. For those that are not clearly stipulated by the law, the platform continuously maximizes the interests of all parties through beneficial exploration, which is the conceptual basis of TikTok Shop platform rules.</p>
<p>Article 3 [Rules and Principles]<br>All parties in the TikTok Shop platform ecosystem respect and abide by the following principles: equality, voluntariness, fairness, and integrity. The behavior of all parties in the TikTok Shop platform ecosystem on the TikTok Shop platform shall not violate the law and public order and good morals.</p>
<p>Article 4 [Applicable Objects]<br>The TikTok Shop platform rules apply to all parties in the TikTok Shop platform ecosystem, including users, members, buyers, sellers, and other relevant parties.</p>
<p>Article 5 [Rule System and Effectiveness]<br>The TikTok Shop platform rule system and effectiveness level are as follows:<br>
(I) [Rule System] The TikTok Shop platform rules are a general term for the following rules:<br>
1. "TikTok Shop Platform Rules General Principles"<br>
2. Specific rules and regulations formulated for the management and violation handling of the TikTok Shop platform member market, industry market management, marketing activities and other necessary matters, including the corresponding implementation details for further refinement of specific rules and regulations (hereinafter referred to as "rules and regulations");<br>
3. Temporary announcements issued in accordance with the temporary management needs of the TikTok Shop platform.</p>
<p>(II) [Effectiveness Level] Where there are provisions in the "General Principles", they shall prevail; where there are special provisions in the rules and regulations or temporary announcements, the special provisions shall prevail. If there is no provision in the TikTok Shop platform rules, TikTok Shop will handle it according to the law or relevant agreements.</p>
<p>Article 6 [Rule Procedure]<br>TikTok Shop shall formulate or modify the TikTok Shop platform rules in a timely and prudent manner in accordance with the requirements of legal provisions and the needs of the development of the ecosystem, and shall publicize them on the TikTok Shop platform rules page. The rules shall take effect from the date of expiration of the publicity period.<br>
The formulated or modified transaction rules shall be subject to the special public consultation procedure in accordance with the law, and shall be reported to the relevant functional departments.</p>
<p>Article 7 [Retroactive Effect of Rules]<br>The rules at that time shall apply to the behavior that occurred before the rules came into effect; the new rules shall apply to the behavior that occurred after the rules came into effect.</p>
<p>Chapter II General Provisions for Members</p>
<p>Article 8 [General Principles]<br>All behaviors of members on the TikTok Shop platform must comply with legal provisions, TikTok Shop platform rules, and follow the instructions on the corresponding pages of the TikTok Shop platform.</p>
<p>Article 9 [Registration]<br>Members shall complete registration in accordance with the procedures and requirements of the TikTok Shop platform.<br>
If the member account is an inactive account, TikTok Shop may recycle it.<br>
Article 10 [Authentication] Members shall provide true and valid information about themselves (including natural persons, legal persons and their principals, non-legal persons and their principals, etc hereinafter the same) in accordance with the authentication requirements of the TikTok Shop platform.<br>
(I) The information that members shall provide includes but is not limited to: personal identity information, personal information, effective contact information, real address, business address, market entity registration information and other relevant information, and other authentication information required by laws and regulations to prove the authenticity, validity and consistency of identity. If the personal information provided by members is incomplete, invalid or may be inaccurate, TikTok Shop may not pass the authentication.<br>
(II) In order to ensure the continued authenticity and validity of member authentication information, TikTok Shop may review the information of members that have passed authentication.</p>
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
(XII) Other violations of laws, social morality, or according to the relevant agreements of the TikTok Shop platform, which are not suitable for posting on the TikTok Shop platform.</p>
<p>Article 12 [Transactions]<br>Members shall comply with the various requirements of the TikTok Shop platform transaction process to conduct real transactions. If a member has a dispute over a transaction on the TikTok Shop platform, he or she may initiate a dispute mediation service request to the TikTok Shop customer service department. TikTok Shop may require the buyer and seller to provide relevant supporting materials as appropriate and handle it in accordance with the "TikTok Shop Rules".</p>
<p>Article 13 [Information and Quality]<br>The product or service information published by sellers and suppliers must comply with the "TikTok Shop Product Release Specifications" and other relevant regulations. Sellers and suppliers should ensure that the goods or services they sell can be used normally within a reasonable period, have the performance they should have, meet the standards indicated on the packaging instructions, etc., and do not pose a risk to personal and property safety, and bear corresponding responsibilities for the quality of the goods or services they sell.<br>
The material descriptions of the goods released by sellers and suppliers must comply with the provisions of the "TikTok Shop Material Standard Definition Table". TikTok Shop may conduct random inspections of the goods or services sold by its sellers and suppliers in accordance with the "TikTok Shop Product Quality Random Inspection Specifications".</p>
<p>Article 14 [Transaction Performance and Service Guarantee]<br>Members can choose the transaction method according to TikTok Shop's requirements and actual needs.<br>
Sellers and suppliers must fulfill their commitments on transactions or services, including timely delivery within the prescribed and promised period (except for special circumstances) in accordance with the rules such as the "TikTok Shop Shipping Management Specifications" and their own commitments.<br>
Sellers and suppliers should protect the legitimate rights and interests of buyers, provide consumer protection services, and comply with relevant regulations such as the "TikTok Shop Seven-Day Unconditional Return Specifications".</p>
<p>Article 15 [Marketing]<br>Sellers and suppliers participating in TikTok Shop marketing activities must comply with the "TikTok Shop Marketing Activity Specifications" or corresponding marketing activity rules and other relevant regulations.</p>
<p>Article 16 [Industry and Featured Markets]<br>TikTok Shop sellers in specific industries or featured markets must comply with the "TikTok Shop Industry Management Specifications" and "TikTok Shop Featured Market Management Specifications".</p>
<p>Article 17 [Service Market Users]<br>Service market users should comply with the "Service Market Management Specifications" and other relevant regulations.</p>
<p>Article 18 [TikTok Shop Live Platform Users]<br>TikTok Shop Live Platform users should comply with the "Content Creator Management Rules", "TikTok Shop Live Management Rules", "TikTok Shop Live Organization Management Specifications", "TikTok Shop Engine Platform Management Rules", "TikTok Shop Engine Platform Dispute Handling Rules" and other relevant regulations.</p>
<p>Article 19 [Other Users]<br>In order to try to meet user needs and continuously improve user experience, the TikTok Shop platform may launch new markets and services from time to time. Users of the corresponding markets and services should comply with the corresponding agreements and the relevant rules and other regulations that are announced and effective on the TikTok Shop platform rules page.</p>
<p>Chapter V Market Management and Violation Handling<br>
Article 20 Risky behaviors and violations of TikTok Shop members shall be handled in accordance with the "TikTok Shop Market Management and Violation Handling Specifications".</p>
<p>Chapter VI Supplementary Provisions<br>
Article 21 These rules shall first take effect on October 10, 2024 and shall be revised on April 3, 2025.</p>
<p>Article 22 The term "above" in the TikTok Shop platform rules includes this number; the term "below" in the TikTok Shop platform rules does not include this number.</p>
<p>Article 23 The term "day" in the TikTok Shop platform rules shall be calculated as 24 hours.</p>
<p>Appendix Definitions</p>
<p>1. User refers to the user of various services on the TikTok Shop platform. Users can browse relevant information on the TikTok Shop platform without registration.</p>
<p>2. Member refers to a user who has signed a service agreement with TikTok Shop and completed the registration process, including natural persons, legal persons and unincorporated organizations of equal civil subjects.</p>
<p>3. Buyer refers to a member who purchases goods or services on the TikTok Shop platform.</p>
<p>4. Seller refers to a member who has successfully created a store on the TikTok Shop platform and is engaged in the business of selling goods or providing services.</p>
<p>5. Supplier refers to manufacturers, middlemen and individual business operators who provide sales of all related products on the TikTok Shop platform.</p>
<p>6. Other related parties refer to individuals or organizations that have a certain relationship with TikTok Shop platform users, such as intellectual property rights holders, supply and marketing platform users, service market users, content creators and institutions, etc.</p>
<p>7. TikTok Shop, the single or collective name of the TikTok Shop platform operator refers to Meta Network Technology Co., Ltd., the operator of the TikTok Shop network.</p>
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

<h3>What Personal Information About Customers Does TikTok Shop Collect?</h3>
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
<p>Our platform does not sell products intended for purchase by children. We sell children's products for adults to buy. If you are under the age of 18, you may only use the TikTok Shop Services with the involvement of a parent or guardian.</p>

<h3>Contact, Notices and Amendments</h3>
<p>If you have any questions about TikTok Shop's privacy, please contact us with a detailed description and we will do our best to resolve it. Our business is constantly changing, and so will our Privacy Statement. You should check our website frequently for recent changes. Unless otherwise stated, our current Privacy Statement applies to all information we have about you and your account. However, we stand by our commitments and will in no way materially change our policies and practices to reduce their protections for customer information collected in the past without the consent of affected customers.</p>
<p>Examples of Information Collected<br>
Information You Provide to Us When Using TikTok Shop Services<br>
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
    const supplierPricePerUnit = parseFloat((price * (1 - commissionPct / 100)).toFixed(2));
    const profitPerUnit = parseFloat((price - supplierPricePerUnit).toFixed(2));

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
        supplierPrice: supplierPricePerUnit,
        profit: parseFloat((profitPerUnit * qty).toFixed(2)),
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
        { name: "London", lat: 51.5074, lng: -0.1278 },
        { name: "Paris", lat: 48.8566, lng: 2.3522 },
        { name: "Berlin", lat: 52.5200, lng: 13.4050 },
        { name: "Amsterdam", lat: 52.3676, lng: 4.9041 },
        { name: "Rome", lat: 41.9028, lng: 12.4964 },
        { name: "Madrid", lat: 40.4168, lng: -3.7038 },
        { name: "Vienna", lat: 48.2082, lng: 16.3738 },
        { name: "Stockholm", lat: 59.3293, lng: 18.0686 },
        { name: "Istanbul", lat: 41.0082, lng: 28.9784 },
        { name: "Warsaw", lat: 52.2297, lng: 21.0122 },
        { name: "Tokyo", lat: 35.6762, lng: 139.6503 },
        { name: "Seoul", lat: 37.5665, lng: 126.9780 },
        { name: "Singapore", lat: 1.3521, lng: 103.8198 },
        { name: "Bangkok", lat: 13.7563, lng: 100.5018 },
        { name: "Kuala Lumpur", lat: 3.1390, lng: 101.6869 },
        { name: "Jakarta", lat: -6.2088, lng: 106.8456 },
        { name: "Manila", lat: 14.5995, lng: 120.9842 },
        { name: "Osaka", lat: 34.6937, lng: 135.5023 },
        { name: "Taipei", lat: 25.0330, lng: 121.5654 },
        { name: "Mumbai", lat: 19.0760, lng: 72.8777 }
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

    // خصم سعر المورد من رصيد البائع (supplierPrice هو سعر الوحدة)
    const supplierCost = parseFloat((order.supplierPrice * order.quantity).toFixed(2));
    if((parseFloat(seller.balance) || 0) < supplierCost){
        return res.json({ success: false, message: "Insufficient balance to ship" });
    }
    seller.balance = ((parseFloat(seller.balance) || 0) - supplierCost).toFixed(2);
    saveUsers();

    // إضافة عملية خصم المورد في قائمة المعاملات
    requests.push({
        id: Date.now(),
        email: order.sellerEmail,
        amount: supplierCost,
        type: "delivery_deduction",
        status: "approved",
        orderRef: order.id,
        createdAt: new Date().toISOString()
    });
    saveRequests();

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
        // supplierPrice = سعر الوحدة، profit = إجمالي الربح (qty مضروبة مسبقاً)
        const supplierTotal = parseFloat((order.supplierPrice * order.quantity).toFixed(2));
        const profitTotal = parseFloat(order.profit);
        const refund = supplierTotal + profitTotal;
        seller.balance = ((parseFloat(seller.balance) || 0) + refund).toFixed(2);
        // Total working capital: أضف الربح فقط
        if(!seller.totalCapital) seller.totalCapital = parseFloat(seller.balance) || 0;
        seller.totalCapital = ((parseFloat(seller.totalCapital) || 0) + profitTotal).toFixed(2);
        // profit today
        const today = new Date().toDateString();
        if(!seller.profitToday || seller.profitTodayDate !== today){
            seller.profitToday = 0;
            seller.profitTodayDate = today;
        }
        seller.profitToday = ((parseFloat(seller.profitToday) || 0) + profitTotal).toFixed(2);
        // total profit credited
        seller.totalProfitCredited = ((parseFloat(seller.totalProfitCredited) || 0) + profitTotal).toFixed(2);
        // turnover
        seller.turnover = ((parseFloat(seller.turnover) || 0) + order.total).toFixed(2);
        // number of orders
        seller.orderCount = (parseInt(seller.orderCount) || 0) + 1;
        // credential rating — حساب حقيقي بناءً على نشاط المتجر
        if(!seller.credentialRating) seller.credentialRating = 0;
        const completedOrders = storeOrders.filter(o => o.sellerEmail === seller.email && o.status === "completed").length + 1;
        const totalOrders     = storeOrders.filter(o => o.sellerEmail === seller.email).length + 1;
        const timeoutOrders   = storeOrders.filter(o => o.sellerEmail === seller.email && o.timedOut).length;
        const productCount    = (sellerProducts[seller.email] || []).length;
        const turnoverVal     = parseFloat(seller.turnover) || 0;

        // معادلة التقييم:
        // - إتمام الطلبات: حتى 2.0 نقطة (كل طلب مكتمل = 0.1، max 20 طلب)
        // - نسبة الإتمام: حتى 1.5 نقطة
        // - المنتجات: حتى 0.5 نقطة (كل 10 منتجات = 0.1)
        // - حجم التداول: حتى 1.0 نقطة (كل 1000$ = 0.1)
        // - خصم: -0.2 لكل طلب timeout (max -1.0)
        let score = 0;
        score += Math.min(2.0, completedOrders * 0.1);
        const completionRate = totalOrders > 0 ? completedOrders / totalOrders : 0;
        score += completionRate * 1.5;
        score += Math.min(0.5, (productCount / 10) * 0.1);
        score += Math.min(1.0, (turnoverVal / 1000) * 0.1);
        score -= Math.min(1.0, timeoutOrders * 0.2);
        score = Math.max(0, Math.min(5, score));
        seller.credentialRating = score.toFixed(1);
        saveUsers();
    }

    order.status = "completed";
    order.completedAt = new Date().toISOString();
    saveStoreOrders();

    // إضافة عملية واحدة تجمع المبلغ المسترد + الربح
    if(seller){
        const supplierTotal = parseFloat((order.supplierPrice * order.quantity).toFixed(2));
        const profitTotal = parseFloat(order.profit);
        const totalReturn = parseFloat((supplierTotal + profitTotal).toFixed(2));
        requests.push({
            id: Date.now() + 1,
            email: order.sellerEmail,
            amount: totalReturn,
            type: "profit",
            status: "approved",
            orderRef: order.id,
            createdAt: new Date().toISOString()
        });
        saveRequests();
    }

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

    // حساب credentialRating لحظياً بناءً على نشاط المتجر الفعلي
    const completedOrders = myOrders.filter(o => o.status === "completed").length;
    const totalOrders     = myOrders.length;
    const timeoutOrders   = myOrders.filter(o => o.timedOut).length;
    const productCount    = (sellerProducts[email] || []).length;
    const turnoverVal     = parseFloat(user.turnover) || 0;

    let liveRating = 0;
    liveRating += Math.min(2.0, completedOrders * 0.1);
    const completionRate = totalOrders > 0 ? completedOrders / totalOrders : 0;
    liveRating += completionRate * 1.5;
    liveRating += Math.min(0.5, (productCount / 10) * 0.1);
    liveRating += Math.min(1.0, (turnoverVal / 1000) * 0.1);
    liveRating -= Math.min(1.0, timeoutOrders * 0.2);
    liveRating = Math.max(0, Math.min(5, liveRating));

    // حفظ التقييم المحدّث
    user.credentialRating = liveRating.toFixed(1);
    saveUsers();

    res.json({
        success: true,
        productsForSale: (sellerProducts[email] || []).length,
        numberOfOrders: myOrders.length,
        turnover: parseFloat(user.turnover) || 0,
        credentialRating: liveRating,
        waitingShipping: myOrders.filter(o => o.status === "waiting_shipping").length,
        waitingDelivery: myOrders.filter(o => o.status === "in_delivery").length,
        waitingRefund: myOrders.filter(o => o.status === "waiting_refund").length,
        waitingPayment: 0,
        availableBalance: parseFloat(user.balance) || 0,
        totalWorkingCapital: parseFloat(user.totalCapital) || 0,
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

// ---- API: عداد الزوار على السيرفر ----
// جلب بيانات الزوار للمتجر
app.get("/store-visitors/:email", authMiddleware, (req, res) => {
    const email = req.userEmail;
    // التحقق أن المستخدم يطلب بياناته هو
    if(decodeURIComponent(req.params.email) !== email) return res.json({ success: false });
    const appl = storeApplications.find(a => a.email === email);
    if(!appl) return res.json({ success: false });
    res.json({
        success: true,
        totalVisitors: appl.totalVisitors || 0,
        todayVisitors: appl.todayVisitors || 0,
        todayDate:     appl.todayDate     || ""
    });
});

// تحديث عداد الزوار (يُستدعى من الداشبورد كل دقيقة)
app.post("/store-visitors/update", authMiddleware, (req, res) => {
    const email = req.userEmail;
    const { todayAdded } = req.body;
    const appl = storeApplications.find(a => a.email === email && a.status === "approved");
    if(!appl) return res.json({ success: false });

    const today = new Date().toDateString();
    // إذا يوم جديد نصفر اليومي
    if(appl.todayDate !== today){
        appl.totalVisitors = (appl.totalVisitors || 0) + (appl.todayVisitors || 0);
        appl.todayVisitors = 0;
        appl.todayDate = today;
    }
    // نضيف الزوار الجدد
    const toAdd = parseInt(todayAdded) || 0;
    if(toAdd > 0){
        appl.todayVisitors = (appl.todayVisitors || 0) + toAdd;
    }
    saveStoreApplications();
    res.json({
        success: true,
        totalVisitors: appl.totalVisitors || 0,
        todayVisitors: appl.todayVisitors || 0
    });
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
            const supplierTotal2 = parseFloat((order.supplierPrice * order.quantity).toFixed(2));
            const profitTotal2 = parseFloat(order.profit);
            const refund = supplierTotal2 + profitTotal2;
            seller.balance = ((parseFloat(seller.balance) || 0) + refund).toFixed(2);
            const today = new Date().toDateString();
            if(!seller.profitToday || seller.profitTodayDate !== today){
                seller.profitToday = 0;
                seller.profitTodayDate = today;
            }
            seller.profitToday = ((parseFloat(seller.profitToday) || 0) + profitTotal2).toFixed(2);
            seller.totalProfitCredited = ((parseFloat(seller.totalProfitCredited) || 0) + profitTotal2).toFixed(2);
            seller.turnover = ((parseFloat(seller.turnover) || 0) + order.total).toFixed(2);
            seller.orderCount = (parseInt(seller.orderCount) || 0) + 1;
            if(!seller.totalCapital) seller.totalCapital = parseFloat(seller.balance) || 0;
            seller.totalCapital = ((parseFloat(seller.totalCapital) || 0) + profitTotal2).toFixed(2);
            saveUsers();

            // إضافة معاملة الإجمالي المسترد + الربح
            const totalReturn2 = parseFloat((supplierTotal2 + profitTotal2).toFixed(2));
            requests.push({
                id: Date.now() + 1,
                email: order.sellerEmail,
                amount: totalReturn2,
                type: "profit",
                status: "approved",
                orderRef: order.id,
                createdAt: new Date().toISOString()
            });
            saveRequests();
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
<title>Listings - TikTok Shop</title>
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
var CLOUD_BASE = 'https://raw.githubusercontent.com/oscerm328-stack';
var CLOUDINARY_CAT = {17:'products_17',19:'products_19',20:'products_20',21:'products_21',22:'products_22',27:'products_27',28:'products_28',31:'products_31',32:'products_32',34:'products_34',35:'products_35',36:'products_36'};

function getCloudImg(p, imgName) {
    imgName = imgName || '1.jpg';
    var catFolder = CLOUDINARY_CAT[p.category_id] || '27_Electronics';
    return CLOUD_BASE + '/' + catFolder + '/main/' + (p.folder||'') + '/' + imgName;
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

// ====== FORMAT AMOUNT ======
function fmtAmt(n){ return parseFloat(n||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2}); }

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
    document.getElementById("popupSupplier").innerText = "US$" + fmtAmt(supplierPrice);
    document.getElementById("popupRetail").innerText = "US$" + fmtAmt(price);
    document.getElementById("popupProfit").innerText = "US$" + fmtAmt(profit);
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
<title>Product - TikTok Shop</title>
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
  <img class="supplier-logo" id="supplierLogo" src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg" onerror="this.src='https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg'">
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

var CLOUD_D = "https://raw.githubusercontent.com/oscerm328-stack";
var CAT_MAP_D = {17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};

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
        ? p.images.map(function(img){ return CLOUD_D+"/"+catFolder+"/main/"+p.folder+"/"+img; })
        : [CLOUD_D+"/"+catFolder+"/main/"+(p.folder||"")+"/1.jpg"];

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

function fmtAmt(n){ return parseFloat(n||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2}); }

function openSheet(){
    var price=parseFloat(p.price);
    var commPct=VIP_COMMISSION[myVipLevel]||15;
    var supplier=price*(1-commPct/100), profit=price-supplier;
    document.getElementById("sheetSub").innerText="VIP "+myVipLevel+" — "+commPct+"% supplier discount";
    document.getElementById("sheetSupplier").innerText="US$"+fmtAmt(supplier);
    document.getElementById("sheetRetail").innerText="US$"+fmtAmt(price);
    document.getElementById("sheetProfit").innerText="US$"+fmtAmt(profit);
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
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;align-items:center;gap:12px;position:relative;box-shadow:0 2px 8px rgba(25,118,210,0.3);}
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
            var catImgMap = {17:'products_17',19:'products_19',20:'products_20',21:'products_21',22:'products_22',27:'products_27',28:'products_28',31:'products_31',32:'products_32',34:'products_34',35:'products_35',36:'products_36'};
            var imgSrc = 'https://raw.githubusercontent.com/oscerm328-stack/' + (catImgMap[p.category_id]||'products_27') + '/main/' + p.folder + '/1.jpg';
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
.map-canvas{width:100%;height:100%;display:none;}
.map-label{position:absolute;bottom:6px;right:8px;font-size:10px;color:#1976d2;background:rgba(255,255,255,0.9);padding:2px 7px;border-radius:8px;z-index:500;}
.map-tooltip{background:white;border:1px solid #ddd;border-radius:8px;font-size:11px;font-weight:700;color:#333;padding:2px 7px;box-shadow:0 2px 6px rgba(0,0,0,0.15);}
.map-tooltip::before{display:none;}
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
.tstat-item{display:flex;flex-direction:column;align-items:center;gap:3px;flex:0 0 auto;}
.tstat-icon{font-size:18px;}
.tstat-label{font-size:10px;font-weight:600;color:#888;text-align:center;}
.tstat-item.active .tstat-label{color:#5c35c7;}
.tstat-line{flex:1;height:3px;background:#e0e0e0;border-radius:3px;margin:0 4px;margin-top:-12px;overflow:hidden;position:relative;}
.tstat-line-fill{height:100%;width:0%;background:linear-gradient(90deg,#5c35c7,#9575cd);border-radius:3px;transition:width 1s linear;}

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
      <div id="track-canvas" style="width:100%;height:200px;"></div>
    </div>
    <div id="track-route" style="padding:0 16px 8px;font-size:13px;color:#555;line-height:1.7;"></div>
    <div id="track-status-bar" style="margin:0 16px 18px;display:flex;align-items:center;justify-content:space-between;">
      <div class="tstat-item" id="tstat-1">
        <div class="tstat-icon">✅</div>
        <div class="tstat-label">Order Confirmed</div>
      </div>
      <div class="tstat-line" id="tline-1"><div class="tstat-line-fill" id="tline-fill-1"></div></div>
      <div class="tstat-item" id="tstat-2">
        <div class="tstat-icon">📦</div>
        <div class="tstat-label">Preparing</div>
      </div>
      <div class="tstat-line" id="tline-2"><div class="tstat-line-fill" id="tline-fill-2"></div></div>
      <div class="tstat-item" id="tstat-3">
        <div class="tstat-icon">✈️</div>
        <div class="tstat-label">On The Way</div>
      </div>
    </div>
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

var catMap = {17:"products_17",19:"products_19",20:"products_20",21:"products_21",22:"products_22",27:"products_27",28:"products_28",31:"products_31",32:"products_32",34:"products_34",35:"products_35",36:"products_36"};

function imgUrl(o){
    var cat = catMap[(o.product&&o.product.category_id)] || "27_Electronics";
    var folder = o.product&&o.product.folder ? o.product.folder : "";
    if(!folder) return "https://via.placeholder.com/65x65?text=No+Image";
    return "https://raw.githubusercontent.com/oscerm328-stack/"+cat+"/main/"+folder+"/1.jpg";
}

function fmtAmt(n){ return parseFloat(n||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2}); }

function buildCard(o){
    var card = document.createElement("div");
    card.className = "ocard";
    var labels = {waiting_shipping:"Waiting to Ship",in_delivery:"In Delivery",waiting_refund:"Pending Confirmation",completed:"Delivered"};
    var cls = {waiting_shipping:"ship",in_delivery:"del",waiting_refund:"ref",completed:"done"};
    var num = orderNum(o.id);
    var img = imgUrl(o);
    var qty = parseInt(o.quantity||1);
    var retailPrice = parseFloat(o.total||0);
    var supplierPrice = parseFloat(o.supplierPrice||0)*qty;  // supplierPrice = سعر الوحدة
    var profit = parseFloat(o.profit||0);  // profit = إجمالي (مضروب بالكمية مسبقاً)
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
        '<div class="ocard-price">US$'+fmtAmt(o.product&&o.product.price||0)+' &times; '+qty+' = US$'+fmtAmt(retailPrice)+'</div>' +
        '</div></div>';

    // --- ORDER DETAILS ---
    html += '<div style="margin:8px 0;padding:8px 10px;background:#f9f9f9;border-radius:8px;font-size:12px;color:#555;line-height:1.9;">' +
        '<div style="display:flex;justify-content:space-between;"><span>Supplier Cost</span><span style="color:#e65100;font-weight:600;">US$'+fmtAmt(supplierPrice)+'</span></div>' +
        '<div style="display:flex;justify-content:space-between;"><span>Retail Price</span><span style="color:#1976d2;font-weight:600;">US$'+fmtAmt(retailPrice)+'</span></div>' +
        '<div style="display:flex;justify-content:space-between;"><span>Profit</span><span style="color:#2e7d32;font-weight:700;">+US$'+fmtAmt(profit)+'</span></div>' +
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
        html += '<div class="map-wrap" id="map-'+o.id+'"></div>';
    }

    if(o.status === "waiting_refund"){
        html += '<div class="map-wrap" style="position:relative;" id="map-ref-'+o.id+'"><span class="map-label" style="z-index:999;">📍 Arrived Now</span></div>';
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
        card.onclick = function(){ openTrackModal(o, true); };
        setTimeout(function(){ drawMap("map-ref-"+o.id, o.trackingPath, o.deliveryStart, true); }, 100);
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
    var pro = parseFloat(o.profit||0);  // profit = إجمالي مسبقاً
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
    var base = "https://raw.githubusercontent.com/oscerm328-stack/"+cat+"/main/";
    slideImgs = folder ? [1,2,3,4,5,6,7,8].map(function(i){ return base+folder+"/"+i+".jpg"; }) : ["https://via.placeholder.com/400x260?text=No+Image"];
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
    document.getElementById("pm-price").innerText = "US$"+fmtAmt(o.total||0);
    document.getElementById("pm-profit").innerText = "+US$"+fmtAmt(o.profit||0)+" profit";

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
function openTrackModal(o, forceArrived){
    document.getElementById("track-num").innerText = "#"+orderNum(o.id);
    document.getElementById("track-title").innerText = o.product ? o.product.title : "";
    var tp = o.trackingPath;
    if(tp){
        var routeColor = forceArrived ? '#2e7d32' : '#5c35c7';
        var routeLabel = forceArrived ? '\u2705 Package has arrived' : '\u2708 Package is on the way';
        document.getElementById("track-route").innerHTML =
            "<b>📍 Route:</b> "+(tp.origin?tp.origin.name:"?")+" \u2192 "+(tp.destination?tp.destination.name:"?")+
            "<br><span style='color:"+routeColor+";font-weight:600;'>"+routeLabel+"</span>";
    }
    // Progress bars — live update every second, each line fills over 12h
    if(window._trackBarInterval) clearInterval(window._trackBarInterval);
    function updateTrackBars(){
        var elapsed2 = o.deliveryStart ? Date.now() - o.deliveryStart : 0;
        var h12 = 6*60*60*1000;
        var fill1 = forceArrived ? 100 : Math.min(100, Math.max(0, (elapsed2 / h12) * 100));
        var fill2 = forceArrived ? 100 : Math.min(100, Math.max(0, ((elapsed2 - h12) / h12) * 100));
        var f1 = document.getElementById("tline-fill-1");
        var f2 = document.getElementById("tline-fill-2");
        if(f1) f1.style.width = fill1.toFixed(2) + "%";
        if(f2) f2.style.width = fill2.toFixed(2) + "%";
        [1,2,3].forEach(function(i){
            var si = document.getElementById("tstat-"+i);
            if(!si) return;
            var isActive = forceArrived ? true : (i===1 ? fill1>0 : i===2 ? fill1>=100 : fill2>=100);
            si.classList.toggle("active", isActive);
        });
    }
    updateTrackBars();
    window._trackBarInterval = setInterval(updateTrackBars, 1000);
    // Update On The Way label to Arrived if needed
    // Update On The Way label to Arrived if needed
    var tstat3label = document.querySelector("#tstat-3 .tstat-label");
    if(tstat3label) tstat3label.innerText = forceArrived ? "Arrived" : "On The Way";
    var tstat3icon = document.querySelector("#tstat-3 .tstat-icon");
    if(tstat3icon) tstat3icon.innerText = forceArrived ? "📍" : "✈️";
    document.getElementById("trackModal").classList.add("open");
    var pid = "track-canvas";
    if(_activeMaps[pid]){ try{ _activeMaps[pid].remove(); }catch(e){} delete _activeMaps[pid]; }
    var el = document.getElementById(pid);
    if(el) el.innerHTML = "";
    setTimeout(function(){
        if(!el) return;
        drawLeafletMap(pid, o.trackingPath, o.deliveryStart, true, forceArrived);
    }, 150);
}
function closeTrackModal(){ document.getElementById("trackModal").classList.remove("open"); if(window._trackBarInterval){ clearInterval(window._trackBarInterval); window._trackBarInterval=null; } }

// ===== LEAFLET MAP SYSTEM =====
var _leafletLoaded = false;
var _leafletCbs = [];
function ensureLeaflet(cb){
    if(window.L){ cb(); return; }
    if(_leafletCbs.length===0){
        var lCss=document.createElement("link"); lCss.rel="stylesheet"; lCss.href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"; document.head.appendChild(lCss);
        var lJs=document.createElement("script"); lJs.src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
        lJs.onload=function(){ _leafletLoaded=true; _leafletCbs.forEach(function(f){f();}); _leafletCbs=[]; };
        document.head.appendChild(lJs);
    }
    _leafletCbs.push(cb);
}

var _activeMaps = {}; // mapId -> L.map instance

function drawMap(canvasId, tp, ds, forceArrived){
    var el = document.getElementById(canvasId);
    if(!el) return;
    // If it's a canvas, replace with div
    if(el.tagName === "CANVAS"){
        var div = document.createElement("div");
        div.id = canvasId;
        div.style.cssText = el.style.cssText || "";
        div.className = el.className;
        el.parentNode.replaceChild(div, el);
        el = div;
    }
    el.style.width = "100%";
    el.style.height = "100%";
    el.style.borderRadius = "12px";
    el.style.overflow = "hidden";
    drawLeafletMap(canvasId, tp, ds, false, forceArrived);
}

function drawMap2(c, tp, ds){
    // c is a canvas element used in modal — we create a sibling div
    if(!c||!tp) return;
    var pid = "leaflet-modal-map";
    var existing = document.getElementById(pid);
    if(existing) existing.remove();
    var div = document.createElement("div");
    div.id = pid;
    div.style.cssText = "width:100%;height:"+(c.offsetHeight||200)+"px;border-radius:14px;overflow:hidden;";
    c.parentNode.insertBefore(div, c);
    c.style.display = "none";
    drawLeafletMap(pid, tp, ds, true);
}

function drawLeafletMap(divId, tp, ds, isModal, forceArrived){
    if(!tp) return;
    ensureLeaflet(function(){
        var el = document.getElementById(divId);
        if(!el) return;
        // destroy old instance if any
        if(_activeMaps[divId]){ try{ _activeMaps[divId].remove(); }catch(e){} delete _activeMaps[divId]; }

        var oLat=tp.origin.lat, oLng=tp.origin.lng, dLat=tp.destination.lat, dLng=tp.destination.lng;
        var cLat=(oLat+dLat)/2, cLng=(oLng+dLng)/2;

        // calculate zoom based on distance
        var dist = Math.sqrt(Math.pow(dLat-oLat,2)+Math.pow(dLng-oLng,2));
        var zoom = dist > 100 ? 3 : dist > 50 ? 4 : 5;

        var map = L.map(divId, {
            zoomControl: false,
            dragging: false,
            scrollWheelZoom: false,
            doubleClickZoom: false,
            touchZoom: false,
            attributionControl: false
        }).setView([cLat, cLng], zoom);
        _activeMaps[divId] = map;

        // OpenStreetMap tiles
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
            maxZoom:19,
            opacity:0.9
        }).addTo(map);

        // Calculate progress — forceArrived means package already delivered
        var elapsed = ds ? Date.now()-ds : 0;
        var prog = forceArrived ? 1 : Math.min(1, elapsed/(72*60*60*1000));

        // Bezier midpoint
        var mLat=tp.midpoint.lat, mLng=tp.midpoint.lng;

        // Build bezier path points
        var pathPts=[];
        for(var t=0;t<=1;t+=0.02){
            var lat=(1-t)*(1-t)*oLat+2*(1-t)*t*mLat+t*t*dLat;
            var lng=(1-t)*(1-t)*oLng+2*(1-t)*t*mLng+t*t*dLng;
            pathPts.push([lat,lng]);
        }

        // Full dashed grey line — only show when in transit
        if(!forceArrived){
            L.polyline(pathPts, {color:'#9e9e9e', weight:3, dashArray:'6,6', opacity:0.5}).addTo(map);
        }

        // Traveled part — only show when in transit
        var lineColor = '#5c35c7';
        if(!forceArrived){
            var traveledPts=[];
            var travelCount = Math.floor(prog * pathPts.length);
            for(var i=0;i<=travelCount;i++) traveledPts.push(pathPts[i]);
            if(traveledPts.length>1) L.polyline(traveledPts, {color:lineColor, weight:4, opacity:1}).addTo(map);
        }

        // Plane icon — only show when in transit
        if(!forceArrived){
            var travelCount2 = Math.floor(prog * pathPts.length);
            var pi = Math.min(travelCount2, pathPts.length-1);
            var planeLat = pathPts[pi] ? pathPts[pi][0] : dLat;
            var planeLng = pathPts[pi] ? pathPts[pi][1] : dLng;
            var planeIcon = L.divIcon({
                html:'<div style="font-size:22px;filter:drop-shadow(0 2px 4px rgba(0,0,0,0.4));transform:rotate(-10deg);">✈️</div>',
                iconAnchor:[11,11], className:''
            });
            L.marker([planeLat,planeLng],{icon:planeIcon, zIndexOffset:1000}).addTo(map);
        }

        // Origin marker — only show when in transit
        if(!forceArrived){
            var shopIcon = L.divIcon({
                html:'<div style="background:white;border-radius:8px;padding:3px 5px;font-size:18px;box-shadow:0 2px 8px rgba(0,0,0,0.25);border:2px solid #e0e0e0;">🏪</div>',
                iconAnchor:[18,18], className:''
            });
            L.marker([oLat,oLng],{icon:shopIcon}).bindTooltip(tp.origin.name,{permanent:true,direction:'top',className:'map-tooltip'}).addTo(map);
        }

        // Destination marker — pulsing house pin if arrived, user icon if in transit
        if(forceArrived){
            if(!document.getElementById('pulse-style')){
                var ps = document.createElement('style');
                ps.id = 'pulse-style';
                ps.innerHTML = '@keyframes pulse-ring{0%{transform:scale(0.6);opacity:0.8}100%{transform:scale(2.2);opacity:0}}';
                document.head.appendChild(ps);
            }
            var arrivedHtml =
                '<div style="position:relative;width:44px;height:56px;">' +
                  '<div style="position:absolute;top:2px;left:2px;width:40px;height:40px;border-radius:50%;background:rgba(229,57,53,0.25);animation:pulse-ring 1.4s ease-out infinite;"></div>' +
                  '<div style="position:absolute;top:2px;left:2px;width:40px;height:40px;border-radius:50%;background:rgba(229,57,53,0.15);animation:pulse-ring 1.4s ease-out 0.5s infinite;"></div>' +
                  '<div style="position:absolute;top:2px;left:6px;background:white;border-radius:10px;padding:4px 6px;font-size:20px;box-shadow:0 3px 10px rgba(0,0,0,0.3);border:2px solid #e53935;z-index:2;">🏠</div>' +
                  '<div style="position:absolute;bottom:0;left:50%;transform:translateX(-50%);width:4px;height:14px;background:#e53935;border-radius:2px;z-index:1;"></div>' +
                  '<div style="position:absolute;bottom:11px;left:50%;transform:translateX(-50%);width:10px;height:10px;background:#e53935;border-radius:50%;z-index:1;"></div>' +
                '</div>';
            var arrivedIcon = L.divIcon({ html:arrivedHtml, iconAnchor:[22,56], className:'' });
            L.marker([dLat,dLng],{icon:arrivedIcon, zIndexOffset:500})
             .bindTooltip(tp.destination.name,{permanent:true,direction:'top',className:'map-tooltip'})
             .addTo(map);
        } else {
            var userHtml = '<div style="background:white;border-radius:8px;padding:3px 5px;font-size:18px;box-shadow:0 2px 8px rgba(0,0,0,0.25);border:2px solid #e0e0e0;">👤</div><div style="background:#e53935;width:10px;height:10px;border-radius:50%;border:2px solid white;margin:-4px auto 0;box-shadow:0 1px 4px rgba(0,0,0,0.3);"></div>';
            var userIcon = L.divIcon({ html:userHtml, iconAnchor:[18,22], className:'' });
            L.marker([dLat,dLng],{icon:userIcon})
             .bindTooltip(tp.destination.name,{permanent:true,direction:'top',className:'map-tooltip'})
             .addTo(map);
        }

        // Status badge bottom-right
        var statusBar = L.control({position:'bottomright'});
        statusBar.onAdd = function(){
            var d = L.DomUtil.create('div');
            var label = forceArrived ? '✅ Arrived' : (prog>=1 ? '📍 Arrived' : '✈ On The Way');
            var bgColor = forceArrived ? '#2e7d32' : '#5c35c7';
            d.innerHTML='<div style="background:'+bgColor+';color:white;border-radius:20px;padding:5px 12px;font-size:12px;font-weight:700;box-shadow:0 2px 8px rgba(0,0,0,0.25);display:flex;align-items:center;gap:6px;margin:8px;">'+label+'</div>';
            return d;
        };
        statusBar.addTo(map);

        // Zoom: arrived → focus on destination city, in transit → show full route
        setTimeout(function(){
            try{
                if(forceArrived){
                    map.setView([dLat, dLng], 11);
                } else {
                    map.fitBounds([[oLat,oLng],[dLat,dLng]], {padding:[20,20]});
                }
            }catch(e){}
        },200);
    });
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
    <img id="logoPreview" class="logo-preview" src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/icon_store_logo.svg" onclick="document.getElementById('logoInput').click()">
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
<title>Instructions - TikTok Shop</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fb;min-height:100vh;padding-bottom:40px;}
.header{background:#1976d2;color:white;padding:12px 15px;display:flex;align-items:center;gap:12px;box-shadow:0 2px 8px rgba(0,0,0,0.4);}
.header h2{font-size:16px;font-weight:700;color:white;}

/* HERO */
.hero{width:100%;text-align:center;position:relative;overflow:hidden;padding:0;line-height:0;}
.hero::before{content:'';position:absolute;inset:0;background:rgba(0,0,0,0.35);}
.hero h1{font-size:26px;font-weight:900;margin-bottom:10px;letter-spacing:0.5px;position:relative;z-index:1;}
.hero h1 span.tt1{color:#69c9d0;}
.hero h1 span.tt2{color:#ee1d52;}
.hero p{font-size:13px;opacity:0.85;line-height:1.8;max-width:340px;margin:0 auto;position:relative;z-index:1;}

/* STATS BAR */
.stats-bar{display:flex;background:transparent;color:white;padding:14px 0;position:relative;z-index:1;}
.stat-item{flex:1;text-align:center;border-right:1px solid rgba(255,255,255,0.4);}
.stat-item:last-child{border-right:none;}
.stat-num{font-size:18px;font-weight:800;color:white;text-shadow:0 1px 4px rgba(0,0,0,0.5);}
.stat-label{font-size:10px;color:rgba(255,255,255,0.9);margin-top:2px;text-shadow:0 1px 3px rgba(0,0,0,0.5);}

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
  <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/hero-bg.png" style="width:100%;height:auto;display:block;" alt="TikTok Shop">
</div>

<!-- HOW IT WORKS -->
<div class="section">
  <h3>🚀 How It Works</h3>
  <div class="step">
    <div class="step-num">1</div>
    <div class="step-text">
      <h4>Register & Open Your Store</h4>
      <p>Sign up with an invite code and apply for a merchant account. Once approved, your personalized TikTok Shop store is instantly live and accessible to customers worldwide. Customize your store name and logo to build your brand identity.</p>
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
    <div class="vip-card"><div class="vip-name">VIP 1</div><div class="vip-pcts">Up to 35 products<br>200 daily visitors<br><span class="vip-disc">17% supplier discount</span></div></div>
    <div class="vip-card"><div class="vip-name">VIP 2</div><div class="vip-pcts">Up to 80 products<br>500 daily visitors<br><span class="vip-disc">20% supplier discount</span></div></div>
    <div class="vip-card"><div class="vip-name">VIP 3</div><div class="vip-pcts">Up to 120 products<br>1,500 daily visitors<br><span class="vip-disc">22% supplier discount</span></div></div>
    <div class="vip-card"><div class="vip-name">VIP 4</div><div class="vip-pcts">Up to 300 products<br>5,000 daily visitors<br><span class="vip-disc">25% supplier discount</span></div></div>
    <div class="vip-card top"><div class="vip-name">VIP 5 ⭐</div><div class="vip-pcts">Up to 1,000 products<br>15,000 daily visitors<br><span class="vip-disc">40% supplier discount</span></div></div>
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
    <div class="faq-a">Customer payments are collected by TikTok Shop and added to your available balance. You can withdraw your earnings at any time through the Wallet section using your registered USDT address.</div>
  </div>
  <div class="faq-item" onclick="this.classList.toggle('open')">
    <div class="faq-q">Do I need to handle shipping myself? <span class="faq-arr">▼</span></div>
    <div class="faq-a">No. TikTok Shop handles all logistics. When you confirm shipment, our supplier network dispatches the product directly to the customer. You simply authorize the transaction from your dashboard.</div>
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

// ================= EMAILJS KEY ENDPOINT (آمن) =================
app.get("/env.js", (req, res) => {
    res.setHeader("Content-Type", "application/javascript");
    const ejsKey = process.env.EMAILJS_KEY || "";
    res.send("window._ejsKey=" + JSON.stringify(ejsKey) + ";");
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
