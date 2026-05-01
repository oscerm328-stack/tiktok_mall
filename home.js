// ================= PUBLIC HOME PAGE =================
// نسخة طبق الأصل من صفحة dashboard - للزوار قبل تسجيل الدخول
// الأزرار الحساسة تحول إلى /login-page
// يتم ربطه في server.js بـ: require('./home')(app);

module.exports = function(app) {

// منع النوم - ping كل 10 دقائق
if(process.env.RENDER_EXTERNAL_URL){
    setInterval(() => {
        fetch(process.env.RENDER_EXTERNAL_URL)
            .then(() => console.log("✅ Home keep-alive ping sent"))
            .catch(() => {});
    }, 10 * 60 * 1000);
}

app.get("/home", (req, res) => {
res.send(`
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TikTok Shop</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
#msgBadge, .globalMsgBadge { display:none !important; }
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
<div onclick="goLogin()" style="cursor:pointer;">☰ Shop</div>
<div class="icons">
<span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
<span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;position:relative;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg><span id="msgBadge" style="display:none !important;position:absolute;top:-5px;right:-5px;background:#ff3b30;color:white;font-size:10px;font-weight:bold;min-width:16px;height:16px;border-radius:8px;align-items:center;justify-content:center;padding:0 3px;line-height:1;border:1.5px solid #1976d2;"></span></span>
<span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
<span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
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
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">📋 My Order</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">💰 Wallet</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">🕒 Search History</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">❤️ My Favorite</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;display:flex;justify-content:space-between;align-items:center;" onclick="goLogin()">
  <span>🎧 Customer Service</span>
  <span id="supportBadge" style="display:none;background:#ff3b30;color:white;font-size:11px;font-weight:bold;min-width:18px;height:18px;border-radius:9px;display:none;align-items:center;justify-content:center;padding:0 5px;"></span>
</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">🏪 Merchant</p>
</div>

<div style="background:white;margin-top:10px;">
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">📍 Address</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">✉️ Manage Email</p>
</div>

<div style="background:white;margin-top:10px;">
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">🔒 Account Password</p>
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">🔑 Transaction Password</p>
</div>

<div style="background:white;margin-top:10px;">
<p style="padding:12px;border-bottom:1px solid #ccc;cursor:pointer;" onclick="goLogin()">🌐 Language</p>
<p style="padding:12px;cursor:pointer;" onclick="goLogin()">🚪 Log out</p>
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

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Clothing & Accessories</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/clothing.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Medical Bags and Sunglasses</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/medical.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Shoes</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/shoes.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Watches</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/watches.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Jewelry</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/jewelry.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Electronics</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/electronics.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Smart Home</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/smarthome.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Luxury Brands</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/luxury.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Beauty and Personal Care</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/beauty.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Men's Fashion</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/mensfashion.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Health and Household</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/health.png" width="70" style="height:70px;object-fit:cover;">
</div>

<div style="background:#ddd;margin:10px;padding:20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;"  onclick="goLogin()">
<span>Home and Kitchen</span>
<img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/kitchen.png" width="70" style="height:70px;object-fit:cover;">
</div>


<div style="background:black;color:white;text-align:center;font-size:40px;padding:20px;margin-top:10px;">
TOPSHOP
</div>

<div style="background:white;padding:15px;">
<p style="font-size:16px;">
Hi, <span id="username"></span> 
<a href="#" onclick="goLogin()" style="color:red; margin-left:10px;">Log out</a>
</p>
<p onclick="goLogin()" 
   style="cursor:pointer; padding:12px; border-bottom:1px solid #ccc;">
🧑 My account
</p>
<p onclick="goLogin()" style="cursor:pointer; color:#1976d2; font-weight:bold;">
📋 My Order
</p>
<p onclick="goLogin()" style="cursor:pointer; color:#1976d2; font-weight:bold;">
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
    <span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;">
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
  <div onclick="goLogin()" style="cursor:pointer;">☰ Shop</div>
  <div style="display:flex;align-items:center;gap:15px;">
    <span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
    <span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;position:relative;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
    <span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
  </div>
</div>

<!-- ===== شريط البحث ===== -->
<div style="padding:15px;display:flex;align-items:center;gap:10px;background:white;border-bottom:1px solid #ddd;">
<span onclick="goLogin()" style="cursor:pointer;display:inline-flex;align-items:center;"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></span>
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

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/clothing.png">
    <div class="cat-label">Clothing &amp; Accessories</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/medical.png">
    <div class="cat-label">Medical Bags and Sunglasses</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/shoes.png">
    <div class="cat-label">Shoes</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/watches.png">
    <div class="cat-label">Watches</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/jewelry.png">
    <div class="cat-label">Jewelry</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/electronics.png">
    <div class="cat-label">Electronics</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/smarthome.png">
    <div class="cat-label">Smart Home</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/luxury.png">
    <div class="cat-label">Luxury Brands</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/beauty.png">
    <div class="cat-label">Beauty and Personal Care</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/mensfashion.png">
    <div class="cat-label">Men's Fashion</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/health.png">
    <div class="cat-label">Health and Household</div>
  </div>

  <div class="cat-item"  onclick="goLogin()">
    <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/kitchen.png">
    <div class="cat-label">Home and Kitchen</div>
  </div>

</div>
</div>

<div style="width:100%;margin:0;padding:0;line-height:0;">
  <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/TikTok%20Shop.png" style="width:100%;height:auto;display:block;" alt="TikTok Shop">
</div>

<div class="section-title">New Product</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-bottom:3px;">
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Strapless Satin Ball Gown Wedding Dresse</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$95.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">LAORENTOU Cow Leather Purses and Small H</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$86.12</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Roll over image to zoom in 2022 Carlinki</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$95.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Google Nest Security Cam (Wired) - 2nd G</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$100.00</div>
  </div>
</div>

<div class="section-title">Hot Selling</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-bottom:3px;">
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">FEICE Men's Automatic Wrist Watch Sapphi</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$670.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Invicta Men's Pro Diver Collection Chron</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$636.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Braided Diamond Anniversary Ring in 925 </div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$100.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">GNG 1.00 Cttw Natural Morganite and Diam</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$465.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/164531_Apple iPhone 17 Pro Max - 256GB512GB 1TB/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Apple iPhone 17 Pro Max</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$1179.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165029_GIGABYTE A16 CMHI2US893SH Gaming Laptop 2025 16 WU/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">GIGABYTE A16 CMHI2US893SH Gaming Laptop </div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$1189.00</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162914_Calvin Klein Womens Petite Double Breasted Peacoat/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">Calvin Klein Women's Petite Double Breas</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$98.06</div>
  </div>
  <div class="card" style="border-radius:0;cursor:pointer;position:relative;" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/162911_GUYRGOT-Formal Wedding Dresses for Women -Womens L/1.jpg" style="width:100%;height:180px;object-fit:cover;" onerror="this.src='https://via.placeholder.com/400x180?text=No+Image'">
    <div style="position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">GUYRGOT-Formal Wedding Dresses for Women</div>
    <div style="position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;">$80.00</div>
  </div>
</div>

<!-- ================= FOOTER CATEGORIES + INFO ================= -->
<div style="background:white;margin-top:15px;padding:10px 0;">

  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Clothing &amp; Accessories</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Medical Bags and Sunglasses</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Shoes</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Watches</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Jewelry</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Electronics</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Smart Home</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Luxury Brands</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Beauty and Personal Care</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Men's Fashion</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Health and Household</div>
  <div  onclick="goLogin()" style="padding:14px 20px;border-bottom:1px solid #eee;cursor:pointer;font-family:Georgia,serif;font-size:15px;">Home and Kitchen</div>


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
// إخفاء أي badge أحمر على أيقونة الرسائل (لا يوجد مستخدم مسجل)
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('#msgBadge, .globalMsgBadge').forEach(function(el) {
    el.style.display = 'none';
  });
});

// الزوار غير المسجلين - كل الأزرار الحساسة تحول لصفحة الدخول
function goLogin() {
  window.location.href = '/login-page';
}

// دالة openCategory للزوار - تحول لصفحة الدخول
function openCategory(name) {
  goLogin();
}

// دالة openRealProduct للزوار - تحول لصفحة الدخول
function openRealProduct(p) {
  goLogin();
}
</script>

</body>
</html>`);
});

};
