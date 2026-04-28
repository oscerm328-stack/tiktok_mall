// ================= PUBLIC HOME PAGE =================
// هذا الملف يحتوي على الصفحة الرئيسية العامة التي تظهر قبل تسجيل الدخول
// يتم استيراده في server.js بسطر واحد: require('./home')(app);

module.exports = function(app) {

    // الصفحة الرئيسية - تحول / إلى /home
    app.get("/home", (req, res) => {
        res.send(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>TikTok Mall</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}

/* TOP BAR */
.topbar{background:#1976d2;color:white;display:flex;align-items:center;justify-content:space-between;padding:0 14px;height:50px;position:sticky;top:0;z-index:100;}
.topbar-left{display:flex;align-items:center;gap:8px;cursor:pointer;}
.topbar-left span{font-size:15px;font-weight:bold;}
.topbar-icons{display:flex;align-items:center;gap:18px;}
.topbar-icons svg{cursor:pointer;}

/* CLASSIFIED */
.classified-title{font-size:20px;font-weight:bold;text-align:center;padding:16px 0 10px;background:white;}

/* CATEGORY SCROLL */
.cat-scroll-wrap{overflow-x:auto;padding:0 10px 10px;background:white;scrollbar-width:none;}
.cat-scroll-wrap::-webkit-scrollbar{display:none;}
.cat-scroll{display:flex;gap:6px;width:max-content;}
.cat-box{width:155px;height:200px;position:relative;border-radius:8px;overflow:hidden;cursor:pointer;flex-shrink:0;}
.cat-box img{width:100%;height:100%;object-fit:cover;}
.cat-box .cat-label{position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:8px;font-size:13px;font-weight:600;}

/* BRAND BANNER */
.brand-banner{background:white;display:flex;align-items:center;gap:14px;padding:16px;margin-top:10px;}
.brand-banner img{width:64px;height:64px;border-radius:14px;object-fit:cover;}
.brand-banner-text{font-size:16px;font-weight:800;color:#1976d2;letter-spacing:0.5px;}
.brand-banner-sub{font-size:12px;color:#1976d2;font-weight:600;margin-top:2px;}

/* SECTION TITLE */
.section-title{font-size:17px;font-weight:bold;padding:14px 12px 10px;background:white;border-bottom:1px solid #eee;margin-top:10px;}

/* PRODUCT GRID */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:3px;background:#f5f5f5;}
.prod-card{background:white;position:relative;cursor:pointer;overflow:hidden;}
.prod-card img{width:100%;height:180px;object-fit:cover;display:block;}
.prod-card .prod-title{position:absolute;bottom:0;left:0;right:0;background:rgba(0,0,0,0.55);color:white;padding:5px 8px;font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;}
.prod-card .prod-price{position:absolute;top:6px;right:6px;background:#1976d2;color:white;font-size:11px;font-weight:bold;padding:2px 7px;border-radius:10px;}

/* CATEGORY LIST */
.cat-list{background:white;margin-top:10px;}
.cat-list-item{padding:14px 16px;border-bottom:1px solid #eee;font-size:15px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;}
.cat-list-item:last-child{border-bottom:none;}
.cat-list-item::after{content:"›";color:#999;font-size:20px;}

/* INFO SECTION */
.info-section{padding:20px 16px 40px;color:#333;font-size:14px;line-height:1.8;background:white;margin-top:10px;}
.info-section p{margin:0 0 14px;}
.flags{display:flex;flex-wrap:wrap;gap:10px;margin-top:8px;}
.flags img{width:44px;height:44px;border-radius:50%;object-fit:cover;}
</style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
  <div class="topbar-left" onclick="goLogin()">
    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <line x1="3" y1="6" x2="21" y2="6"/>
      <line x1="3" y1="12" x2="21" y2="12"/>
      <line x1="3" y1="18" x2="21" y2="18"/>
    </svg>
    <span>Shop</span>
  </div>
  <div class="topbar-icons">
    <!-- Search -->
    <svg onclick="goLogin()" xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
    <!-- Messages -->
    <svg onclick="goLogin()" xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
      <polyline points="22,6 12,13 2,6"/>
    </svg>
    <!-- Account -->
    <svg onclick="goLogin()" xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
      <circle cx="12" cy="7" r="4"/>
    </svg>
    <!-- Globe -->
    <svg onclick="goLogin()" xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  </div>
</div>

<!-- CLASSIFIED -->
<div class="classified-title">Classified</div>
<div class="cat-scroll-wrap">
  <div class="cat-scroll">
    <div class="cat-box" onclick="goLogin()">
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/clothing.png" onerror="this.src='https://via.placeholder.com/155x200/1976d2/white?text=Clothing'">
      <div class="cat-label">Clothing &amp; Accessories</div>
    </div>
    <div class="cat-box" onclick="goLogin()">
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/shoes.png" onerror="this.src='https://via.placeholder.com/155x200/1976d2/white?text=Shoes'">
      <div class="cat-label">Shoes</div>
    </div>
    <div class="cat-box" onclick="goLogin()">
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/jewelry.png" onerror="this.src='https://via.placeholder.com/155x200/1976d2/white?text=Jewelry'">
      <div class="cat-label">Jewelry</div>
    </div>
    <div class="cat-box" onclick="goLogin()">
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/bags.png" onerror="this.src='https://via.placeholder.com/155x200/1976d2/white?text=Bags'">
      <div class="cat-label">Medical Bags and Sunglasses</div>
    </div>
    <div class="cat-box" onclick="goLogin()">
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/watches.png" onerror="this.src='https://via.placeholder.com/155x200/1976d2/white?text=Watches'">
      <div class="cat-label">Watches</div>
    </div>
    <div class="cat-box" onclick="goLogin()">
      <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/electronics.png" onerror="this.src='https://via.placeholder.com/155x200/1976d2/white?text=Electronics'">
      <div class="cat-label">Electronics</div>
    </div>
  </div>
</div>

<!-- BRAND BANNER -->
<div class="brand-banner">
  <img src="https://cdn.jsdelivr.net/gh/oscerm328-stack/tiktok_mall@main/logo.png"
       onerror="this.style.background='#ee1d52';this.style.borderRadius='14px'">
  <div>
    <div class="brand-banner-text">TikTok Mall</div>
    <div class="brand-banner-sub">Selected Good Products</div>
    <div class="brand-banner-sub">Provide Excellent service</div>
  </div>
</div>

<!-- NEW PRODUCTS -->
<div class="section-title">New Product</div>
<div class="grid2">
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165148_Strapless Satin Ball Gown Wedding Dresses for Brid/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">Strapless Satin Ball Gown Weddi...</div>
    <div class="prod-price">$95.00</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165070_LAORENTOU Cow Leather Purses and Small Handbag for/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">LAORENTOU Cow Leather Purse...</div>
    <div class="prod-price">$86.12</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165150_Roll over image to zoom in 2022 Carlinkit 30 Wire/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">Roll over image to zoom in 2022...</div>
    <div class="prod-price">$95.00</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165149_Google Nest Security Cam Wired - 2nd Generation -/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">Google Nest Security Cam (Wired...</div>
    <div class="prod-price">$100.00</div>
  </div>
</div>

<!-- HOT SELLING -->
<div class="section-title">Hot Selling</div>
<div class="grid2">
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165109_FEICE Mens Automatic Wrist Watch Sapphire Crystal/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">FEICE Men's Automatic Wrist Wat...</div>
    <div class="prod-price">$670.00</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_21/main/165036_Invicta Mens Pro Diver Collection Chronograph Watc/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">Invicta Men's Pro Diver Collection...</div>
    <div class="prod-price">$636.00</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165151_Braided Diamond Anniversary Ring in 925 Sterling S/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">Braided Diamond Anniversary Rin...</div>
    <div class="prod-price">$100.00</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_22/main/165145_GNG 100 Cttw Natural Morganite and Diamond Halo En/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">GNG 1.00 Cttw Natural Morganite...</div>
    <div class="prod-price">$465.00</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165146_Apple iPhone 17 Pro Max/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">Apple iPhone 17 Pro Max</div>
    <div class="prod-price">$1179.00</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_27/main/165147_GIGABYTE A16 CMHI2US893SH/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">GIGABYTE A16 CMHI2US893SH...</div>
    <div class="prod-price">$1189.00</div>
  </div>
  <div class="prod-card" onclick="goLogin()">
    <img src="https://raw.githubusercontent.com/oscerm328-stack/products_17/main/165060_Calvin Klein Womens Petite Double-Breasted Wool Bl/1.jpg" onerror="this.src='https://via.placeholder.com/200x180'">
    <div class="prod-title">Calvin Klein Women's Petite Dou...</div>
    <div class="prod-price">$98.06</div>
  </div>
</div>

<!-- CATEGORY LIST -->
<div class="cat-list">
  <div class="cat-list-item" onclick="goLogin()">Clothing &amp; Accessories</div>
  <div class="cat-list-item" onclick="goLogin()">Medical Bags and Sunglasses</div>
  <div class="cat-list-item" onclick="goLogin()">Shoes</div>
  <div class="cat-list-item" onclick="goLogin()">Watches</div>
  <div class="cat-list-item" onclick="goLogin()">Jewelry</div>
  <div class="cat-list-item" onclick="goLogin()">Electronics</div>
  <div class="cat-list-item" onclick="goLogin()">Smart Home</div>
  <div class="cat-list-item" onclick="goLogin()">Luxury Brands</div>
  <div class="cat-list-item" onclick="goLogin()">Beauty and Personal Care</div>
  <div class="cat-list-item" onclick="goLogin()">Men's Fashion</div>
  <div class="cat-list-item" onclick="goLogin()">Health and Household</div>
  <div class="cat-list-item" onclick="goLogin()">Home and Kitchen</div>
</div>

<!-- INFO SECTION -->
<div class="info-section">
  <p>TikTok Mall will soon become your one-stop platform for choosing the best products in your daily life with our full efforts!</p>
  <p>Shopping on TikTok Mall, start your unique fashion journey, every click is a surprise! Discover different shopping fun, just slide your fingertips on TikTok Mall and enjoy the best products in the world! Save time and enjoy the best discounts! Shopping on TikTok Mall, easily find your favorite products! Your shopping dream comes true here, TikTok Mall platform brings together everything you want!</p>
  <p>Shopping on TikTok Mall, make every day a sales feast for you, grab exclusive offers! Smart recommendations, accurate matching! Shopping on TikTok Mall, you will never miss your favorite products! Enjoy a convenient and safe shopping experience, TikTok Mall brings you different joy!</p>
  <p>Shopping on TikTok Mall, irresistible good offers are waiting for you, come and explore! Shopping is not just about buying things, but discovering new trends with friends on TikTok Mall!</p>
  <p style="font-size:13px;color:#555;">Some of our international sites:</p>
  <div class="flags">
    <img src="https://flagcdn.com/w40/es.png" title="Spain">
    <img src="https://flagcdn.com/w40/de.png" title="Germany">
    <img src="https://flagcdn.com/w40/au.png" title="Australia">
    <img src="https://flagcdn.com/w40/fr.png" title="France">
    <img src="https://flagcdn.com/w40/us.png" title="USA">
    <img src="https://flagcdn.com/w40/dk.png" title="Denmark">
    <img src="https://flagcdn.com/w40/it.png" title="Italy">
    <img src="https://flagcdn.com/w40/nl.png" title="Netherlands">
    <img src="https://flagcdn.com/w40/pl.png" title="Poland">
    <img src="https://flagcdn.com/w40/se.png" title="Sweden">
  </div>
</div>

<script>
function goLogin() {
  window.location.href = '/login-page';
}
</script>
</body>
</html>`);
    });

};
