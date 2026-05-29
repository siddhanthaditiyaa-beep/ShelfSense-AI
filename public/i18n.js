/**
 * ShelfSense AI — Global Multilanguage Engine (i18n.js)
 * Supports: English (en), Hindi (hi), Marathi (mr)
 * Usage: include before </body> on every page
 * Auto-detects device language on first visit
 */

(function() {
  /* ============================================================
     TRANSLATION DICTIONARY
     Keys follow pattern: page.element or shared.element
     ============================================================ */
  const I18N = {
    en: {
      // ── Shared / Global ──
      "logout": "Logout",
      "login": "Login",
      "register": "Register",
      "save": "Save",
      "cancel": "Cancel",
      "close": "Close",
      "search": "Search",
      "loading": "Loading...",
      "error": "Error",
      "success": "Success",
      "refresh": "Refresh",
      "back": "Back",
      "next": "Next",
      "submit": "Submit",
      "delete": "Delete",
      "edit": "Edit",
      "add": "Add",
      "update": "Update",
      "confirm": "Confirm",
      "yes": "Yes",
      "no": "No",
      "na": "N/A",
      "lang-label": "Language",

      // ── Admin Topbar ──
      "alerts": "🔊 Alerts",
      "notifications": "Notifications",
      "clear-all": "Clear all",

      // ── Admin Sidebar Groups ──
      "group-main": "📊 Main",
      "group-analytics": "📈 Analytics",
      "group-inventory": "📦 Inventory Mgmt",
      "group-customers": "👥 Customers",
      "group-marketing": "📢 Marketing",
      "group-finance": "💰 Finance",
      "group-security": "🛡️ Security",
      "group-ai": "🤖 AI & Research",
      "group-system": "⚙️ System",

      // ── Admin Sidebar Items ──
      "nav-overview": "Overview",
      "nav-inventory": "Inventory",
      "nav-ai-agents": "AI Agents",
      "nav-shelf-scan": "Shelf Scan",
      "nav-franchises": "Franchises",
      "nav-purchase-orders": "Purchase Orders",
      "nav-orders": "Orders",
      "nav-settings": "Settings",
      "nav-store-settings": "Store Settings",
      "nav-my-customers": "My Customers",
      "nav-segments": "Segments",
      "nav-engagement": "Engagement",
      "nav-retention": "Retention",
      "nav-nps": "NPS Score",
      "nav-coupons": "Coupons",
      "nav-campaigns": "Campaigns",
      "nav-financial-summary": "Financial Summary",
      "nav-gst": "GST Report",
      "nav-pl": "P&L Statement",
      "nav-security": "Security",
      "nav-logs": "Logs",
      "nav-themes": "Themes",
      "nav-system-health": "System Health",
      "nav-staff": "Staff",

      // ── Admin Overview Page ──
      "overview-title": "📊 Store Overview",
      "overview-score": "🏆 Store Performance Score",
      "overview-stock": "📈 Stock Overview",
      "overview-alerts": "🚨 Recent Agent Alerts",
      "overview-actions": "🤖 Recent Agent Actions",

      // ── Admin Inventory Page ──
      "inv-add-title": "➕ Add New Item",
      "inv-name-placeholder": "Item name (e.g. Chocolates)",
      "inv-stock-placeholder": "Initial stock quantity",
      "inv-add-btn": "Add Item",
      "inv-list-title": "📦 Current Inventory",
      "inv-reset-btn": "🧹 Reset All Logs & Stocks",
      "inv-download-btn": "📥 Download Stock CSV",

      // ── Admin Orders Page ──
      "orders-title": "🧾 Manage Orders",
      "orders-search": "Search orders...",
      "orders-filter-all": "All",
      "orders-filter-placed": "Placed",
      "orders-filter-processing": "Processing",
      "orders-filter-ready": "Ready",
      "orders-filter-delivered": "Delivered",

      // ── Admin Settings ──
      "settings-store-name": "Store Name",
      "settings-address": "Address",
      "settings-phone": "Phone",
      "settings-save": "Save Settings",

      // ── Ask AI ──
      "nlq-title": "🧠 Ask AI About Your Store",
      "nlq-subtitle": "Type any question in plain language and get instant answers from your live store data.",
      "nlq-btn": "🔍 Ask AI",
      "nlq-placeholder": "Ask anything about your store...",
      "nlq-q1": "Which products run out this week?",
      "nlq-q2": "Total revenue today?",
      "nlq-q3": "Out of stock items?",
      "nlq-q4": "Top selling products?",
      "nlq-q5": "Pending reorders?",

      // ── Agent Control Panel ──
      "agent-panel-title": "⚡ Agent Control Panel",
      "agent-panel-subtitle": "Toggle agents on/off without restarting server",
      "agent-running": "▶ Running",
      "agent-stopped": "⏹ Stopped",

      // ── Login Page ──
      "login-store-tab": "🏪 Store Owner",
      "login-customer-tab": "👤 Customer",
      "login-store-title": "Welcome back, Store Owner",
      "login-customer-title": "Welcome back, Shopper!",
      "login-email": "Email Address",
      "login-password": "Password",
      "login-store-btn": "Login to Dashboard",
      "login-customer-btn": "Login to My Account",
      "login-forgot": "Forgot password?",
      "login-no-store": "Don't have a store?",
      "login-register-free": "Register free →",
      "login-customer-signup": "Customer signup",
      "login-google": "Continue with Google",
      "login-demo-title": "🔑 Demo Credentials",
      "login-demo-customer": "🛍️ Demo Customer",

      // ── Register Page ──
      "register-title": "Create Your Store",
      "register-store-name": "Store Name",
      "register-owner-name": "Owner Name",
      "register-email": "Email Address",
      "register-password": "Password",
      "register-btn": "Create Store",
      "register-have-account": "Already have a store?",

      // ── Landing Page ──
      "landing-nav-agents": "Agents",
      "landing-nav-features": "Features",
      "landing-nav-pricing": "Pricing",
      "landing-nav-how": "How It Works",
      "landing-nav-shop": "🏪 Shop",
      "landing-login": "Login",
      "landing-trial": "Start Free Trial",
      "landing-hero-badge": "🤖 40+ AI Agents Working 24/7",
      "landing-hero-title": "The AI Brain for Your Retail Store",
      "landing-hero-subtitle": "Automate inventory, predict demand, prevent stockouts and grow revenue — all powered by intelligent agents.",
      "landing-get-started": "🚀 Get Started Free",
      "landing-view-demo": "View Demo",

      // ── Marketplace ──
      "market-title": "🏪 ShelfSense Marketplace",
      "market-subtitle": "Discover stores near you. Browse live inventory and shop from multiple stores.",
      "market-search": "Search stores by name…",
      "market-filter-all": "All Stores",
      "market-filter-open": "🟢 Open Now",
      "market-filter-pro": "⭐ Pro Stores",
      "market-shop-now": "🛍️ Shop Now",
      "market-stores": "Active Stores",
      "market-products": "Products Listed",
      "market-orders": "Orders Fulfilled",
    },

    hi: {
      // ── Shared ──
      "logout": "लॉगआउट",
      "login": "लॉगिन",
      "register": "रजिस्टर करें",
      "save": "सहेजें",
      "cancel": "रद्द करें",
      "close": "बंद करें",
      "search": "खोजें",
      "loading": "लोड हो रहा है...",
      "error": "त्रुटि",
      "success": "सफलता",
      "refresh": "रीफ्रेश",
      "back": "वापस",
      "next": "अगला",
      "submit": "जमा करें",
      "delete": "हटाएं",
      "edit": "संपादित करें",
      "add": "जोड़ें",
      "update": "अपडेट करें",
      "confirm": "पुष्टि करें",
      "yes": "हाँ",
      "no": "नहीं",
      "na": "उपलब्ध नहीं",
      "lang-label": "भाषा",

      // ── Admin Topbar ──
      "alerts": "🔊 अलर्ट",
      "notifications": "सूचनाएं",
      "clear-all": "सभी साफ करें",

      // ── Admin Sidebar Groups ──
      "group-main": "📊 मुख्य",
      "group-analytics": "📈 विश्लेषण",
      "group-inventory": "📦 इन्वेंटरी प्रबंधन",
      "group-customers": "👥 ग्राहक",
      "group-marketing": "📢 मार्केटिंग",
      "group-finance": "💰 वित्त",
      "group-security": "🛡️ सुरक्षा",
      "group-ai": "🤖 AI और अनुसंधान",
      "group-system": "⚙️ सिस्टम",

      // ── Admin Sidebar Items ──
      "nav-overview": "अवलोकन",
      "nav-inventory": "इन्वेंटरी",
      "nav-ai-agents": "AI एजेंट",
      "nav-shelf-scan": "शेल्फ स्कैन",
      "nav-franchises": "फ्रैंचाइज़",
      "nav-purchase-orders": "खरीद आदेश",
      "nav-orders": "ऑर्डर",
      "nav-settings": "सेटिंग्स",
      "nav-store-settings": "स्टोर सेटिंग्स",
      "nav-my-customers": "मेरे ग्राहक",
      "nav-segments": "सेगमेंट",
      "nav-engagement": "एंगेजमेंट",
      "nav-retention": "रिटेंशन",
      "nav-nps": "NPS स्कोर",
      "nav-coupons": "कूपन",
      "nav-campaigns": "अभियान",
      "nav-financial-summary": "वित्तीय सारांश",
      "nav-gst": "GST रिपोर्ट",
      "nav-pl": "P&L विवरण",
      "nav-security": "सुरक्षा",
      "nav-logs": "लॉग्स",
      "nav-themes": "थीम",
      "nav-system-health": "सिस्टम स्वास्थ्य",
      "nav-staff": "स्टाफ",

      // ── Admin Overview ──
      "overview-title": "📊 स्टोर अवलोकन",
      "overview-score": "🏆 स्टोर प्रदर्शन स्कोर",
      "overview-stock": "📈 स्टॉक अवलोकन",
      "overview-alerts": "🚨 हालिया एजेंट अलर्ट",
      "overview-actions": "🤖 हालिया एजेंट कार्य",

      // ── Admin Inventory ──
      "inv-add-title": "➕ नई वस्तु जोड़ें",
      "inv-name-placeholder": "वस्तु का नाम (जैसे चॉकलेट)",
      "inv-stock-placeholder": "प्रारंभिक स्टॉक मात्रा",
      "inv-add-btn": "वस्तु जोड़ें",
      "inv-list-title": "📦 वर्तमान इन्वेंटरी",
      "inv-reset-btn": "🧹 सभी लॉग और स्टॉक रीसेट करें",
      "inv-download-btn": "📥 स्टॉक CSV डाउनलोड करें",

      // ── Admin Orders ──
      "orders-title": "🧾 ऑर्डर प्रबंधन",
      "orders-search": "ऑर्डर खोजें...",
      "orders-filter-all": "सभी",
      "orders-filter-placed": "दिया गया",
      "orders-filter-processing": "प्रक्रिया में",
      "orders-filter-ready": "तैयार",
      "orders-filter-delivered": "डिलीवर हो गया",

      // ── Admin Settings ──
      "settings-store-name": "स्टोर का नाम",
      "settings-address": "पता",
      "settings-phone": "फ़ोन",
      "settings-save": "सेटिंग्स सहेजें",

      // ── Ask AI ──
      "nlq-title": "🧠 अपने स्टोर के बारे में AI से पूछें",
      "nlq-subtitle": "कोई भी सवाल सीधी भाषा में पूछें और लाइव डेटा से तुरंत जवाब पाएं।",
      "nlq-btn": "🔍 AI से पूछें",
      "nlq-placeholder": "अपने स्टोर के बारे में कुछ भी पूछें...",
      "nlq-q1": "इस हफ्ते कौन से उत्पाद खत्म होंगे?",
      "nlq-q2": "आज की कुल आय?",
      "nlq-q3": "स्टॉक से बाहर आइटम?",
      "nlq-q4": "सबसे ज्यादा बिकने वाले उत्पाद?",
      "nlq-q5": "लंबित पुनर्ऑर्डर?",

      // ── Agent Panel ──
      "agent-panel-title": "⚡ एजेंट नियंत्रण पैनल",
      "agent-panel-subtitle": "सर्वर पुनः आरंभ किए बिना एजेंट चालू/बंद करें",
      "agent-running": "▶ चल रहा है",
      "agent-stopped": "⏹ रुका हुआ",

      // ── Login ──
      "login-store-tab": "🏪 स्टोर मालिक",
      "login-customer-tab": "👤 ग्राहक",
      "login-store-title": "वापसी पर स्वागत, स्टोर मालिक",
      "login-customer-title": "वापसी पर स्वागत!",
      "login-email": "ईमेल पता",
      "login-password": "पासवर्ड",
      "login-store-btn": "डैशबोर्ड में लॉगिन करें",
      "login-customer-btn": "मेरे खाते में लॉगिन करें",
      "login-forgot": "पासवर्ड भूल गए?",
      "login-no-store": "स्टोर नहीं है?",
      "login-register-free": "मुफ्त रजिस्टर करें →",
      "login-customer-signup": "ग्राहक साइनअप",
      "login-google": "Google से जारी रखें",
      "login-demo-title": "🔑 डेमो क्रेडेंशियल",
      "login-demo-customer": "🛍️ डेमो ग्राहक",

      // ── Register ──
      "register-title": "अपना स्टोर बनाएं",
      "register-store-name": "स्टोर का नाम",
      "register-owner-name": "मालिक का नाम",
      "register-email": "ईमेल पता",
      "register-password": "पासवर्ड",
      "register-btn": "स्टोर बनाएं",
      "register-have-account": "पहले से स्टोर है?",

      // ── Landing ──
      "landing-nav-agents": "एजेंट",
      "landing-nav-features": "विशेषताएं",
      "landing-nav-pricing": "मूल्य निर्धारण",
      "landing-nav-how": "कैसे काम करता है",
      "landing-nav-shop": "🏪 दुकान",
      "landing-login": "लॉगिन",
      "landing-trial": "मुफ्त ट्रायल शुरू करें",
      "landing-hero-badge": "🤖 40+ AI एजेंट 24/7 काम कर रहे हैं",
      "landing-hero-title": "आपके रिटेल स्टोर का AI दिमाग",
      "landing-hero-subtitle": "इन्वेंटरी स्वचालित करें, मांग का अनुमान लगाएं, स्टॉकआउट रोकें और राजस्व बढ़ाएं।",
      "landing-get-started": "🚀 मुफ्त शुरू करें",
      "landing-view-demo": "डेमो देखें",

      // ── Marketplace ──
      "market-title": "🏪 ShelfSense बाज़ार",
      "market-subtitle": "आसपास की दुकानें खोजें। लाइव इन्वेंटरी ब्राउज़ करें और खरीदारी करें।",
      "market-search": "स्टोर का नाम खोजें…",
      "market-filter-all": "सभी दुकानें",
      "market-filter-open": "🟢 अभी खुला है",
      "market-filter-pro": "⭐ प्रो दुकानें",
      "market-shop-now": "🛍️ अभी खरीदें",
      "market-stores": "सक्रिय दुकानें",
      "market-products": "उत्पाद सूचीबद्ध",
      "market-orders": "ऑर्डर पूरे हुए",
    },

    mr: {
      // ── Shared ──
      "logout": "बाहेर पडा",
      "login": "लॉगिन",
      "register": "नोंदणी करा",
      "save": "जतन करा",
      "cancel": "रद्द करा",
      "close": "बंद करा",
      "search": "शोधा",
      "loading": "लोड होत आहे...",
      "error": "त्रुटी",
      "success": "यशस्वी",
      "refresh": "रिफ्रेश",
      "back": "मागे",
      "next": "पुढे",
      "submit": "सबमिट करा",
      "delete": "हटवा",
      "edit": "संपादित करा",
      "add": "जोडा",
      "update": "अपडेट करा",
      "confirm": "पुष्टी करा",
      "yes": "होय",
      "no": "नाही",
      "na": "उपलब्ध नाही",
      "lang-label": "भाषा",

      // ── Admin Topbar ──
      "alerts": "🔊 सूचना",
      "notifications": "अधिसूचना",
      "clear-all": "सर्व साफ करा",

      // ── Admin Sidebar Groups ──
      "group-main": "📊 मुख्य",
      "group-analytics": "📈 विश्लेषण",
      "group-inventory": "📦 इन्व्हेंटरी व्यवस्थापन",
      "group-customers": "👥 ग्राहक",
      "group-marketing": "📢 विपणन",
      "group-finance": "💰 वित्त",
      "group-security": "🛡️ सुरक्षा",
      "group-ai": "🤖 AI आणि संशोधन",
      "group-system": "⚙️ सिस्टम",

      // ── Admin Sidebar Items ──
      "nav-overview": "आढावा",
      "nav-inventory": "इन्व्हेंटरी",
      "nav-ai-agents": "AI एजंट",
      "nav-shelf-scan": "शेल्फ स्कॅन",
      "nav-franchises": "फ्रँचाइज",
      "nav-purchase-orders": "खरेदी आदेश",
      "nav-orders": "ऑर्डर",
      "nav-settings": "सेटिंग्ज",
      "nav-store-settings": "स्टोर सेटिंग्ज",
      "nav-my-customers": "माझे ग्राहक",
      "nav-segments": "विभाग",
      "nav-engagement": "सहभाग",
      "nav-retention": "धारण",
      "nav-nps": "NPS स्कोर",
      "nav-coupons": "कूपन",
      "nav-campaigns": "मोहिमा",
      "nav-financial-summary": "आर्थिक सारांश",
      "nav-gst": "GST अहवाल",
      "nav-pl": "P&L विवरण",
      "nav-security": "सुरक्षा",
      "nav-logs": "लॉग्ज",
      "nav-themes": "थीम",
      "nav-system-health": "सिस्टम आरोग्य",
      "nav-staff": "कर्मचारी",

      // ── Admin Overview ──
      "overview-title": "📊 स्टोर आढावा",
      "overview-score": "🏆 स्टोर कामगिरी स्कोर",
      "overview-stock": "📈 स्टॉक आढावा",
      "overview-alerts": "🚨 अलीकडील एजंट सूचना",
      "overview-actions": "🤖 अलीकडील एजंट कृती",

      // ── Admin Inventory ──
      "inv-add-title": "➕ नवीन वस्तू जोडा",
      "inv-name-placeholder": "वस्तूचे नाव (उदा. चॉकलेट)",
      "inv-stock-placeholder": "प्रारंभिक स्टॉक प्रमाण",
      "inv-add-btn": "वस्तू जोडा",
      "inv-list-title": "📦 सध्याची इन्व्हेंटरी",
      "inv-reset-btn": "🧹 सर्व लॉग व स्टॉक रीसेट करा",
      "inv-download-btn": "📥 स्टॉक CSV डाउनलोड करा",

      // ── Admin Orders ──
      "orders-title": "🧾 ऑर्डर व्यवस्थापन",
      "orders-search": "ऑर्डर शोधा...",
      "orders-filter-all": "सर्व",
      "orders-filter-placed": "दिले",
      "orders-filter-processing": "प्रक्रियेत",
      "orders-filter-ready": "तयार",
      "orders-filter-delivered": "वितरित",

      // ── Admin Settings ──
      "settings-store-name": "स्टोरचे नाव",
      "settings-address": "पत्ता",
      "settings-phone": "फोन",
      "settings-save": "सेटिंग्ज जतन करा",

      // ── Ask AI ──
      "nlq-title": "🧠 तुमच्या स्टोरबद्दल AI ला विचारा",
      "nlq-subtitle": "कोणताही प्रश्न साध्या भाषेत विचारा आणि लाइव्ह डेटावरून त्वरित उत्तर मिळवा.",
      "nlq-btn": "🔍 AI ला विचारा",
      "nlq-placeholder": "तुमच्या स्टोरबद्दल काहीही विचारा...",
      "nlq-q1": "या आठवड्यात कोणते उत्पादन संपेल?",
      "nlq-q2": "आजचा एकूण महसूल?",
      "nlq-q3": "स्टॉक नसलेल्या वस्तू?",
      "nlq-q4": "सर्वाधिक विकल्या जाणाऱ्या वस्तू?",
      "nlq-q5": "प्रलंबित पुनर्ऑर्डर?",

      // ── Agent Panel ──
      "agent-panel-title": "⚡ एजंट नियंत्रण पॅनेल",
      "agent-panel-subtitle": "सर्व्हर न थांबवता एजंट चालू/बंद करा",
      "agent-running": "▶ चालू आहे",
      "agent-stopped": "⏹ थांबले",

      // ── Login ──
      "login-store-tab": "🏪 स्टोर मालक",
      "login-customer-tab": "👤 ग्राहक",
      "login-store-title": "पुन्हा स्वागत, स्टोर मालक",
      "login-customer-title": "पुन्हा स्वागत!",
      "login-email": "ईमेल पत्ता",
      "login-password": "पासवर्ड",
      "login-store-btn": "डॅशबोर्डमध्ये लॉगिन करा",
      "login-customer-btn": "माझ्या खात्यात लॉगिन करा",
      "login-forgot": "पासवर्ड विसरलात?",
      "login-no-store": "स्टोर नाही?",
      "login-register-free": "मोफत नोंदणी करा →",
      "login-customer-signup": "ग्राहक साइनअप",
      "login-google": "Google ने सुरू ठेवा",
      "login-demo-title": "🔑 डेमो क्रेडेन्शियल",
      "login-demo-customer": "🛍️ डेमो ग्राहक",

      // ── Register ──
      "register-title": "तुमचे स्टोर तयार करा",
      "register-store-name": "स्टोरचे नाव",
      "register-owner-name": "मालकाचे नाव",
      "register-email": "ईमेल पत्ता",
      "register-password": "पासवर्ड",
      "register-btn": "स्टोर तयार करा",
      "register-have-account": "आधीच स्टोर आहे?",

      // ── Landing ──
      "landing-nav-agents": "एजंट",
      "landing-nav-features": "वैशिष्ट्ये",
      "landing-nav-pricing": "किंमत",
      "landing-nav-how": "कसे कार्य करते",
      "landing-nav-shop": "🏪 दुकान",
      "landing-login": "लॉगिन",
      "landing-trial": "मोफत ट्रायल सुरू करा",
      "landing-hero-badge": "🤖 40+ AI एजंट 24/7 काम करत आहेत",
      "landing-hero-title": "तुमच्या रिटेल स्टोरचा AI मेंदू",
      "landing-hero-subtitle": "इन्व्हेंटरी स्वयंचलित करा, मागणीचा अंदाज घ्या, स्टॉकआउट रोका आणि महसूल वाढवा.",
      "landing-get-started": "🚀 मोफत सुरू करा",
      "landing-view-demo": "डेमो पाहा",

      // ── Marketplace ──
      "market-title": "🏪 ShelfSense बाजारपेठ",
      "market-subtitle": "जवळच्या दुकाना शोधा. लाइव्ह इन्व्हेंटरी ब्राउझ करा आणि खरेदी करा.",
      "market-search": "स्टोरचे नाव शोधा…",
      "market-filter-all": "सर्व दुकाने",
      "market-filter-open": "🟢 आत्ता उघडे",
      "market-filter-pro": "⭐ प्रो दुकाने",
      "market-shop-now": "🛍️ आत्ता खरेदी करा",
      "market-stores": "सक्रिय दुकाने",
      "market-products": "उत्पादने सूचीबद्ध",
      "market-orders": "ऑर्डर पूर्ण झाले",
    }
  };

  /* ============================================================
     CORE ENGINE
     ============================================================ */

  // Get saved lang, or auto-detect from device
  function detectLang() {
    const saved = localStorage.getItem("ss-lang");
    if (saved) return saved;
    // Auto-detect from browser
    const nav = navigator.language || navigator.userLanguage || "en";
    if (nav.startsWith("hi")) return "hi";
    if (nav.startsWith("mr")) return "mr";
    return "en";
  }

  let currentLang = detectLang();

  // Translate a single key
  function t(key) {
    return I18N[currentLang]?.[key] || I18N["en"]?.[key] || key;
  }

  // Apply translations to all elements with data-i18n attribute
  function applyAll() {
    document.querySelectorAll("[data-i18n]").forEach(el => {
      const key = el.getAttribute("data-i18n");
      const val = t(key);
      // Decide whether to set textContent or placeholder
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA") {
        el.placeholder = val;
      } else {
        el.textContent = val;
      }
    });

    // data-i18n-placeholder (for inputs that also have other content)
    document.querySelectorAll("[data-i18n-ph]").forEach(el => {
      el.placeholder = t(el.getAttribute("data-i18n-ph"));
    });

    // Update <html lang="...">
    document.documentElement.lang = currentLang;

    // Highlight active lang button
    ["en","hi","mr"].forEach(l => {
      const btn = document.getElementById(`i18n-btn-${l}`);
      if (btn) btn.classList.toggle("i18n-active", l === currentLang);
    });
  }

  // Set language and re-apply
  function setLang(lang) {
    currentLang = lang;
    localStorage.setItem("ss-lang", lang);
    applyAll();
    // Fire custom event so page JS can react if needed
    document.dispatchEvent(new CustomEvent("langchange", { detail: { lang } }));
  }

  // Inject the language switcher widget into any element with id="i18n-mount"
  function mountSwitcher() {
    const mount = document.getElementById("i18n-mount");
    if (!mount) return;
    mount.innerHTML = `
      <div class="i18n-switcher">
        <button id="i18n-btn-en" class="i18n-btn ${currentLang==="en"?"i18n-active":""}" onclick="window.SS_I18N.setLang('en')" title="English">EN</button>
        <button id="i18n-btn-hi" class="i18n-btn ${currentLang==="hi"?"i18n-active":""}" onclick="window.SS_I18N.setLang('hi')" title="हिंदी">हि</button>
        <button id="i18n-btn-mr" class="i18n-btn ${currentLang==="mr"?"i18n-active":""}" onclick="window.SS_I18N.setLang('mr')" title="मराठी">म</button>
      </div>`;
  }

  // Expose globally
  window.SS_I18N = { t, setLang, applyAll, currentLang: () => currentLang, detectLang };

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function() { mountSwitcher(); applyAll(); });
  } else {
    mountSwitcher(); applyAll();
  }

  // Also expose shorthand
  window.ssT = t;

})();
