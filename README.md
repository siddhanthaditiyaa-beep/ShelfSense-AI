<div align="center">

<img src="https://img.shields.io/badge/ShelfSense%20AI-v1.0.0-6366f1?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0tMiAxNWwtNS01IDEuNDEtMS40MUwxMCAxNC4xN2w3LjU5LTcuNTlMMTkgOGwtOSA5eiIvPjwvc3ZnPg==" />

# 🧠 ShelfSense AI

### Multi-Agent Retail Intelligence Platform with Cybersecurity

**A comprehensive SaaS system featuring 40 AI agents, 13-layer cybersecurity, YOLOv8 shelf detection, and a multi-store marketplace — built as a Computer Engineering internship research project targeting IEEE publication.**

<br/>

[![Live Demo](https://img.shields.io/badge/🚀%20Live%20Demo-shelfsense--ai--lptz.onrender.com-22c55e?style=for-the-badge)](https://shelfsense-ai-lptz.onrender.com)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://mongodb.com)
[![License](https://img.shields.io/badge/License-ISC-blue?style=for-the-badge)](LICENSE)

<br/>

[![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-100%25-brightgreen?style=flat-square)](https://owasp.org)
[![ISO 27001](https://img.shields.io/badge/ISO%2027001-93%25-6366f1?style=flat-square)](https://iso.org)
[![NIST](https://img.shields.io/badge/NIST%20CSF-88%25-f59e0b?style=flat-square)](https://nist.gov)
[![PCI-DSS](https://img.shields.io/badge/PCI--DSS-85%25-ef4444?style=flat-square)](https://pcisecuritystandards.org)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Live Demo & Credentials](#-live-demo--credentials)
- [Features at a Glance](#-features-at-a-glance)
- [40 AI Agents](#-40-ai-agents)
- [Cybersecurity Architecture](#-cybersecurity-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Environment Variables](#-environment-variables)
- [API Reference](#-api-reference)
- [Screenshots](#-screenshots)
- [Research & IEEE Paper](#-research--ieee-paper)
- [Team](#-team)

---

## 🎯 Overview

ShelfSense AI is a **full-stack multi-agent SaaS platform** for retail store management. It combines real-time AI monitoring, computer vision, predictive analytics, and enterprise-grade security into a single deployable system.

| Metric | Value |
|--------|-------|
| 🤖 AI Agents | **40** (18 dashboard-controlled, 22 background) |
| 🛡️ Security Layers | **13** |
| 📄 Features Built | **332** across 12 development batches |
| 📊 Dashboard Pages | **100+** |
| 🎨 UI Themes | **10** (5 dark, 5 light) |
| 📡 API Routes | **461** |
| 📝 Backend Code | **10,800+ lines** (single `server.js`) |
| 🏗️ Architecture | Multi-tenant SaaS |

---

## 🚀 Live Demo & Credentials

**Live URL:** [`https://shelfsense-ai-lptz.onrender.com`](https://shelfsense-ai-lptz.onrender.com)

### Demo Accounts

| Role | Email | Password | Access |
|------|-------|----------|--------|
| 🏪 Demo Store Owner | `demo@shelfsense.ai` | `demo1234` | Full admin dashboard + 45 seeded orders |
| 🛍️ Demo Customer | `shopper@shelfsense.ai` | `shopper123` | Customer shop + order history |
| 🔧 Test Store Owner | `test@test.com` | `test123` | Basic admin access |
| 👑 Super Admin | `superadmin@shelfsense.ai` | `superadmin123` | Platform-wide control |

### Setup Endpoints

```
GET /setup-demo-store     → Seeds demo store with 45 orders, 12 products, demo customer
GET /health               → Server + DB health check
GET /unlock-store/demo%40shelfsense.ai → Unlock demo account if locked
```

> **Note:** Run `/setup-demo-store` once after first deployment to seed all demo data.

---

## ✨ Features at a Glance

<details>
<summary><strong>🤖 AI & Intelligence</strong></summary>

- **40 AI Agents** with individual kill switches — pause any agent without restarting the server
- **YOLOv8 Shelf Detection** — upload shelf images, get real-time occupied/empty slot detection
- **Groq LLaMA3 Chatbot** — natural language store queries ("Which products run out this week?")
- **Demand Forecasting** — exponential smoothing + seasonality detection
- **Dynamic Pricing** — auto-adjusts prices based on demand velocity and competitor data
- **Anomaly Detection** — Z-score analysis detects unusual stock drops (theft detection)
- **Churn Prediction** — identifies at-risk customers before they leave
- **Market Basket Analysis** — association rule mining for bundle recommendations
- **Price Elasticity Modeling** — finds optimal price points per product
- **Explainable AI (XAI)** — every agent decision logged with reasoning

</details>

<details>
<summary><strong>🏪 Multi-Store Marketplace</strong></summary>

- **Public store directory** — customers discover all registered stores
- **Live inventory browsing** — see stock levels before entering a store
- **Cross-store shopping** — one customer account, shop from multiple stores
- **Store switching** — seamless transition between store contexts
- **Nearby franchise locator** — out-of-stock? Find nearest store with the item + distance in km
- **Admin customer view** — each store owner sees their own customer list + spend data
- **Superadmin global view** — see all customers, which stores they shop at, cross-store spend

</details>

<details>
<summary><strong>📊 Analytics (40+ Pages)</strong></summary>

- Sales Analytics, Revenue Forecast, Cohort Revenue
- Customer LTV, Funnel Analytics, Retention, Engagement
- Inventory Health, Stockout Risk, Aging Report, Turnover Ratio
- Demand Heatmap, Product Heatmap, Traffic Heatmap
- Gross Margins, GST Report, P&L Statement, Financial Summary
- Bundle Analytics, Sales Velocity, Product Performance
- NPS Score, Sentiment Analysis, Wishlist Analytics, Review Summary
- Competitor Analysis, Spend Predictor, Radar Metrics
- Statistical Significance Testing, Ablation Study, ROAS Simulator

</details>

<details>
<summary><strong>🛍️ Customer Portal</strong></summary>

- Product browsing with real-time stock levels and expiry indicators
- Cart, wishlist, compare products side-by-side
- Razorpay UPI/card/netbanking payments
- Google OAuth login
- Order tracking with status updates
- Loyalty points system with tier levels
- Referral program (auto-generated codes, +50 points per referral)
- Customer check-in, achievements, gamification leaderboard
- Subscription orders, bundle deals, flash sales
- Review & ratings system (submitted by customer, approved by admin)
- Multi-language support (EN / हिंदी / मराठी)
- 10 UI themes shared with admin

</details>

<details>
<summary><strong>⚙️ Operations</strong></summary>

- Purchase orders with auto-reorder triggers
- Product expiry calendar with auto-discount (30% off within 7 days)
- Planogram editor — visual shelf slot management
- Product watchlist — alert when stock drops below threshold
- Coupon & discount engine
- Flash deals with countdown timers
- Staff management
- Supplier scorecard
- Inventory snapshots
- What-If simulator — test pricing scenarios before applying
- Bulk price updates by category
- CSV stock export

</details>

---

## 🤖 40 AI Agents

### Dashboard-Controlled Agents (18) — Toggle on/off without server restart

| Agent | Trigger | Function |
|-------|---------|----------|
| **Monitoring Agent** | Every 30s | Watches stock levels, fires low-stock alerts |
| **Forecasting Agent** | Every 15min | Predicts demand using exponential smoothing |
| **Anomaly Detection Agent** | Every 45s | Z-score analysis detects theft/shrinkage |
| **Dynamic Pricing Agent** | Every hour | Adjusts prices based on demand + competitor data |
| **Competitor Analysis Agent** | Daily 9AM | Compares your prices vs tracked competitors |
| **Supplier Agent** | Every 2hrs | Auto-generates purchase orders at minimum stock |
| **Customer Behavior Agent** | Daily 1AM | Association rule mining for bundle suggestions |
| **Weather Agent** | Daily 8AM | Fetches Open-Meteo data, adjusts stock recommendations |
| **Expiry Agent** | Daily 7AM | Applies 30% discount on items expiring within 7 days |
| **Route Optimization Agent** | Weekly | Optimizes delivery routes for purchase orders |
| **Sentiment Analysis Agent** | Daily | Analyzes customer reviews for store sentiment score |
| **Demand Surge Agent** | Every 4hrs | Detects unusual demand spikes, adjusts pricing |
| **Fraud Detection Agent** | Every 30min | Flags suspicious transactions and login patterns |
| **Smart Upsell Agent** | Daily | Generates upsell recommendations per customer |
| **Loyalty Tier Agent** | Daily midnight | Upgrades/downgrades customer tiers based on spend |
| **Seasonal Demand Agent** | Weekly | Adjusts forecasts for seasonal patterns |
| **Churn Prediction Agent** | Weekly | Identifies customers at risk of leaving |
| **Goal Tracking Agent** | Daily | Tracks revenue/order targets, sends progress emails |

### Background Agents (22) — Always running, no user control

| Agent | Function |
|-------|----------|
| **NLQ Agent** | Processes natural language store queries via Groq |
| **Abandoned Cart Agent** | Recovers abandoned carts with email reminders |
| **Daily Briefing Agent** | Morning email with store summary + top alerts |
| **Weekly Summary Agent** | Weekly performance report email |
| **Newsletter Agent** | Customer newsletter with deals and new products |
| **Review Request Agent** | Post-delivery review request emails |
| **Recommendation Email Agent** | Personalized product recommendation emails |
| **Points Expiry Agent** | Warns customers about expiring loyalty points |
| **Peak Hours Agent** | Tracks busiest hours, staffing suggestions |
| **Price Elasticity Agent** | Models demand curves per product |
| **Price Optimization Agent** | Finds revenue-maximizing price points |
| **Dead Stock Agent** | Flags slow-moving inventory for markdown |
| **Market Basket Agent** | Finds frequently bought together combinations |
| **Reorder Point Agent** | Calculates optimal reorder trigger levels |
| **Reorder Reminder Agent** | Supplier reminder emails for pending orders |
| **Subscription Agent** | Manages recurring subscription orders |
| **Shrinkage Alert Agent** | Detects inventory shrinkage beyond expected loss |
| **Auto Discount Agent** | Applies time-based promotional discounts |
| **Smart Notification Agent** | Intelligent alert routing (email/Telegram/in-app) |
| **Stockout Broadcaster Agent** | Real-time SSE broadcast when item hits zero |
| **DB Backup Agent** | Periodic MongoDB collection snapshots |
| **Health Broadcaster Agent** | Streams system health metrics via SSE |

---

## 🛡️ Cybersecurity Architecture

ShelfSense AI implements **13 security layers** benchmarked against 4 international standards.

### Compliance Scores

```
✅ OWASP Top 10        100%  ████████████████████
🔵 ISO 27001:2022       93%  ██████████████████░░
🟡 NIST CSF 2.0         88%  █████████████████░░░
🔴 PCI-DSS              85%  █████████████████░░░
```

### Security Layers

| Layer | Implementation |
|-------|---------------|
| **Authentication** | JWT with token blacklisting, 24h expiry, role-based access (customer/admin/superadmin) |
| **Password Security** | bcrypt hashing (12 rounds), 5-attempt lockout, 30-min cooldown |
| **Transport Security** | Helmet.js HTTP headers, HTTPS enforced, HSTS |
| **Rate Limiting** | express-rate-limit per route category, express-slow-down for progressive throttling |
| **Input Sanitization** | express-mongo-sanitize (NoSQL injection), xss-clean (XSS), hpp (HTTP parameter pollution) |
| **Bot Detection** | Honeypot fields on all forms — bots fill hidden fields, humans don't |
| **Fraud Detection** | Real-time transaction scoring, suspicious IP tracking across sessions |
| **Biometric Anomaly** | Typing speed + session pattern analysis, flags anomalous login behavior (80% threshold, 5 sessions min) |
| **Audit Logging** | Every auth event, admin action, and security incident logged with IP + timestamp |
| **Session Security** | connect-mongo session store, rotating secrets, cookie security flags |
| **Two-Factor Auth** | OTP via email for high-risk actions |
| **CSRF Protection** | Token-based CSRF on all state-changing routes |
| **Security Monitoring** | Real-time attack simulator, Zero Trust log, breach detection dashboard |

---

## 🔧 Tech Stack

### Backend
```
Node.js 18+          Runtime
Express.js 4.x       Web framework
MongoDB Atlas        Database (Mongoose 9.x ODM)
node-cron 4.x        Agent scheduling (40 cron jobs)
JWT (jsonwebtoken)   Authentication
bcryptjs             Password hashing
Passport.js          Google OAuth 2.0
Nodemailer           Email alerts
Razorpay             Payment gateway
Helmet.js            Security headers
```

### AI & ML
```
YOLOv8 (Ultralytics)    Retail shelf object detection
Flask (Python)           ML microservice wrapper
Google Colab             Free GPU training environment
Roboflow                 Retail shelf dataset
ngrok                    Colab ↔ server tunnel
Groq API (LLaMA3)        Natural language query processing
Open-Meteo API           Weather data for demand adjustment
```

### Frontend
```
Vanilla HTML/CSS/JS      No framework overhead
Chart.js                 Analytics visualizations
10 custom CSS themes     5 dark + 5 light
Progressive Web App      Service worker + manifest
```

### Infrastructure
```
Render.com               Hosting (free tier)
MongoDB Atlas            Database (free tier M0)
UptimeRobot              External uptime monitoring
Self-ping (4min)         Render sleep prevention
```

---

## 📁 Project Structure

```
ShelfSense-AI/
│
├── server.js                 # Main backend — 10,800+ lines, 461 routes, 40 agents
├── slotProductMapper.js      # YOLOv8 slot → product mapping logic
├── retail_shelf.pt           # Trained YOLOv8 model weights
├── package.json
│
├── ml-service/
│   └── app.py                # Flask microservice for YOLOv8 inference
│
└── public/                   # All frontend files (served as static)
    ├── landing.html          # Marketing landing page
    ├── about.html            # About page (founders, tech stack, story)
    ├── login.html            # Store owner + customer login (tabbed)
    ├── register.html         # Store owner registration
    ├── customer-register.html# Customer registration
    ├── admin.html            # Admin dashboard (100+ pages, 40 agents)
    ├── customer.html         # Customer shopping portal
    ├── marketplace.html      # Public store discovery page
    ├── superadmin.html       # Platform-wide control panel
    ├── onboarding.html       # New store owner onboarding wizard
    ├── contact.html          # Contact page
    ├── about.html            # About page
    ├── privacy.html          # Privacy policy
    ├── terms.html            # Terms of service
    ├── reset-password.html   # Password reset
    ├── style.css             # Global styles + full responsive system
    ├── theme.js              # 10-theme engine
    ├── sw.js                 # Service worker (PWA)
    └── manifest.json         # PWA manifest
```

---

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- MongoDB Atlas account (free tier works)
- Git

### Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/siddhanthaditiyaa-beep/ShelfSense-AI.git
cd ShelfSense-AI

# 2. Install dependencies
npm install

# 3. Create environment file
cp .env.example .env
# Edit .env with your values (see Environment Variables section)

# 4. Start the server
npm start
# Server runs on http://localhost:3000

# 5. Seed demo data (run once)
# Visit: http://localhost:3000/setup-demo-store
```

### YOLOv8 ML Service Setup (Optional)

The shelf scanning feature requires the Python ML service running separately.

```bash
# Option A: Run locally
cd ml-service
pip install ultralytics flask pillow numpy
python app.py
# Runs on http://localhost:5000

# Option B: Google Colab (recommended — free GPU)
# 1. Upload app.py and retail_shelf.pt to Colab
# 2. Install ngrok: !pip install pyngrok
# 3. Run app.py and expose with ngrok
# 4. Set ML_SERVICE_URL in your .env to the ngrok URL
```

---

## 🔑 Environment Variables

Create a `.env` file in the project root:

```env
# ── REQUIRED ──────────────────────────────────────
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/shelfsense
JWT_SECRET=your_super_secret_jwt_key_minimum_32_chars
SESSION_SECRET=your_session_secret_key

# ── SERVER ────────────────────────────────────────
PORT=3000
NODE_ENV=production
BASE_URL=https://your-app.onrender.com
FRONTEND_URL=https://your-app.onrender.com
RENDER_EXTERNAL_URL=https://your-app.onrender.com

# ── EMAIL ALERTS ──────────────────────────────────
ALERT_EMAIL=your.email@gmail.com
ALERT_EMAIL_PASSWORD=your_gmail_app_password
ADMIN_ALERT_EMAIL=admin@yourdomain.com

# ── GOOGLE OAUTH (optional) ───────────────────────
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret

# ── PAYMENTS (optional) ───────────────────────────
RAZORPAY_KEY_ID=rzp_test_your_key_id
RAZORPAY_KEY_SECRET=your_razorpay_secret

# ── AI (optional — falls back to rule-based) ──────
GROQ_API_KEY=gsk_your_groq_api_key

# ── ML SERVICE (optional) ─────────────────────────
ML_SERVICE_URL=https://your-ngrok-url.ngrok.io

# ── TELEGRAM ALERTS (optional) ────────────────────
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id
```

> **Gmail setup:** Enable 2FA → Generate App Password → use that as `ALERT_EMAIL_PASSWORD`
>
> **Groq API:** Free at [console.groq.com](https://console.groq.com) — powers the Ask AI chatbot

---

## 📡 API Reference

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/login` | None | Customer login |
| `POST` | `/login-store` | None | Store owner login |
| `POST` | `/register` | None | Customer registration |
| `POST` | `/register-store` | None | Store owner registration |
| `POST` | `/logout` | JWT | Logout + blacklist token |

### Store Owner (Admin)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin-data` | Full inventory + store data |
| `POST` | `/admin/add-item` | Add new inventory item |
| `POST` | `/admin/update-stock` | Update item stock level |
| `POST` | `/admin/update-price` | Update item price |
| `POST` | `/admin/update-expiry` | Set product expiry date |
| `POST` | `/admin/update-sale` | Toggle sale + discount % |
| `GET` | `/admin/orders` | All orders for this store |
| `POST` | `/admin/nlq` | Natural language AI query |
| `POST` | `/admin/toggle-agent` | Enable/disable specific agent |
| `GET` | `/admin/agent-logs` | Agent activity logs |
| `POST` | `/admin/watchlist` | Add product to watchlist |
| `GET` | `/admin/funnel-analytics` | Customer funnel data |
| `GET` | `/admin/store-customers` | Customers who ordered from this store |
| `GET` | `/admin/testimonials` | Customer reviews (approve/delete) |
| `POST` | `/admin/submit-item` | Submit item for approval workflow |

### Customer

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/shop-items` | Products for active store |
| `POST` | `/place-order` | Place a new order |
| `GET` | `/my-orders` | Customer's order history |
| `GET` | `/customer/all-orders` | Orders across all stores |
| `POST` | `/customer/testimonial` | Submit store review |
| `GET` | `/customer/my-reviews` | View submitted reviews |
| `GET` | `/customer/referral` | Get referral code + stats |

### Marketplace (Public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/public/stores` | All active stores with stats |
| `GET` | `/public/store/:id` | Single store profile + products |

### Superadmin

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/superadmin/stats` | Platform-wide statistics |
| `GET` | `/superadmin/stores` | All registered stores |
| `GET` | `/superadmin/customers` | All customers + cross-store activity |
| `GET` | `/setup-demo-store` | Seed demo data |

### YOLOv8 Shelf Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/admin/scan-shelf` | Upload shelf image → returns stock counts |
| `GET` | `/health` | Server + DB status check |

---

## 🎨 UI Themes

ShelfSense AI ships with **10 complete themes** — each changes the entire color system via CSS variables.

| Theme | Type | Primary Color |
|-------|------|--------------|
| 🌌 ShelfSense Dark | Dark | Indigo `#6366f1` |
| 🖥️ Midnight Command | Dark | Green `#22c55e` |
| ⚡ Cyberpunk | Dark | Amber `#f59e0b` |
| 🌊 Deep Ocean | Dark | Cyan `#06b6d4` |
| 🌹 Rose Gold | Dark | Rose `#f43f5e` |
| ⬜ ShelfSense White | Light | Indigo `#6366f1` |
| 🌿 Mint Fresh | Light | Emerald `#059669` |
| 🩵 Sky Blue | Light | Sky `#0284c7` |
| 🍑 Warm Peach | Light | Orange `#ea580c` |
| 💜 Lavender | Light | Violet `#7c3aed` |

---

## 📖 Research & IEEE Paper

ShelfSense AI is being prepared for **IEEE conference/journal submission**. The research focuses on:

- **Multi-agent coordination** in retail inventory management
- **YOLOv8 computer vision** for automated shelf monitoring
- **Layered cybersecurity** benchmarked against ISO 27001, NIST CSF, OWASP, PCI-DSS
- **Agentic AI architecture** — kill-switch controlled agents with explainable decisions
- **Real-world deployment** — fully functional SaaS system, not a prototype

### Key Research Contributions

1. First open-source multi-agent retail SaaS with 40 specialized agents
2. Novel integration of YOLOv8 shelf detection with automated inventory management
3. 13-layer cybersecurity framework achieving OWASP Top 10 100% compliance
4. Multi-store marketplace architecture for retail SaaS
5. Natural language query interface using open-source LLMs (Groq LLaMA3) for retail analytics

---

## 👥 Team

<table>
<tr>
<td align="center" width="50%">

### Siddhanthaditiyaa Vettakal
**Co-Founder & Lead Developer**

🏫 Pillai College of Engineering, Mumbai

Built the complete platform — 10,800+ lines of backend, 40 AI agents, 13-layer cybersecurity, YOLOv8 integration, multi-store marketplace, Groq chatbot, Razorpay payments, 100+ dashboard pages across 12 development batches.

`Node.js` `MongoDB` `YOLOv8` `Cybersecurity` `AI/ML` `Full Stack`

</td>
<td align="center" width="50%">

### Sneha Pillai
**Co-Founder & Security Researcher**

🏫 Pillai College of Engineering, Mumbai

Contributed to anomaly detection algorithms, cybersecurity framework design (ISO 27001/NIST/OWASP/PCI-DSS compliance benchmarking), security architecture, and the IEEE research paper documentation.

`Cybersecurity` `Threat Detection` `IEEE Research` `Anomaly Detection` `Security Architecture`

</td>
</tr>
</table>

---

## 📜 License

This project is licensed under the **ISC License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [Ultralytics YOLOv8](https://github.com/ultralytics/ultralytics) — Object detection model
- [Roboflow](https://roboflow.com) — Retail shelf training dataset
- [Groq](https://groq.com) — Free LLaMA3 inference API
- [Open-Meteo](https://open-meteo.com) — Free weather API
- [Razorpay](https://razorpay.com) — Payment gateway
- [Render](https://render.com) — Free hosting platform
- [MongoDB Atlas](https://mongodb.com/atlas) — Free cloud database

---

<div align="center">

**Built with ❤️ by Siddhanthaditiyaa Vettakal & Sneha Pillai**
**Pillai College of Engineering, Mumbai — Computer Engineering Internship Project 2025–2026**

⭐ **Star this repo if you found it useful!**

[![GitHub stars](https://img.shields.io/github/stars/siddhanthaditiyaa-beep/ShelfSense-AI?style=social)](https://github.com/siddhanthaditiyaa-beep/ShelfSense-AI)

</div>
