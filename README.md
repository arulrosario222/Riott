# SheetMart – Excel template store (production version)

Node.js + Express + PostgreSQL. Customers see the store at `/`, you manage everything at `/#admin`.
Payments: customers pay with GPay / PhonePe / Paytm / any UPI app, then submit the UPI transaction (UTR) number.
You check it in your bank/UPI app and set the order to **Paid** in Admin; the customer is emailed and downloads unlock.

## Deploy for free – step by step

### 1. Database (Neon, free)
1. Sign up at neon.tech → create a project → copy the **connection string** (starts with `postgresql://`).
2. Tables are created automatically the first time the server starts.

### 2. Put the code on GitHub
1. Create a free GitHub account and a new **private** repository.
2. Upload every file in this folder (server.js, package.json, public/, README.md, .gitignore). Do NOT upload a `.env` file.

### 3. Web service (Render, free)
1. Sign up at render.com → New → **Web Service** → connect your GitHub repo.
2. Runtime: Node. Build command: `npm install`. Start command: `npm start`. Plan: Free.
3. Add Environment Variables (see `.env.example`):
   - `DATABASE_URL` – the Neon connection string
   - `JWT_SECRET` – a long random string (e.g. 40+ random characters)
   - `ADMIN_PASSWORD` – your strong admin password
   - `BASE_URL` – your Render address, e.g. https://your-store.onrender.com
   - `RESEND_API_KEY`, `FROM_EMAIL` – optional, for emails (step 4)
4. Deploy. Open your Render address – the store is live.

### 4. Emails (optional, Resend free tier)
Sign up at resend.com, create an API key, add your domain and verify it, then set `RESEND_API_KEY` and `FROM_EMAIL`.
Emails sent: new-order alert to you, "payment confirmed" to the customer, contact-form messages to your support email.

### 5. First login
1. Open `https://your-store.onrender.com/#admin` and log in with `ADMIN_PASSWORD`.
2. On the very first login the demo products (with the 4 Excel templates) are saved to the database.
3. Go to **Website settings** and enter your real **UPI ID**, payee name, email, phone and logo.
4. Edit products, prices, homepage and reviews – changes show for all visitors immediately.

### 6. Custom domain (optional, paid)
Buy a `.in` domain, then Render → Settings → Custom Domains and follow the DNS steps. HTTPS is automatic.

## Good to know
- **Free Render sleeps** after ~15 min idle; the first visit then takes ~30 s. Upgrade to a paid plan when you have regular sales.
- Excel files are stored in the database (fine for a small catalogue) and are only served to the customer who owns a **Paid** order.
- Passwords are hashed (bcrypt); login cookies are httpOnly; login endpoints are rate-limited; prices and coupons are checked on the server.
- Use a **business** UPI ID (PhonePe Business / bank merchant UPI). Personal IDs can be restricted by GPay/PhonePe for business collections.
- Automatic payment confirmation needs a payment-gateway account (Razorpay / Cashfree / PhonePe PG); not included here.
- Before selling the HR template, have a CA confirm the PF, ESI and professional-tax rates.
- Terms, Privacy and Refund pages are not included. Payment gateways usually require them.
