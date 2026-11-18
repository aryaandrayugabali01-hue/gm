import { PRODUCT_ASSETS_GZIP } from "./product-assets.js";
const cors = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type,x-telegram-bot-api-secret-token" };

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", ...cors } });
}
function html(body) {
  return new Response(body, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin" } });
}
const TERMS_VERSION = "2026-11-14";
const PRODUCT_ASSET_CACHE = new Map();
async function getProductAsset(name) {
  if (!/^\d{2}-(?:hero|benefit)\.svg$/.test(name)) return null;
  if (PRODUCT_ASSET_CACHE.has(name)) return PRODUCT_ASSET_CACHE.get(name);
  const encoded = PRODUCT_ASSETS_GZIP[name];
  if (!encoded) return null;
  const compressed = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
  const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream("gzip"));
  const svg = await new Response(stream).text();
  if (!/^\s*(?:<\?xml[^>]*>\s*)?<svg\b/i.test(svg) || !/<\/svg>\s*$/i.test(svg)) return null;
  PRODUCT_ASSET_CACHE.set(name, svg);
  return svg;
}
const TERMS_MESSAGE = "SYARAT & KETENTUAN JKT STARS STORES\n\n1. Pesanan diproses melalui bot. Setelah Telegram mengonfirmasi pembayaran, pesanan masuk pemeriksaan kualitas sebelum akses dikirim.\n2. Jangan membagikan detail login atau akses akun kepada pihak lain.\n3. Klaim garansi wajib diajukan melalui Bantuan Pesanan dengan mencantumkan Order ID dan kendala.\n4. Harga dan masa akses mengikuti keterangan pada produk saat dipesan.\n5. Permintaan bantuan dan pengembalian dana ditinjau sesuai kondisi pesanan serta ketentuan Telegram. Hubungi /paysupport untuk masalah pembayaran.\n\nDengan menekan tombol Bayar pada detail produk, Anda menyatakan telah membaca dan menyetujui syarat ini.";
async function tg(env, method, payload) {
  if (!env.BOT_TOKEN) throw new Error("BOT_NOT_CONFIGURED");
  const response = await fetch("https://api.telegram.org/bot" + env.BOT_TOKEN + "/" + method, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload)
  });
  const data = await response.json();
  if (!response.ok || !data.ok) {
    const error = new Error(data.description || "TELEGRAM_API_ERROR");
    error.telegramRejected = true;
    throw error;
  }
  return data.result;
}
async function hmac(keyBytes, message) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}
function hex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function validateInitData(initData, botToken) {
  if (!initData || !botToken) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;
  params.delete("hash");
  const pairs = Array.from(params.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  const check = pairs.map(([k, v]) => k + "=" + v).join("\n");
  const secret = await hmac(new TextEncoder().encode("WebAppData"), botToken);
  const actual = hex(await hmac(secret, check));
  if (actual.length !== hash.length) return null;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ hash.charCodeAt(i);
  if (diff !== 0) return null;
  const authDate = Number(params.get("auth_date") || 0);
  const now = Math.floor(Date.now() / 1000);
  if (!authDate || authDate > now + 300 || now - authDate > 86400) return null;
  try { return JSON.parse(params.get("user") || "null"); } catch { return null; }
}
async function requireUser(request, env) {
  const data = await request.json();
  const user = await validateInitData(data.initData, env.BOT_TOKEN);
  if (!user || !user.id) return { error: json({ ok: false, error: "TELEGRAM_AUTH_REQUIRED", message: "Buka Mini App dari Telegram untuk melanjutkan." }, 401) };
  return { user, data };
}
async function telegramPaymentsReady(env, origin) {
  if (!env.BOT_TOKEN || !env.WEBHOOK_SECRET || !env.ADMIN_TELEGRAM_ID || !env.BOT_USERNAME) return false;
  try {
    const [me, webhook] = await Promise.all([tg(env, "getMe", {}), tg(env, "getWebhookInfo", {})]);
    const expected = new URL("/telegram/webhook", origin).toString().replace(/\/$/, "");
    const actual = String(webhook.url || "").replace(/\/$/, "");
    const username = String(env.BOT_USERNAME || "").replace(/^@/, "").toLowerCase();
    const allowedUpdates = Array.isArray(webhook.allowed_updates) ? webhook.allowed_updates : null;
    const preCheckoutUpdatesEnabled = allowedUpdates === null || allowedUpdates.length === 0 || allowedUpdates.includes("pre_checkout_query");
    return String(me.username || "").toLowerCase() === username && actual === expected && preCheckoutUpdatesEnabled;
  } catch { return false; }
}
async function handleWebhook(request, env) {
  if (!env.WEBHOOK_SECRET || request.headers.get("x-telegram-bot-api-secret-token") !== env.WEBHOOK_SECRET) return new Response("Unauthorized", { status: 401 });
  const update = await request.json();
  if (update.update_id == null) return new Response("OK");

  const claim = await env.DB.prepare("INSERT INTO webhook_updates (update_id) VALUES (?) ON CONFLICT(update_id) DO NOTHING").bind(update.update_id).run();
  if (Number(claim.meta && claim.meta.changes || 0) === 0) return new Response("OK");

  try {
    return await processWebhookUpdate(update, env, new URL(request.url).origin);
  } catch (error) {
    console.error("telegram_webhook_update_failed", { update_id:update.update_id, name:error && error.name, message:String(error && error.message || error).slice(0,500) });
    await env.DB.prepare("DELETE FROM webhook_updates WHERE update_id = ?").bind(update.update_id).run();
    throw error;
  }
}

async function processWebhookUpdate(update, env, origin) {
  if (update.pre_checkout_query) {
    const q = update.pre_checkout_query;
    const order = await env.DB.prepare("SELECT o.id,o.telegram_user_id,o.status,o.amount_stars,o.currency,o.terms_accepted_at,o.terms_version,p.is_active,p.delivery_mode,p.price_stars FROM orders o JOIN products p ON p.id=o.product_id WHERE o.id = ?").bind(q.invoice_payload).first();
    const valid = !!order &&
      order.telegram_user_id === String(q.from.id) &&
      order.status === "PENDING_PAYMENT" &&
      q.currency === "XTR" &&
      Number(q.total_amount) === Number(order.amount_stars) &&
      order.currency === "XTR" &&
      Number(order.price_stars) > 0 &&
      Number(order.price_stars) === Number(order.amount_stars) &&
      Number(order.is_active) === 1 &&
      order.delivery_mode === "manual" &&
      !!order.terms_accepted_at &&
      !!order.terms_version;
    await tg(env, "answerPreCheckoutQuery", {
      pre_checkout_query_id: q.id,
      ok: valid,
      ...(valid ? {} : { error_message: "Pesanan tidak valid, produk tidak tersedia, atau detail pembayaran berubah. Silakan buat pesanan baru." })
    });
    return new Response("OK");
  }

  if (update.message) {
    const msg = update.message;
    const userId = String(msg.from && msg.from.id || "");
    const text = String(msg.text || "");
    if (msg.successful_payment) {
      const payment = msg.successful_payment;
      const orderId = String(payment.invoice_payload || "");
      const chargeId = String(payment.telegram_payment_charge_id || "");
      let order = await env.DB.prepare("SELECT * FROM orders WHERE id = ? AND telegram_user_id = ?").bind(orderId, userId).first();

      if (!order) {
        if (env.ADMIN_TELEGRAM_ID) await tg(env, "sendMessage", { chat_id: env.ADMIN_TELEGRAM_ID, text: "PEMBAYARAN PERLU PEMERIKSAAN\nPayload pesanan tidak ditemukan.\nPembeli: " + userId + "\nCharge ID: " + chargeId + "\nCurrency: " + payment.currency + "\nNominal: " + payment.total_amount });
        await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pembayaran terdeteksi, tetapi pesanan belum dapat dicocokkan. Tim admin akan memeriksa transaksi ini. Simpan bukti pembayaran Anda." });
        return new Response("OK");
      }

      const amountValid = payment.currency === "XTR" &&
        Number.isSafeInteger(Number(payment.total_amount)) &&
        Number(payment.total_amount) === Number(order.amount_stars) &&
        order.currency === "XTR" &&
        !!order.terms_accepted_at &&
        !!order.terms_version &&
        !!chargeId;

      if (!amountValid) {
        const reviewPayload = JSON.stringify({ currency: payment.currency, total_amount: payment.total_amount, user_id: userId, charge_id: chargeId, reason: "PAYMENT_DETAILS_MISMATCH" });
        await env.DB.prepare("INSERT INTO payment_events (order_id,event_type,telegram_payment_charge_id,payload_json) SELECT ?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM payment_events WHERE order_id=? AND event_type='PAYMENT_REVIEW_REQUIRED' AND telegram_payment_charge_id=?)")
          .bind(orderId, "PAYMENT_REVIEW_REQUIRED", chargeId || null, reviewPayload, orderId, chargeId).run();
        if (env.ADMIN_TELEGRAM_ID) await tg(env, "sendMessage", { chat_id: env.ADMIN_TELEGRAM_ID, text: "PEMBAYARAN PERLU PEMERIKSAAN\nOrder: " + orderId + "\nNominal/currency/persetujuan tidak cocok.\nDiterima: " + payment.total_amount + " " + payment.currency + "\nCharge ID: " + chargeId });
        await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pembayaran terdeteksi dan sedang diperiksa admin karena detail transaksi perlu dicocokkan. Simpan bukti pembayaran Anda." });
        return new Response("OK");
      }

      if (order.status === "PENDING_PAYMENT" && !order.telegram_payment_charge_id) {
        const payload = JSON.stringify({ currency: payment.currency, total_amount: payment.total_amount, user_id: userId });
        const results = await env.DB.batch([
          env.DB.prepare("UPDATE orders SET status='QA_PENDING',telegram_payment_charge_id=?,provider_payment_charge_id=?,paid_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND telegram_user_id=? AND status='PENDING_PAYMENT' AND currency='XTR' AND amount_stars=? AND telegram_payment_charge_id IS NULL")
            .bind(chargeId, payment.provider_payment_charge_id || null, orderId, userId, Number(payment.total_amount)),
          env.DB.prepare("INSERT INTO payment_events (order_id,event_type,telegram_payment_charge_id,payload_json) SELECT ?,'SUCCESSFUL_PAYMENT',?,? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND status='QA_PENDING' AND telegram_payment_charge_id=?) AND NOT EXISTS (SELECT 1 FROM payment_events WHERE order_id=? AND event_type='SUCCESSFUL_PAYMENT' AND telegram_payment_charge_id=?)")
            .bind(orderId, chargeId, payload, orderId, chargeId, orderId, chargeId)
        ]);
        if (Number(results[0].meta && results[0].meta.changes || 0) === 1) {
          order.status = "QA_PENDING";
          order.telegram_payment_charge_id = chargeId;
        } else {
          order = await env.DB.prepare("SELECT * FROM orders WHERE id=? AND telegram_user_id=?").bind(orderId, userId).first();
        }
      }

      if (order && order.telegram_payment_charge_id === chargeId && ["QA_PENDING","QA_APPROVED","DELIVERED","REFUND_PENDING","REFUNDED"].includes(order.status)) {
        const payload = JSON.stringify({ currency: payment.currency, total_amount: payment.total_amount, user_id: userId });
        await env.DB.prepare("INSERT INTO payment_events (order_id,event_type,telegram_payment_charge_id,payload_json) SELECT ?,'SUCCESSFUL_PAYMENT',?,? WHERE NOT EXISTS (SELECT 1 FROM payment_events WHERE order_id=? AND event_type='SUCCESSFUL_PAYMENT' AND telegram_payment_charge_id=?)")
          .bind(orderId, chargeId, payload, orderId, chargeId).run();
        if (order.status === "QA_PENDING" && env.ADMIN_TELEGRAM_ID) {
          try {
            await tg(env, "sendMessage", { chat_id: env.ADMIN_TELEGRAM_ID, text:
              "PEMBAYARAN BARU\nOrder: " + orderId + "\nProduk: " + order.product_name_snapshot + "\nPembeli: " + userId +
              "\nNominal: " + payment.total_amount + " XTR\nStatus: QA_PENDING\n\nPeriksa ketersediaan dan kualitas akses secara manual. Kirim: /deliver " + orderId + "|detail akses" });
          } catch (notifyError) {
            console.error("payment_admin_notify_failed",{order_id:orderId,message:String(notifyError && notifyError.message || notifyError).slice(0,250)});
          }
        }
        await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pembayaran " + payment.total_amount + " Stars telah tercatat. Pesanan Anda masuk antrean pemeriksaan kualitas sebelum akses dikirim." });
      } else {
        if (env.ADMIN_TELEGRAM_ID) await tg(env, "sendMessage", { chat_id: env.ADMIN_TELEGRAM_ID, text: "PEMBAYARAN GANDA / STATUS TIDAK COCOK\nOrder: " + orderId + "\nPembeli: " + userId + "\nCharge ID baru: " + chargeId + "\nStatus pesanan: " + (order && order.status || "TIDAK DIKETAHUI") + "\nPeriksa transaksi Telegram Stars secara manual." });
        await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pembayaran diterima Telegram dan memerlukan pemeriksaan admin sebelum pesanan dapat diproses. Simpan bukti transaksi Anda." });
      }
      return new Response("OK");
    }

    const command = text.trim().split(/\s+/)[0].split("@")[0].toLowerCase();
    const isAdminPrivate = !!msg.chat && msg.chat.type === "private" && userId === String(env.ADMIN_TELEGRAM_ID || "");
    if (command === "/start") {
      if (!origin) throw new Error("WEBHOOK_ORIGIN_UNAVAILABLE");
      try {
        await tg(env, "setChatMenuButton", {
          chat_id: msg.chat.id,
          menu_button: { type: "web_app", text: "Buka App", web_app: { url: origin } }
        });
      } catch (menuError) {
        console.warn("chat_menu_button_setup_failed", String(menuError && menuError.message || menuError).slice(0, 180));
      }
      await tg(env, "sendMessage", {
        chat_id: msg.chat.id,
        text: "🌟 JKT STARS STORES\n\nToko digital khusus layanan Streaming dan Music.\nBelanja praktis menggunakan Telegram Stars (XTR).\n\n✅ Katalog produk dan detail harga\n✅ Pembayaran langsung melalui Telegram\n✅ Pemeriksaan pesanan dan pengiriman manual oleh admin\n\nTekan tombol di bawah untuk mulai berbelanja.",
        reply_markup: { inline_keyboard: [
          [{ text: "🚀 BUKA MINI APP", web_app: { url: origin } }],
          [{ text: "📦 KATALOG PRODUK", callback_data: "catalog" }, { text: "🧾 PESANAN SAYA", callback_data: "orders" }],
          [{ text: "⭐ INFO STARS", callback_data: "payment_info" }, { text: "🆘 BANTUAN", callback_data: "support" }],
          [{ text: "📜 SYARAT & KETENTUAN", callback_data: "terms" }, { text: "ℹ️ TENTANG", callback_data: "about" }]
        ] }
      });
    } else if (command === "/stars") {
      const catalog = await env.DB.prepare("SELECT name,period_label,price_stars,is_active FROM products WHERE is_active=1 AND delivery_mode='manual' ORDER BY name").all();
      const rows = catalog.results || [];
      const active = rows.filter(p => Number(p.is_active) === 1);
      const listing = rows.map(p => "• " + p.name + " (" + p.period_label + "): " + p.price_stars + " Stars" + (Number(p.is_active) === 1 ? " — tersedia" : " — belum tersedia")).join("\n");
      const message = active.length
        ? "⭐ PEMBAYARAN TELEGRAM STARS\n\n" + listing + "\n\nBuka toko melalui /start untuk melihat produk yang tersedia."
        : "⭐ INFORMASI TELEGRAM STARS\n\n" + listing + "\n\nPembelian sedang ditutup selama tahap pengujian. Belum ada invoice atau pemotongan Stars. Silakan buka /start untuk melihat informasi toko.";
      await tg(env, "sendMessage", { chat_id: msg.chat.id, text: message });
    } else if (command === "/terms") {
      await tg(env, "sendMessage", { chat_id: msg.chat.id, text: TERMS_MESSAGE });
    } else if (["/help","/support","/paysupport"].includes(command)) {
      await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Bantuan PremiumDigital_ID\n\nKirim pesan dengan format:\nOrder ID: (nomor pesanan)\nKendala: (jelaskan kendala)\n\nTim akan memeriksa tiket Anda." });
    } else if (isAdminPrivate && command === "/simulasi_buat") {
      const productKey = text.trim().split(/\s+/)[1] || "";
      const product = await env.DB.prepare("SELECT * FROM products WHERE (id=? OR slug=?) AND is_active=1 AND delivery_mode='manual'").bind(productKey,productKey).first();
      if (!product) {
        await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Produk simulasi tidak ditemukan. Gunakan salah satu: prod_netflix, prod_spotify, prod_youtube, prod_disney, prod_canva.\nContoh: /simulasi_buat prod_netflix" });
      } else {
        const orderId = "TEST-" + crypto.randomUUID();
        const chargeId = "SIMULATED-" + crypto.randomUUID();
        const payload = JSON.stringify({ simulated:true, no_real_payment:true, currency:"XTR", total_amount:product.price_stars, user_id:userId, note:"ADMIN_QA_ONLY" });
        await env.DB.batch([
          env.DB.prepare("INSERT INTO orders (id,telegram_user_id,telegram_username,product_id,product_name_snapshot,amount_stars,currency,status,terms_accepted_at,terms_version,telegram_payment_charge_id,paid_at) VALUES (?,?,?, ?,?,?, 'XTR','QA_PENDING',datetime('now'),?,?,datetime('now'))")
            .bind(orderId,userId,msg.from.username || null,product.id,product.name,product.price_stars,TERMS_VERSION,chargeId),
          env.DB.prepare("INSERT INTO payment_events (order_id,event_type,telegram_payment_charge_id,payload_json) VALUES (?,'SIMULATED_PAYMENT',?,?)")
            .bind(orderId,chargeId,payload)
        ]);
        await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"🧪 PESANAN SIMULASI BERHASIL DIBUAT\n\nOrder: "+orderId+"\nProduk: "+product.name+"\nNilai simulasi: "+product.price_stars+" XTR\nStatus: QA_PENDING\nCharge: "+chargeId+"\n\nTidak ada Stars yang dibayar atau dipotong.\n\nUji pengiriman dengan:\n/deliver "+orderId+"|AKSES UJI - bukan akun atau layanan sungguhan"});
      }
    } else if (isAdminPrivate && command === "/simulasi_refund") {
      const orderId=text.trim().split(/\s+/).slice(1).join(" ").trim();
      const order=await env.DB.prepare("SELECT * FROM orders WHERE id=? AND telegram_user_id=?").bind(orderId,userId).first();
      if (!order || !order.telegram_payment_charge_id || !order.telegram_payment_charge_id.startsWith("SIMULATED-") || !["QA_PENDING","QA_APPROVED"].includes(order.status) || order.delivery_claimed_at) {
        await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Order simulasi tidak ditemukan atau statusnya tidak memenuhi syarat. Gunakan order simulasi baru yang masih QA_PENDING."});
      } else {
        await env.DB.batch([
          env.DB.prepare("UPDATE orders SET status='REFUNDED',updated_at=datetime('now') WHERE id=? AND status IN ('QA_PENDING','QA_APPROVED') AND telegram_payment_charge_id LIKE 'SIMULATED-%'").bind(orderId),
          env.DB.prepare("INSERT INTO payment_events (order_id,event_type,telegram_payment_charge_id,payload_json) SELECT ?,'SIMULATED_REFUND',?,? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND status='REFUNDED') AND NOT EXISTS (SELECT 1 FROM payment_events WHERE order_id=? AND event_type='SIMULATED_REFUND')")
            .bind(orderId,order.telegram_payment_charge_id,JSON.stringify({simulated:true,no_real_refund:true,refunded_by:userId}),orderId,orderId)
        ]);
        await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"🧪 REFUND SIMULASI BERHASIL\nOrder: "+orderId+"\nStatus: REFUNDED\nTidak ada Stars yang dikembalikan karena tidak ada pembayaran nyata."});
      }
    } else if (isAdminPrivate && command === "/ticket_balas") {
      const input = text.trim().split(/\s+/).slice(1).join(" ");
      const separator = input.indexOf("|");
      if (separator < 1 || !input.slice(separator + 1).trim()) {
        await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Format: /ticket_balas TICKET_ID|pesan untuk pembeli"});
      } else {
        const ticketId = input.slice(0,separator).trim();
        const reply = input.slice(separator+1).trim().slice(0,3000);
        const ticket = await env.DB.prepare("SELECT id,telegram_user_id,status FROM support_tickets WHERE id=? AND status IN ('OPEN','IN_PROGRESS')").bind(ticketId).first();
        if (!ticket) {
          await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Tiket tidak ditemukan atau sudah selesai."});
        } else {
          try {
            await tg(env,"sendMessage",{chat_id:ticket.telegram_user_id,text:"📩 BALASAN ADMIN PREMIUMDIGITAL_ID\nTicket ID: "+ticketId+"\n\n"+reply});
            await env.DB.prepare("UPDATE support_tickets SET status='IN_PROGRESS' WHERE id=? AND status='OPEN'").bind(ticketId).run();
            await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Balasan untuk tiket "+ticketId+" berhasil dikirim ke pembeli."});
          } catch (sendError) {
            await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Balasan tidak terkirim. Periksa apakah pembeli sudah pernah membuka chat bot. Detail: "+String(sendError && sendError.message || sendError).slice(0,180)});
          }
        }
      }
    } else if (isAdminPrivate && command === "/tickets") {
      const rows = await env.DB.prepare("SELECT id,telegram_user_id,message,created_at FROM support_tickets WHERE status IN ('OPEN','IN_PROGRESS') ORDER BY created_at ASC LIMIT 10").all();
      const lines = (rows.results || []).map(t => t.id + " | " + t.telegram_user_id + " | " + t.created_at + "\n" + String(t.message || "").slice(0,180));
      await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"TIKET TERBUKA (maks. 10)\n\n"+(lines.join("\n\n")||"Tidak ada tiket terbuka.")});
    } else if (isAdminPrivate && command === "/ticket_selesai") {
      const ticketId = text.trim().split(/\s+/)[1] || "";
      if (!ticketId) await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Format: /ticket_selesai TICKET_ID"});
      else {
        const ticket = await env.DB.prepare("SELECT telegram_user_id FROM support_tickets WHERE id=? AND status IN ('OPEN','IN_PROGRESS')").bind(ticketId).first();
        if (!ticket) { await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Tiket tidak ditemukan atau sudah selesai."}); }
        else {
          const sql = "UPDATE support_tickets SET status='RESOLVED' WHERE id=? AND status IN ('OPEN','IN_PROGRESS')";
          const result = await env.DB.prepare(sql).bind(ticketId).run();
          if (Number(result.meta && result.meta.changes || 0) === 1) {
            try { await tg(env,"sendMessage",{chat_id:ticket.telegram_user_id,text:"✅ Tiket bantuan "+ticketId+" telah diselesaikan oleh admin PremiumDigital_ID. Hubungi bot kembali jika kendala masih terjadi."}); }
            catch (notifyError) { console.error("ticket_resolution_notify_failed",{ticket_id:ticketId,message:String(notifyError && notifyError.message || notifyError).slice(0,180)}); }
            await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Tiket "+ticketId+" ditandai RESOLVED."});
          } else { await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Status tiket berubah. Periksa /tickets."}); }
        }
      }
    } else if (isAdminPrivate && command === "/orders") {
      const rows = await env.DB.prepare("SELECT id,product_name_snapshot,telegram_user_id,status,amount_stars,created_at,delivery_claimed_at FROM orders ORDER BY created_at DESC LIMIT 10").all();
      const lines = (rows.results || []).map(o => o.id + " | " + o.product_name_snapshot + " | " + o.status + " | " + o.telegram_user_id + (o.delivery_claimed_at ? " | DELIVERY_LOCK" : ""));
      await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "10 PESANAN TERBARU\n\n" + (lines.join("\n") || "Belum ada pesanan.") });
    } else if (isAdminPrivate && command === "/deliver") {
      const input = text.trim().split(/\s+/).slice(1).join(" ");
      const split = input.indexOf("|");
      if (split < 1 || !input.slice(split + 1).trim()) {
        await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Format: /deliver ORDER_ID|detail akses untuk pelanggan" });
      } else {
        const orderId = input.slice(0, split).trim();
        const delivery = input.slice(split + 1).trim();
        const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(orderId).first();
        if (!order || !["QA_PENDING","QA_APPROVED"].includes(order.status)) {
          await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pesanan tidak ditemukan atau statusnya bukan antrean QA." });
        } else {
          const claim = await env.DB.prepare("UPDATE orders SET delivery_claimed_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND status IN ('QA_PENDING','QA_APPROVED') AND delivery_claimed_at IS NULL").bind(orderId).run();
          if (Number(claim.meta && claim.meta.changes || 0) !== 1) {
            await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pengiriman pesanan sedang diproses atau sudah diklaim admin lain. Periksa /orders sebelum mencoba kembali." });
          } else {
            let customerReceived = false;
            let deliveryFinalized = false;
            try {
              await tg(env, "sendMessage", { chat_id: order.telegram_user_id, text: "✅ AKSES PESANAN ANDA\nProduk: " + order.product_name_snapshot + "\n\n" + delivery + "\n\nSimpan informasi akses ini dengan aman. Hubungi @JktStarsStores_bot untuk bantuan." });
              customerReceived = true;
              const completed = await env.DB.batch([
                env.DB.prepare("UPDATE orders SET status='DELIVERED',delivered_at=datetime('now'),delivery_claimed_at=NULL,updated_at=datetime('now') WHERE id=? AND status IN ('QA_PENDING','QA_APPROVED') AND delivery_claimed_at IS NOT NULL").bind(orderId),
                env.DB.prepare("INSERT INTO payment_events (order_id,event_type,payload_json) SELECT ?,'DELIVERED',? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND status='DELIVERED') AND NOT EXISTS (SELECT 1 FROM payment_events WHERE order_id=? AND event_type='DELIVERED')")
                  .bind(orderId, JSON.stringify({ delivered_by:userId }), orderId, orderId)
              ]);
              deliveryFinalized = Number(completed[0].meta && completed[0].meta.changes || 0) === 1;
              if (!deliveryFinalized) throw new Error("DELIVERY_STATUS_COMMIT_FAILED");
            } catch (error) {
              if (!customerReceived) {
                await env.DB.prepare("UPDATE orders SET delivery_claimed_at=NULL,updated_at=datetime('now') WHERE id=? AND status IN ('QA_PENDING','QA_APPROVED')").bind(orderId).run();
                await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pengiriman gagal: akses belum terkirim. Order tetap dalam antrean QA. Periksa username pelanggan dan coba kembali." });
              } else {
                await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Akses sudah terkirim ke pelanggan, tetapi pencatatan status belum terverifikasi. Kunci pengiriman dipertahankan sementara agar akses tidak terkirim dua kali. Periksa D1 sebelum tindakan lanjutan." });
              }
            }
            if (deliveryFinalized) {
              await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pengiriman berhasil. Order " + orderId + " ditandai DELIVERED." });
            }
          }
        }
      }
    } else if (isAdminPrivate && command === "/delivery_unlock") {
      const orderId = text.trim().split(/\s+/)[1] || "";
      const order = orderId ? await env.DB.prepare("SELECT id,status,delivery_claimed_at FROM orders WHERE id=?").bind(orderId).first() : null;
      if (!order || !["QA_PENDING","QA_APPROVED"].includes(order.status) || !order.delivery_claimed_at) {
        await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"Kunci pengiriman tidak ditemukan atau pesanan bukan antrean QA."});
      } else {
        const unlockSql = "UPDATE orders SET delivery_claimed_at=NULL,updated_at=datetime('now') WHERE id=? AND status IN ('QA_PENDING','QA_APPROVED') AND delivery_claimed_at IS NOT NULL";
        const eventSql = "INSERT INTO payment_events (order_id,event_type,payload_json) SELECT ?,'DELIVERY_LOCK_RELEASED',? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND delivery_claimed_at IS NULL AND status IN ('QA_PENDING','QA_APPROVED'))";
        const result = await env.DB.batch([env.DB.prepare(unlockSql).bind(orderId),env.DB.prepare(eventSql).bind(orderId,JSON.stringify({released_by:userId,manual:true}),orderId)]);
        await tg(env,"sendMessage",{chat_id:msg.chat.id,text:Number(result[0].meta && result[0].meta.changes || 0)===1?"Kunci pengiriman dilepas. Pastikan pelanggan belum menerima akses sebelum /deliver ulang.":"Kunci pengiriman berubah. Periksa /orders."});
      }
    } else if (isAdminPrivate && command === "/refund") {
      const orderId = text.trim().split(/\s+/)[1] || "";
      const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(orderId).first();
      if (!order || !order.telegram_payment_charge_id || order.telegram_payment_charge_id.startsWith("SIMULATED-") || !["QA_PENDING","QA_APPROVED"].includes(order.status) || order.delivery_claimed_at) {
        const detail = order && order.telegram_payment_charge_id && order.telegram_payment_charge_id.startsWith("SIMULATED-")
          ? "Pesanan ini hanya simulasi. Gunakan /simulasi_refund ORDER_ID; tidak ada refund nyata yang dikirim ke Telegram."
          : order && order.status === "REFUND_PENDING"
            ? "Refund sudah berstatus REFUND_PENDING. Verifikasi transaksi Stars terlebih dahulu; jangan mengirim permintaan refund ulang."
            : "Pesanan tidak memenuhi syarat refund atau sedang dalam proses pengiriman.";
        await tg(env, "sendMessage", { chat_id: msg.chat.id, text: detail });
      } else {
        const previousStatus = order.status;
        const claim = await env.DB.batch([
          env.DB.prepare("UPDATE orders SET status='REFUND_PENDING',updated_at=datetime('now') WHERE id=? AND status=? AND delivery_claimed_at IS NULL")
            .bind(orderId, previousStatus),
          env.DB.prepare("INSERT INTO payment_events (order_id,event_type,telegram_payment_charge_id,payload_json) SELECT ?,'REFUND_REQUESTED',?,? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND status='REFUND_PENDING') AND NOT EXISTS (SELECT 1 FROM payment_events WHERE order_id=? AND event_type='REFUND_REQUESTED')")
            .bind(orderId, order.telegram_payment_charge_id, JSON.stringify({ requested_by:userId }), orderId, orderId)
        ]);
        if (Number(claim[0].meta && claim[0].meta.changes || 0) !== 1) {
          await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Pesanan sedang diproses oleh tindakan admin lain. Periksa /orders." });
        } else {
          try {
            await tg(env, "refundStarPayment", { user_id: Number(order.telegram_user_id), telegram_payment_charge_id: order.telegram_payment_charge_id });
          } catch (error) {
            if (error.telegramRejected) {
              await env.DB.batch([
                env.DB.prepare("UPDATE orders SET status=?,updated_at=datetime('now') WHERE id=? AND status='REFUND_PENDING'").bind(previousStatus, orderId),
                env.DB.prepare("INSERT INTO payment_events (order_id,event_type,telegram_payment_charge_id,payload_json) VALUES (?,?,?,?)")
                  .bind(orderId, "REFUND_REJECTED", order.telegram_payment_charge_id, JSON.stringify({ reason:String(error.message || "TELEGRAM_REJECTED").slice(0,300) }))
              ]);
              await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Telegram menolak refund. Status pesanan dikembalikan ke " + previousStatus + ". Detail: " + String(error.message || "API rejected").slice(0,250) });
            } else {
              await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Hasil permintaan refund belum dapat dipastikan. Status tetap REFUND_PENDING agar tidak terjadi refund ganda. Periksa transaksi Telegram Stars sebelum tindakan berikutnya." });
            }
            return new Response("OK");
          }
          const refunded = await env.DB.batch([
            env.DB.prepare("UPDATE orders SET status='REFUNDED',updated_at=datetime('now') WHERE id=? AND status='REFUND_PENDING' AND telegram_payment_charge_id=?")
              .bind(orderId, order.telegram_payment_charge_id),
            env.DB.prepare("INSERT INTO payment_events (order_id,event_type,telegram_payment_charge_id,payload_json) SELECT ?,'REFUNDED',?,? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND status='REFUNDED') AND NOT EXISTS (SELECT 1 FROM payment_events WHERE order_id=? AND event_type='REFUNDED')")
              .bind(orderId, order.telegram_payment_charge_id, JSON.stringify({ refunded_by:userId }), orderId, orderId)
          ]);
          if (Number(refunded[0].meta && refunded[0].meta.changes || 0) === 1) {
            await tg(env, "sendMessage", { chat_id: order.telegram_user_id, text: "Refund Telegram Stars untuk pesanan " + orderId + " telah diproses." });
            await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Refund Stars berhasil. Order " + orderId + " berstatus REFUNDED." });
          } else {
            await tg(env, "sendMessage", { chat_id: msg.chat.id, text: "Telegram menerima refund, tetapi status D1 masih perlu rekonsiliasi. Periksa order " + orderId + " dengan status REFUND_PENDING." });
          }
        }
      }
    }
  }

  if (update.message && update.message.chat && update.message.chat.type === "private" && update.message.from && !update.message.from.is_bot && !String(update.message.text || "").startsWith("/") && String(update.message.text || "").trim()) {
    const msg = update.message;
    const userId = String(msg.from.id || "");
    const message = String(msg.text || "").trim().slice(0, 1500);
    if (userId) {
      const ticketId = "TG-" + String(update.update_id);
      await env.DB.prepare("INSERT OR IGNORE INTO support_tickets (id,telegram_user_id,telegram_username,message) VALUES (?,?,?,?)").bind(ticketId,userId,msg.from.username || null,message).run();
      if (env.ADMIN_TELEGRAM_ID) { try { await tg(env,"sendMessage",{chat_id:env.ADMIN_TELEGRAM_ID,text:"TIKET BANTUAN BARU\nID: "+ticketId+"\nPengguna: "+userId+"\n\n"+message}); } catch (notifyError) { console.error("bot_ticket_admin_notify_failed",{ticket_id:ticketId,message:String(notifyError && notifyError.message || notifyError).slice(0,250)}); } }
      await tg(env,"sendMessage",{chat_id:msg.chat.id,text:"✅ Pesan bantuan Anda sudah dicatat. Ticket ID: "+ticketId});
    }
  }
  if (update.callback_query && ["support","terms","payment_info","catalog","orders","about"].includes(update.callback_query.data)) {
    const callback = update.callback_query;
    try { await tg(env,"answerCallbackQuery",{callback_query_id:callback.id}); }
    catch (error) { console.warn("callback_ack_failed",{id:callback.id,message:String(error && error.message || error).slice(0,180)}); }
    const opensApp = callback.data === "catalog" || callback.data === "orders";
    const route = callback.data === "orders" ? "orders" : "catalog";
    const responseText = callback.data === "terms" ? TERMS_MESSAGE
      : callback.data === "payment_info" ? "⭐ PEMBAYARAN TELEGRAM STARS\n\nPembayaran dilakukan langsung melalui Telegram Stars (XTR). Harga mengikuti detail pada katalog. Setelah Telegram mengonfirmasi pembayaran, pesanan masuk pemeriksaan kualitas dan akses dikirim oleh admin secara manual."
      : callback.data === "about" ? "🌟 JKT STARS STORES\n\nToko digital untuk layanan Streaming dan Music. Pembayaran menggunakan Telegram Stars (XTR), sedangkan pemeriksaan pesanan dan pengiriman akses dilakukan secara manual oleh admin."
      : callback.data === "catalog" ? "📦 Katalog produk tersedia di Mini App. Pilih kategori Streaming atau Music untuk melihat layanan yang tersedia."
      : callback.data === "orders" ? "🧾 Riwayat dan status pesanan Anda tersedia di menu Pesanan dalam Mini App."
      : "🆘 Bantuan: kirim Order ID dan kendala yang Anda alami. Pesan Anda akan dicatat sebagai tiket bantuan.";
    await tg(env,"sendMessage",{
      chat_id:callback.message && callback.message.chat ? callback.message.chat.id : callback.from.id,
      text:responseText,
      ...(opensApp ? { reply_markup:{ inline_keyboard:[[{
        text:callback.data === "orders" ? "🧾 BUKA PESANAN SAYA" : "📦 BUKA KATALOG",
        web_app:{ url:origin + "?page=" + route }
      }]] } } : {})
    });
  }
  return new Response("OK");
}

const PAGE = String.raw`<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#080713"><meta name="description" content="JKT Stars Stores - katalog Streaming dan Music premium dengan pembayaran Telegram Stars.">
<title>JKT Stars Stores | Mini App</title>

<style>
:root{color-scheme:dark;--gold:#d8b45c;--gold2:#f3d98e;--ink:#edf3fb;--muted:#9cabc0;--line:rgba(216,180,92,.22)}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:16px}
body{margin:0;background:radial-gradient(ellipse at 80% -10%,#1b3654 0,transparent 42%),linear-gradient(180deg,#071321,#091a2d 65%,#071321);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}
main{width:100%;max-width:760px;margin:auto;padding:13px 12px calc(104px + env(safe-area-inset-bottom))}
.hero{margin:2px 0 15px;padding:18px 17px;border:1px solid var(--line);border-radius:19px;background:linear-gradient(125deg,#142d49f2,#0d1c2df2);position:relative;overflow:hidden}
.hero:after{content:"P";position:absolute;right:12px;top:-38px;font:170px Georgia,serif;color:#d8b45c0a;pointer-events:none}
.herohead{display:flex;align-items:center;justify-content:space-between;gap:10px;position:relative;z-index:1}
.eyebrow{color:var(--gold);font-size:9px;font-weight:850;letter-spacing:1.8px}
.hero h1{font:500 clamp(26px,7vw,34px)/1.05 Georgia,serif;margin:7px 0 0;color:#f2e3ba}
.live-status{font-size:9px;font-weight:850;letter-spacing:.7px;color:#a7e8c2;border:1px solid #5bba873f;background:#43a56c18;padding:7px 9px;border-radius:99px;white-space:nowrap}
.hero p{color:#b4c1d2;font-size:12px;line-height:1.55;margin:11px 0 0;max-width:550px;position:relative;z-index:1}
.sectionhead{display:flex;align-items:end;justify-content:space-between;margin:16px 2px 11px;gap:10px}
.sectionhead h2{font:23px Georgia,serif;margin:0;color:#f2e3ba}.sectionhead span{font-size:10px;color:var(--muted);margin:4px 0 0}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}
.card{border:1px solid var(--line);border-radius:15px;padding:11px 10px 10px;background:linear-gradient(145deg,#142b45,#0d2035);box-shadow:0 8px 20px #0003;min-width:0;display:flex;flex-direction:column;gap:7px}
.cardtop{display:flex;align-items:center;gap:8px;min-width:0}.producticon{width:36px;height:36px;border-radius:11px;background:linear-gradient(145deg,#ead18a,#aa8133);color:#142238;display:grid;place-items:center;font-weight:900;font-size:16px;flex:0 0 36px}
.productmeta{min-width:0}.name{font-size:12px;font-weight:800;line-height:1.25;overflow-wrap:anywhere}.period{font-size:10px;color:var(--muted);margin-top:3px}
.warranty{display:inline-flex;align-self:flex-start;max-width:100%;border:1px solid #d8b45c44;background:#d8b45c12;color:#f0d893;padding:4px 6px;border-radius:99px;font-size:8px;font-weight:800;letter-spacing:.3px;line-height:1.2}
.desc{font-size:10px;line-height:1.45;color:#aebbd0;margin:0;min-height:43px;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:3;overflow:hidden}
.cardfoot{margin-top:auto;display:flex;flex-direction:column;gap:8px}.price{font-size:14px;font-weight:900;color:var(--gold2);line-height:1.2}.price small{display:block;font-size:9px;color:var(--muted);font-weight:600;margin-top:4px}
.buy{width:100%;min-height:36px;border:0;border-radius:10px;background:linear-gradient(135deg,#f2d88f,#c69d45);color:#101e2d;padding:9px 8px;font-size:11px;font-weight:900;letter-spacing:.3px;cursor:pointer}.buy:disabled{opacity:.55;cursor:not-allowed;background:#6c7885;color:#ecf1f6}
.notice{margin-top:12px;border:1px solid #ffffff18;border-radius:13px;padding:11px 12px;color:var(--muted);font-size:10px;line-height:1.55;background:#ffffff06}.notice b{color:#e9d39a}
.termsbox label{display:flex;align-items:flex-start;gap:8px;color:#e6d7b2;font-size:11px;line-height:1.45}.termsbox input{accent-color:#d8b45c;width:16px;height:16px;flex:0 0 auto;margin:0}.termsbox details{margin-top:8px}.termsbox summary{color:#f3d98e;cursor:pointer;font-weight:750;font-size:10px}.termsbox details p{margin:7px 0;color:#aebbd0}
.panel-section{scroll-margin-top:16px;margin-top:23px}.panel-heading{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:0 2px 10px}.panel-heading h2{font:23px Georgia,serif;color:#f2e3ba;margin:0}.panel-heading span{font-size:10px;color:var(--muted)}
.orderlist{display:grid;grid-template-columns:1fr;gap:8px}.orderitem{border:1px solid var(--line);border-radius:12px;background:#10243b;padding:11px 12px}.orderhead{display:flex;justify-content:space-between;gap:8px;align-items:center}.ordername{font-size:12px;font-weight:800}.orderstatus{font-size:9px;color:var(--gold2);border:1px solid var(--line);border-radius:99px;padding:5px 7px;white-space:nowrap}.ordermeta{font-size:10px;color:var(--muted);margin-top:7px;line-height:1.55;overflow-wrap:anywhere}
.supportbox{margin-top:23px}.supportbox p{margin:6px 0 8px}.supportbox textarea{width:100%;min-height:78px;resize:vertical;margin:8px 0;border:1px solid #ffffff22;border-radius:10px;background:#091a2d;color:var(--ink);padding:11px;font:inherit;font-size:11px;outline:none}.supportbox textarea:focus{border-color:var(--gold)}.supportactions{display:grid;grid-template-columns:1fr 1fr;gap:8px}.supportactions .buy{font-size:10px}.buy.secondary{background:#233a53;color:#e7d6aa;border:1px solid var(--line)}
.empty{color:var(--muted);font-size:10px;padding:7px 2px;margin:0}.footer{text-align:center;color:#78899f;font-size:9px;margin:20px 0 0;letter-spacing:.5px}
.bottomnav{position:fixed;z-index:20;left:0;right:0;bottom:0;display:grid;grid-template-columns:repeat(3,1fr);gap:5px;padding:8px 12px calc(8px + env(safe-area-inset-bottom));background:#091827ed;border-top:1px solid #ffffff16;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px)}
.navitem{border:0;background:transparent;color:#91a2b7;border-radius:12px;padding:6px 4px 5px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;font:inherit;cursor:pointer;min-height:46px}.navitem .navicon{font-size:17px;line-height:1}.navitem .navlabel{font-size:9px;font-weight:750;letter-spacing:.2px}.navitem.active{color:#f3d98e;background:#d8b45c14}
.toast{position:fixed;left:14px;right:14px;bottom:78px;margin:auto;max-width:460px;border:1px solid var(--line);background:#142940;color:#f3e2b4;padding:12px 14px;border-radius:12px;box-shadow:0 12px 30px #0009;display:none;font-size:11px;z-index:30}.toast.show{display:block}
@media(min-width:560px){main{padding:18px 18px 110px}.grid{gap:12px}.card{padding:14px}.name{font-size:14px}.desc{font-size:11px}.producticon{width:42px;height:42px;flex-basis:42px}.buy{min-height:39px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
.hero{padding:15px 13px 10px}.hero:after{display:none}
.hero-carousel{position:relative;z-index:1;margin-top:13px}
.hero-stage{position:relative;height:190px;border-radius:15px;overflow:hidden;background:#10243a;isolation:isolate}
.hero-slide{position:absolute;inset:0;display:grid;grid-template-columns:minmax(0,1.22fr) minmax(106px,.78fr);align-items:center;gap:2px;padding:15px 12px 13px;opacity:0;visibility:hidden;transform:translateX(14px);transition:opacity .55s ease,transform .55s ease,visibility .55s;pointer-events:none;overflow:hidden}
.hero-slide:before{content:'';position:absolute;width:180px;height:180px;right:-55px;top:-52px;border:1px solid #e5c87520;border-radius:50%;box-shadow:0 0 0 18px #e5c87508,0 0 0 38px #e5c87505;pointer-events:none}
.hero-slide.is-active{opacity:1;visibility:visible;transform:translateX(0);pointer-events:auto}
.hero-slide-copy{position:relative;z-index:2;min-width:0;align-self:center}
.hero-kicker{display:block;color:#e7c978;font-size:7px;font-weight:900;letter-spacing:1.1px;line-height:1.4;margin-bottom:6px}
.hero-slide-copy h2{font:500 clamp(17px,4.5vw,22px)/1.08 Georgia,serif;color:#f6e7bd;margin:0 0 7px;max-width:220px}
.hero-slide-copy p{color:#c0cbd9;font-size:9px;line-height:1.42;margin:0 0 9px;max-width:210px;position:relative;z-index:2}
.hero-cta{display:inline-flex;align-items:center;gap:7px;padding:6px 9px;border:1px solid #e6c87570;border-radius:99px;background:#d8b45c17;color:#f6dfa1;text-decoration:none;font-size:9px;font-weight:850;white-space:nowrap}
.hero-cta span{font-size:12px;line-height:1}
.hero-slide-art{position:relative;z-index:1;display:flex;align-items:center;justify-content:center;min-width:0;height:100%}
.hero-slide-art svg{display:block;width:100%;max-width:166px;height:auto;max-height:156px;overflow:visible;filter:drop-shadow(0 9px 14px #0006)}
.hero-controls{height:28px;display:flex;align-items:center;justify-content:center;gap:11px;padding-top:6px}
.hero-arrow{width:23px;height:22px;border:1px solid #d8b45c3a;border-radius:7px;background:#d8b45c10;color:#e8d18e;font-size:18px;line-height:16px;display:grid;place-items:center;padding:0;cursor:pointer}
.hero-dots{display:flex;align-items:center;justify-content:center;gap:5px}
.hero-dot{width:6px;height:6px;border:0;border-radius:99px;background:#74859b;padding:0;opacity:.65;transition:width .25s ease,opacity .25s ease,background .25s ease;cursor:pointer}
.hero-dot.is-active{width:19px;background:#e6c875;opacity:1}
.hero-count{font-size:8px;color:#98a8ba;font-weight:800;letter-spacing:.5px;min-width:31px;text-align:center}
@media(max-width:380px){.hero-stage{height:184px}.hero-slide{grid-template-columns:minmax(0,1.28fr) minmax(92px,.72fr);padding:13px 10px}.hero-slide-copy h2{font-size:17px}.hero-slide-copy p{font-size:8px}.hero-slide-art svg{max-width:128px}}
@media(min-width:560px){.hero{padding:17px}.hero-stage{height:205px}.hero-slide{padding:17px 19px}.hero-slide-copy h2{font-size:25px}.hero-slide-copy p{font-size:11px}.hero-slide-art svg{max-width:184px}}
@media(prefers-reduced-motion:reduce){.hero-slide,.hero-dot{transition:none}}
.app-page{display:none;min-height:calc(100vh - 86px);padding:8px 0 18px;scroll-margin-top:10px}
.app-page.is-active{display:block}
.page-title{margin:2px 2px 13px;padding:7px 2px 2px}
.page-title h2{font:26px Georgia,serif;color:#f2e3ba;margin:0 0 3px}
.page-title span{font-size:11px;color:var(--muted)}
.support-page .help-terms{margin:10px 0 14px;padding:14px}
.support-page .supportbox{margin:0}
.support-page .supportbox p{margin:8px 0 12px}
.support-page .termsbox label{align-items:flex-start}
.support-page .termsbox details{margin-top:12px}
#ordersPanel .panel-heading{margin:2px 2px 14px}
#ordersPanel .orderlist{margin-top:8px}
.app-page .footer{margin-top:22px}
.hero{margin:0 0 15px;padding:10px 0 12px;border:0;border-radius:0;background:transparent;overflow:visible}.hero:after{display:none}
.herohead{align-items:center;padding:8px 3px 15px;gap:8px}.brand-lockup{display:flex;align-items:center;gap:10px;min-width:0}.brand-emblem{width:40px;height:40px;flex:0 0 40px;border-radius:13px;background:linear-gradient(145deg,#17395d,#0b1b30);border:1px solid #e4c7776e;display:grid;place-items:center;box-shadow:0 5px 16px #0005}.brand-emblem svg{width:29px;height:29px}.brand-copy{min-width:0}.brand-copy .eyebrow{font-size:8px;letter-spacing:1.7px;color:#e5c16d}.hero h1{font:700 clamp(20px,5.5vw,27px)/1.04 Georgia,serif;margin:4px 0 3px;color:#f8e9bd;letter-spacing:-.3px}.brand-copy p{margin:0;color:#9fb2ca;font-size:10px;line-height:1.35;max-width:240px}.live-status{font-size:8px;padding:6px 7px;letter-spacing:.35px}
.hero-carousel{position:relative;z-index:1;margin:0}.hero-stage{position:relative;height:252px;border-radius:20px;overflow:hidden;isolation:isolate;background:radial-gradient(ellipse at 50% 80%,#124d91 0,#0b2447 40%,#06152b 78%);border:1px solid #3b7bc0a3;box-shadow:0 14px 35px #0007}.hero-stage:before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 50% 20%,#388cfa33 0,transparent 45%),linear-gradient(180deg,#04122600 60%,#1c65b6a0 100%);z-index:0}.hero-stage:after{content:'';position:absolute;left:0;right:0;bottom:0;height:34px;background:linear-gradient(180deg,transparent,#1c6bc04a);z-index:1;pointer-events:none}
.hero-slide{position:absolute;inset:0;display:block;padding:0;opacity:0;visibility:hidden;transform:translateX(15px) scale(.99);transition:opacity .5s ease,transform .5s ease,visibility .5s;pointer-events:none;overflow:hidden;background:transparent}.hero-slide.is-active{opacity:1;visibility:visible;transform:translateX(0) scale(1);pointer-events:auto}.hero-fan{position:absolute;inset:0;overflow:hidden}.hero-fan-card{position:absolute;bottom:30px;width:104px;height:151px;border-radius:13px;border:1px solid #75b9ff86;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;box-shadow:0 10px 25px #0008,inset 0 0 20px #ffffff10;opacity:.76;overflow:hidden}.hero-fan-card:after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,#ffffff18,transparent 35%,#0005)}.hero-fan-card b{font-size:48px;line-height:1;font-weight:950;text-shadow:0 4px 18px #0009;z-index:1}.hero-fan-card span{font-size:12px;font-weight:900;text-shadow:0 3px 8px #0009;z-index:1}
.fan-netflix{left:-23px;transform:perspective(500px) rotateY(24deg) rotateZ(-7deg);background:linear-gradient(145deg,#31121c,#080d1e 72%);color:#ff3045}.fan-spotify{left:12%;bottom:43px;transform:perspective(500px) rotateY(17deg) rotateZ(-4deg);background:linear-gradient(145deg,#0b4a36,#071c20);color:#20e58a}.fan-youtube{right:12%;bottom:43px;transform:perspective(500px) rotateY(-17deg) rotateZ(4deg);background:linear-gradient(145deg,#203f7b,#11152a);color:#ff3445}.fan-disney{right:-23px;transform:perspective(500px) rotateY(-24deg) rotateZ(7deg);background:linear-gradient(145deg,#103b79,#071528 72%);color:#b8d8ff}
.hero-main-card{position:absolute;z-index:2;left:11%;right:11%;top:14%;min-height:171px;border-radius:19px;border:1px solid #8ec7ffad;background:linear-gradient(145deg,#09213edb,#06152af5 65%,#172b45ed);box-shadow:0 13px 30px #0009,inset 0 1px 0 #ffffff2b,0 4px 0 #c58e35;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:12px 10px 13px}.hero-main-card:before{content:'';position:absolute;inset:5px;border:1px solid #d9b55e36;border-radius:14px;pointer-events:none}.hero-crown{font-size:31px;line-height:1;color:#ffd76b;text-shadow:0 3px 14px #ffa40080;margin-bottom:2px}.hero-main-card .hero-kicker{font-size:7px;letter-spacing:1.5px;color:#e8c36f;margin:0 0 4px}.hero-main-card h2{font:800 clamp(17px,4.6vw,23px)/1.1 Inter,system-ui,sans-serif;color:#fff;margin:0 0 7px;letter-spacing:-.5px;text-shadow:0 2px 12px #0008}.hero-main-card p{font-size:11px;line-height:1.35;color:#e9f2ff;margin:0 auto 11px;max-width:260px;font-weight:600}.hero-benefits{display:flex;justify-content:center;align-items:center;gap:5px;flex-wrap:wrap;position:relative;z-index:1}.hero-benefits span{display:inline-flex;align-items:center;gap:3px;padding:5px 7px;border:1px solid #e7c46b49;background:#d4a94316;border-radius:99px;color:#f5d884;font-size:7px;font-weight:850;white-space:nowrap}
.hero-controls{height:31px;display:flex;align-items:center;justify-content:center;gap:11px;padding-top:7px;position:relative;z-index:3}.hero-arrow{width:23px;height:23px;border:1px solid #e4c27166;border-radius:8px;background:#0c2340a8;color:#f5d98c;font-size:18px;line-height:16px;display:grid;place-items:center;padding:0;cursor:pointer}.hero-dot{width:7px;height:7px;border:0;border-radius:99px;background:#91a6c2;padding:0;opacity:.6;transition:width .25s ease,opacity .25s ease,background .25s ease;cursor:pointer}.hero-dot.is-active{width:18px;background:#ffce37;opacity:1}.hero-count{font-size:8px;color:#d2e4fa;font-weight:850;letter-spacing:.5px;min-width:31px;text-align:center}
.catalog-heading{align-items:center;margin:15px 2px 11px}.catalog-heading h2{font:700 21px Georgia,serif;letter-spacing:-.2px}.catalog-heading>div>span:last-child{display:block;margin-top:4px}.catalog-eyebrow{font-size:8px!important;letter-spacing:1.5px;color:#d9b65f!important;font-weight:850}.catalog-trust{border:1px solid #d8b45c42;border-radius:99px;padding:6px 9px;color:#e8ca7c!important;background:#d8b45c10;font-size:9px!important;font-weight:850}
.grid{gap:10px}.card.product-card{padding:8px;border-radius:16px;cursor:pointer;gap:8px;transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease;outline:none}.card.product-card:active{transform:scale(.985)}.card.product-card:focus-visible{border-color:#f0d17c;box-shadow:0 0 0 2px #e8c87555}
.live-info{display:flex;align-items:center;gap:10px;margin:16px 0 22px;padding:13px 14px;border:1px solid rgba(224,184,87,.58);border-radius:15px;background:linear-gradient(110deg,#0b1c31,#173653);box-shadow:0 5px 18px rgba(0,0,0,.18);min-height:58px}.live-info-label{flex:0 0 auto;color:#f3d17b;font-size:10px;font-weight:900;letter-spacing:1px}.live-info-text{flex:1;color:#e5edf6;font-size:12px;line-height:1.45}.live-info-count{flex:0 0 auto;color:#c7d4e5;font-size:10px;font-weight:800}.asset-art{width:100%;aspect-ratio:16/9;overflow:hidden;border-radius:16px;background:#0a1b31;border:1px solid rgba(216,181,94,.24);margin-bottom:12px}.asset-art img{width:100%;height:100%;display:block;object-fit:cover;object-position:center 42%}.asset-art-large{aspect-ratio:16/9;margin-bottom:18px}.checkout-legal{font-size:12px;line-height:1.55;color:#aebdd0;text-align:center;margin:10px 4px 0}.checkout-legal details{display:inline}.checkout-legal summary{display:inline;color:#f0d17b;font-weight:700;text-decoration:underline;cursor:pointer}.checkout-legal .terms-inline{display:block;text-align:left;margin-top:10px;padding:12px;border:1px solid rgba(216,181,94,.3);border-radius:12px;background:#10243a;color:#d9e2ee}.detail-buy{width:100%;margin-top:14px}.detail-price-under{text-align:center;color:#f4d77f;font-size:21px;font-weight:800;margin-top:8px}.product-art{height:93px;border-radius:11px;position:relative;overflow:hidden;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:0;isolation:isolate;color:#fff}.product-art:before{content:'';position:absolute;inset:0;background:repeating-linear-gradient(125deg,#ffffff0b 0 1px,transparent 1px 14px),radial-gradient(circle at 50% 45%,#ffffff20,transparent 58%);z-index:-1}.product-art:after{content:'';position:absolute;left:0;right:0;bottom:0;height:30px;background:linear-gradient(transparent,#020816a6);z-index:-1}.product-art-mark{font-size:42px;font-weight:950;line-height:.95;letter-spacing:-2px;text-shadow:0 4px 16px #0009}.product-art-word{font-size:13px;font-weight:950;letter-spacing:1.5px;text-shadow:0 3px 12px #0009}.product-art-tag{position:absolute;bottom:7px;left:9px;font-size:6px;font-weight:900;letter-spacing:1.4px;color:#ffffffbd}.art-netflix{background:linear-gradient(135deg,#3c101b,#110e20 62%,#09162a)}.art-netflix .product-art-mark{font-family:Georgia,serif;color:#f22f43;font-size:52px}.art-spotify{background:radial-gradient(circle at 50% 38%,#126c43,#062a22 65%,#061a22)}.art-spotify .product-art-mark{font-size:40px;color:#1ee58a}.art-youtube{background:linear-gradient(125deg,#102b55,#4c1523 54%,#071429)}.art-youtube .product-art-mark{font-size:38px;color:#ff4545;background:#fff;border-radius:13px;padding:0 10px 3px;text-shadow:none}.art-disney{background:radial-gradient(circle at 50% 30%,#234f91,#091c3c 68%,#071427)}.art-disney .product-art-mark{font-size:37px;color:#d6e7ff;font-family:Georgia,serif}.art-canva{background:linear-gradient(130deg,#1172bd,#5d3ca2 58%,#0f264b)}.art-canva .product-art-mark{font:italic 900 45px Georgia,serif;color:#fff}
.product-card .cardtop{align-items:flex-start}.product-card .name{font-size:11px;min-height:27px}.product-card .period{font-size:9px}.product-card .warranty{font-size:7px}.product-card .desc{font-size:9px;min-height:38px;-webkit-line-clamp:3}.product-card .cardfoot{display:flex;flex-direction:row;align-items:center;justify-content:space-between;gap:4px;margin-top:auto}.product-card .price{font-size:12px;white-space:nowrap}.detail-hint{color:#f3d88c;font-size:8px;font-weight:850;white-space:nowrap}
.product-modal{position:fixed;inset:0;z-index:60;display:flex;align-items:flex-end;justify-content:center;padding:18px 12px calc(16px + env(safe-area-inset-bottom));opacity:0;visibility:hidden;pointer-events:none;transition:opacity .2s ease,visibility .2s ease}.product-modal.is-open{opacity:1;visibility:visible;pointer-events:auto}.product-modal-backdrop{position:absolute;inset:0;background:#020914d9;border:0;padding:0;backdrop-filter:blur(7px);-webkit-backdrop-filter:blur(7px)}.product-dialog{position:relative;z-index:1;width:100%;max-width:470px;max-height:min(84vh,760px);overflow:auto;border:1px solid #d8b45c67;border-radius:22px;background:linear-gradient(155deg,#142d49,#081827 78%);box-shadow:0 22px 65px #000b;padding:15px;transform:translateY(20px);transition:transform .22s ease}.product-modal.is-open .product-dialog{transform:translateY(0)}.product-modal-close{position:absolute;right:11px;top:11px;width:32px;height:32px;border:1px solid #ffffff2b;border-radius:50%;background:#071321d9;color:#f6e8c1;font-size:22px;line-height:1;z-index:2;cursor:pointer}.product-detail-art{height:145px;margin:-2px -2px 14px;border-radius:15px;overflow:hidden}.product-detail-art .product-art{height:100%;border-radius:15px}.detail-kicker{font-size:8px;letter-spacing:1.5px;color:#e6c46c;font-weight:900}.detail-name{font:700 24px/1.1 Georgia,serif;color:#f7e8bd;margin:5px 38px 3px 0}.detail-period{font-size:11px;color:#9fb2ca}.detail-description{font-size:12px;line-height:1.6;color:#cad6e5;margin:14px 0}.detail-facts{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:12px 0 15px}.detail-fact{padding:10px;border:1px solid #ffffff1a;background:#ffffff08;border-radius:12px;min-width:0}.detail-fact small{display:block;color:#9fb0c4;font-size:8px;margin-bottom:4px}.detail-fact strong{font-size:12px;color:#f5d98a;overflow-wrap:anywhere}.detail-manual{font-size:10px;line-height:1.45;color:#aabbd0;margin:10px 0 14px}.detail-benefit-art{margin:10px 0 13px;border:1px solid rgba(216,181,94,.24);border-radius:12px;overflow:hidden;background:#0a1b31}.detail-benefit-art img{width:100%;height:auto;display:block}.detail-buy{width:100%;min-height:45px;font-size:12px;border-radius:12px}.detail-buy:disabled{opacity:.6}.modal-open{overflow:hidden}
@media(min-width:560px){.hero-stage{height:285px}.hero-main-card{left:15%;right:15%;top:16%;min-height:190px}.hero-fan-card{width:125px;height:180px;bottom:38px}.product-art{height:112px}.product-card .name{font-size:13px}.product-card .price{font-size:14px}.detail-facts{grid-template-columns:repeat(3,1fr)}.product-modal{align-items:center}}@media(max-width:380px){.brand-emblem{width:35px;height:35px;flex-basis:35px}.brand-copy p{font-size:9px}.hero-stage{height:232px}.hero-main-card{left:8%;right:8%;top:15%;min-height:166px;padding:10px 7px}.hero-main-card h2{font-size:18px}.hero-main-card p{font-size:10px}.hero-benefits span{font-size:6px;padding:4px 5px}.hero-fan-card{width:84px;height:128px;bottom:28px}.fan-spotify{left:8%}.fan-youtube{right:8%}.product-art{height:82px}.card.product-card{padding:7px}.detail-hint{font-size:7px}}@media(prefers-reduced-motion:reduce){.hero-slide,.product-modal,.product-dialog,.card.product-card{transition:none}}
/* JKT Stars Stores - purple/blue premium storefront */
:root{--gold:#b66cff;--gold2:#e4c4ff;--ink:#f5f1ff;--muted:#a8a0c5;--line:rgba(164,105,255,.30)}
body{background:radial-gradient(ellipse at 88% -8%,#3b1769 0,transparent 42%),radial-gradient(ellipse at 5% 40%,#102d68 0,transparent 44%),linear-gradient(180deg,#080713,#0d0a1b 62%,#080713);color:var(--ink)}
.brand-emblem{background:linear-gradient(145deg,#8b2ce8,#153ea8);border:1px solid #dcb5ff8a;box-shadow:0 0 20px #822ce866}
.hero h1{color:#fff}.hero-stage{background:radial-gradient(ellipse at 50% 80%,#7924d0 0,#21104c 45%,#090d24 82%);border:1px solid #8d3ff0;box-shadow:0 14px 35px #0008,0 0 22px #7223c44d}
.hero-stage:before{background:radial-gradient(ellipse at 50% 20%,#b45dff38 0,transparent 48%),linear-gradient(180deg,#04122600 55%,#5221a7a8 100%)}
.hero-stage:after{background:linear-gradient(180deg,transparent,#6021bd65)}
.hero-main-card{border-color:#c78aff;background:linear-gradient(145deg,#32106cf0,#0c1639f5 68%,#1c1d65f0);box-shadow:0 13px 30px #0009,inset 0 1px 0 #ffffff2b,0 4px 0 #2867e9}
.hero-main-card:before{border-color:#d9b5ff5e}.hero-main-card h2{color:#fff}.hero-main-card p{color:#e6d8ff}
.hero-benefits span{border-color:#c17aff70;background:#a342ff26;color:#f1dfff}.hero-arrow{border-color:#ad72f4;color:#e6c9ff;background:#32145d}.hero-dot.is-active{background:#d28aff}
.live-info{border-color:#7845bb;background:linear-gradient(110deg,#140c2c,#25114a);box-shadow:0 5px 18px #0005}.live-info-label,.catalog-eyebrow{color:#d7a6ff}.live-info-text{color:#e8defe}
.catalog-trust{border-color:#a65be9;background:#8d3be821;color:#e8ccff!important}.card,.orderitem{border-color:#69439c;background:linear-gradient(145deg,#1d1537,#101a38);box-shadow:0 8px 22px #0005}
.product-art{background:#170f2e}.warranty{border-color:#a65be966;background:#8d3be81c;color:#e6c7ff}.price,.detail-price-under{color:#e0b2ff}
.buy{background:linear-gradient(120deg,#c02cff,#573bff 58%,#168cf5);color:#fff;box-shadow:0 7px 18px #682ce64d}.buy:disabled{background:#55516c;color:#dad6e7;box-shadow:none}.buy.secondary{background:#21183b;color:#e8d5ff;border:1px solid #8655be}
.navitem.active{color:#fff;background:linear-gradient(135deg,#8d28db,#254ee5);box-shadow:0 4px 16px #6c28c65c}.navitem{color:#b5a7d1}.bottomnav{background:#0c0a1bed;border-top-color:#8b54bb55}
.toast{background:#21143c;border-color:#8956bf;color:#f4e5ff}.product-dialog{border-color:#9a5dd2;background:linear-gradient(155deg,#241345,#0b1027 78%)}
.detail-fact{background:#ffffff09;border-color:#ffffff20}.detail-fact strong,.detail-kicker,.checkout-legal summary{color:#e1b6ff}
.welcome-line{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:13px 2px 16px}.welcome-line h2{margin:0;color:#fff;font-size:22px;font-weight:850;letter-spacing:-.45px}.welcome-line p{margin:4px 0 0;color:#bdb2d7;font-size:11px}
.welcome-pill{flex:0 0 auto;border:1px solid #9e5bdc;border-radius:99px;background:#8129cf25;color:#edcfff;padding:7px 9px;font-size:8px;font-weight:850;letter-spacing:.5px}
.category-section,.popular-section{margin:17px 0 20px}.category-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.category-tile{display:flex;align-items:center;gap:10px;min-height:88px;padding:13px;border:1px solid #8447cb;border-radius:17px;background:linear-gradient(135deg,#401075,#171a50 72%,#101d49);color:#fff;text-align:left;cursor:pointer;box-shadow:0 9px 22px #0005}
.category-tile:nth-child(2){background:linear-gradient(135deg,#21166c,#191b50 66%,#0f2d67);border-color:#4d63dc}.category-tile:active{transform:scale(.985)}.category-emoji{font-size:29px;line-height:1}
.category-tile strong{display:block;font-size:14px;font-weight:850}.category-tile small{display:block;color:#c4b8e4;font-size:9px;margin-top:4px}
.section-link{border:0;background:transparent;color:#bca0ff;font-size:10px;font-weight:850;cursor:pointer;padding:6px 0}
.featured-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.featured-item{display:flex;align-items:center;gap:9px;min-width:0;padding:10px;border:1px solid #5c438e;border-radius:14px;background:linear-gradient(145deg,#1a1534,#111933);color:#fff;text-align:left;cursor:pointer}
.featured-logo{width:43px;height:43px;flex:0 0 43px;border-radius:12px;background:#0a1025;display:grid;place-items:center;padding:9px}.featured-logo img{width:100%;height:100%;object-fit:contain}.featured-copy{min-width:0}
.featured-copy strong{display:block;font-size:10px;line-height:1.25;overflow-wrap:anywhere}.featured-copy small{display:block;color:#b5a8d4;font-size:8px;margin-top:4px}
.brand-art{display:flex;align-items:center;justify-content:center;flex-direction:row;gap:10px;padding:13px;background:radial-gradient(circle at 50% 20%,#472080,#10152f 75%);border:1px solid #8151bd55}.brand-art img{width:48px;height:48px;object-fit:contain;filter:drop-shadow(0 3px 12px #0009)}.brand-art.brand-art-large img{width:65px;height:65px}.brand-art span{font-size:11px;font-weight:850;letter-spacing:.3px}
.generic-brand-icon{display:grid;place-items:center;width:48px;height:48px;border-radius:12px;background:linear-gradient(145deg,#54208a,#172d68);color:#e9c7ff;font-size:29px;line-height:1;flex:0 0 48px}
.brand-art-large .generic-brand-icon{width:65px;height:65px;flex-basis:65px;font-size:36px}
.featured-logo .generic-brand-icon{width:32px;height:32px;flex-basis:32px;font-size:20px;border-radius:9px}
.account-profile{margin:10px 0 15px;padding:14px;border-color:#8450b8;background:linear-gradient(135deg,#21143d,#111a38)}
.account-profile strong{display:block;color:#f2ddff;font-size:15px;margin:5px 2px 4px}
.account-profile .panel-heading{margin:0 0 8px}.account-profile .panel-heading h2{font-size:16px}
.account-profile p{margin:0}
.catalog-page-title{margin:5px 2px 14px}.catalog-page-title h2{margin:0 0 4px;color:#fff;font-size:24px}.catalog-page-title p{margin:0;color:#b9afd2;font-size:10px}
.category-filters{display:flex;gap:7px;overflow-x:auto;padding:2px 1px 12px;scrollbar-width:none}.category-filters::-webkit-scrollbar{display:none}
.category-filter{flex:0 0 auto;border:1px solid #64448e;border-radius:99px;background:#17132c;color:#c4b8df;padding:8px 12px;font-size:10px;font-weight:800;cursor:pointer}.category-filter.active{background:linear-gradient(120deg,#8f2ee0,#3056e7);border-color:#b67aff;color:#fff}
.bottomnav{grid-template-columns:repeat(4,minmax(0,1fr))}@media(max-width:380px){.welcome-line h2{font-size:19px}.welcome-pill{font-size:7px;padding:6px 7px}.category-tile{padding:10px;min-height:82px}.featured-item{padding:8px}.featured-logo{width:38px;height:38px;flex-basis:38px}}

/* Final reference match: dark premium violet + electric blue */
:root{color-scheme:dark;--gold:#c28aff;--gold2:#e4c4ff;--ink:#f7f3ff;--muted:#b7acd0;--line:rgba(165,112,255,.32)}
body{background:radial-gradient(ellipse at 88% -8%,#4b1b80 0,transparent 39%),radial-gradient(ellipse at 8% 28%,#102d68 0,transparent 40%),linear-gradient(180deg,#080713 0%,#100a21 58%,#080713 100%);color:#f7f3ff}
main{max-width:640px;padding:12px 12px calc(100px + env(safe-area-inset-bottom))}
.brand-emblem{background:linear-gradient(145deg,#9a35eb,#2454dd)!important;border:1px solid #d9b5ff9c!important;box-shadow:0 0 22px #842fe766!important}
.brand-copy .eyebrow,.eyebrow{color:#d8a6ff!important}
.hero h1{color:#fff!important}
.live-status{color:#d9c5ff!important;border-color:#9361d9!important;background:#8634d428!important}
.hero-stage{height:258px!important;border:1px solid #884ee5!important;background:radial-gradient(ellipse at 50% 78%,#6f29bf 0,#28134f 46%,#090d23 84%)!important;box-shadow:0 16px 36px #0009,0 0 24px #7428c24d!important}
.hero-stage:before{background:radial-gradient(ellipse at 50% 18%,#bd77ff39 0,transparent 48%),linear-gradient(180deg,#07142b00 54%,#5723a5a8 100%)!important}
.hero-stage:after{background:linear-gradient(180deg,transparent,#4b25a96b)!important}
.hero-slide:before{border-color:#bc83ff25!important;box-shadow:0 0 0 18px #a04bff0b,0 0 0 38px #2f71ff0a!important}
.hero-fan-card{border-color:#a977ef9c!important;box-shadow:0 10px 26px #0009,inset 0 0 22px #ffffff12!important}
.fan-netflix{background:linear-gradient(145deg,#4a102d,#14102e 72%)!important;color:#ff526d!important}
.fan-spotify{background:linear-gradient(145deg,#12553e,#101b38)!important;color:#50e99a!important}
.fan-youtube{background:linear-gradient(145deg,#263a87,#17112f)!important;color:#ff5b79!important}
.fan-disney{background:linear-gradient(145deg,#243f9a,#12102e 72%)!important;color:#c7baff!important}
.hero-main-card{left:10%!important;right:10%!important;top:8%!important;bottom:8%!important;min-height:0!important;border:1px solid #c08aff!important;background:linear-gradient(145deg,#34106cf2,#10163ff7 66%,#1d236bf2)!important;box-shadow:0 14px 32px #000a,inset 0 1px 0 #ffffff35,0 4px 0 #2867e9!important;padding:10px 9px!important}
.hero-main-card:before{border-color:#d9b5ff55!important}
.hero-crown{color:#e6c5ff!important;text-shadow:0 3px 16px #8d35e5a8!important}
.hero-main-card .hero-kicker{color:#d8a6ff!important}
.hero-main-card h2{color:#fff!important;text-shadow:0 2px 14px #000a!important}
.hero-main-card p{color:#e8defe!important}
.hero-benefits span{border-color:#bd88ff78!important;background:#9b46f52b!important;color:#f0dcff!important}
.hero-cta-button{position:relative;z-index:2;display:inline-flex;align-items:center;justify-content:center;gap:9px;min-height:29px;margin-top:9px;padding:7px 14px;border:1px solid #d8b6ff;border-radius:999px;background:linear-gradient(110deg,#b62de8,#6139ef 58%,#168cf5);color:#fff;font-size:9px;font-weight:950;letter-spacing:.7px;box-shadow:0 5px 17px #5d2dca75;cursor:pointer}
.hero-cta-button span{font-size:13px;line-height:1}
.hero-controls{height:31px!important}
.hero-arrow{border-color:#9e72da!important;background:#261447!important;color:#ead6ff!important}
.hero-dot{background:#75658f!important}.hero-dot.is-active{background:#cf8cff!important}.hero-count{color:#d6c4ef!important}
.live-info{border-color:#8052bd!important;background:linear-gradient(110deg,#170d2c,#28134d)!important;box-shadow:0 6px 20px #0007!important;margin:13px 0 17px!important;min-height:54px!important;padding:11px 13px!important}
.live-info-label,.catalog-eyebrow{color:#d7a6ff!important}.live-info-text{color:#eee4ff!important}.live-info-count{color:#cdb9eb!important}
.welcome-line{margin:12px 2px 15px!important}.welcome-line h2{color:#fff!important}.welcome-line p{color:#c3b5dd!important}
.welcome-pill{border-color:#a86be5!important;background:#792ac62a!important;color:#ead5ff!important}
.sectionhead h2,.panel-heading h2,.page-title h2{color:#fff!important}.catalog-heading h2{color:#fff!important}
.catalog-trust{border-color:#9c65da!important;background:#842ece24!important;color:#e8d3ff!important}
.category-section,.popular-section{margin:16px 0 19px!important}
.category-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.category-tile{position:relative;display:flex;flex-direction:column;align-items:flex-start;justify-content:space-between;gap:10px;min-height:128px;padding:13px!important;border:1px solid #8750ca!important;border-radius:17px!important;background:linear-gradient(145deg,#3c126f 0%,#1a174e 64%,#101e50 100%)!important;color:#fff!important;text-align:left;box-shadow:0 10px 24px #0007,inset 0 1px 0 #ffffff15!important;overflow:hidden}
.category-tile:after{content:"";position:absolute;width:100px;height:100px;right:-34px;top:-42px;border:1px solid #c393ff25;border-radius:50%;box-shadow:0 0 0 14px #bb7aff0b,0 0 0 28px #bb7aff08;pointer-events:none}
.category-tile:nth-child(2){background:linear-gradient(145deg,#21176e 0%,#1a1b58 63%,#0d2d67 100%)!important;border-color:#5267d7!important}
.category-tile:active{transform:scale(.985)}
.category-logos{display:flex;align-items:center;gap:7px;min-height:30px}
.category-logos img{display:block;width:24px;height:24px;object-fit:contain;filter:drop-shadow(0 2px 6px #0008)}
.category-copy{display:block;max-width:88%;position:relative;z-index:1}
.category-copy strong{display:block;color:#fff;font-size:14px;font-weight:900;letter-spacing:.1px}
.category-copy small{display:block;color:#d0c1ed;font-size:9px;margin-top:4px}
.category-arrow{position:absolute;right:13px;bottom:13px;color:#e3c7ff;font-size:19px;font-weight:900}
.section-link{color:#d2a8ff!important}
.featured-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}
.featured-item{border-color:#69499d!important;background:linear-gradient(145deg,#21143d,#111a3d)!important;box-shadow:0 8px 20px #0006,inset 0 1px 0 #ffffff0d!important}
.featured-logo{background:#0b1029!important;border:1px solid #65459e55}
.featured-copy strong{color:#f8f2ff!important}.featured-copy small{color:#c0b1dc!important}
.card,.orderitem{border-color:#69499b!important;background:linear-gradient(145deg,#211637,#111a3b)!important}
.card.product-card{box-shadow:0 8px 22px #0007!important}
.asset-art{background:#130d2a!important;border-color:#8152c36b!important}
.brand-art{background:radial-gradient(circle at 50% 20%,#45217b,#10152f 75%)!important;border-color:#8959c56b!important}
.brand-art img{width:52px!important;height:52px!important;max-width:52px!important;max-height:52px!important;object-fit:contain!important;filter:drop-shadow(0 3px 12px #0009)}
.brand-art span{color:#f2e7ff!important;font-size:10px!important;font-weight:850!important;letter-spacing:.15px!important}
.generic-brand-icon{background:linear-gradient(145deg,#6d2eaa,#1e428e)!important;color:#f1dfff!important}
.warranty{border-color:#9a66ce88!important;background:#8a38cf28!important;color:#e7d1ff!important}
.price,.detail-price-under{color:#e4c4ff!important}
.buy{background:linear-gradient(110deg,#b62de8,#633af0 58%,#168cf5)!important;color:#fff!important;box-shadow:0 7px 19px #672fe866!important}
.buy:disabled{background:#514b68!important;color:#d5cee4!important;box-shadow:none!important}
.buy.secondary{background:#24183e!important;color:#e8d5ff!important;border:1px solid #805ab0!important}
.navitem{color:#c5b8dc!important}.navitem.active{color:#fff!important;background:linear-gradient(135deg,#9129df,#3155e6)!important;box-shadow:0 4px 16px #6c28c65c!important}
.bottomnav{grid-template-columns:repeat(4,minmax(0,1fr))!important;background:#0c091bee!important;border-top:1px solid #8b54bb66!important}
.brand-icon-strip{display:flex;align-items:center;gap:15px;min-height:42px;margin:12px 2px 14px;padding:3px 2px;overflow-x:auto;overscroll-behavior-x:contain;scrollbar-width:none}
.brand-icon-strip::-webkit-scrollbar{display:none}
.brand-icon-strip img{display:block;width:32px;height:32px;min-width:32px;object-fit:contain;filter:drop-shadow(0 3px 8px #0008)}
.navicon{display:grid;place-items:center;width:22px;height:22px}
.navicon svg{display:block;width:21px;height:21px;overflow:visible}
.navitem.active .navicon svg{filter:drop-shadow(0 1px 4px #d5a4ff55)}
@media(max-width:380px){.brand-icon-strip{gap:15px;margin-top:10px;margin-bottom:12px}.brand-icon-strip img{width:32px;height:32px;min-width:32px}}
.toast{background:#21143c!important;border-color:#8956bf!important;color:#f4e5ff!important}
.product-dialog{border-color:#9a5dd2!important;background:linear-gradient(155deg,#241345,#0b1027 78%)!important}
.detail-fact{background:#ffffff09!important;border-color:#ffffff20!important}
.detail-fact strong,.detail-kicker,.checkout-legal summary{color:#e1b6ff!important}
.detail-manual,.detail-period,.detail-description{color:#cbbde4!important}
.detail-benefit-art{border-color:#8959c56b!important;background:#130d2a!important}
.termsbox label{color:#e9d9ff!important}.termsbox input{accent-color:#a64bed!important}.termsbox summary{color:#d8a6ff!important}
.account-profile{border-color:#8450b8!important;background:linear-gradient(135deg,#21143d,#111a38)!important}
.catalog-page-title h2{color:#fff!important}.category-filter{border-color:#69499b!important;background:#17132d!important;color:#cabce3!important}
.category-filter.active{background:linear-gradient(120deg,#8f2ee0,#3056e7)!important;border-color:#bd87ff!important;color:#fff!important}
@media(max-width:380px){
 .hero-stage{height:246px!important}.hero-main-card{left:7%!important;right:7%!important;top:6%!important;bottom:6%!important;padding:8px 7px!important}
 .hero-crown{font-size:26px!important}.hero-main-card h2{font-size:17px!important}.hero-main-card p{font-size:9px!important;margin-bottom:7px!important}
 .hero-benefits{gap:4px!important}.hero-benefits span{font-size:6px!important;padding:4px 5px!important}
 .hero-cta-button{min-height:26px;margin-top:7px;font-size:8px;padding:6px 11px}
 .category-tile{min-height:120px;padding:10px!important}.category-logos{gap:5px}.category-logos img{width:21px;height:21px}
 .category-copy strong{font-size:13px}.featured-item{padding:8px!important}
}
</style>
</head>
<body><main>
<div class="app-page is-active" id="homePage">
<section class="hero" id="home">
 <div class="herohead"><div class="brand-lockup"><div class="brand-emblem" aria-hidden="true"><svg viewBox="0 0 48 48"><path d="M24 4l4 5h-8z" fill="#f4d77f"/><path d="M20 10h8l-2 5v19h-4V15z" fill="#f4d77f"/><path d="M16 34h16l4 5H12z" fill="#d5a94f"/><path d="M8 23l4 3 2-5 3 4 3-3 4 4 4-4 3 3 3-4 2 5 4-3-2 11H10z" fill="none" stroke="#f4d77f" stroke-width="1.5"/><path d="M24 2l1 2 2 .3-1.5 1.5.4 2.2L24 7l-1.9 1 .4-2.2L21 4.3l2-.3z" fill="#fff0ac"/></svg></div><div class="brand-copy"><div class="eyebrow">JAKARTA · TELEGRAM STARS</div><h1>JKT Stars Stores</h1><p>Toko digital dengan pembayaran Telegram Stars</p></div></div><span class="live-status" id="mode">KATALOG AKTIF</span></div>
 <div class="brand-icon-strip" aria-label="Layanan populer">
  <img src="https://cdn.simpleicons.org/spotify" alt="Spotify" width="32" height="32" loading="eager" decoding="async">
  <img src="https://cdn.simpleicons.org/youtube" alt="YouTube" width="32" height="32" loading="eager" decoding="async">
  <img src="https://cdn.simpleicons.org/crunchyroll" alt="Crunchyroll" width="32" height="32" loading="eager" decoding="async">
 </div>
 <div class="hero-carousel" id="heroCarousel" aria-label="Banner JKT Stars Stores"><div class="hero-stage"><article class="hero-slide is-active" data-hero-slide="0" aria-hidden="false"><div class="hero-fan" aria-hidden="true"><div class="hero-fan-card fan-netflix"><b>N</b><span>NETFLIX</span></div><div class="hero-fan-card fan-spotify"><b>◉</b><span>Spotify</span></div><div class="hero-fan-card fan-youtube"><b>▶</b><span>YouTube</span></div><div class="hero-fan-card fan-disney"><b>✦</b><span>Disney+</span></div></div><div class="hero-main-card"><div class="hero-crown" aria-hidden="true">♛</div><span class="hero-kicker">PREMIUM DIGITAL ACCESS</span><h2>JKT Stars Stores</h2><p>Streaming &amp; Music Premium melalui Telegram Stars</p><div class="hero-benefits"><span>✦ Pembayaran XTR</span><span>⚡ Pemenuhan Manual</span><span>✓ Bantuan Admin</span></div><button class="hero-cta-button" type="button" data-open-catalog>JELAJAHI KATALOG <span>↗</span></button></div></article>
<article class="hero-slide " data-hero-slide="1" aria-hidden="true"><div class="hero-fan" aria-hidden="true"><div class="hero-fan-card fan-netflix"><b>N</b><span>NETFLIX</span></div><div class="hero-fan-card fan-spotify"><b>◉</b><span>Spotify</span></div><div class="hero-fan-card fan-youtube"><b>▶</b><span>YouTube</span></div><div class="hero-fan-card fan-disney"><b>✦</b><span>Disney+</span></div></div><div class="hero-main-card"><div class="hero-crown" aria-hidden="true">♛</div><span class="hero-kicker">STREAMING · ENTERTAINMENT</span><h2>Hiburan Premium</h2><p>Pilihan streaming untuk menemani waktu terbaik Anda.</p><div class="hero-benefits"><span>▣ Pilihan Streaming</span><span>✦ Paket Digital</span><span>✓ Detail Transparan</span></div><button class="hero-cta-button" type="button" data-open-catalog>JELAJAHI KATALOG <span>↗</span></button></div></article>
<article class="hero-slide " data-hero-slide="2" aria-hidden="true"><div class="hero-fan" aria-hidden="true"><div class="hero-fan-card fan-netflix"><b>N</b><span>NETFLIX</span></div><div class="hero-fan-card fan-spotify"><b>◉</b><span>Spotify</span></div><div class="hero-fan-card fan-youtube"><b>▶</b><span>YouTube</span></div><div class="hero-fan-card fan-disney"><b>✦</b><span>Disney+</span></div></div><div class="hero-main-card"><div class="hero-crown" aria-hidden="true">♛</div><span class="hero-kicker">MUSIC · CREATIVITY</span><h2>Musik &amp; Kreativitas</h2><p>Layanan digital untuk hiburan dan produktivitas harian.</p><div class="hero-benefits"><span>♫ Musik Premium</span><span>✎ Kreativitas</span><span>⚡ Praktis</span></div><button class="hero-cta-button" type="button" data-open-catalog>JELAJAHI KATALOG <span>↗</span></button></div></article>
<article class="hero-slide " data-hero-slide="3" aria-hidden="true"><div class="hero-fan" aria-hidden="true"><div class="hero-fan-card fan-netflix"><b>N</b><span>NETFLIX</span></div><div class="hero-fan-card fan-spotify"><b>◉</b><span>Spotify</span></div><div class="hero-fan-card fan-youtube"><b>▶</b><span>YouTube</span></div><div class="hero-fan-card fan-disney"><b>✦</b><span>Disney+</span></div></div><div class="hero-main-card"><div class="hero-crown" aria-hidden="true">♛</div><span class="hero-kicker">PILIHAN LAYANAN DIGITAL</span><h2>Temukan Favorit Anda</h2><p>Jelajahi katalog dan lihat detail setiap produk sebelum membeli.</p><div class="hero-benefits"><span>▦ 5 Produk Aktif</span><span>◉ Detail Produk</span><span>✓ Bantuan Admin</span></div><button class="hero-cta-button" type="button" data-open-catalog>JELAJAHI KATALOG <span>↗</span></button></div></article>
<article class="hero-slide " data-hero-slide="4" aria-hidden="true"><div class="hero-fan" aria-hidden="true"><div class="hero-fan-card fan-netflix"><b>N</b><span>NETFLIX</span></div><div class="hero-fan-card fan-spotify"><b>◉</b><span>Spotify</span></div><div class="hero-fan-card fan-youtube"><b>▶</b><span>YouTube</span></div><div class="hero-fan-card fan-disney"><b>✦</b><span>Disney+</span></div></div><div class="hero-main-card"><div class="hero-crown" aria-hidden="true">♛</div><span class="hero-kicker">ORDER MELALUI TELEGRAM</span><h2>Praktis dengan Stars</h2><p>Pilih layanan, periksa detailnya, lalu lanjutkan melalui Telegram Stars.</p><div class="hero-benefits"><span>★ 250 XTR</span><span>⌁ Checkout Telegram</span><span>✓ Pemenuhan Manual</span></div><button class="hero-cta-button" type="button" data-open-catalog>JELAJAHI KATALOG <span>↗</span></button></div></article></div><div class="hero-controls"><button class="hero-arrow" type="button" data-hero-prev aria-label="Banner sebelumnya">‹</button><div class="hero-dots" aria-label="Pilih banner"><button class="hero-dot is-active" type="button" data-hero-dot="0" aria-label="Banner 1"></button><button class="hero-dot" type="button" data-hero-dot="1" aria-label="Banner 2"></button><button class="hero-dot" type="button" data-hero-dot="2" aria-label="Banner 3"></button><button class="hero-dot" type="button" data-hero-dot="3" aria-label="Banner 4"></button><button class="hero-dot" type="button" data-hero-dot="4" aria-label="Banner 5"></button></div><span class="hero-count" id="heroCount">01 / 05</span><button class="hero-arrow" type="button" data-hero-next aria-label="Banner berikutnya">›</button></div></div>
</section>
<section class="live-info" aria-live="polite"><span class="live-info-label">INFO TOKO</span><span class="live-info-text" id="liveInfoText">Pembayaran menggunakan Telegram Stars (XTR).</span><span class="live-info-count" id="liveInfoCount">1 / 5</span></section>
<section class="welcome-line"><div><h2>Hai, <span id="greetingName">Sobat</span> 👋</h2><p>Pilih layanan digital favoritmu</p></div><span class="welcome-pill">JKT STARS STORES</span></section>
<section class="category-section"><div class="sectionhead"><div><span class="catalog-eyebrow">JELAJAHI LAYANAN</span><h2>Kategori</h2><span>Streaming dan musik premium</span></div></div><div class="category-grid">
<button class="category-tile" type="button" data-category-select="streaming"><span class="category-logos" aria-hidden="true"><img src="https://cdn.simpleicons.org/netflix" alt="" loading="lazy"><img src="https://cdn.simpleicons.org/crunchyroll" alt="" loading="lazy"><img src="https://cdn.simpleicons.org/appletv" alt="" loading="lazy"><img src="https://cdn.simpleicons.org/bilibili" alt="" loading="lazy"></span><span class="category-copy"><strong>Streaming</strong><small>Film, serial &amp; hiburan</small></span><span class="category-arrow" aria-hidden="true">↗</span></button>
<button class="category-tile" type="button" data-category-select="music"><span class="category-logos" aria-hidden="true"><img src="https://cdn.simpleicons.org/spotify" alt="" loading="lazy"><img src="https://cdn.simpleicons.org/youtubemusic" alt="" loading="lazy"><img src="https://cdn.simpleicons.org/applemusic" alt="" loading="lazy"><img src="https://cdn.simpleicons.org/deezer" alt="" loading="lazy"></span><span class="category-copy"><strong>Music</strong><small>Musik dan audio premium</small></span><span class="category-arrow" aria-hidden="true">↗</span></button></div></section>
<section class="popular-section"><div class="sectionhead catalog-heading"><div><span class="catalog-eyebrow">PILIHAN LAYANAN</span><h2>Produk Pilihan</h2><span>Lihat layanan yang tersedia</span></div><button class="section-link" type="button" data-open-catalog>Lihat Semua →</button></div><div class="featured-grid" id="featuredProducts"><article class="featured-item"><span class="featured-copy"><strong>Memuat produk...</strong></span></article></div></section>
</div>
<section class="app-page" id="catalogPanel"><div class="catalog-page-title"><h2>Katalog Produk</h2><p>Pilih layanan Streaming atau Music favoritmu</p></div>
<div class="category-filters" id="categoryFilters"><button class="category-filter active" type="button" data-category-filter="all">Semua</button><button class="category-filter" type="button" data-category-filter="streaming">Streaming</button><button class="category-filter" type="button" data-category-filter="music">Music</button></div>
<div class="sectionhead catalog-heading"><div><span class="catalog-eyebrow">KATALOG AKTIF</span><h2>Semua Produk</h2><span>Ketuk produk untuk melihat detail</span></div><span class="catalog-trust">✦ Telegram Stars</span></div>
<section class="grid" id="products"><article class="card"><div class="desc">Memuat katalog...</div></article></section></section>

<section class="app-page" id="ordersPanel">
 <div class="panel-heading"><div><h2>Pesanan</h2><span>Riwayat transaksi dan akses Anda</span></div><button class="buy" type="button" id="refreshOrders" style="width:auto;min-height:32px;padding:7px 10px">Perbarui</button></div>
 <section class="orderlist" id="orders"><p class="empty">Buka toko melalui Telegram untuk melihat pesanan Anda.</p></section>
</section>
<section class="app-page support-page" id="accountPanel">
 <div class="panel-heading page-title"><div><h2>Akun</h2><span>Profil Telegram, bantuan, dan informasi toko</span></div></div>
 <section class="notice account-profile">
  <div class="panel-heading"><div><h2>Profil Telegram</h2><span>Terhubung melalui Telegram</span></div><span class="welcome-pill">AKTIF</span></div>
  <strong id="accountName">Akun Telegram Anda</strong>
  <p class="empty">Pesanan dan bantuan dikelola melalui akun Telegram yang sedang digunakan.</p>
 </section>
 <section class="notice termsbox help-terms">
  <label><input type="checkbox" id="termsAgree"> Saya telah membaca dan menyetujui <b>Syarat &amp; Ketentuan</b>.</label>
  <details><summary>Lihat Syarat &amp; Ketentuan</summary>
   <p>1. Pesanan diproses setelah pembayaran Telegram terkonfirmasi dan masuk pemeriksaan kualitas sebelum akses dikirim.</p>
   <p>2. Jangan membagikan detail login atau akses akun kepada pihak lain.</p>
   <p>3. Klaim garansi diajukan melalui Bantuan Pesanan dengan Order ID dan penjelasan kendala.</p>
   <p>4. Harga dan masa akses mengikuti keterangan produk saat dipesan.</p>
   <p>5. Permintaan bantuan dan refund ditinjau sesuai ketentuan layanan dan aturan Telegram. Untuk kendala pembayaran, gunakan Bantuan Pesanan.</p>
  </details>
 </section>
 <section class="notice supportbox">
 <div class="panel-heading"><div><h2>Bantuan Pesanan</h2><span>Admin JKT Stars Stores</span></div></div>
 <p class="empty">Kirim tiket dengan mencantumkan Order ID dan kendala yang dialami, atau hubungi bot layanan.</p>
 <textarea id="supportMessage" maxlength="1500" placeholder="Contoh: Order ID ... / Kendala ..."></textarea>
 <div class="supportactions"><button class="buy" type="button" id="sendSupport">Kirim Tiket</button><button class="buy secondary" type="button" id="chatBot">Chat Admin</button></div>
 </section>
</section>
<div class="footer">JKT STARS STORES · PEMENUHAN MANUAL</div>
</main>
<div class="product-modal" id="productModal" aria-hidden="true"><button class="product-modal-backdrop" type="button" data-close-product aria-label="Tutup detail produk"></button><section class="product-dialog" role="dialog" aria-modal="true" aria-labelledby="productDetailName"><button class="product-modal-close" type="button" id="closeProductModal" aria-label="Tutup">×</button><div id="productDetailContent"></div></section></div>
<nav class="bottomnav" aria-label="Navigasi utama">
<button class="navitem active" type="button" data-target="homePage"><span class="navicon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m3 10 9-7 9 7"/><path d="M5 9v11h14V9M9 20v-6h6v6"/></svg></span><span class="navlabel">Beranda</span></button>
<button class="navitem" type="button" data-target="catalogPanel"><span class="navicon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg></span><span class="navlabel">Katalog</span></button>
<button class="navitem" type="button" data-target="ordersPanel"><span class="navicon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 3h8l4 4v14H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/><path d="M15 3v5h5M9 13h6M9 17h6"/></svg></span><span class="navlabel">Pesanan</span></button>
<button class="navitem" type="button" data-target="accountPanel"><span class="navicon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg></span><span class="navlabel">Akun</span></button></nav>
<div class="toast" id="toast"></div>
<script>(function(){
'use strict';
var tg=null,initData='',box=document.getElementById('products'),featuredBox=document.getElementById('featuredProducts'),termsAgree=document.getElementById('termsAgree'),orderBox=document.getElementById('orders'),supportInput=document.getElementById('supportMessage'),sendSupport=document.getElementById('sendSupport'),navItems=Array.prototype.slice.call(document.querySelectorAll('.navitem')),catalog=[],paymentsReady=false,checkoutBusy=false,toastTimer=null,currentCategory='all';
var liveInfoItems=['Pembayaran menggunakan Telegram Stars (XTR).','Harga produk ditampilkan sebelum Anda membayar.','Pesanan diproses setelah pembayaran dikonfirmasi Telegram.','Pengiriman akses dilakukan secara manual oleh admin.','Periksa perkembangan transaksi melalui menu Pesanan.'];var liveInfoIndex=0;function rotateLiveInfo(){var text=document.getElementById('liveInfoText'),count=document.getElementById('liveInfoCount');if(text)text.textContent=liveInfoItems[liveInfoIndex];if(count)count.textContent=(liveInfoIndex+1)+' / '+liveInfoItems.length;liveInfoIndex=(liveInfoIndex+1)%liveInfoItems.length;}
function toast(message){var el=document.getElementById('toast');if(!el)return;el.textContent=message;el.classList.add('show');if(toastTimer)clearTimeout(toastTimer);toastTimer=setTimeout(function(){el.classList.remove('show');},4200);}
function escapeHtml(value){return String(value==null?'':value).replace(/[&<>]/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':'&gt;';}).replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function stars(value){var n=Number(value);return Number.isFinite(n)&&n>0?String(n)+' XTR':'Harga belum ditetapkan';}
function warrantyLabel(product){var d=String(product.description||'').toLowerCase();return d.indexOf('garansi 30 hari')!==-1?'GARANSI 30 HARI':'GARANSI SESUAI KETENTUAN';}
function statusLabel(status){var labels={PENDING_PAYMENT:'Menunggu pembayaran',QA_PENDING:'Pemeriksaan pesanan',QA_APPROVED:'Lolos pemeriksaan',DELIVERED:'Akses terkirim',QA_REJECTED:'Tidak dapat dipenuhi',REFUND_PENDING:'Refund diproses',REFUNDED:'Refund selesai',CANCELLED:'Dibatalkan'};return labels[status]||status;}
function updateMode(){var active=catalog.some(function(p){return Number(p.is_active)===1;});var mode=document.getElementById('mode');if(mode)mode.textContent=active&&paymentsReady?'TOKO AKTIF':'PREVIEW';}
function simpleIconSlug(product){
 var text=(String(product.id||'')+' '+String(product.name||'')).toLowerCase();
 var brands=[
  [/netflix/,'netflix'],[/spotify/,'spotify'],[/crunchyroll/,'crunchyroll'],[/youtube music/,'youtubemusic'],[/youtube/,'youtube'],[/apple music/,'applemusic'],[/apple tv/,'appletv'],[/bilibili/,'bilibili'],[/hbo|max/,'hbomax'],[/deezer/,'deezer'],[/soundcloud/,'soundcloud'],[/tidal/,'tidal']
 ];
 for(var i=0;i<brands.length;i++)if(brands[i][0].test(text))return brands[i][1];
 return null;
}
function productArt(product,large){
 var slug=simpleIconSlug(product),label=escapeHtml(product.name),asset=String(product.hero_asset||'').trim(),logo='';
 if(slug){
  logo='<img src="https://cdn.simpleicons.org/'+slug+'" alt="'+label+'" width="'+(large?'65':'48')+'" height="'+(large?'65':'48')+'" loading="lazy" decoding="async" referrerpolicy="no-referrer">';
 }else if(/^\d{2}-hero\.svg$/.test(asset)){
  logo='<img src="/assets/products/'+asset+'" alt="'+label+'" width="'+(large?'65':'48')+'" height="'+(large?'65':'48')+'" loading="lazy" decoding="async">';
 }else{
  logo='<span class="generic-brand-icon" aria-hidden="true">✦</span>';
 }
 return '<div class="asset-art brand-art '+(large?'brand-art-large':'')+'">'+logo+'<span>'+label+'</span></div>';
}
function openProductDetail(productId){
 var product=catalog.find(function(item){return String(item.id)===String(productId);});
 if(!product){toast('Detail produk belum tersedia.');return;}
 var content=document.getElementById('productDetailContent'),modal=document.getElementById('productModal');if(!content||!modal)return;
 var warranty=warrantyLabel(product),active=Number(product.is_active)===1,hasPrice=Number.isSafeInteger(Number(product.price_stars))&&Number(product.price_stars)>0,canPay=active&&hasPrice&&paymentsReady&&!!(tg&&initData);
 content.innerHTML=productArt(product,true)+(String(product.benefit_asset||"").match(/^\d{2}-benefit\.svg$/)?'<div class="detail-benefit-art"><img src="/assets/products/'+product.benefit_asset+'" alt="Informasi manfaat '+escapeHtml(product.name)+'" loading="lazy" decoding="async"></div>':"")+'<div class="detail-kicker">DETAIL PRODUK</div><h2 class="detail-name" id="productDetailName">'+escapeHtml(product.name)+'</h2><div class="detail-period">Masa akses: '+escapeHtml(product.period_label||'-')+'</div><p class="detail-description">'+escapeHtml(product.description||'Informasi produk belum tersedia.')+'</p><div class="detail-facts"><div class="detail-fact"><small>GARANSI</small><strong>'+escapeHtml(warranty)+'</strong></div><div class="detail-fact"><small>PEMENUHAN</small><strong>Manual</strong></div></div><p class="detail-manual">Akses diproses secara manual setelah pembayaran Telegram Stars terkonfirmasi. Detail akses dikirim melalui chat bot.</p><button class="buy detail-buy" type="button" id="productDetailBuy" '+(canPay?'':'disabled')+'>'+(canPay?'Bayar Sekarang':(!active?'Produk tidak aktif':(!hasPrice?'Harga belum ditetapkan':(!paymentsReady?'Pembayaran tidak tersedia':'Buka melalui Telegram untuk Membeli'))))+'</button><div class="detail-price-under">'+stars(product.price_stars)+'</div><div class="checkout-legal">Dengan menekan Bayar, Anda menyetujui <details><summary>Syarat &amp; Ketentuan</summary><div class="terms-inline"><p>1. Pesanan diproses setelah pembayaran Telegram terkonfirmasi dan masuk pemeriksaan sebelum akses dikirim.</p><p>2. Jangan membagikan detail login atau akses akun kepada pihak lain.</p><p>3. Klaim garansi diajukan melalui Bantuan Pesanan dengan Order ID dan penjelasan kendala.</p><p>4. Harga dan masa akses mengikuti keterangan produk saat dipesan.</p><p>5. Bantuan dan refund ditinjau sesuai kondisi pesanan serta ketentuan Telegram. Untuk kendala pembayaran, hubungi bot layanan.</p></div></details>.</div>';
 modal.setAttribute('aria-hidden','false');modal.classList.add('is-open');document.body.classList.add('modal-open');
 var buy=document.getElementById('productDetailBuy');if(buy)buy.addEventListener('click',function(){closeProductDetail();checkout(product.id);});
}
function closeProductDetail(){var modal=document.getElementById('productModal');if(!modal)return;modal.classList.remove('is-open');modal.setAttribute('aria-hidden','true');document.body.classList.remove('modal-open');}
function categoryKey(value){var key=String(value||'').toLowerCase();return key.indexOf('musik')>=0||key.indexOf('music')>=0?'music':'streaming';}
function setCategory(category){currentCategory=category||'all';Array.prototype.slice.call(document.querySelectorAll('[data-category-filter]')).forEach(function(button){button.classList.toggle('active',button.getAttribute('data-category-filter')===currentCategory);});renderProducts();}
function renderFeaturedProducts(){
 if(!featuredBox)return;
 if(!catalog.length){featuredBox.innerHTML='<article class="featured-item"><span class="featured-copy"><strong>Produk belum tersedia</strong><small>Katalog sedang diperbarui</small></span></article>';return;}
 var preferred=['netflix','spotify','hbomax','youtube','applemusic','crunchyroll'];
 var selected=[];
 preferred.forEach(function(slug){var item=catalog.find(function(p){return simpleIconSlug(p)===slug&&selected.indexOf(p)===-1;});if(item)selected.push(item);});
 catalog.forEach(function(p){if(selected.length<4&&selected.indexOf(p)===-1)selected.push(p);});
 featuredBox.innerHTML=selected.slice(0,4).map(function(p){
  var slug=simpleIconSlug(p),logo=slug
   ? '<img src="https://cdn.simpleicons.org/'+slug+'" alt="" width="32" height="32" loading="lazy" decoding="async" referrerpolicy="no-referrer">'
   : '<span class="generic-brand-icon" aria-hidden="true">✦</span>';
  return '<button class="featured-item" type="button" data-featured-product="'+escapeHtml(p.id)+'"><span class="featured-logo">'+logo+'</span><span class="featured-copy"><strong>'+escapeHtml(p.name)+'</strong><small>'+escapeHtml(p.category||'Digital Premium')+' · '+stars(p.price_stars)+'</small></span></button>';
 }).join('');
}
function renderProducts(){
 if(!box)return;
 if(!catalog.length){if(box.getAttribute('data-ssr')!=='1')box.innerHTML='<article class="card"><div class="desc">Katalog belum tersedia.</div></article>';renderFeaturedProducts();updateMode();return;}
 box.removeAttribute('data-ssr');
 var visible=currentCategory==='all'?catalog:catalog.filter(function(p){return categoryKey(p.category)===currentCategory;});
 box.innerHTML=visible.length?visible.map(function(p){return '<article class="card product-card" role="button" tabindex="0" data-product-id="'+escapeHtml(p.id)+'" aria-label="Lihat detail '+escapeHtml(p.name)+'">'+productArt(p,false)+'<div class="cardtop"><div class="productmeta"><div class="name">'+escapeHtml(p.name)+'</div><div class="period">'+escapeHtml(p.category)+' · '+escapeHtml(p.period_label)+'</div></div></div><span class="warranty">'+warrantyLabel(p)+'</span><p class="desc">'+escapeHtml(p.description)+'</p><div class="cardfoot"><div class="price">'+stars(p.price_stars)+'</div><span class="detail-hint">Lihat detail ↗</span></div></article>';}).join(''):'<article class="card"><div class="desc">Belum ada produk aktif pada kategori ini.</div></article>';
 renderFeaturedProducts();updateMode();
}
if(box){box.addEventListener('click',function(event){var card=event.target.closest('.product-card');if(card&&box.contains(card))openProductDetail(card.getAttribute('data-product-id'));});box.addEventListener('keydown',function(event){var card=event.target.closest('.product-card');if(card&&box.contains(card)&&(event.key==='Enter'||event.key===' ')){event.preventDefault();openProductDetail(card.getAttribute('data-product-id'));}});}
var closeDetail=document.getElementById('closeProductModal'),detailBackdrop=document.querySelector('[data-close-product]');if(closeDetail)closeDetail.addEventListener('click',closeProductDetail);if(detailBackdrop)detailBackdrop.addEventListener('click',closeProductDetail);document.addEventListener('keydown',function(event){if(event.key==='Escape')closeProductDetail();});
function loadProducts(){
 fetch('/api/products',{method:'GET',cache:'no-store',headers:{'accept':'application/json'}}).then(function(response){if(!response.ok)throw new Error('Katalog gagal dimuat ('+response.status+').');return response.json();}).then(function(data){
  catalog=Array.isArray(data.products)?data.products:[];paymentsReady=data.payments_ready===true;renderProducts();
 }).catch(function(error){var mode=document.getElementById('mode');if(mode)mode.textContent='KONEKSI';});
}
function connectTelegram(){
 var api=window.Telegram&&window.Telegram.WebApp?window.Telegram.WebApp:null;if(!api)return false;
 tg=api;initData=api.initData||'';var tgUser=api.initDataUnsafe&&api.initDataUnsafe.user;var greeting=document.getElementById('greetingName'),accountName=document.getElementById('accountName');if(greeting&&tgUser&&tgUser.first_name)greeting.textContent=tgUser.first_name;if(accountName&&tgUser&&tgUser.first_name)accountName.textContent=tgUser.first_name+(tgUser.last_name?' '+tgUser.last_name:'');
 try{api.ready();if(typeof api.expand==='function')api.expand();if(typeof api.setHeaderColor==='function')api.setHeaderColor('#241044');if(typeof api.setBackgroundColor==='function')api.setBackgroundColor('#080713');if(typeof api.setBottomBarColor==='function')api.setBottomBarColor('#0c0a1b');}catch(error){}
 renderProducts();loadOrders();return true;
}
function resumeInvoice(orderId,invoiceLink){
 if(!tg||!initData){toast('Buka toko melalui Telegram untuk melanjutkan pembayaran.');return;}
 if(!invoiceLink||typeof tg.openInvoice!=='function'){toast('Invoice tidak tersedia. Buat pesanan baru melalui katalog.');return;}
 if(checkoutBusy){toast('Invoice sedang diproses.');return;}
 checkoutBusy=true;
 try{tg.openInvoice(invoiceLink,function(status){checkoutBusy=false;if(status==='paid'){toast('Pembayaran diterima. Memperbarui status pesanan.');loadOrders();window.setTimeout(loadOrders,1500);window.setTimeout(loadOrders,4000);}else if(status==='failed')closeInvoiceOrder(orderId,'FAILED');else if(status==='cancelled')closeInvoiceOrder(orderId,'CANCELLED');});}
 catch(error){checkoutBusy=false;toast('Invoice tidak dapat dibuka. Coba kembali dari riwayat pesanan.');}
}
function loadOrders(){
 if(!orderBox)return;
 if(!tg||!initData){orderBox.innerHTML='<p class="empty">Buka toko melalui @JktStarsStores_bot untuk melihat pesanan Anda.</p>';return;}
 orderBox.innerHTML='<p class="empty">Memuat pesanan...</p>';
 fetch('/api/orders',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({initData:initData})}).then(function(response){return response.json().then(function(data){if(!response.ok)throw new Error(data.message||'Status pesanan gagal dimuat.');return data;});}).then(function(data){
  var rows=Array.isArray(data.orders)?data.orders:[];if(!rows.length){orderBox.innerHTML='<p class="empty">Belum ada pesanan untuk akun Telegram ini.</p>';return;}
  orderBox.innerHTML=rows.map(function(order){return '<article class="orderitem"><div class="orderhead"><div class="ordername">'+escapeHtml(order.product_name_snapshot)+'</div><span class="orderstatus">'+escapeHtml(statusLabel(order.status))+'</span></div><div class="ordermeta">Order ID: '+escapeHtml(order.id)+'<br>'+escapeHtml(order.amount_stars)+' '+escapeHtml(order.currency||'XTR')+'<br>Dibuat: '+escapeHtml(order.created_at||'-')+'</div></article>';}).join('');
  rows.forEach(function(order,index){if(order.status==='PENDING_PAYMENT'&&order.invoice_link){var item=orderBox.children[index];if(item){var button=document.createElement('button');button.type='button';button.className='buy secondary';button.textContent='Lanjutkan Pembayaran';button.setAttribute('data-resume-order',order.id);button.setAttribute('data-invoice-link',order.invoice_link);button.style.marginTop='9px';item.appendChild(button);}}});
 }).catch(function(error){orderBox.innerHTML='<p class="empty">'+escapeHtml(error.message||'Pesanan gagal dimuat.')+'</p>';});
}
if(orderBox)orderBox.addEventListener('click',function(event){var button=event.target.closest('[data-resume-order]');if(button&&orderBox.contains(button))resumeInvoice(button.getAttribute('data-resume-order'),button.getAttribute('data-invoice-link'));});
function closeInvoiceOrder(orderId,reason){
 fetch('/api/orders/close',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({initData:initData,orderId:orderId,reason:reason})}).then(function(response){return response.json().then(function(data){if(!response.ok)throw new Error(data.message||'Status invoice gagal dicatat.');return data;});}).then(function(){toast(reason==='FAILED'?'Pembayaran gagal. Order ditutup, Anda dapat mencoba kembali.':'Invoice ditutup. Order dibatalkan tanpa pembayaran.');loadOrders();}).catch(function(error){toast(error.message||'Status invoice belum dapat diperbarui.');loadOrders();});
}
function checkout(productId){
 if(!tg||!initData){toast('Buka toko melalui @JktStarsStores_bot di Telegram untuk melakukan pembayaran.');return;}
 if(!paymentsReady){toast('Pembayaran sedang tidak tersedia.');return;}
 if(checkoutBusy){toast('Checkout sedang diproses. Tunggu hasil invoice terlebih dahulu.');return;}
 checkoutBusy=true;
 fetch('/api/checkout',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({initData:initData,productId:productId,termsAccepted:true})}).then(function(response){return response.json().then(function(data){if(!response.ok)throw new Error(data.message||'Checkout gagal.');return data;});}).then(function(data){if(!data.invoiceLink||typeof tg.openInvoice!=='function'){if(data.orderId)closeInvoiceOrder(data.orderId,'FAILED');throw new Error('Invoice Telegram tidak tersedia. Order ditutup agar tidak tertinggal sebagai menunggu pembayaran.');}try{tg.openInvoice(data.invoiceLink,function(status){checkoutBusy=false;if(status==='paid'){toast('Pembayaran diterima. Pesanan masuk pemeriksaan kualitas.');loadOrders();window.setTimeout(loadOrders,1500);window.setTimeout(loadOrders,4000);}else if(status==='failed')closeInvoiceOrder(data.orderId,'FAILED');else if(status==='cancelled')closeInvoiceOrder(data.orderId,'CANCELLED');});}catch(openError){checkoutBusy=false;if(data.orderId)closeInvoiceOrder(data.orderId,'FAILED');throw openError;}}).catch(function(error){checkoutBusy=false;toast(error.message||'Checkout gagal.');});
}
function submitSupport(){
 if(!tg||!initData){toast('Buka toko melalui @JktStarsStores_bot untuk mengirim tiket bantuan.');return;}
 var message=supportInput?supportInput.value.trim():'';if(!message){toast('Tuliskan Order ID dan kendala terlebih dahulu.');return;}
 if(sendSupport)sendSupport.disabled=true;
 fetch('/api/support',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({initData:initData,message:message})}).then(function(response){return response.json().then(function(data){if(!response.ok)throw new Error(data.message||'Tiket bantuan gagal dikirim.');return data;});}).then(function(data){if(supportInput)supportInput.value='';toast(data.adminNotified?'Tiket bantuan terkirim: '+data.ticketId:'Tiket tersimpan: '+data.ticketId+'. Simpan ID ini dan hubungi bot jika belum ada balasan.');}).catch(function(error){toast(error.message||'Tiket bantuan gagal dikirim.');}).then(function(){if(sendSupport)sendSupport.disabled=false;});
}
function initHeroCarousel(){
 var root=document.getElementById('heroCarousel');if(!root)return;
 var slides=Array.prototype.slice.call(root.querySelectorAll('[data-hero-slide]')),dots=Array.prototype.slice.call(root.querySelectorAll('[data-hero-dot]')),count=document.getElementById('heroCount'),active=0,timer=null,touchX=null;
 // Keep carousel indicators exactly aligned with the slides actually rendered.
 if(dots.length>slides.length){dots.slice(slides.length).forEach(function(dot){dot.remove();});dots=dots.slice(0,slides.length);}
 if(dots.length<slides.length){var container=root.querySelector('.hero-dots');for(var i=dots.length;i<slides.length;i++){var dot=document.createElement('button');dot.type='button';dot.className='hero-dot';dot.setAttribute('data-hero-dot',String(i));dot.setAttribute('aria-label','Banner '+(i+1));container&&container.appendChild(dot);}dots=Array.prototype.slice.call(root.querySelectorAll('[data-hero-dot]'));}
 var reduce=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
 function show(index){if(!slides.length)return;active=(index+slides.length)%slides.length;slides.forEach(function(slide,i){var on=i===active;slide.classList.toggle('is-active',on);slide.setAttribute('aria-hidden',on?'false':'true');});dots.forEach(function(dot,i){var on=i===active;dot.classList.toggle('is-active',on);dot.setAttribute('aria-pressed',on?'true':'false');});if(count)count.textContent=String(active+1).padStart(2,'0')+' / '+String(slides.length).padStart(2,'0');}
 function stop(){if(timer){window.clearInterval(timer);timer=null;}}function start(){stop();if(reduce||document.hidden||slides.length<2)return;timer=window.setInterval(function(){show(active+1);},4000);}
 dots.forEach(function(dot){dot.addEventListener('click',function(){show(Number(dot.getAttribute('data-hero-dot'))||0);start();});});
 var previous=root.querySelector('[data-hero-prev]'),next=root.querySelector('[data-hero-next]');if(previous)previous.addEventListener('click',function(){show(active-1);start();});if(next)next.addEventListener('click',function(){show(active+1);start();});
 root.addEventListener('mouseenter',stop);root.addEventListener('mouseleave',start);root.addEventListener('focusin',stop);root.addEventListener('focusout',start);
 root.addEventListener('touchstart',function(event){if(event.changedTouches&&event.changedTouches.length)touchX=event.changedTouches[0].clientX;},{passive:true});root.addEventListener('touchend',function(event){if(touchX===null||!event.changedTouches||!event.changedTouches.length)return;var delta=event.changedTouches[0].clientX-touchX;if(Math.abs(delta)>35)show(active+(delta<0?1:-1));touchX=null;start();},{passive:true});
 document.addEventListener('visibilitychange',function(){if(document.hidden)stop();else start();});show(0);start();
}
if(termsAgree)termsAgree.addEventListener('change',renderProducts);
var refresh=document.getElementById('refreshOrders');if(refresh)refresh.addEventListener('click',loadOrders);
if(sendSupport)sendSupport.addEventListener('click',submitSupport);
var chat=document.getElementById('chatBot');if(chat)chat.addEventListener('click',function(){if(tg&&typeof tg.openTelegramLink==='function')tg.openTelegramLink('https://t.me/JktStarsStores_bot');else window.open('https://t.me/JktStarsStores_bot','_blank','noopener');});
function showPage(pageId){var pages=Array.prototype.slice.call(document.querySelectorAll('.app-page'));var found=pages.some(function(page){return page.id===pageId;});if(!found)return;pages.forEach(function(page){page.classList.toggle('is-active',page.id===pageId);});navItems.forEach(function(item){item.classList.toggle('active',item.getAttribute('data-target')===pageId);});window.scrollTo({top:0,behavior:'auto'});if(pageId==='ordersPanel')loadOrders();}
navItems.forEach(function(item){item.addEventListener('click',function(){showPage(item.getAttribute('data-target'));});});
Array.prototype.slice.call(document.querySelectorAll('[data-category-select]')).forEach(function(button){button.addEventListener('click',function(){setCategory(button.getAttribute('data-category-select'));showPage('catalogPanel');});});
Array.prototype.slice.call(document.querySelectorAll('[data-category-filter]')).forEach(function(button){button.addEventListener('click',function(){setCategory(button.getAttribute('data-category-filter'));});});
Array.prototype.slice.call(document.querySelectorAll('[data-open-catalog]')).forEach(function(button){button.addEventListener('click',function(){setCategory('all');showPage('catalogPanel');});});
if(featuredBox)featuredBox.addEventListener('click',function(event){var item=event.target.closest('[data-featured-product]');if(item)openProductDetail(item.getAttribute('data-featured-product'));});
var requestedPage=new URLSearchParams(window.location.search).get('page');if(requestedPage==='catalog'){setCategory('all');showPage('catalogPanel');}else if(requestedPage==='orders'){showPage('ordersPanel');}
initHeroCarousel();rotateLiveInfo();window.setInterval(rotateLiveInfo,5000);loadProducts();loadOrders();
var sdk=document.createElement('script');sdk.src='https://telegram.org/js/telegram-web-app.js';sdk.async=true;sdk.onload=function(){connectTelegram();};sdk.onerror=function(){var mode=document.getElementById('mode');if(mode)mode.textContent='KATALOG AKTIF';};document.head.appendChild(sdk);
})();</script></body></html>`;

function escapePageHtml(value) {
  return String(value == null ? "" : value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\"/g, "&quot;").replace(/'/g, "&#39;");
}
function productArtPage(p) {
 const text=(String(p.id||"")+" "+String(p.name||"")).toLowerCase();
 const brands=[
  [/netflix/,"netflix"],[/spotify/,"spotify"],[/crunchyroll/,"crunchyroll"],[/youtube music/,"youtubemusic"],[/youtube/,"youtube"],[/apple music/,"applemusic"],[/apple tv/,"appletv"],[/bilibili/,"bilibili"],[/hbo|max/,"hbomax"],[/deezer/,"deezer"],[/soundcloud/,"soundcloud"],[/tidal/,"tidal"]
 ];
 let slug=null;
 for(const [pattern,value] of brands){if(pattern.test(text)){slug=value;break;}}
 const asset=String(p.hero_asset||"").trim();
 const logo=slug
  ? '<img src="https://cdn.simpleicons.org/'+slug+'" alt="'+escapePageHtml(p.name)+'" width="48" height="48" loading="lazy" decoding="async" referrerpolicy="no-referrer">'
  : /^\d{2}-hero\.svg$/.test(asset)
    ? '<img src="/assets/products/'+asset+'" alt="'+escapePageHtml(p.name)+'" width="48" height="48" loading="lazy" decoding="async">'
    : '<span class="generic-brand-icon" aria-hidden="true">✦</span>';
 return '<div class="asset-art brand-art">'+logo+'<span>'+escapePageHtml(p.name)+'</span></div>';
}
async function renderHomePage(env) { let page=PAGE;try{const result=await env.DB.prepare("SELECT id,name,period_label,description,icon,price_stars,is_active,category,hero_asset FROM products WHERE is_active=1 AND delivery_mode='manual' ORDER BY name").all();const rows=result.results||[];const cards=rows.map(function(p){const description=String(p.description||""),warranty=description.toLowerCase().includes("garansi 30 hari")?"GARANSI 30 HARI":"GARANSI SESUAI KETENTUAN";return '<article class="card product-card" role="button" tabindex="0" data-product-id="'+escapePageHtml(p.id)+'" aria-label="Lihat detail '+escapePageHtml(p.name)+'">'+productArtPage(p)+'<div class="cardtop"><div class="productmeta"><div class="name">'+escapePageHtml(p.name)+'</div><div class="period">'+escapePageHtml(p.category)+' · '+escapePageHtml(p.period_label)+'</div></div></div><span class="warranty">'+warranty+'</span><p class="desc">'+escapePageHtml(description)+'</p><div class="cardfoot"><div class="price">'+String(Number(p.price_stars)||0)+' XTR</div><span class="detail-hint">Lihat detail ↗</span></div></article>';}).join("");const empty='<article class="card"><div class="desc">Katalog belum tersedia.</div></article>';const target='<section class="grid" id="products"><article class="card"><div class="desc">Memuat katalog...</div></article></section>';page=page.replace(target,'<section class="grid" id="products" data-ssr="1">'+(cards||empty)+'</section>');}catch(error){console.error("homepage_catalog_render_failed",String(error&&error.message||error).slice(0,300));}return html(page);}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    try {
      if (url.pathname.startsWith("/assets/products/") && request.method === "GET") {
        const filename=url.pathname.slice("/assets/products/".length);
        const svg=await getProductAsset(filename);
        if(!svg)return new Response("Not found",{status:404,headers:{"cache-control":"no-store"}});
        return new Response(svg,{headers:{"content-type":"image/svg+xml; charset=utf-8","cache-control":"public, max-age=86400, immutable","x-content-type-options":"nosniff"}});
      }
      if (url.pathname === "/" && request.method === "GET") return await renderHomePage(env);
      if (url.pathname === "/api/health" && request.method === "GET") {
        let database = false;
        let activeProducts = 0;
        let catalogCount = 0;
        try {
          await env.DB.prepare("SELECT 1 AS ok").first();
          database = true;
          const counts = await env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN is_active=1 AND delivery_mode='manual' THEN 1 ELSE 0 END) AS active FROM products").first();
          catalogCount = Number(counts && counts.active || 0);
          activeProducts = Number(counts && counts.active || 0);
        } catch {}
        let telegram = { connected:false, username:null, usernameMatches:false, webhookConfigured:false, webhookUrlMatches:false, preCheckoutUpdatesEnabled:null, allowedUpdates:null, pendingUpdateCount:null, lastErrorMessage:null };
        try {
          const me = await tg(env, "getMe", {});
          const webhook = await tg(env, "getWebhookInfo", {});
          const expectedWebhook = new URL("/telegram/webhook", url.origin).toString();
          const actualWebhook = String(webhook.url || "").replace(/\/$/, "");
          const expected = expectedWebhook.replace(/\/$/, "");
          const username = String(me.username || "");
          const allowedUpdates = Array.isArray(webhook.allowed_updates) ? webhook.allowed_updates : null;
          telegram = {
            connected:true,
            username:username,
            usernameMatches:username.toLowerCase() === String(env.BOT_USERNAME || "").replace(/^@/,"").toLowerCase(),
            webhookConfigured:!!webhook.url,
            webhookUrlMatches:actualWebhook === expected,
            allowedUpdates:allowedUpdates,
            preCheckoutUpdatesEnabled:allowedUpdates === null || allowedUpdates.length === 0 || allowedUpdates.includes("pre_checkout_query"),
            pendingUpdateCount:Number(webhook.pending_update_count || 0),
            lastErrorMessage:webhook.last_error_message || null,
            lastErrorDate:webhook.last_error_date || null
          };
        } catch (error) {
          telegram.lastErrorMessage = String(error.message || "Telegram API unavailable").slice(0,250);
        }
        const webhookSecretConfigured = !!env.WEBHOOK_SECRET;
        const adminConfigured = !!env.ADMIN_TELEGRAM_ID;
        const paymentsReady = database && telegram.connected && telegram.usernameMatches && telegram.webhookUrlMatches && telegram.preCheckoutUpdatesEnabled !== false && webhookSecretConfigured && adminConfigured && activeProducts > 0;
        return json({
          ok:database && telegram.connected && telegram.usernameMatches && telegram.webhookUrlMatches && webhookSecretConfigured && adminConfigured,
          service:"PremiumDigital_ID",
          database:database,
          telegram:telegram,
          catalog:{ total:catalogCount, activeManual:activeProducts },
          botConfigured:!!env.BOT_TOKEN,
          webhookSecretConfigured:webhookSecretConfigured,
          adminConfigured:adminConfigured,
          paymentsReady:paymentsReady,
          paymentDiagnostics:{ readinessScope:"CONFIGURATION_WEBHOOK_AND_PRECHECKOUT", customerAuth:"VALIDATED_PER_REQUEST", invoiceCreation:"CHECKED_DURING_CHECKOUT", paymentConfirmation:"SUCCESSFUL_PAYMENT_WEBHOOK", liveTransactionTest:"NOT_TESTED_BY_HEALTH_ENDPOINT" }
        });
      }
      if (url.pathname === "/api/products" && request.method === "GET") {
        const rows = await env.DB.prepare("SELECT id,slug,name,period_label,description,icon,price_stars,is_active,catalog_no,category,hero_asset,benefit_asset FROM products WHERE is_active=1 AND delivery_mode='manual' ORDER BY name").all();
        const active = await env.DB.prepare("SELECT COUNT(*) AS total FROM products WHERE is_active=1 AND delivery_mode='manual'").first();
        const hasCatalog = Number(active && active.total || 0) > 0;
        const paymentsReady = hasCatalog && await telegramPaymentsReady(env, url.origin);
        return json({ products: rows.results || [], payments_ready: paymentsReady });
      }
      if (url.pathname === "/api/orders" && request.method === "POST") {
        const auth = await requireUser(request, env);
        if (auth.error) return auth.error;
        const rows = await env.DB.prepare("SELECT o.id,o.product_name_snapshot,o.amount_stars,o.currency,o.status,o.created_at,o.paid_at,o.delivered_at,(SELECT json_extract(pe.payload_json,'$.invoice_link') FROM payment_events pe WHERE pe.order_id=o.id AND pe.event_type='INVOICE_CREATED' ORDER BY pe.id DESC LIMIT 1) AS invoice_link FROM orders o WHERE o.telegram_user_id=? ORDER BY o.created_at DESC LIMIT 20")
          .bind(String(auth.user.id)).all();
        return json({ ok:true, orders:rows.results || [] });
      }
      if (url.pathname === "/api/orders/close" && request.method === "POST") {
        const auth = await requireUser(request, env);
        if (auth.error) return auth.error;
        const orderId = String(auth.data.orderId || "").trim().slice(0,100);
        const reason = String(auth.data.reason || "").toUpperCase();
        if (!orderId || !["FAILED","CANCELLED"].includes(reason)) return json({ok:false,message:"Data penutupan invoice tidak valid."},400);
        const eventType = reason === "FAILED" ? "INVOICE_FAILED" : "INVOICE_CANCELLED";
        const result = await env.DB.batch([
          env.DB.prepare("UPDATE orders SET status='CANCELLED',updated_at=datetime('now') WHERE id=? AND telegram_user_id=? AND status='PENDING_PAYMENT' AND telegram_payment_charge_id IS NULL")
            .bind(orderId,String(auth.user.id)),
          env.DB.prepare("INSERT INTO payment_events (order_id,event_type,payload_json) SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND status='CANCELLED' AND telegram_user_id=?) AND NOT EXISTS (SELECT 1 FROM payment_events WHERE order_id=? AND event_type=?)")
            .bind(orderId,eventType,JSON.stringify({reason:reason,source:"mini_app_invoice_callback"}),orderId,String(auth.user.id),orderId,eventType)
        ]);
        if (Number(result[0].meta && result[0].meta.changes || 0) !== 1) return json({ok:false,error:"ORDER_NOT_PENDING",message:"Pesanan tidak ditemukan, sudah dibayar, atau sudah ditutup."},409);
        return json({ok:true,orderId:orderId,status:"CANCELLED"});
      }
      if (url.pathname === "/api/checkout" && request.method === "POST") {
        if (!env.BOT_TOKEN || !env.WEBHOOK_SECRET || !env.ADMIN_TELEGRAM_ID || !env.BOT_USERNAME) return json({ ok:false, error:"PAYMENTS_NOT_CONFIGURED", message:"Pembayaran belum siap. Bot, webhook, atau konfigurasi admin belum lengkap." }, 503);
        const auth = await requireUser(request, env);
        if (auth.error) return auth.error;
        if (auth.data.termsAccepted !== true) return json({ ok:false, error:"TERMS_REQUIRED", message:"Baca dan setujui Syarat & Ketentuan sebelum checkout." }, 400);
        const product = await env.DB.prepare("SELECT * FROM products WHERE id=? AND is_active=1 AND delivery_mode='manual'").bind(String(auth.data.productId || "")).first();
        if (!product) return json({ ok: false, error: "PRODUCT_UNAVAILABLE", message: "Produk belum tersedia untuk dibeli." }, 409);
        if (!Number.isSafeInteger(Number(product.price_stars)) || Number(product.price_stars) <= 0) return json({ ok:false, error:"PRODUCT_PRICE_NOT_SET", message:"Produk aktif, tetapi harga Telegram Stars belum ditetapkan." }, 409);
        if (!(await telegramPaymentsReady(env, url.origin))) return json({ ok:false, error:"PAYMENTS_NOT_READY", message:"Pembayaran sementara tidak tersedia. Periksa koneksi bot dan webhook." }, 503);
        const orderId = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO orders (id,telegram_user_id,telegram_username,product_id,product_name_snapshot,amount_stars,currency,status,terms_accepted_at,terms_version) VALUES (?,?,?,?,?,?, 'XTR','PENDING_PAYMENT',datetime('now'),?)")
          .bind(orderId, String(auth.user.id), auth.user.username || null, product.id, product.name, product.price_stars, TERMS_VERSION).run();
        try {
          const invoiceLink = await tg(env, "createInvoiceLink", {
            title: product.name.slice(0, 32), description: (product.description + " · " + product.period_label).slice(0, 255),
            payload: orderId, provider_token: "", currency: "XTR",
            prices: [{ label: product.name.slice(0, 32), amount: product.price_stars }],
            need_name: false, need_phone_number: false, need_email: false, need_shipping_address: false, is_flexible: false
          });
          await env.DB.prepare("INSERT INTO payment_events (order_id,event_type,payload_json) VALUES (?,?,?)").bind(orderId,"INVOICE_CREATED",JSON.stringify({ user_id:auth.user.id, product_id:product.id, invoice_link:invoiceLink })).run();
          return json({ ok: true, orderId: orderId, invoiceLink: invoiceLink });
        } catch (e) {
          await env.DB.prepare("UPDATE orders SET status='CANCELLED',updated_at=datetime('now') WHERE id=?").bind(orderId).run();
          return json({ ok: false, error: "INVOICE_FAILED", message: "Invoice Telegram gagal dibuat. Silakan coba kembali." }, 502);
        }
      }
      if (url.pathname === "/api/support" && request.method === "POST") {
        const auth = await requireUser(request, env);
        if (auth.error) return auth.error;
        const message = String(auth.data.message || "").trim().slice(0, 1500);
        if (!message) return json({ ok:false, message:"Isi pesan bantuan terlebih dahulu." }, 400);
        const ticketId = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO support_tickets (id,telegram_user_id,telegram_username,message) VALUES (?,?,?,?)")
          .bind(ticketId,String(auth.user.id),auth.user.username || null,message).run();
        let adminNotified = false;
        if (env.BOT_TOKEN && env.ADMIN_TELEGRAM_ID) {
          try { await tg(env,"sendMessage",{chat_id:env.ADMIN_TELEGRAM_ID,text:"TIKET BANTUAN BARU\nID: "+ticketId+"\nPengguna: "+auth.user.id+"\n\n"+message}); adminNotified = true; }
          catch (notifyError) { console.error("support_ticket_admin_notify_failed",{ticket_id:ticketId,message:String(notifyError && notifyError.message || notifyError).slice(0,250)}); }
        }
        return json({ ok:true, ticketId:ticketId, adminNotified:adminNotified });
      }
      if (url.pathname === "/telegram/webhook" && request.method === "POST") return await handleWebhook(request, env);
      return json({ ok:false, error:"NOT_FOUND" }, 404);
    } catch (error) {
      console.error("worker_request_failed", { path:new URL(request.url).pathname, name:error && error.name, message:String(error && error.message || error).slice(0,500) });
      return json({ ok:false, error:"INTERNAL_ERROR", message:"Terjadi kesalahan pada server." }, 500);
    }
  }
};
