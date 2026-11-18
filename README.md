# PremiumDigital_ID / JKT Stars Stores

Source repository for the existing production Cloudflare Worker `premiumdigital-store`.

## Production resources

- Worker: `premiumdigital-store`
- D1 database: `premiumdigital-db`
- Telegram bot: `@JktStarsStores_bot`
- Mini App: `https://premiumdigital-store.premiumdigital-id.workers.dev/`
- Payment currency: Telegram Stars (`XTR`)
- Catalog: 28 active manual-delivery products: 22 Streaming and 6 Musik, with per-product IDR and Telegram Stars (XTR) prices synchronized from the approved catalog workbook

## Catalog scope

The public catalog contains only the `Streaming` and `Musik` categories. Products in other categories are disabled and retained in D1 where needed to preserve historical order references. The storefront, API catalog, and bot catalog listing expose active manual-delivery products only.

## Source of truth

`worker.mjs` is synchronized with production Worker version 37. `product-assets.js` retains the existing SVG artwork for the registered products, including inactive products preserved for historical order references.

This repository does not contain live Telegram credentials. Configure secrets in the Cloudflare Worker environment.

## Required bindings

| Binding | Type | Purpose |
|---|---|---|
| `DB` | D1 | Existing `premiumdigital-db` |
| `BOT_TOKEN` | Secret | Telegram Bot API token |
| `WEBHOOK_SECRET` | Secret | Telegram webhook secret token |
| `ADMIN_TELEGRAM_ID` | Secret or plain text | Store administrator chat/user ID |
| `BOT_USERNAME` | Variable | `JktStarsStores_bot` |

## Local and deployment commands

Install Wrangler, then:

```sh
npx wrangler dev
npx wrangler deploy
```

Configure the secret values through Cloudflare/Wrangler secret management before deploying. Keep the existing Worker name, D1 database ID, webhook URL and Telegram bot unchanged.

## Payment flow

1. Mini App submits Telegram `initData` and product ID to `/api/checkout`.
2. Worker validates the Telegram HMAC signature and creates a `PENDING_PAYMENT` order.
3. Worker creates an XTR invoice link through Telegram Bot API.
4. Telegram sends `pre_checkout_query`; Worker validates the order and answers it.
5. Telegram sends `successful_payment` after funds are successfully charged.
6. Worker stores the Telegram charge ID and moves the order to `QA_PENDING`.
7. Admin checks availability and delivers access through the existing bot workflow.

A successful health check is a configuration check, not proof that a real payment has completed. A live Telegram Stars transaction is still required for end-to-end sign-off.
