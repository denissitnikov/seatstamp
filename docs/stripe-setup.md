# Stripe Setup Guide

By default, SeatStamp uses the buyer's **Stripe Checkout Session ID (`cs_live_...`)** as their license key.

Because Stripe generates a unique `cs_live_...` ID for every completed Payment Link checkout, you do not need a webhook endpoint, a database of pre-generated keys, or an email server.

## 1. Create a Stripe Payment Link

1. Open **Stripe Dashboard -> Payment Links -> + New**.
2. Select a one-time payment product (`mode: "payment"`). The Worker rejects recurring `subscription` sessions.
3. Under the **After payment** tab, choose **Don't show confirmation page -> Redirect customers to your website** and enter your Worker's `/thank-you` URL with Stripe's literal `{CHECKOUT_SESSION_ID}` placeholder:
   ```text
   https://activate.yourdomain.com/thank-you?session_id={CHECKOUT_SESSION_ID}
   ```
   *(Or `https://<worker-name>.<your-subdomain>.workers.dev/thank-you?session_id={CHECKOUT_SESSION_ID}` if using `workers.dev`.)*
4. Save the link and note two values:
   - The checkout URL (`https://buy.stripe.com/...`) for your website's Buy button.
   - The Payment Link ID (`plink_...`, shown in the Payment Link details panel in Stripe Dashboard) for Step 3.

### Buyer flow and key recovery
1. After payment, Stripe redirects the browser to `/thank-you?session_id=cs_live_...`.
2. During the post-checkout window (`THANK_YOU_WINDOW_SECONDS`, default 1 hour) and while seats remain available, the Worker renders the key with **Copy Key** and **Save `.txt` File** buttons and saves a backup copy in the browser's `localStorage`. After 1 hour (or once all seats are claimed), the server stops printing the key in the page. This does not hide the key: the page URL contains `session_id=cs_live_...`, and that value is the license key, so anyone who can read this browser's history or a copied link has the key. The browser also keeps a copy in `localStorage` for 30 days, one copy per order, and the page has a "Clear saved key" button. On a shared Mac, clear the saved key and delete the history entry after saving the key elsewhere.
3. On macOS browsers, `/thank-you` triggers `myapp://activate?key=cs_live_...` after 200ms so your app opens with the key pre-filled. (On iOS/Android browsers, the automatic custom-scheme redirect is skipped so mobile Safari does not show an invalid-address alert.)
4. Optional one-time backup email (the email address is not stored): if you set `RESEND_API_KEY` (`npx wrangler -c worker/wrangler.jsonc secret put RESEND_API_KEY`) and `"RECEIPT_FROM_EMAIL": "MyApp <keys@myapp.com>"` in `worker/wrangler.jsonc`, the first `/thank-you` visit atomically claims `meta.email_claimed_at` in `SeatCoordinator` and sends one backup email (HTML with an "Open in App" button plus plain-text fallback) to `session.customer_details.email` in the background. The customer's email address is never written to SQLite, KV, or logs, and refreshing `/thank-you` sends nothing after a successful send. After a failed send the next page load retries, up to 3 attempts in total. Nothing reports a failed send to you, so check your email provider's dashboard after setup. Every backup or recovery email leaves the license key readable in your email provider's logs for 30 days (Resend keeps message content, metadata, and logs that long on the Free, Pro, and Scale plans). Switching content storage off is a paid add-on for Pro or Scale teams that you request from Resend support. Keep open and click tracking off for the sending domain, because a tracked link would send the activation link through a redirect service. Name the provider in your privacy policy.
5. The same two settings enable in-app key recovery (`action: "recover"`): the buyer types their purchase email into the license field, the Worker lists completed sessions filtered by `customer_details[email]` with the existing `Checkout Sessions: Read` scope, and emails every paid, unrefunded `cs_live_...` key. No extra Stripe permissions or bindings are needed. Leave either secret unset and the endpoint answers `501 recovery_unconfigured`.

## 2. Create a Restricted Read-Only Stripe Key

In **Stripe Dashboard -> Developers -> API keys -> Create restricted key**, grant **Read** on four resources and leave everything else at **None**:

- `Checkout Sessions`: reads `/v1/checkout/sessions/cs_live_...` (`livemode`, `mode`, `status`, `payment_status`, `payment_link`). The same scope also lets the closed-tab fallback for `beginBrowserCheckout` list `/v1/checkout/sessions?status=complete&created[gte]=...` for your whole account (at most two pages of 100, at most once per 15 seconds per handoff) to find the session whose `client_reference_id` matches the app's handoff token. Set `STRIPE_ALLOWED_PAYMENT_LINKS` (up to 8 links) so each list call is pinned to one of your links and the Worker never lists sessions of your other products.
- `PaymentIntents`: expands `payment_intent` (`status === "succeeded"`, `amount_received`)
- `Charges`: expands `payment_intent.latest_charge` (`refunded`, `disputed`, `amount_refunded`)
- `Disputes`: lists `/v1/disputes?payment_intent=...` when a charge is marked `disputed`, to tell a dispute you won (`won`, `warning_closed`) from a lost or open one

Stripe leaves `checkout.session.payment_status` set to `"paid"` after a refund or dispute. The Worker requests `?expand[]=payment_intent.latest_charge` to inspect the underlying charge. If `PaymentIntents: Read` or `Charges: Read` is missing, Stripe returns `403` and the Worker returns `502` rather than skipping the refund check. The same applies to the list call used by `claim_checkout` with `fallbackSearch: true`: a `403` or `5xx` from Stripe surfaces as `502 upstream_unavailable`, not as `202 pending`. Every Stripe request carries `Stripe-Version: 2026-10-28.endive` (constant `STRIPE_API_VERSION` in `worker/worker.js`), so an API upgrade of your Stripe account does not change what the Worker receives. Check the Worker in Stripe test mode before you change that constant.

Upload the restricted key as a Worker secret:

```sh
npx wrangler -c worker/wrangler.jsonc secret put STRIPE_SECRET_KEY
```

## 3. Pin Your Payment Link IDs (`STRIPE_ALLOWED_PAYMENT_LINKS`)

Without this setting the Worker accepts every completed one-time payment on your Stripe account, including payments for other products. If your Stripe account sells (or may later sell) more than one product, restrict which Payment Links are accepted by this Worker before the second product goes live:

```sh
npx wrangler -c worker/wrangler.jsonc secret put STRIPE_ALLOWED_PAYMENT_LINKS
# Example: plink_1AbCdEfGhIjKlMnO,plink_1PqRsTuVwXyZ0123
```

## 4. Testing with Stripe Test Mode

1. Set `STRIPE_SECRET_KEY` to a test restricted key (`rk_test_...` with the same four Read scopes).
2. Create a test-mode Payment Link redirecting to `/thank-you?session_id={CHECKOUT_SESSION_ID}`.
3. Complete checkout with Stripe's test card (`4242 4242 ...`). The Worker accepts `cs_test_...` sessions while `STRIPE_SECRET_KEY` is a `_test_` key, and rejects all `cs_test_...` sessions as soon as you switch `STRIPE_SECRET_KEY` to `rk_live_...`.
