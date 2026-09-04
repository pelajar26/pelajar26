# Pixabay — Manual Test Checklist (Authenticated)
**Untuk:** acc2 (`user_id=57416195`) dan acc1 (perlu daftar baru)  
**Cara:** Buka URL dalam pelayar sambil log masuk. Lapor status HTTP, kandungan respons, dan apa-apa yang luar biasa.

---

## BAHAGIAN A — Perlukan acc1 DAN acc2 (IDOR Cross-Account)

**Sediakan acc1 dahulu:**
1. Daftar akaun baru di `https://pixabay.com/accounts/register/` dari pelayar anda (bukan dari server)
2. Log masuk sebagai acc1, catat `user_id` dari cookie
3. Buat collection baru, upload gambar/video (jika ada)

### A-1 — IDOR: Collections
Sambil log masuk sebagai **acc2**, akses collection acc1:
```
https://pixabay.com/users/{acc1_username}/collections/{collection_id}/
```
Juga cuba URL terus dengan ID:
```
https://pixabay.com/users/collections/{collection_id}/
https://pixabay.com/api/collections/{collection_id}/
```
**Jangka:** 403 atau data acc1 tidak boleh dilihat acc2

---

### A-2 — IDOR: API Keys
Sambil log masuk sebagai acc2, cuba akses pengurusan API key acc1:
```
https://pixabay.com/api/keys/
https://pixabay.com/accounts/api/
https://pixabay.com/accounts/developer/
```
Buka DevTools → Network semasa buka halaman settings acc2, cari request `/api/keys/` atau serupa.
**Catatkan:** Adakah API key ditunjukkan dalam response? Adakah ID numerikal dalam URL?

---

### A-3 — IDOR: Direct Messages
Sambil log masuk sebagai acc2, hantar mesej ke acc1. Kemudian cuba akses:
```
https://pixabay.com/accounts/messages/{thread_id}/
```
Tukar `thread_id` kepada nombor lain (thread acc1 yang berbeza).
**Jangka:** 403 jika betul

---

## BAHAGIAN B — acc2 Sahaja

### B-1 — CSRF: Tukar Email
1. Buka `https://pixabay.com/accounts/settings/` → tab email/password
2. Buka DevTools → Network → filter XHR
3. Cuba tukar email, perhatikan request:
   - Adakah `csrftoken` dihantar dalam header `X-CSRFToken`?
   - Atau dalam form body `csrfmiddlewaretoken`?
   - Adakah ada header `Referer` check?
4. Salin full request (curl format dari DevTools) dan hantar kepada saya

### B-2 — Upload: SVG XSS
1. Buka `https://pixabay.com/accounts/media/upload/`
2. Cuba upload fail SVG dengan kandungan:
   ```xml
   <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
     <text>test</text>
   </svg>
   ```
3. Jika diterima, buka URL CDN fail SVG dalam tab baru
4. Lapor: `content-type` header untuk fail SVG yang diupload

### B-3 — Upload: File Type Bypass
Cuba upload fail dengan extension berbeza:
- `evil.svg` → tukar nama kepada `evil.jpg` (buka fail SVG, ubah nama)
- `test.php` (PHP webshell kandungan mudah)
- `test.html` (kandungan HTML biasa)
Lapor apa mesej ralat yang ditunjukkan, atau jika fail diterima.

### B-4 — Forum Post XSS
1. Buka `https://pixabay.com/forum/` → buat post baru
2. Cuba masukkan dalam body post:
   ```
   <script>alert(1)</script>
   <img src=x onerror=alert(1)>
   [url=javascript:alert(1)]click[/url]
   ```
3. Submit dan tengok sama ada difilter atau dirender

### B-5 — API Key Discovery
1. Buka `https://pixabay.com/api/docs/` sambil log masuk
2. DevTools → Network → refresh page
3. Cari response yang mengandungi API key anda
4. Lapor: dalam request yang mana, field apa

### B-6 — Pre-Publication Content Access
1. Upload gambar/video tetapi JANGAN publish (simpan sebagai draft jika ada)
2. Cuba akses URL CDN terus untuk fail tersebut
3. **Tujuan:** Tengok sama ada fail tidak-published boleh diakses via CDN

---

## BAHAGIAN C — Info Cookie Cloudflare (Untuk Ujian dari Server)

Buka DevTools dalam pelayar yang sedang log masuk ke Pixabay:
- **F12** → **Application** tab → **Cookies** → `https://pixabay.com`

Cari dan salin nilai cookie berikut (jika ada):
| Cookie | Fungsi |
|---|---|
| `cf_clearance` | Cloudflare challenge clearance (24 jam) |
| `sessionid` | Django session |
| `csrftoken` | CSRF token |
| `user_id` | User ID |

**Paling penting:** `cf_clearance` — ini berbeza dari `__cf_bm` dan mungkin boleh digunakan dari IP lain.

---

## BAHAGIAN D — Sahkan P-001 Impact (Ujian Penting)

**Ini sahkan sama ada P-001 benar-benar significant:**

1. Log masuk sebagai acc2
2. Pergi ke mana-mana video page, e.g. `https://pixabay.com/videos/nature-163869/`
3. Klik butang "Download" → perhatikan URL yang digunakan dalam request download (DevTools → Network)
4. Lapor: Adakah URL yang digunakan adalah:
   - URL CDN terus (e.g. `cdn.pixabay.com/video/.../{id}.mp4`)?
   - Atau URL yang signed/tokenized (ada parameter `X-Amz-Signature` atau serupa)?
   - Atau URL yang berbeza (e.g. `pixabay.com/videos/download/...`)?

Jika download URL = URL CDN terus (tanpa signature), maka P-001 = medium severity (auth gate adalah kosmetik sahaja).
Jika download URL = signed URL, P-001 = low (CDN original adalah "bonus" content yang lebih besar/mentah).

---

*Lapor balik setiap hasil — walau sekecil mana pun.*
