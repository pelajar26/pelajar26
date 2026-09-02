# Verisign Bug Bounty — Findings Report
**Tarikh:** 2026-09-02  
**Program:** Verisign Bug Bounty  
**Pengkaji:** naqkhaie.f055@gmail.com  
**Branch:** claude/bug-bounty-capabilities-l4fryb

---

## Ringkasan Eksekutif

Pengujian dilakukan ke atas infrastruktur Verisign dari 2026-09-02. Tiga (3) penemuan tahap LOW/INFORMATIONAL dijumpai. Tiada RCE atau kerentanan kritikal yang berjaya dieksploitasi disebabkan oleh had akses proksi, penguatan input yang ketat, dan pengesahan mutual TLS pada servis EPP.

---

## F-001: Tomcat Cluster Node Disclosure via JSESSIONID

**Tahap Keterukan:** LOW / Informational  
**Sasaran:** `registrar.verisign-grs.com/webwhois-ui/`  
**CVSS:** 3.1 (Low)

### Penerangan

Atribut suffix pada cookie `JSESSIONID` mendedahkan pengecam nod kluster Tomcat secara langsung kepada pelanggan. Tiga nod berbeza dikenal pasti:

- `.d3a61a62` — nod utama (permintaan biasa)
- `.c55c42fa` — nod kedua (permohonan OPTIONS)
- `.fcf59aa8` — nod ketiga (permohonan POST)

### Bukti

```http
GET /webwhois-ui/ HTTP/1.1
Host: registrar.verisign-grs.com

HTTP/1.1 302 Found
Set-Cookie: JSESSIONID=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.d3a61a62; Path=/webwhois-ui; Secure; HttpOnly
```

Pengecam nod yang sama kelihatan pada `webwhois.verisign.com` (`.d3a61a62`), mengesahkan kedua-dua domain berkongsi kluster Tomcat yang sama.

### Impak

Penyerang boleh menggunakan maklumat ini untuk:
- Menyasarkan serangan ke nod tertentu (session fixation, nod-specific timing)
- Memetakan seni bina kluster dalaman
- Merancang serangan denial-of-service nod spesifik

### Cadangan Pembaikan

Konfigurasi Tomcat untuk menggunakan suffix nod rawak atau enkripsi identifier nod dalam `JSESSIONID`.

---

## F-002: HTTP 500 Internal Server Error pada Method OPTIONS

**Tahap Keterukan:** LOW / Informational  
**Sasaran:** `registrar.verisign-grs.com/webwhois-ui/rest/whois`  
**CVSS:** 2.5 (Low)

### Penerangan

Endpoint REST WebWhois mengembalikan **HTTP 500 Internal Server Error** apabila menerima permintaan HTTP `OPTIONS`. Ini menunjukkan pengecualian pelayan tidak ditangani (unhandled exception) apabila kaedah HTTP yang tidak disokong digunakan.

### Bukti

```http
OPTIONS /webwhois-ui/rest/whois?q=google.com&tld=com&type=quick HTTP/1.1
Host: registrar.verisign-grs.com

HTTP/1.1 500 Internal Server Error
Server: Apache
Content-Type: text/html
```

Berbanding endpoint lain yang mengembalikan 405 Method Not Allowed dengan betul.

### Impak

- Mendedahkan ralat pelayan yang tidak ditangani
- Boleh membocorkan maklumat stack trace (bergantung kepada konfigurasi)
- Menunjukkan pengurusan ralat yang tidak lengkap dalam aplikasi

### Cadangan Pembaikan

Tambahkan pengendalian eksplisit untuk kaedah HTTP yang tidak disokong, mengembalikan 405 dengan header `Allow` yang betul.

---

## F-003: Seni Bina Tiered Access WHOIS — Potensi Logik Autentikasi

**Tahap Keterukan:** INFORMATIONAL  
**Sasaran:** `registrar.verisign-grs.com/webwhois-tiered-ui/`  
**CVSS:** N/A

### Penerangan

Sistem Tiered Access WHOIS mengandungi aplikasi berasingan (`/webwhois-tiered-ui/`) yang boleh dicapai melalui endpoint REST yang berbeza. Logik JavaScript dalam `all.js` menunjukkan laluan REST berbeza digunakan berdasarkan medan borang `authpage`:

```javascript
var verifyAuth = $('input[name="authpage"]').val();
if (verifyAuth) {
    restPath = "../rest/whois";  // path berbeza untuk pengguna berautentikasi
}
```

### Bukti

```
GET /webwhois-tiered-ui/ → 302 redirect ke verisigninc.com
GET /webwhois-tiered-ui/rest/whois → 302 redirect ke verisigninc.com
GET /webwhois-tiered-ui/rest/epp/statuscode/ → 302 redirect
```

Semua laluan dalam `/webwhois-tiered-ui/` mengembalikan 302 untuk pengguna tidak berautentikasi.

### Impak

Seni bina ini merupakan penemuan menarik yang menunjukkan lapisan akses berbeza. Walau bagaimanapun, perlindungan autentikasi kelihatan berfungsi dengan betul (redirect ke verisigninc.com). Pengujian lanjut memerlukan akaun Tiered Access yang sah.

---

## Permukaan Tidak Dapat Dicapai

| Sasaran | Sebab |
|---------|-------|
| EPP (`epptool-ctld.verisign-grs.com:700`) | Memerlukan mutual TLS + sijil klien berizin |
| DNS root/gTLD AXFR | Firewall — connection timeout |
| `whois.verisign.com` | Diblock oleh proksi persekitaran |
| `nsw-config.verisign.com` | HTTP 403 semua laluan |
| `nsw-api.verisign.com` | HTTP 403 |
| `nsw-service.verisign.com` | HTTP 403 |

---

## Kesimpulan

Infrastruktur Verisign yang boleh dicapai adalah **sangat terkeras** dengan penguatan input yang ketat pada WebWhois, tiada SQL injection atau RCE yang berjaya dieksploitasi. Penemuan yang dijumpai adalah tahap LOW/INFORMATIONAL sahaja.

**Cadangan:** Pertimbangkan untuk menukar sasaran kepada program bug bounty lain yang memberikan akses lebih luas.

