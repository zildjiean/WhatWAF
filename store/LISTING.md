# Chrome Web Store — ข้อมูลสำหรับกรอก

คัดลอกข้อความภาษาอังกฤษในกล่องไปวางในหน้า Developer Dashboard ได้เลย
(https://chrome.google.com/webstore/devconsole)

---

## 0. ก่อนเริ่ม: บัญชี Developer (ข้อ 5)

- [ ] สมัคร Developer และจ่ายค่าสมัคร 5 USD (ครั้งเดียว)
- [ ] เปิด 2-Step Verification ที่บัญชี Google (ต้องเปิดก่อน publish)
- [ ] ยืนยันอีเมลติดต่อในแท็บ **Account**
- [ ] กรอกสถานะ **Trader / Non-trader** (กฎ EU DSA)
  - ถ้าทำแจกฟรีเป็นงานส่วนตัว ไม่ได้ทำในนามธุรกิจ → เลือก **Non-trader**
  - ถ้าทำในนามบริษัทหรือหารายได้ → เลือก **Trader** ซึ่งต้องเปิดเผยที่อยู่และเบอร์โทรต่อสาธารณะ
- [x] privacy policy อยู่บน GitHub Pages แล้ว: https://zildjiean.github.io/WhatWAF/privacy-policy.html (ไฟล์ต้นฉบับคือ `docs/privacy-policy.html`)
- [ ] สร้าง zip ด้วย `./build.sh` แล้ว upload `dist/waf-detector-<version>.zip`

---

## 1. แท็บ Store listing

**Description** (รายละเอียดเต็ม)
```
WAF Detector shows which web application firewall (WAF), CDN or edge service is in front of the website you're viewing — with one click.

HOW IT WORKS
Open the popup on any website. WAF Detector sends a single request to that site and compares its HTTP response headers against a built-in list of known signatures. It shows every service it recognizes, plus the exact header that identified it.

WHAT IT RECOGNIZES
Around two dozen widely used WAF, anti-DDoS, CDN and hosting/edge platforms. Each result is labelled by type, so you can tell a security service from a delivery network. The full, up-to-date list of supported services is published in the project's GitHub repository.

PRIVACY FIRST
• Asks for access one site at a time — no blanket access to your browsing.
• Never sends your cookies with the check request.
• Collects nothing. No analytics, no tracking, no external servers.

GOOD TO KNOW
Detection is based on response headers. Some WAFs hide or strip their headers, so "no known signature found" does not mean a site is unprotected. CDN results show the delivery network; they don't confirm that a WAF is enabled.

Useful for security researchers, penetration testers, developers and anyone curious about how a website is protected.

Open source (MIT): https://github.com/zildjiean/WhatWAF
```

> ⚠️ **ห้ามใส่รายชื่อยี่ห้อใน description** — ครั้งแรกโดน reject ด้วยรหัส **Yellow Argon (keyword spam)**
> เพราะเขียนรายชื่อ 24 ยี่ห้อเรียงกัน (2026-11-12) ให้ใส่รายชื่อเต็มไว้ใน README บน GitHub แทน

| ช่อง | ค่า |
|---|---|
| Category | **Developer Tools** |
| Language | English |
| Store icon | `icons/icon128.png` (มีขอบ 16px ตามข้อแนะนำแล้ว) |
| Screenshots | `store/screenshot-1-detect.png`, `screenshot-2-permission.png`, `screenshot-3-honest.png`, `screenshot-4-dark.png` (1280×800, v1.5 UI; popup content comes from real checks) |
| Small promo tile | `store/promo-small-440x280.png` |
| Marquee promo tile | ไม่ต้องใส่ (ไม่บังคับ) |
| Homepage URL | https://github.com/zildjiean/WhatWAF |
| Support URL | https://github.com/zildjiean/WhatWAF/issues |

---

## 2. แท็บ Privacy practices

**Single purpose description**
```
Identify the web application firewall (WAF), CDN or edge service protecting the website in the current tab by inspecting that site's HTTP response headers.
```

**Permission justification — activeTab**
```
Used to read the URL of the current tab when the user clicks the extension icon, so the extension knows which website to check. No other tab data is accessed.
```

**Permission justification — Host permissions** (ช่องนี้ครอบคลุม `optional_host_permissions: <all_urls>`)
```
Host access is optional and requested at runtime, one site at a time, only when the user clicks "Allow & check" for the site they want to inspect. It is required so the extension can send a single HEAD/GET request to that site and read its HTTP response headers (e.g. cf-ray, x-iinfo), which cross-origin rules otherwise hide. Requests are sent without cookies, and the headers are only compared locally against built-in signatures; nothing is stored or transmitted elsewhere. The pattern <all_urls> is declared only because the user may check any website.
```

**Are you using remote code?** → **No, I am not using remote code**

**Data usage** — ไม่ต้องติ๊กหมวดข้อมูลใด
> Google นับว่าเป็นการ "collect" เมื่อข้อมูลถูกส่งออกจากเครื่องผู้ใช้ไปหาผู้พัฒนาหรือบุคคลที่สาม
> extension นี้ใช้ URL ของ tab แค่ในเครื่อง และ request เดียวที่ส่งออกไปก็ส่งตรงไปยังเว็บที่ผู้ใช้เลือกตรวจ
> ถ้าอยากระมัดระวังเป็นพิเศษจะติ๊ก **Web history** ก็ได้ ไม่ผิดกฎ แต่จะทำให้หน้า Store แสดงว่า extension เก็บข้อมูล

ติ๊กรับรองทั้ง 3 ข้อ:
- [x] I do not sell or transfer user data to third parties, outside of the approved use cases
- [x] I do not use or transfer user data for purposes that are unrelated to my item's single purpose
- [x] I do not use or transfer user data to determine creditworthiness or for lending purposes

**Privacy policy URL** → `https://zildjiean.github.io/WhatWAF/privacy-policy.html`

---

## 3. แท็บ Distribution

- Visibility: **Public** (หรือเลือก **Unlisted** ก่อน เพื่อทดสอบกับคนกลุ่มเล็ก)
- Regions: All regions

---

## หมายเหตุสำหรับ review

- หน้า Store: https://chromewebstore.google.com/detail/waf-detector/pdeecpdiafdmaehnabfdaofcdhiooofa
- ประวัติ: 1.4 เผยแพร่แล้วหลังแก้ description (2026-11-12) และส่ง 1.5 เข้า review ต่อ

- เนื่องจากประกาศ `<all_urls>` (แม้จะเป็นแบบ optional) review อาจใช้เวลาหลายวัน
- ถ้าโดน reject ให้อ่านเหตุผลในอีเมล ส่วนใหญ่แก้ได้ที่ข้อความ justification แล้วส่ง review ใหม่
- ทุกครั้งที่อัปเดตต้องเพิ่ม `version` ใน `manifest.json` ก่อนรัน `./build.sh`
