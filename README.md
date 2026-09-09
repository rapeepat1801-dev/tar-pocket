# TAr POCKET — Authenticated finance app

โปรเจกต์นี้ต่อยอดจากไฟล์ HTML เดิมให้เป็น TAr POCKET พร้อมระบบสมาชิกและหลังบ้าน โดยใช้ Node.js core modules จึงไม่ต้องติดตั้ง dependency เพิ่ม

## ฟีเจอร์

- สมัครสมาชิกพร้อมตรวจรหัสผ่านสองช่องให้ตรงกัน
- ยืนยันสองชั้นด้วยรหัส TOTP 6 หลักจาก Google Authenticator หลังสมัครและทุกครั้งที่ล็อกอิน
- เก็บรหัสผ่านแบบ salted `scrypt` hash ใน `data/store.json`
- session แบบ HttpOnly cookie
- ข้อมูลรายรับ/รายจ่าย/เป้าหมาย/งบประมาณแยกตามบัญชีใน browser localStorage
- แนบสลิปกับรายการได้ทั้งอัปโหลดไฟล์ภาพหรือถ่ายจากกล้อง ระบบย่อภาพ บันทึกไว้กับรายการ และส่งให้ Groq Vision อ่านยอด/วันที่/ร้าน/หมวดหมู่เพื่อเติมฟอร์ม
- หลังบ้านสำหรับดูสมาชิก, สถิติ, ระงับ/เปิดใช้งานบัญชี และเปลี่ยนสิทธิ์ user/admin

## เริ่มใช้งาน

```powershell
npm start
```

เปิด [http://localhost:3000](http://localhost:3000)

บัญชีหลังบ้านเริ่มต้นสำหรับเดโม:

- อีเมล: `admin@tafinx.local`
- รหัสผ่าน: `Admin@12345`

สามารถกำหนดรหัสผ่านใหม่ก่อนเริ่มเซิร์ฟเวอร์ด้วย `TAFINX_ADMIN_PASSWORD`

## Groq Vision อ่านสลิป

สร้าง API key ที่ [Groq Console](https://console.groq.com/keys) แล้วตั้งค่าเป็น environment variable `GROQ_API_KEY` หรือ Render Secret File ชื่อ `tarpocket.key` ห้ามใส่คีย์ใน `public/index.html` หรือ commit ลง GitHub เด็ดขาด ระบบใช้ `qwen/qwen3.6-27b` เป็นค่าเริ่มต้น และเปลี่ยนรุ่นได้ด้วย `GROQ_VISION_MODEL` ตั้ง `FRONTEND_ORIGINS` เป็น URL ของเว็บ InfinityFree (คั่นหลาย URL ด้วย comma) เพื่อให้ล็อกอินและอ่านสลิปจากโดเมนนั้นได้

เมื่ออัปโหลดหรือถ่ายภาพ ระบบจะส่งภาพไปให้ backend อ่าน แล้วเติมยอดเงิน วันที่ รายละเอียด และหมวดหมู่ให้ตรวจสอบก่อนกด “บันทึกข้อมูล” หากอ่านไม่ชัดให้แก้ค่าด้วยตัวเองก่อนบันทึก

## Google Authenticator

ระบบไม่ได้ส่งรหัสไปทางอีเมลหรือ SMS แต่สร้างรหัส TOTP บน Google Authenticator โดยตรง ครั้งแรกหลังสมัครหรือเข้าสู่ระบบบัญชีที่ยังไม่ได้ตั้งค่า ระบบจะแสดง `Setup Key` ให้เพิ่มในแอป Google Authenticator แล้วกรอกรหัส 6 หลักล่าสุดเพื่อยืนยัน

ในโหมด development ระบบจะแสดงรหัส TOTP ปัจจุบันในหน้าเว็บและ terminal เพื่อให้ทดสอบได้ทันที ส่วน production จะไม่แสดงรหัสทดสอบ และควรใช้ HTTPS, rate limiting, secret/env แยก รวมถึงเพิ่ม recovery codes ก่อนใช้งานจริง

## สลิปและหลักฐานการโอน

เปิดหน้า “รายการเงิน” แล้วกดเพิ่มหรือแก้ไขรายการ จากนั้นเลือก “อัปโหลดสลิป” หรือ “ถ่ายภาพสลิป” ภาพจะถูกย่อขนาดและเก็บในรายการเดียวกันบน browser ของบัญชีที่กำลังใช้งาน พร้อมเรียก AI อ่านข้อมูล เมื่อบันทึกแล้วจะมีปุ่ม “ดูสลิป” ในรายการนั้น

## InfinityFree

InfinityFree Free Hosting รองรับ HTML/PHP แต่ไม่รองรับ Node.js ดังนั้นให้อัปโหลดเฉพาะไฟล์ในโฟลเดอร์ `infinityfree-upload` ไปไว้ใน `htdocs` และให้ backend/API/Groq ทำงานบน Render ต่อไป จากนั้นเพิ่ม URL ของโดเมน InfinityFree ใน `FRONTEND_ORIGINS` บน Render เช่น `https://ชื่อเว็บ.infinityfreeapp.com` ก่อนใช้งานจริง
