# Sandworm report viewer / หน้าอ่านรายงาน

The `web/` folder is a static, browser-local report viewer. Actual engines run through the CLI documented in README; this page never executes scanners, model calls or document converters.

```sh
python -m http.server 8787 --bind 127.0.0.1 --directory web
```

Open `http://127.0.0.1:8787`. Load the bundled synthetic report or import the normalized `report.json` produced by this project's CLI. Raw upstream reports need their documented importer first. The fixture badge identifies demo data even where an actual upstream engine generated that synthetic example. Live engine evidence is recorded separately under `reports/`.

รายงานนำเข้าต้องเป็น UTF-8 JSON ไม่มี BOM ขนาดไม่เกิน 2 MiB และเป็น envelope ของโปรเจกต์นี้ (`schema_version: 1`, `project`, `mode`, `summary`) ไม่รับ key ซ้ำ ตัวเลขเกินขอบเขต หรือโครงสร้างลึกเกิน 40 ชั้น

The viewer shows at most 300 matching finding cards at once; full validated report JSON remains available. Imported text is rendered using textContent, never HTML. It does not upload or store reports. Export preserves the imported report fields and requires the review checkbox; it is not another redaction layer. A hash detects changed text, not trustworthiness or authenticity.

The cover SVG is an original illustration, not a browser screenshot. Embedded fonts are Chakra Petch, Anuphan and JetBrains Mono under OFL; license texts are in `web/fonts/`. Theme graphics and layout are original Sandworm work.

```sh
node --test tests/web.test.cjs
```
