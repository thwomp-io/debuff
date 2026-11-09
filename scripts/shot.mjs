// The eye: render the console headlessly so the image can be read back. Uses Playwright from
// $PLAYWRIGHT_DIR, with the Chromium sandbox on, and only ever loads this console on loopback.
//   node shot.mjs <playwright-dir> <url> <out.png> <desktop|phone|WxH> <dark|light> [selectors to click, a||b]
import { createRequire } from "node:module";
import { join } from "node:path";

const [dir, url, out, viewport, colorScheme, click] = process.argv.slice(2);
const { chromium } = createRequire(join(dir, "package.json"))("playwright");
const sizes = { desktop: { width: 1440, height: 900 }, phone: { width: 390, height: 844 } };
let size = sizes[viewport];
if (!size) {
  const [width, height] = viewport.split("x").map(Number);
  size = { width, height };
}
const browser = await chromium.launch({ chromiumSandbox: true });
const page = await (await browser.newContext({ viewport: size, colorScheme, deviceScaleFactor: 2 })).newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
await page.goto(url, { waitUntil: "load" });
for (const sel of (click ?? "").split("||").filter(Boolean)) await page.click(sel);
// The page may not scroll sideways, and neither may the pane: it scrolls on its own, so a card clipped
// inside it never shows up on the document.
const overflow = await page.evaluate(() =>
  Math.max(...[document.documentElement, document.querySelector(".pane")].filter(Boolean).map((el) => el.scrollWidth - el.clientWidth)),
);
const overlaps = await page.evaluate(() => {
  const r = [...document.querySelectorAll(".card")].map((c) => c.getBoundingClientRect());
  let n = 0;
  for (let i = 0; i < r.length; i++)
    for (let j = i + 1; j < r.length; j++)
      if (r[i].left < r[j].right && r[j].left < r[i].right && r[i].top < r[j].bottom && r[j].top < r[i].bottom) n++;
  return n;
});
await page.screenshot({ path: out });
await browser.close();
if (overflow > 0) errors.push(`page overflows horizontally by ${overflow}px`);
if (overlaps) errors.push(`${overlaps} pairs of cards overlap`);
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
