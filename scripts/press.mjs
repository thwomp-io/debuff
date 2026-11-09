// Press a button in a real browser, the only place the Origin a browser really sends can be seen.
//   node press.mjs <playwright-dir> <url> <out.png> [expect-scanning|expect-updating]
// Rescan by default; expect-updating presses a row's Update instead. Fails if the press is refused, the page
// breaks policy, or the work doesn't finish.
import { createRequire } from "node:module";
import { join } from "node:path";

const [dir, url, out, expecting] = process.argv.slice(2);
const { chromium } = createRequire(join(dir, "package.json"))("playwright");
const browser = await chromium.launch({ chromiumSandbox: true });
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark" })).newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
let answer = 0;
page.on("response", (r) => {
  if (r.url().endsWith("/rescan") || r.url().endsWith("/update")) answer = r.status();
});
await page.goto(url, { waitUntil: "load" });
if (expecting === "expect-updating") {
  await page.locator(".update-all button").click();
  // Update all is pressed (the first amber button), so every row it covers says Updating… at once.
  await page.getByRole("button", { name: "Updating…" }).first().waitFor({ timeout: 15000 });
  // Then a rescan starts by itself.
  await page.getByRole("button", { name: "Scanning…" }).waitFor({ timeout: 30000 });
} else {
  await page.locator(".rescan button").click();
  if (expecting) await page.getByRole("button", { name: "Scanning…" }).waitFor({ timeout: 15000 });
}
await page.getByRole("button", { name: "Rescan", exact: true }).waitFor({ timeout: 300000 });
await page.screenshot({ path: out });
await browser.close();
if (answer !== 303) errors.push(`the press answered ${answer}, not 303`);
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
console.log("✓ the press worked");
