// Record a short walk through the console on sample data, as a video for scripts/tour.sh to turn into a GIF.
//   node tour.mjs <playwright-dir> <url> <video-dir> <dark|light>
import { createRequire } from "node:module";
import { join } from "node:path";

const [dir, url, videoDir, colorScheme] = process.argv.slice(2);
const { chromium } = createRequire(join(dir, "package.json"))("playwright");
const size = { width: 1280, height: 800 };
const browser = await chromium.launch({ chromiumSandbox: true });
const context = await browser.newContext({ viewport: size, colorScheme, recordVideo: { dir: videoDir, size } });
const page = await context.newPage();
const pause = (ms) => page.waitForTimeout(ms);

await page.goto(url, { waitUntil: "load" });
await pause(2200);
await page.locator(".card .findings summary").first().click();
await pause(1500);
await page.locator(".card .row summary").first().click();
await pause(3000);
await page.getByRole("link", { name: "Known exploited" }).click();
await pause(2000);
await page.getByRole("link", { name: "Updates" }).click();
await pause(2200);
await page.locator(".update-all button").click();
await page.getByRole("button", { name: "Scanning…" }).waitFor({ timeout: 30000 });
await pause(1500);
await page.getByRole("button", { name: "Rescan", exact: true }).waitFor({ timeout: 60000 });
await pause(1500);
await page.getByRole("link", { name: "Inbox" }).click();
await pause(2000);
await context.close();
await browser.close();
