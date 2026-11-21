/**
 * The README's pictures, taken from a running demo: ./run_demo.sh, then
 *
 *   npm --prefix web run screenshots
 *
 * BASE is where the demo is (http://localhost:8080), PASSWORD its password (demodemo), OUT
 * where the pictures go (docs/screenshots), ONLY a comma-separated list of names to take.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Browser, findChromium, waitFor } from "../cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..", "..");
const BASE = process.env.BASE ?? "http://localhost:8080";
const PASSWORD = process.env.PASSWORD ?? "demodemo";
const OUT = process.env.OUT ?? join(root, "docs", "screenshots");
const ONLY = (process.env.ONLY ?? "").split(",").filter(Boolean);
const SCALE = Number(process.env.SCALE ?? 2);

const chromium = findChromium();
if (!chromium) {
  console.error("No Chromium or Chrome found; set CHROMIUM to one.");
  process.exit(2);
}

const port = await new Promise((done) => {
  const s = createServer().listen(0, () => {
    const { port } = s.address();
    s.close(() => done(port));
  });
});
const profile = mkdtempSync(join(tmpdir(), "f2b-shots-"));
const browser = await Browser.launch({ chromium, port, profile, base: BASE });
mkdirSync(OUT, { recursive: true });

const step = (m) => console.log(`==> ${m}`);

try {
  await browser.send("Emulation.setTimezoneOverride", { timezoneId: "UTC" });
  await browser.send("Emulation.setLocaleOverride", { locale: "en-US" });
  await browser.viewport(1280, 900, SCALE);
  await browser.scheme("light");

  step(`signing in at ${BASE}`);
  await browser.load(`${BASE}/login`);
  const status = await browser.eval(
    `fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: ${JSON.stringify(PASSWORD)} }) }).then((r) => r.status)`,
  );
  if (status !== 204) throw new Error(`signing in answered ${status}`);

  /** Waits until no dummy is left on the page and the fonts are in. */
  const settled = () =>
    waitFor(async () =>
      (await browser.eval(
        "document.fonts.status === 'loaded' && document.querySelectorAll('.dummy').length === 0",
      ))
        ? true
        : undefined,
    );

  const shots = [
    { name: "overview", path: "/" },
    { name: "overview-dark", path: "/", scheme: "dark" },
    { name: "bans", path: "/bans" },
    { name: "history", path: "/history" },
    { name: "config", path: "/config" },
    {
      name: "filter",
      path: "/config/filters/caddy-scanners.local",
      then: async () => {
        await browser.eval(
          `[...document.querySelectorAll("button")].find((b) => b.textContent.includes("Run fail2ban-regex")).click()`,
        );
        await waitFor(async () =>
          (await browser.eval(`document.body.textContent.includes("matched")`))
            ? true
            : undefined,
        );
      },
      full: true,
    },
    { name: "log", path: "/log" },
    { name: "phone", path: "/", phone: true },
  ];

  for (const shot of shots) {
    if (ONLY.length && !ONLY.includes(shot.name)) continue;
    step(shot.name);
    await browser.scheme(shot.scheme ?? "light");
    if (shot.phone) await browser.viewport(390, 844, 3, true);
    else await browser.viewport(1280, 900, SCALE);
    await browser.open(shot.path);
    await settled();
    await shot.then?.();
    await new Promise((r) => setTimeout(r, 400));
    let clip;
    if (shot.full) {
      const height = await browser.eval(
        "document.documentElement.scrollHeight",
      );
      await browser.viewport(1280, Math.min(height, 2400), SCALE);
      await new Promise((r) => setTimeout(r, 300));
    }
    writeFileSync(join(OUT, `${shot.name}.png`), await browser.png(clip));
  }
  step(`written to ${OUT}`);
} finally {
  browser.close();
  // Chromium is still writing its profile as it exits.
  await new Promise((r) => setTimeout(r, 500));
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {}
}
