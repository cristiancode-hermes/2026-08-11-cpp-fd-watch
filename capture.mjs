import puppeteer from 'puppeteer';
import { mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function captureCppTerminal() {
  const htmlPath = '/opt/data/cpp-projects/2026-08-11-cpp-fd-watch/screenshot.html';
  const assetsDir = '/opt/data/portafolio/public/assets';
  mkdirSync(assetsDir, { recursive: true });
  const slug = 'cpp-fd-watch';

  const browser = await puppeteer.launch({
    executablePath: '/opt/data/.agent-browser/browsers/chromium/chrome-linux/chrome',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });

  try {
    const page = await browser.newPage();

    // Desktop capture
    await page.setViewport({ width: 1440, height: 900 });
    await page.goto('file://' + htmlPath, { waitUntil: 'networkidle0', timeout: 15000 });
    await page.waitForSelector('.terminal', { timeout: 5000 });
    await new Promise(r => setTimeout(r, 1000));

    const terminalEl = await page.$('.terminal');
    const box = await terminalEl.boundingBox();
    console.log(`Terminal boundingBox: ${JSON.stringify(box)}`);

    const padding = 40;
    if (box.height + padding > 900) {
      await page.setViewport({ width: 1440, height: Math.ceil(box.height + padding + 60) });
    }

    await page.screenshot({
      path: join(assetsDir, `${slug}.png`),
      clip: {
        x: Math.max(0, box.x - 40),
        y: Math.max(0, box.y - 20),
        width: Math.min(box.width + 80, 1440),
        height: Math.min(box.height + 40, 900 + 60),
      },
    });

    // Mobile capture
    await page.setViewport({ width: 390, height: 844 });
    await page.goto('file://' + htmlPath, { waitUntil: 'networkidle0', timeout: 15000 });
    await page.waitForSelector('.terminal', { timeout: 5000 });
    await new Promise(r => setTimeout(r, 1000));

    const terminalEl2 = await page.$('.terminal');
    const box2 = await terminalEl2.boundingBox();

    await page.screenshot({
      path: join(assetsDir, `${slug}-m.png`),
      clip: {
        x: Math.max(0, box2.x - 20),
        y: Math.max(0, box2.y - 10),
        width: Math.min(box2.width + 40, 390),
        height: Math.min(box2.height + 20, 844),
      },
    });

    console.log('Screenshots captured successfully');
    console.log(`Desktop: ${join(assetsDir, `${slug}.png`)}`);
    console.log(`Mobile: ${join(assetsDir, `${slug}-m.png`)}`);
  } finally {
    await browser.close();
  }
}

captureCppTerminal().catch(err => {
  console.error('Capture failed:', err);
  process.exit(1);
});
