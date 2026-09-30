import { test, expect, eq, sleep } from './harness.mjs';
import { SEED, MAIN_PAGES } from './fixtures.mjs';

const RESPONSIVE = [...MAIN_PAGES, 'results'];   // results-print is a fixed print layout

test('layout: no page scrolls sideways at phone, tablet or desktop width', async ({ page, base }) => {
  await page.seedAssessment(base, SEED);
  const bad = [];
  for (const p of RESPONSIVE) {
    for (const w of [320, 390, 768, 1280]) {
      await page.goto(base, `/${p}.html`, { width: w });
      const over = await page.eval('document.documentElement.scrollWidth - document.documentElement.clientWidth');
      if (over > 0) bad.push(`${p}@${w}px (+${over}px)`);
    }
  }
  eq(bad, [], 'pages with horizontal overflow');
});

test('layout: scroll-reveal never leaves content invisible (regression: 13,000px mapping table on a phone)', async ({ page, base }) => {
  for (const p of MAIN_PAGES) {
    // Real motion settings, so the reveal effect actually runs; scroll like a visitor would.
    await page.goto(base, `/${p}.html`, { width: 390, height: 800, reduceMotion: false });
    for (let y = 0; y < 16000; y += 500) { await page.eval(`window.scrollTo(0, ${y}); true`); await sleep(70); }
    await sleep(800);
    const stuck = await page.eval("[...document.querySelectorAll('.reveal')].filter((e) => getComputedStyle(e).display !== 'none' && getComputedStyle(e).opacity === '0').map((e) => e.className)");
    eq(stuck, [], `${p}: elements still invisible after scrolling`);
  }
});

test('layout: scroll-reveal shows an element taller than ten screens (13,000px) once it is scrolled into view', async ({ page, base }) => {
  // Tests the mechanism itself, independent of any page's content: a ratio-based threshold can never be met by such an element.
  await page.goto(base, '/index.html', { width: 390, height: 800, reduceMotion: false });
  await page.eval(`(() => { const el = document.createElement('div'); el.id = 'tall'; el.className = 'reveal'; el.style.height = '13000px';
    document.querySelector('main').appendChild(el); window.GHReveal.observe(el); return true; })()`);
  eq(await page.eval("getComputedStyle(document.getElementById('tall')).opacity"), '0', 'starts hidden');
  await page.eval("document.getElementById('tall').scrollIntoView(); true");
  await page.waitFor("getComputedStyle(document.getElementById('tall')).opacity === '1'", 5000);
});

test('layout: the mapping table is readable as cards on a phone', async ({ page, base }) => {
  await page.goto(base, '/mapping.html', { width: 390, height: 800, reduceMotion: false });
  await page.eval("document.getElementById('view-table').scrollIntoView(); true");
  await sleep(600);
  const info = await page.eval(`(() => {
    const card = document.querySelector('#view-table .card');
    const td = document.querySelector('#tableBody td:nth-child(2)');
    return { opacity: getComputedStyle(card).opacity, rows: document.querySelectorAll('#tableBody tr[data-i]').length, label: td && td.dataset.label, display: getComputedStyle(document.querySelector('#tableBody tr')).display };
  })()`);
  eq(info.opacity, '1', 'table card opacity');
  eq(info.rows, 153, 'rows rendered');
  eq(info.label, 'Ghana Requirement', 'cell label used in card layout');
  eq(info.display, 'block', 'rows are cards on a phone');
});

test('navigation: mobile menu opens, traps focus, closes on Escape and returns focus', async ({ page, base }) => {
  await page.goto(base, '/index.html', { width: 390, height: 800 });
  eq(await page.eval("getComputedStyle(document.getElementById('desktopNav')).display"), 'none', 'desktop nav hidden on phones');
  eq(await page.eval("getComputedStyle(document.getElementById('drawer')).visibility"), 'hidden', 'closed drawer is not focusable');
  await page.eval("document.getElementById('menuBtn').focus(); document.getElementById('menuBtn').click(); true");
  await page.waitFor("document.getElementById('drawer').classList.contains('open')");
  eq(await page.eval("document.getElementById('menuBtn').getAttribute('aria-expanded')"), 'true');
  expect(await page.waitFor("document.getElementById('drawer').contains(document.activeElement)"), 'focus moved into the drawer');
  const links = await page.eval("[...document.querySelectorAll('#drawer .nav-link')].map((a) => a.textContent.trim())");
  eq(links, ['Dashboard', 'Control Mapping', 'Assessment', 'Results', 'Action Plan', 'Gap Analysis']);
  await page.key('Escape', 'Escape', 27);
  await page.waitFor("!document.getElementById('drawer').classList.contains('open')");
  eq(await page.eval("document.activeElement.id"), 'menuBtn', 'focus returns to the menu button');
});
