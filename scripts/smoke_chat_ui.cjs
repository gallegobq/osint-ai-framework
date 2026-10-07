// Isolated browser verification with synthetic API fixtures; no credentials or live queries.
const { readFileSync } = require("node:fs");
const assert = require("node:assert/strict");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");

(async () => {
  const browser = await chromium.launch({ channel: "msedge", headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const date = new Date().toISOString();
    const investigation = { id: 3, project_id: 1, title: "Caso sintético de chat", kind: "domain",
      operation_mode: "attack_surface", status: "active", priority: "low", updated_at: date, created_at: date };
    let run = null, reads = 0;
    const messages = [];
    await page.route("**/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (["/", "/app.js", "/styles.css"].includes(path)) {
        return route.fulfill({ contentType: path.endsWith(".js") ? "application/javascript" : path.endsWith(".css") ? "text/css" : "text/html",
          body: readFileSync(`app/web/${path === "/" ? "index.html" : path.slice(1)}`, "utf8") });
      }
      let body = [];
      if (path.endsWith("/auth/refresh")) body = { access_token: "synthetic-not-a-real-token" };
      else if (path.endsWith("/auth/me")) body = { id: 1, username: "Prueba local", is_superuser: true };
      else if (path.endsWith("/health/ready")) body = { status: "ready" };
      else if (path === "/api/v1/projects") body = [{ id: 1, name: "Prueba", status: "active", updated_at: date }];
      else if (path === "/api/v1/projects/1/investigations") body = [investigation];
      else if (path.endsWith("/chat")) {
        const request = route.request().postDataJSON();
        messages.push(request);
        if (request.prompt === "hola") body = { message: "¿Qué objetivo quieres investigar?", needs_clarification: true };
        else {
          run = { id: messages.length + 5, objective: request.prompt, status: "queued", created_at: date,
            policy: { chat: { analysis_type: "Infraestructura y exposición", message: "Voy a elegir fuentes pasivas.", decisions: ["Sólo consultas pasivas."] } },
            plan: { steps: [{ collector: "domain_dns", reason: "<img src=x onerror=alert(1)>" }] },
            result_summary: { succeeded_tools: 1, failed_tools: 1, evidence_ids: [1] } };
          reads = 0;
          body = { run, needs_clarification: false };
        }
      } else if (path.endsWith("/search-runs")) {
        if (run) { reads++; run.status = reads < 2 ? "running" : "partial"; body = [run]; }
      } else if (path === "/api/v1/investigations/3") body = investigation;
      else if (!path.startsWith("/api/v1/")) return route.abort();
      return route.fulfill({ json: body });
    });
    await page.goto("http://linterna.test/");
    await page.locator('[data-action="open-investigation"][data-id="3"]').first().click();
    await page.locator("#chat-prompt").waitFor();
    assert.equal(await page.locator("#chat-form select").count(), 0);
    await page.locator("#chat-authorization").check();
    await page.locator("#chat-prompt").fill("hola");
    await page.locator('#chat-form button[type="submit"]').click();
    await page.locator("#chat-notes").filter({ hasText: "¿Qué objetivo" }).waitFor();
    await page.locator("#chat-prompt").fill("Investiga example.com");
    await page.locator('#chat-form button[type="submit"]').click();
    await page.getByText("La consulta fue parcial:", { exact: false }).waitFor();
    assert.equal(await page.locator(".chat-assistant img").count(), 0);
    assert.equal(messages[1].parent_run_id, null);
    await page.locator("#chat-prompt").fill("Ahora revisa su reputación");
    await page.locator('#chat-form button[type="submit"]').click();
    await page.waitForFunction(() => document.querySelectorAll(".chat-user")[0]?.textContent.includes("Ahora revisa"));
    assert.equal(messages[2].parent_run_id, 7);
    assert.equal(messages[2].authorization_confirmed, true);
    await page.locator("#chat-title").scrollIntoViewIfNeeded();
    await page.screenshot({ path: "data/chat-smoke-desktop.png" });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: "data/chat-smoke-mobile.png" });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    assert.deepEqual(errors, []);
    console.log("Chat UI smoke passed: prompt-only form, clarification, polling, partial results, safe escaping, follow-up context, desktop/mobile.");
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
