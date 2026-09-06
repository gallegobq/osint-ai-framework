const API = "/api/v1";

const state = {
  accessToken: sessionStorage.getItem("linterna_access_token"),
  refreshToken: localStorage.getItem("linterna_refresh_token"),
  user: null,
  projects: [],
  investigations: new Map(),
  currentProject: null,
  currentInvestigation: null,
  view: "dashboard",
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const loginView = $("#login-view");
const workspaceView = $("#workspace-view");
const loginForm = $("#login-form");
const loginError = $("#login-error");
const content = $("#app-content");

const labels = {
  active: "Activo", archived: "Archivado", draft: "Borrador", paused: "Pausada",
  completed: "Completada", low: "Baja", medium: "Media", high: "Alta",
  critical: "Crítica", person: "Persona", company: "Empresa", domain: "Dominio",
  mixed: "Mixta", queued: "En cola", running: "En curso", succeeded: "Completada",
  partial: "Parcial", failed: "Fallida", note: "Nota", todo: "Pendiente",
  in_progress: "En curso", blocked: "Bloqueada", done: "Completada",
  informational: "Informativa", open: "Abierto", triaged: "Clasificado",
  accepted: "Aceptado", resolved: "Resuelto", false_positive: "Falso positivo",
  attack_surface: "Superficie de ataque", incident_response: "Respuesta a incidentes",
  pentest: "Pentesting autorizado",
  playbook: "Playbook", runbook: "Runbook", standard: "Estándar",
  incident: "Incidente", threat_intel: "Inteligencia",
};

const operationModeHelp = {
  attack_surface: "Descubrimiento y seguimiento pasivo de activos expuestos.",
  incident_response: "Enriquecimiento de IOC, cronología y preservación de evidencia.",
  pentest: "Pruebas activas limitadas por autorización, alcance y ventana temporal.",
};

function escapeHtml(value) {
  const span = document.createElement("span");
  span.textContent = value ?? "";
  return span.innerHTML;
}

function label(value) { return labels[value] || String(value || "—"); }
function formatDate(value, detail = false) {
  if (!value) return "Sin fecha";
  return new Intl.DateTimeFormat("es-CO", detail
    ? { dateStyle: "medium", timeStyle: "short" }
    : { day: "2-digit", month: "short", year: "numeric" }).format(new Date(value));
}
function truncate(value, length = 170) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, length).trim()}…` : text;
}

function setTokens(tokens) {
  state.accessToken = tokens.access_token;
  state.refreshToken = tokens.refresh_token;
  sessionStorage.setItem("linterna_access_token", tokens.access_token);
  localStorage.setItem("linterna_refresh_token", tokens.refresh_token);
}

function clearSession() {
  state.accessToken = null;
  state.refreshToken = null;
  state.user = null;
  state.projects = [];
  state.investigations.clear();
  sessionStorage.removeItem("linterna_access_token");
  localStorage.removeItem("linterna_refresh_token");
}

async function refreshAccessToken() {
  if (!state.refreshToken) return false;
  const response = await fetch(`${API}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: state.refreshToken }),
  });
  if (!response.ok) return false;
  setTokens(await response.json());
  return true;
}

async function api(path, options = {}, retry = true) {
  const headers = new Headers(options.headers || {});
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (state.accessToken) headers.set("Authorization", `Bearer ${state.accessToken}`);
  const response = await fetch(`${API}${path}`, { ...options, headers });
  if (response.status === 401 && retry && (await refreshAccessToken())) return api(path, options, false);
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const details = payload?.error?.details?.[0]?.message;
    throw new Error(details || payload?.error?.message || `La solicitud falló (${response.status}).`);
  }
  if (response.status === 204) return null;
  return response.json();
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.style.background = error ? "#8e2f1d" : "";
  toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.hidden = true; }, 4200);
}

function showLogin(message = "") {
  workspaceView.hidden = true;
  loginView.hidden = false;
  loginError.textContent = message;
  loginError.hidden = !message;
}

function showWorkspace() {
  loginView.hidden = true;
  workspaceView.hidden = false;
  $("#user-name").textContent = state.user.username;
  $("#user-initial").textContent = state.user.username.slice(0, 1).toUpperCase();
}

function setHeader(title, breadcrumb = "Espacio de trabajo /") {
  $("#view-title").textContent = title;
  $("#breadcrumb").textContent = breadcrumb;
}

function setActiveNav(view) {
  state.view = view;
  $$(".nav-item[data-view]").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
}

function loading() { content.innerHTML = `<div class="loading">Preparando el espacio de trabajo…</div>`; }

async function ensureInvestigations(force = false) {
  await Promise.all(state.projects.map(async (project) => {
    if (!force && state.investigations.has(project.id)) return;
    const items = await api(`/projects/${project.id}/investigations`);
    state.investigations.set(project.id, items);
  }));
}

function allInvestigations() {
  return [...state.investigations.values()].flat().sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
}

function projectCard(project, index) {
  const count = state.investigations.get(project.id)?.length || 0;
  return `<article class="project-card clickable" data-action="open-project" data-id="${project.id}" tabindex="0">
    <span class="card-index">${String(index + 1).padStart(2, "0")}</span>
    <h4>${escapeHtml(project.name)}</h4>
    <p>${escapeHtml(truncate(project.description || "Sin descripción todavía.", 120))}</p>
    <footer><span>${count} ${count === 1 ? "investigación" : "investigaciones"}</span><span>${formatDate(project.updated_at)}</span></footer>
  </article>`;
}

async function renderDashboard() {
  setActiveNav("dashboard");
  setHeader("Panel de investigación");
  loading();
  await ensureInvestigations();
  const investigations = allInvestigations();
  content.innerHTML = `
    <section class="hero-row">
      <div><p class="eyebrow ink">Panorama operativo</p><h2>Todo lo importante,<br />a la vista.</h2></div>
      <button class="button button-primary" data-action="new-project" type="button">Nuevo proyecto <span>＋</span></button>
    </section>
    <section class="stats" aria-label="Resumen">
      <article><span>Proyectos</span><strong>${state.projects.length}</strong><small>visibles para ti</small></article>
      <article><span>Investigaciones</span><strong>${investigations.length}</strong><small>${investigations.filter((item) => item.status === "active").length} activas ahora</small></article>
      <article class="status-stat"><span>Estado del sistema</span><strong><i></i>Operativo</strong><small>API y servicios locales</small></article>
    </section>
    <section class="section-block">
      <div class="section-heading"><div><p class="section-kicker">Actividad</p><h3>Tus proyectos</h3></div><button class="back-button" data-view-link="projects" type="button">Ver todos <span>→</span></button></div>
      <div class="project-grid">${state.projects.length ? state.projects.slice(0, 6).map(projectCard).join("") : `<div class="empty-state"><strong>No hay proyectos todavía.</strong><br />Crea el primero para organizar tu investigación.</div>`}</div>
    </section>
    ${investigations.length ? `<section class="section-block recent-block"><div class="section-heading"><div><p class="section-kicker">Continuar</p><h3>Investigaciones recientes</h3></div></div><div class="list-stack">${investigations.slice(0, 4).map(investigationListItem).join("")}</div></section>` : ""}`;
}

function investigationListItem(item) {
  const project = state.projects.find((candidate) => candidate.id === item.project_id);
  return `<article class="list-card clickable" data-action="open-investigation" data-id="${item.id}" tabindex="0">
    <div><div class="tag-row"><span class="badge ${item.status}">${label(item.status)}</span> <span class="badge ${item.priority}">${label(item.priority)}</span> <span class="badge">${label(item.operation_mode)}</span></div><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(project?.name || "Proyecto")} · ${label(item.kind)}</p></div>
    <aside><strong>→</strong><small>${formatDate(item.updated_at)}</small></aside>
  </article>`;
}

function operationBanner(investigation) {
  const pentest = investigation.operation_mode === "pentest";
  const windowText = pentest
    ? `${formatDate(investigation.engagement_start_at, true)} — ${formatDate(investigation.engagement_end_at, true)}`
    : "Solo fuentes pasivas";
  return `<section class="operation-banner ${pentest ? "pentest" : ""}"><div><strong>${label(investigation.operation_mode)}</strong><span>${escapeHtml(operationModeHelp[investigation.operation_mode] || "Modo operativo controlado por el servidor.")}</span></div><small>${escapeHtml(windowText)}</small></section>`;
}

async function renderProjects() {
  setActiveNav("projects");
  setHeader("Proyectos", "Espacio de trabajo / Organización /");
  loading();
  await ensureInvestigations();
  content.innerHTML = `<section class="page-head"><div><p class="section-kicker">Organización</p><h2>Proyectos</h2><p class="muted">Agrupa investigaciones por objetivo, equipo o alcance autorizado.</p></div><button class="button button-primary" data-action="new-project" type="button">Nuevo proyecto <span>＋</span></button></section>
    <div class="project-grid">${state.projects.length ? state.projects.map(projectCard).join("") : `<div class="empty-state"><strong>Tu mesa está despejada.</strong><br />Crea un proyecto para comenzar.</div>`}</div>`;
}

async function renderInvestigations() {
  setActiveNav("investigations");
  setHeader("Investigaciones", "Espacio de trabajo / Casos /");
  loading();
  await ensureInvestigations(true);
  const investigations = allInvestigations();
  content.innerHTML = `<section class="page-head"><div><p class="section-kicker">Casos</p><h2>Investigaciones</h2><p class="muted">Todos los casos a los que tienes acceso, ordenados por actividad reciente.</p></div>${state.projects.length ? `<button class="button button-primary" data-action="new-investigation" type="button">Nueva investigación <span>＋</span></button>` : ""}</section>
    <div class="list-stack">${investigations.length ? investigations.map(investigationListItem).join("") : `<div class="empty-state"><strong>Aún no hay investigaciones.</strong><br />Abre un proyecto y define el primer caso.</div>`}</div>`;
}

async function renderKnowledge(projectId = null) {
  setActiveNav("knowledge");
  setHeader("Linterna SOC", "Espacio de trabajo / Conocimiento / ");
  const selectedId = Number(projectId || state.currentProject?.id || state.projects[0]?.id || 0);
  const selectedProject = state.projects.find((item) => item.id === selectedId);
  loading();
  const documents = selectedProject ? await api(`/projects/${selectedId}/soc-knowledge/documents`) : [];
  content.innerHTML = `<section class="page-head"><div><p class="section-kicker">Copiloto defensivo con RAG</p><h2>Linterna SOC</h2><p class="muted">Consulta playbooks, runbooks e inteligencia interna con respuestas trazables. Cada afirmación debe citar un fragmento recuperado.</p></div></section>
    ${state.projects.length ? `<label class="knowledge-project">Base de conocimiento del proyecto<select id="knowledge-project-select">${state.projects.map((project) => `<option value="${project.id}" ${project.id === selectedId ? "selected" : ""}>${escapeHtml(project.name)}</option>`).join("")}</select></label>
    <div class="knowledge-grid"><section class="surface"><div class="surface-head"><div><h3>Preguntar a Linterna</h3><p>La respuesta se limita al conocimiento indexado</p></div></div><div class="surface-body"><form id="rag-query-form" class="knowledge-form"><input name="project_id" type="hidden" value="${selectedId}" /><label>Pregunta SOC<textarea name="question" minlength="5" maxlength="4000" rows="4" required placeholder="Ej. ¿Qué pasos de contención exige nuestro playbook ante un endpoint comprometido?"></textarea></label><button class="button button-dark" type="submit">Consultar con citas <span>→</span></button></form><div id="rag-answer" class="rag-answer" hidden></div></div></section>
    <section class="surface"><div class="surface-head"><div><h3>Entrenar el contexto</h3><p>Incorpora texto autorizado y con procedencia</p></div></div><div class="surface-body"><form id="knowledge-ingest-form" class="knowledge-form"><input name="project_id" type="hidden" value="${selectedId}" /><label>Título<input name="title" minlength="2" maxlength="255" required placeholder="Playbook de respuesta EDR" /></label><div class="form-row"><label>Tipo<select name="source_type"><option value="playbook">Playbook</option><option value="runbook">Runbook</option><option value="standard">Estándar</option><option value="incident">Incidente revisado</option><option value="threat_intel">Inteligencia de amenazas</option><option value="note">Nota</option></select></label><label>Origen o URL<input name="source_uri" maxlength="2048" placeholder="Repositorio, versión o URL" /></label></div><label>Contenido<textarea name="document_content" minlength="50" maxlength="500000" rows="8" required placeholder="Pega aquí contenido revisado y autorizado. No incluyas secretos."></textarea></label><button class="button button-primary" type="submit">Indexar conocimiento <span>＋</span></button></form></div></section></div>
    <section class="section-block"><div class="section-heading"><div><p class="section-kicker">Corpus activo</p><h3>${documents.length} ${documents.length === 1 ? "documento" : "documentos"}</h3></div></div><div class="list-stack">${documents.length ? documents.map((document) => `<article class="list-card"><div><div class="tag-row"><span class="badge">${escapeHtml(label(document.source_type))}</span><span class="badge succeeded">Indexado</span></div><h4>${escapeHtml(document.title)}</h4><p>${document.chunk_count} fragmentos · ${escapeHtml(document.embedding_model)}${document.source_uri ? ` · ${escapeHtml(document.source_uri)}` : ""}</p></div><aside><strong>K${document.id}</strong><small>${formatDate(document.created_at)}</small></aside></article>`).join("") : `<div class="empty-state"><strong>La base SOC está vacía.</strong><br />Añade el primer playbook o runbook revisado.</div>`}</div></section>` : `<div class="empty-state"><strong>Necesitas un proyecto.</strong><br />Crea uno antes de construir la base de conocimiento SOC.</div>`}`;
}

async function renderProject(projectId) {
  const project = state.projects.find((item) => item.id === Number(projectId));
  if (!project) return renderProjects();
  state.currentProject = project;
  setActiveNav("projects");
  setHeader(project.name, "Espacio de trabajo / Proyectos /");
  loading();
  const investigations = await api(`/projects/${project.id}/investigations`);
  state.investigations.set(project.id, investigations);
  content.innerHTML = `<button class="back-button" data-view-link="projects" type="button">← Volver a proyectos</button>
    <section class="page-head"><div><p class="section-kicker">Proyecto · ${escapeHtml(project.slug)}</p><h2>${escapeHtml(project.name)}</h2><p class="muted">${escapeHtml(project.description || "Sin descripción definida.")}</p></div><div class="page-actions"><span class="badge ${project.status}">${label(project.status)}</span><button class="button button-primary" data-action="new-investigation" data-project-id="${project.id}" type="button">Nueva investigación <span>＋</span></button></div></section>
    <div class="project-detail-grid"><section class="surface"><div class="surface-head"><div><h3>Investigaciones</h3><p>${investigations.length} ${investigations.length === 1 ? "caso registrado" : "casos registrados"}</p></div></div><div class="surface-body"><div class="list-stack">${investigations.length ? investigations.map(investigationListItem).join("") : `<div class="inline-empty">Este proyecto aún no tiene investigaciones.</div>`}</div></div></section>
    <aside class="surface scope-card"><p class="section-kicker">Ficha local</p><h3>Alcance del proyecto</h3><p>${escapeHtml(project.description || "Añade una descripción para dejar claros el objetivo y los límites de este espacio.")}</p><dl><div><dt>Propietario</dt><dd>Usuario #${project.owner_id}</dd></div><div><dt>Creado</dt><dd>${formatDate(project.created_at)}</dd></div><div><dt>Estado</dt><dd>${label(project.status)}</dd></div><div><dt>Casos</dt><dd>${investigations.length}</dd></div></dl></aside></div>`;
}

async function renderInvestigation(investigationId) {
  let investigation = allInvestigations().find((item) => item.id === Number(investigationId));
  if (!investigation) investigation = await api(`/investigations/${Number(investigationId)}`);
  const project = state.projects.find((item) => item.id === investigation.project_id);
  state.currentInvestigation = investigation;
  state.currentProject = project;
  setActiveNav("investigations");
  setHeader(investigation.title, `Espacio de trabajo / ${project?.name || "Proyecto"} /`);
  loading();
  const [evidence, runs, tasks, findings, schedules] = await Promise.all([
    api(`/investigations/${investigation.id}/evidence`),
    api(`/investigations/${investigation.id}/search-runs`),
    api(`/investigations/${investigation.id}/tasks`),
    api(`/investigations/${investigation.id}/findings`),
    api(`/investigations/${investigation.id}/search-schedules`),
  ]);
  const latestRuns = [...runs].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  content.innerHTML = `<button class="back-button" data-action="open-project" data-id="${investigation.project_id}" type="button">← Volver a ${escapeHtml(project?.name || "proyecto")}</button>
    <section class="page-head investigation-head"><div><div class="tag-row"><span class="badge ${investigation.status}">${label(investigation.status)}</span><span class="badge ${investigation.priority}">${label(investigation.priority)}</span><span class="badge">${label(investigation.kind)}</span><span class="badge">${label(investigation.operation_mode)}</span></div><h2>${escapeHtml(investigation.title)}</h2><p class="muted">${escapeHtml(investigation.description || "Sin descripción de caso.")}</p></div><div class="page-actions"><button class="button button-quiet" data-action="download-report" data-id="${investigation.id}" type="button">Reporte</button><button class="button button-dark" data-action="new-search" data-id="${investigation.id}" type="button">Buscar fuentes <span>◎</span></button></div></section>
    ${operationBanner(investigation)}
    <section class="stats compact-stats" aria-label="Resumen del caso"><article><span>Evidencias</span><strong>${evidence.length}</strong><small>registros trazables</small></article><article><span>Hallazgos</span><strong>${findings.length}</strong><small>${findings.filter((item) => !["resolved","false_positive"].includes(item.status)).length} abiertos</small></article><article><span>Vigilancias</span><strong>${schedules.filter((item) => item.enabled).length}</strong><small>${runs.length} búsquedas ejecutadas</small></article></section>
    <div class="workbench"><div class="stack-column"><section class="surface"><div class="surface-head"><div><h3>Hallazgos SOC</h3><p>Severidad, estado, confianza y remediación</p></div><button class="back-button" data-action="new-finding" data-id="${investigation.id}" type="button">＋ Crear</button></div><div class="surface-body">${findings.length ? findings.map(findingItem).join("") : `<div class="inline-empty">Aún no hay hallazgos clasificados.</div>`}</div></section><section class="surface"><div class="surface-head"><div><h3>Evidencia</h3><p>Registros conservados con procedencia y huella digital</p></div><button class="back-button" data-action="new-evidence" data-id="${investigation.id}" type="button">＋ Añadir</button></div><div class="surface-body">${evidence.length ? evidence.map(evidenceItem).join("") : `<div class="inline-empty">No hay evidencia registrada todavía.<br />Añade una nota manual o inicia una búsqueda.</div>`}</div></section></div>
      <aside><section class="surface"><div class="surface-head"><div><h3>Acciones</h3><p>Herramientas del caso</p></div></div><div class="surface-body action-menu"><button class="action-card" data-action="new-search" data-id="${investigation.id}" type="button"><span>◎</span><span><strong>Búsqueda OSINT</strong><small>Ejecución única o programada</small></span><span>→</span></button><button class="action-card" data-action="new-finding" data-id="${investigation.id}" type="button"><span>!</span><span><strong>Hallazgo SOC</strong><small>Clasifica severidad y estado</small></span><span>→</span></button><button class="action-card" data-action="download-report" data-id="${investigation.id}" type="button"><span>↓</span><span><strong>Reporte narrativo</strong><small>Inglés claro, formato Markdown</small></span><span>→</span></button><button class="action-card" data-action="download-stix" data-id="${investigation.id}" type="button"><span>⇄</span><span><strong>STIX 2.1</strong><small>MISP y OpenCTI</small></span><span>↓</span></button><button class="action-card" data-action="download-siem" data-id="${investigation.id}" type="button"><span>≡</span><span><strong>SIEM NDJSON</strong><small>Ingesta de eventos</small></span><span>↓</span></button></div></section>
      <section class="surface runs-surface"><div class="surface-head"><div><h3>Búsquedas recientes</h3><p>Estado del orquestador</p></div><button class="back-button" data-action="refresh-investigation" data-id="${investigation.id}" type="button" aria-label="Actualizar">↻</button></div><div class="surface-body">${latestRuns.length ? `<div class="run-list">${latestRuns.slice(0,5).map(runItem).join("")}</div>` : `<div class="inline-empty">Sin búsquedas todavía.</div>`}</div></section></aside></div>`;
}

function findingItem(item) {
  return `<article class="evidence-item"><header><div><span class="badge ${item.severity}">${label(item.severity)}</span><span class="badge ${item.status}">${label(item.status)}</span><h4>${escapeHtml(item.title)}</h4></div><small>F${item.id}</small></header><p>${escapeHtml(truncate(item.description, 360))}</p><small>Confianza ${Math.round(Number(item.confidence) * 100)}% · ${formatDate(item.updated_at, true)}</small></article>`;
}

function evidenceItem(item) {
  return `<article class="evidence-item"><header><div><span class="badge">${escapeHtml(label(item.kind))}</span><h4>${escapeHtml(item.title)}</h4></div><small>E${item.id}</small></header><p>${escapeHtml(truncate(item.content, 420))}</p><small>Fuente registrada · ${formatDate(item.collected_at, true)}</small></article>`;
}

function runItem(run) {
  const target = run.targets?.[0];
  return `<article class="run-item"><header><span class="badge ${run.status}">${label(run.status)}</span><small>${formatDate(run.created_at)}</small></header><p><strong>${escapeHtml(target?.value || "Objetivo")}</strong><br />${escapeHtml(truncate(run.objective, 100))}</p>${run.error ? `<p class="form-error">${escapeHtml(truncate(run.error, 130))}</p>` : ""}</article>`;
}

function openDialog(id) {
  const dialog = $(`#${id}`);
  $(".dialog-error", dialog).hidden = true;
  dialog.showModal();
  setTimeout(() => $("input:not([type=hidden]), textarea", dialog)?.focus(), 40);
}

function openNewProject() { $("#project-form").reset(); openDialog("project-dialog"); }
function openNewInvestigation(projectId = null) {
  if (!state.projects.length) return showToast("Crea un proyecto antes de abrir una investigación.", true);
  const selectedId = Number(projectId || state.currentProject?.id || state.projects[0].id);
  $("#investigation-form").reset();
  $("#investigation-project-id").innerHTML = state.projects.map((project) =>
    `<option value="${project.id}">${escapeHtml(project.name)}</option>`).join("");
  $("#investigation-project-id").value = selectedId;
  syncInvestigationMode();
  openDialog("investigation-dialog");
}
function openNewEvidence(investigationId) {
  $("#evidence-form").reset();
  $("#evidence-investigation-id").value = investigationId;
  $("#evidence-kind").value = "note"; $("#evidence-collector").value = "manual"; $("#evidence-source-type").value = "web";
  openDialog("evidence-dialog");
}
function openNewFinding(investigationId) {
  $("#finding-form").reset();
  $("#finding-investigation-id").value = investigationId;
  $("#finding-confidence").value = "0.75";
  openDialog("finding-dialog");
}
function openNewSearch(investigationId) {
  $("#search-form").reset();
  $("#search-schedule-fields").hidden = true;
  $("#search-investigation-id").value = investigationId;
  const investigation = allInvestigations().find((item) => item.id === Number(investigationId)) || state.currentInvestigation;
  const pentest = investigation?.operation_mode === "pentest";
  $("#search-active-panel").hidden = !pentest;
  $("#search-mode-note").textContent = `${label(investigation?.operation_mode)}: ${operationModeHelp[investigation?.operation_mode] || "se aplicará la política registrada."}`;
  openDialog("search-dialog");
}

async function downloadReport(investigationId) {
  let response = await fetch(`${API}/investigations/${investigationId}/report.md`, { headers: { Authorization: `Bearer ${state.accessToken}` } });
  if (response.status === 401 && await refreshAccessToken()) response = await fetch(`${API}/investigations/${investigationId}/report.md`, { headers: { Authorization: `Bearer ${state.accessToken}` } });
  if (!response.ok) throw new Error("No fue posible generar el reporte.");
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = `investigacion-${investigationId}.md`; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast("Reporte narrativo descargado.");
}

async function downloadArtifact(investigationId, suffix, filename, message) {
  let response = await fetch(`${API}/investigations/${investigationId}/${suffix}`, { headers: { Authorization: `Bearer ${state.accessToken}` } });
  if (response.status === 401 && await refreshAccessToken()) response = await fetch(`${API}/investigations/${investigationId}/${suffix}`, { headers: { Authorization: `Bearer ${state.accessToken}` } });
  if (!response.ok) throw new Error("No fue posible generar la exportación.");
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast(message);
}

async function navigate(view) {
  try {
    if (view === "projects") await renderProjects();
    else if (view === "investigations") await renderInvestigations();
    else if (view === "knowledge") await renderKnowledge();
    else await renderDashboard();
  } catch (error) { showToast(error.message, true); }
}

async function loadWorkspace() {
  const [user, projects] = await Promise.all([api("/auth/me"), api("/projects")]);
  state.user = user;
  state.projects = projects;
  showWorkspace();
  await renderDashboard();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = loginForm.querySelector("button[type=submit]");
  button.disabled = true;
  loginError.hidden = true;
  try {
    const tokens = await api("/auth/login", { method: "POST", body: JSON.stringify({ username: $("#username").value.trim(), password: $("#password").value, mfa_code: $("#mfa-code").value.trim() || null }) });
    setTokens(tokens);
    await loadWorkspace();
    $("#password").value = "";
  } catch (error) {
    clearSession();
    showLogin(error.message === "Invalid credentials." ? "Usuario o contraseña incorrectos." : error.message);
  } finally { button.disabled = false; }
});

$("#logout-button").addEventListener("click", async () => {
  try { await api("/auth/logout", { method: "POST" }); } catch (_) { /* cierre local aunque la sesión haya vencido */ }
  clearSession(); showLogin();
});

$$(`[data-close-dialog]`).forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
$$(`dialog`).forEach((dialog) => dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); }));
$$(`.nav-item[data-view]`).forEach((button) => button.addEventListener("click", () => navigate(button.dataset.view)));

content.addEventListener("keydown", (event) => {
  if ((event.key === "Enter" || event.key === " ") && event.target.matches("[data-action].clickable")) event.target.click();
});
content.addEventListener("click", async (event) => {
  const viewLink = event.target.closest("[data-view-link]");
  if (viewLink) return navigate(viewLink.dataset.viewLink);
  const target = event.target.closest("[data-action]");
  if (!target) return;
  const action = target.dataset.action;
  try {
    if (action === "new-project") openNewProject();
    else if (action === "new-investigation") openNewInvestigation(target.dataset.projectId);
    else if (action === "open-project") await renderProject(target.dataset.id);
    else if (action === "open-investigation" || action === "refresh-investigation") await renderInvestigation(target.dataset.id);
    else if (action === "new-evidence") openNewEvidence(target.dataset.id);
    else if (action === "new-finding") openNewFinding(target.dataset.id);
    else if (action === "new-search") openNewSearch(target.dataset.id);
    else if (action === "download-report") await downloadReport(target.dataset.id);
    else if (action === "download-stix") await downloadArtifact(target.dataset.id, "report.stix.json", `investigacion-${target.dataset.id}.stix.json`, "STIX 2.1 descargado.");
    else if (action === "download-siem") await downloadArtifact(target.dataset.id, "report.ndjson", `investigacion-${target.dataset.id}.ndjson`, "Exportación SIEM descargada.");
  } catch (error) { showToast(error.message, true); }
});

content.addEventListener("change", async (event) => {
  if (event.target.id !== "knowledge-project-select") return;
  try { await renderKnowledge(Number(event.target.value)); }
  catch (error) { showToast(error.message, true); }
});

content.addEventListener("submit", async (event) => {
  if (!event.target.matches("#rag-query-form, #knowledge-ingest-form")) return;
  event.preventDefault();
  const form = event.target;
  const button = $("button[type=submit]", form);
  button.disabled = true;
  try {
    const data = new FormData(form);
    const projectId = Number(data.get("project_id"));
    if (form.id === "knowledge-ingest-form") {
      await api(`/projects/${projectId}/soc-knowledge/documents`, { method: "POST", body: JSON.stringify({ title: String(data.get("title")).trim(), source_type: data.get("source_type"), source_uri: String(data.get("source_uri") || "").trim() || null, content: String(data.get("document_content")).trim(), metadata: {} }) });
      showToast("Conocimiento SOC indexado con procedencia.");
      await renderKnowledge(projectId);
    } else {
      const answerBox = $("#rag-answer");
      answerBox.hidden = false;
      answerBox.innerHTML = `<div class="loading">Recuperando contexto y verificando citas…</div>`;
      const result = await api(`/projects/${projectId}/soc-knowledge/query`, { method: "POST", body: JSON.stringify({ question: String(data.get("question")).trim(), top_k: 6, minimum_score: 0.15 }) });
      answerBox.innerHTML = `<p class="section-kicker">Respuesta fundamentada · confianza ${Math.round(result.confidence * 100)}%</p><div class="rag-response">${escapeHtml(result.answer)}</div>${result.citations.length ? `<h4>Citas</h4><ol>${result.citations.map((citation) => `<li><strong>${escapeHtml(citation.document_title)} · K${citation.chunk_id}</strong><span>${escapeHtml(citation.claim)}</span><small>Relevancia ${Math.round(citation.score * 100)}%${citation.source_uri ? ` · ${escapeHtml(citation.source_uri)}` : ""}</small></li>`).join("")}</ol>` : ""}${result.gaps.length ? `<h4>Vacíos</h4><ul>${result.gaps.map((gap) => `<li>${escapeHtml(gap)}</li>`).join("")}</ul>` : ""}<small>Requiere revisión humana antes de actuar.</small>`;
    }
  } catch (error) { showToast(error.message, true); }
  finally { button.disabled = false; }
});

$("#project-name").addEventListener("input", (event) => {
  $("#project-slug").value = event.target.value.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
});

function syncInvestigationMode() {
  const mode = $("#investigation-operation-mode").value;
  $("#investigation-mode-help").textContent = operationModeHelp[mode];
  $("#pentest-policy-fields").hidden = mode !== "pentest";
}

$("#investigation-operation-mode").addEventListener("change", syncInvestigationMode);
$("#search-scheduled").addEventListener("change", (event) => {
  $("#search-schedule-fields").hidden = !event.target.checked;
  $("#search-allow-active").checked = false;
});

$("#project-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const button = $("button[type=submit]", form); button.disabled = true;
  try {
    const project = await api("/projects", { method: "POST", body: JSON.stringify({ name: $("#project-name").value.trim(), slug: $("#project-slug").value.trim(), description: $("#project-description").value.trim() || null }) });
    state.projects.push(project); state.investigations.set(project.id, []); $("#project-dialog").close(); showToast("Proyecto creado."); await renderProject(project.id);
  } catch (error) { const box = $(".dialog-error", form); box.textContent = error.message; box.hidden = false; } finally { button.disabled = false; }
});

$("#investigation-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const button = $("button[type=submit]", form); button.disabled = true;
  try {
    const projectId = Number($("#investigation-project-id").value);
    const operationMode = $("#investigation-operation-mode").value;
    const authorizationScope = $("#investigation-authorization-scope").value.trim();
    const engagementStart = $("#investigation-engagement-start").value;
    const engagementEnd = $("#investigation-engagement-end").value;
    const activeAuthorized = $("#investigation-active-authorized").checked;
    if (operationMode === "pentest" && (authorizationScope.length < 20 || !engagementStart || !engagementEnd || !activeAuthorized)) throw new Error("Pentesting requiere alcance detallado, ventana completa y autorización activa.");
    const investigation = await api(`/projects/${projectId}/investigations`, { method: "POST", body: JSON.stringify({ title: $("#investigation-title").value.trim(), kind: $("#investigation-kind").value, priority: $("#investigation-priority").value, description: $("#investigation-description").value.trim() || null, operation_mode: operationMode, authorization_scope: operationMode === "pentest" ? authorizationScope : null, active_testing_authorized: operationMode === "pentest" && activeAuthorized, engagement_start_at: operationMode === "pentest" ? new Date(engagementStart).toISOString() : null, engagement_end_at: operationMode === "pentest" ? new Date(engagementEnd).toISOString() : null, jurisdiction: $("#investigation-jurisdiction").value.trim() || null, legal_basis: $("#investigation-legal-basis").value.trim() || null, data_classification: $("#investigation-data-classification").value }) });
    const items = state.investigations.get(projectId) || []; items.unshift(investigation); state.investigations.set(projectId, items); $("#investigation-dialog").close(); showToast("Investigación creada."); await renderInvestigation(investigation.id);
  } catch (error) { const box = $(".dialog-error", form); box.textContent = error.message; box.hidden = false; } finally { button.disabled = false; }
});

$("#evidence-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const button = $("button[type=submit]", form); button.disabled = true;
  try {
    const investigationId = Number($("#evidence-investigation-id").value);
    await api(`/investigations/${investigationId}/evidence`, { method: "POST", body: JSON.stringify({ title: $("#evidence-title").value.trim(), kind: $("#evidence-kind").value.trim(), collector: $("#evidence-collector").value.trim(), source_type: $("#evidence-source-type").value.trim(), locator: $("#evidence-locator").value.trim(), content: $("#evidence-content").value.trim(), source_metadata: {}, raw_data: {} }) });
    $("#evidence-dialog").close(); showToast("Evidencia registrada y firmada."); await renderInvestigation(investigationId);
  } catch (error) { const box = $(".dialog-error", form); box.textContent = error.message; box.hidden = false; } finally { button.disabled = false; }
});

$("#finding-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const button = $("button[type=submit]", form); button.disabled = true;
  try {
    const investigationId = Number($("#finding-investigation-id").value);
    await api(`/investigations/${investigationId}/findings`, { method: "POST", body: JSON.stringify({ title: $("#finding-title").value.trim(), description: $("#finding-description").value.trim(), severity: $("#finding-severity").value, confidence: Number($("#finding-confidence").value), remediation: $("#finding-remediation").value.trim() || null }) });
    $("#finding-dialog").close(); showToast("Hallazgo SOC registrado."); await renderInvestigation(investigationId);
  } catch (error) { const box = $(".dialog-error", form); box.textContent = error.message; box.hidden = false; } finally { button.disabled = false; }
});

$("#search-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const button = $("button[type=submit]", form); button.disabled = true;
  try {
    const investigationId = Number($("#search-investigation-id").value);
    const targetType = $("#search-target-type").value;
    const targetValue = $("#search-target-value").value.trim();
    const allowActive = !$("#search-active-panel").hidden && $("#search-allow-active").checked;
    const scheduled = $("#search-scheduled").checked;
    if ((targetType && !targetValue) || (!targetType && targetValue)) throw new Error("Selecciona tipo y valor, o deja ambos vacíos para la detección automática.");
    if (allowActive && $("#search-scope-note").value.trim().length < 10) throw new Error("Las pruebas activas requieren una nota de alcance específica.");
    const targets = targetType ? [{ type: targetType, value: targetValue }] : [];
    if (scheduled) {
      if (!targets.length) throw new Error("Una búsqueda programada requiere un objetivo explícito.");
      if ($("#search-scope-note").value.trim().length < 10) throw new Error("Describe el alcance autorizado de la vigilancia.");
      await api(`/investigations/${investigationId}/search-schedules`, { method: "POST", body: JSON.stringify({ name: $("#search-schedule-name").value.trim(), objective: $("#search-objective").value.trim(), targets, max_tools: 40, interval_minutes: Number($("#search-schedule-interval").value), authorization_confirmed: $("#search-authorization").checked, authorization_scope: $("#search-scope-note").value.trim(), enabled: true }) });
    } else {
      await api(`/investigations/${investigationId}/search-runs`, { method: "POST", body: JSON.stringify({ objective: $("#search-objective").value.trim(), targets, max_tools: 40, allow_active: allowActive, authorization_confirmed: $("#search-authorization").checked, scope_note: $("#search-scope-note").value.trim() || null }) });
    }
    $("#search-dialog").close(); showToast(scheduled ? "Vigilancia pasiva programada." : "Búsqueda enviada al orquestador local."); await renderInvestigation(investigationId);
  } catch (error) { const box = $(".dialog-error", form); box.textContent = error.message; box.hidden = false; } finally { button.disabled = false; }
});

(async function bootstrap() {
  if (!state.accessToken && !state.refreshToken) return showLogin();
  try { await loadWorkspace(); } catch (_) { clearSession(); showLogin("Tu sesión terminó. Vuelve a entrar."); }
})();
