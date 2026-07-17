"use strict";

const state = { status: null, offset: 0, limit: 25, selected: new Set(), nodes: null, job: null, startingJob: false, pollTimer: null, refreshTimer: null };
const $ = (id) => document.getElementById(id);
const text = (value, fallback = "—") => value === null || value === undefined || value === "" ? fallback : String(value);
const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };
const make = (tag, value, className) => { const node = document.createElement(tag); if (value !== undefined) node.textContent = text(value, ""); if (className) node.className = className; return node; };
const statusClass = (value) => `status-${String(value || "unknown").toLowerCase().replace(/[^a-z0-9_-]/g, "") || "unknown"}`;
const badge = (value, label) => make("span", label || value, `status-pill ${statusClass(value)}`);

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? text(value) : new Intl.DateTimeFormat("zh-TW", { dateStyle: "short", timeStyle: "medium" }).format(date);
}
function formatCheckedAt(value) {
  if (value === null || value === undefined || value === "") return "—";
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) return formatDate(numeric < 1e12 ? numeric * 1000 : numeric);
  return formatDate(value);
}
function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes)) return "—";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(Math.max(bytes, 1)) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}
function formatSpeed(value) { return value === null || value === undefined ? "—" : `${Number(value).toFixed(2)} MB/s`; }
function api(path, options) {
  const request = options || {};
  const headers = { Accept: "application/json", ...(request.body ? { "Content-Type": "application/json" } : {}), ...(request.headers || {}) };
  return fetch(path, { ...request, headers })
    .then(async (response) => { const body = await response.json().catch(() => ({})); if (!response.ok) throw new Error(body.detail || body.error || `HTTP ${response.status}`); return body; });
}
function setConnection(mode, label) {
  const node = $("connection-state"); node.className = `connection ${mode}`; node.textContent = "";
  node.append(make("i")); node.append(document.createTextNode(label));
}
function setDetailList(id, pairs) {
  const list = $(id); clear(list);
  pairs.forEach(([key, value]) => { list.append(make("dt", key)); list.append(make("dd", value)); });
}

function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function firstValue(...values) { return values.find((value) => value !== null && value !== undefined && value !== ""); }
function countValue(...values) {
  const raw = firstValue(...values); const value = Number(raw);
  return Number.isInteger(value) && value >= 0 ? value : null;
}
function booleanValue(...values) {
  const raw = firstValue(...values);
  if (raw === true || raw === false) return raw;
  if (raw === "true" || raw === 1 || raw === "1") return true;
  if (raw === "false" || raw === 0 || raw === "0") return false;
  return null;
}
function formatAge(value) {
  if (value === null || value === undefined || value === "") return "—";
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return `${Math.round(seconds)} 秒`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} 分鐘`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(seconds < 36000 ? 1 : 0)} 小時`;
  return `${(seconds / 86400).toFixed(seconds < 864000 ? 1 : 0)} 天`;
}
function verificationSnapshot(primary, fallback) {
  const first = isRecord(primary) ? primary : {}; const second = isRecord(fallback) ? fallback : {};
  const nested = [first.verify, first.verification, first.nodes].find(isRecord) || first;
  const fallbackNested = [second.verify, second.verification, second.nodes].find(isRecord) || second;
  const read = (key, ...aliases) => firstValue(nested[key], ...aliases.map((name) => nested[name]), fallbackNested[key], ...aliases.map((name) => fallbackNested[name]));
  const alive = countValue(read("alive", "live")); const dead = countValue(read("dead", "failed"));
  const total = countValue(read("total", "node_count"));
  let verified = countValue(read("verified", "checked"));
  if (verified === null && alive !== null && dead !== null) verified = alive + dead;
  let unverified = countValue(read("unverified", "pending"));
  if (unverified === null && total !== null && verified !== null) unverified = Math.max(0, total - verified);
  return {
    total, verified, alive, dead, unverified,
    tier1Alive: countValue(read("tier1_alive")),
    tier2Passed: countValue(read("tier2_passed")),
    completed: booleanValue(read("completed")),
  };
}
function renderVerificationMetrics(id, snapshot) {
  const list = $(id); clear(list);
  [["總數", snapshot.total], ["已驗證", snapshot.verified], ["存活", snapshot.alive], ["失敗", snapshot.dead], ["待驗證", snapshot.unverified]].forEach(([label, value]) => {
    const group = make("div", undefined, "verification-metric");
    group.append(make("dt", label), make("dd", value === null ? "—" : value)); list.append(group);
  });
}
function normalizeStatus(value) {
  const status = String(value || "").trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
  return status || "unknown";
}
function hasRemoteSnapshot(remote) {
  return Boolean(firstValue(remote.generated_at)) && isRecord(remote.verify);
}
function deriveLocalStatus(local, snapshot) {
  if (local && local.status) return normalizeStatus(local.status);
  if (snapshot.total === null || snapshot.verified === null) return "unknown";
  if (snapshot.completed !== true || (snapshot.unverified || 0) > 0) return "attention";
  if ((snapshot.dead || 0) > 0) return "degraded";
  return "healthy";
}
function deriveRemoteStatus(remote, hasRemote) {
  if (!hasRemote) return "unknown";
  const configured = booleanValue(remote.configured); const stale = booleanValue(remote.stale, remote.is_stale);
  if (configured !== true) return configured === false ? "missing" : "unknown";
  if (stale !== false) return stale === true && hasRemoteSnapshot(remote) ? "stale" : "unknown";
  const sourceStatus = normalizeStatus(remote.status);
  if (!["healthy", "ok", "ready", "passed", "completed"].includes(sourceStatus)) return sourceStatus;
  return normalizeStatus(firstValue(remote.pipeline_status, remote.status));
}
function remotePipelineErrorName(value) {
  return ({
    invalid_config: "遠端狀態來源設定無效",
    http_error: "遠端狀態端點回應異常",
    invalid_response: "遠端狀態回應內容無效",
    response_too_large: "遠端狀態回應超出大小限制",
    network_error: "遠端狀態連線失敗",
    invalid_schema: "遠端狀態資料格式不符",
    remote_pipeline_http_error: "遠端狀態端點回應異常",
    remote_pipeline_invalid_schema: "遠端狀態資料格式不符",
    remote_pipeline_timeout: "取得遠端狀態逾時",
    remote_pipeline_network_error: "遠端狀態連線失敗",
    remote_pipeline_not_configured: "遠端狀態來源尚未設定",
    remote_pipeline_invalid_url: "遠端狀態來源設定無效",
    remote_pipeline_response_too_large: "遠端狀態回應超出大小限制",
    remote_pipeline_redirect_rejected: "遠端狀態端點重新導向遭拒",
  })[String(value || "").toLowerCase()] || "遠端狀態來源回報錯誤";
}
function setStateNote(id, message, tone) {
  const node = $(id); node.textContent = message || ""; node.className = `state-note${tone ? ` state-note-${tone}` : ""}`;
}

function renderOverview(payload) {
  state.status = payload;
  const nodes = payload.nodes || {}; const sources = payload.sources || {}; const serving = payload.serving || {};
  const hasRemote = isRecord(payload.remote_pipeline); const remote = hasRemote ? payload.remote_pipeline : {};
  const local = isRecord(payload.local_verification) ? payload.local_verification : {};
  const remoteVerification = verificationSnapshot(remote); const localVerification = verificationSnapshot(local, nodes);
  const remoteStatus = deriveRemoteStatus(remote, hasRemote); const localStatus = deriveLocalStatus(local, localVerification);
  $("generated-at").textContent = `最後更新：${formatDate(payload.generated_at)}`;
  $("tab-node-count").textContent = text(localVerification.total, "0");
  $("refresh-interval").textContent = `每 ${text(payload.refresh_seconds, "30")} 秒更新`;
  renderVerificationMetrics("remote-verification-metrics", remoteVerification);
  renderVerificationMetrics("local-verification-metrics", localVerification);
  $("remote-generated-at").textContent = `產生時間：${formatDate(remote.generated_at)}`;
  $("local-updated-at").textContent = `更新時間：${formatDate(local.updated_at)}`;
  const remoteBadge = $("pipeline-status"); remoteBadge.className = `status-pill ${statusClass(remoteStatus)}`; remoteBadge.textContent = `遠端自動化：${statusName(remoteStatus)}`;
  const localBadge = $("local-verification-status"); localBadge.className = `status-pill ${statusClass(localStatus)}`; localBadge.textContent = `本機：${statusName(localStatus)}`;
  const remoteStale = booleanValue(remote.stale, remote.is_stale); const remoteConfigured = booleanValue(remote.configured);
  const remoteHasSnapshot = hasRemoteSnapshot(remote);
  const freshness = !remoteHasSnapshot ? "尚無有效快照" : remoteStale === false ? "新鮮" : remoteStale === true ? "已過期（保守判定）" : "未知（保守判定）";
  const sourceAvailability = remoteConfigured === true ? "已設定" : remoteConfigured === false ? "未設定" : "未知（保守判定）";
  setDetailList("remote-pipeline-details", [
    ["狀態來源", sourceAvailability],
    ["快照新鮮度", freshness],
    ["資料年齡", formatAge(remote.age_seconds)],
    ["擷取時間", formatDate(remote.fetched_at)],
    ["遠端讀取", statusName(remote.status || "unknown")],
    ["自動化判定", statusName(remote.pipeline_status || "unknown")],
  ]);
  const remoteError = remote.error ? remotePipelineErrorName(remote.error) : "";
  if (remoteConfigured !== true) setStateNote("remote-pipeline-note", `${remoteConfigured === false ? "遠端狀態來源尚未設定；目前不宣告自動化成功。" : "遠端狀態來源未知；目前採保守判定。"}${remoteError ? `${remoteError}。` : ""}`, "warning");
  else if (!remoteHasSnapshot) setStateNote("remote-pipeline-note", `尚未取得有效的遠端自動化快照；目前狀態為未知。${remoteError ? `${remoteError}。` : ""}`, "warning");
  else if (remoteStale === true) setStateNote("remote-pipeline-note", `遠端自動化快照已過期；狀態採保守判定，對外服務另依即時健康檢查顯示。${remoteError ? `${remoteError}。` : ""}`, "warning");
  else if (remoteStale !== false) setStateNote("remote-pipeline-note", `遠端快照新鮮度未知；目前不宣告自動化成功。${remoteError ? `${remoteError}。` : ""}`, "warning");
  else if (remoteError) setStateNote("remote-pipeline-note", `${remoteError}。`, "warning");
  else if (remoteStatus !== "healthy") setStateNote("remote-pipeline-note", `遠端快照新鮮，但自動化狀態為${statusName(remoteStatus)}；目前採保守判定，尚未視為完成。`, "warning");
  else setStateNote("remote-pipeline-note", "遠端狀態快照新鮮；此判定與本機候選池驗證分開計算。", "ok");
  const localProgress = [];
  if (localVerification.unverified !== null && localVerification.unverified > 0) localProgress.push(`${localVerification.unverified} 個節點尚待本機驗證`);
  if (localVerification.tier1Alive !== null) localProgress.push(`第一階段存活 ${localVerification.tier1Alive}`);
  if (localVerification.tier2Passed !== null) localProgress.push(`第二階段通過 ${localVerification.tier2Passed}`);
  if (!localProgress.length && localVerification.completed === true) localProgress.push("本輪本機驗證已完成");
  if (!localProgress.length) localProgress.push("本機驗證資料尚不完整，狀態採保守判定");
  setStateNote("local-verification-note", `${localProgress.join("；")}。此狀態只描述本機候選池。`, localStatus === "healthy" ? "ok" : "warning");
  const validArtifacts = Array.isArray(payload.artifacts) ? payload.artifacts.filter((item) => item && item.valid).length : null;
  const metrics = [[serving.subscription_nodes, "對外訂閱節點"], [nodes.published, "本機已發佈"], [sources.enabled, "啟用來源"], [validArtifacts, "有效輸出"], [nodes.median_latency_ms === null || nodes.median_latency_ms === undefined ? "—" : `${nodes.median_latency_ms} ms`, "本機中位延遲"]];
  const grid = $("metric-grid"); clear(grid); metrics.forEach(([value, label]) => { const card = make("div", undefined, "metric"); card.append(make("div", value === null || value === undefined ? "—" : value, "value"), make("div", label, "label")); grid.append(card); });
  const pipeline = payload.latest_run || payload.latest_pipeline || {};
  const lastRun = $("last-command"); const lastRunStatus = pipeline.status || "unknown"; lastRun.className = `status-pill ${statusClass(lastRunStatus)}`; lastRun.textContent = pipeline.command ? `最近 ${pipeline.command}：${statusName(lastRunStatus)}` : "最近執行：—";
  const servingStatus = serving.status || "unknown";
  const serviceBadge = $("serving-status"); serviceBadge.className = `status-pill ${statusClass(servingStatus)}`; serviceBadge.textContent = statusName(servingStatus);
  const servingSummary = $("serving-summary-status"); servingSummary.className = `status-pill ${statusClass(servingStatus)}`; servingSummary.textContent = `對外服務：${statusName(servingStatus)}`;
  setDetailList("serving-details", [["服務狀態", statusName(servingStatus)], ["Worker", serving.configured ? text(serving.base_url) : "未設定"], ["Health HTTP", text(serving.health_http_status)], ["訂閱節點", text(serving.subscription_nodes)], ["訂閱驗證", serving.subscription_valid === true ? "通過" : serving.subscription_valid === false ? "未通過" : "—"], ["遠端延遲", serving.latency_ms === undefined ? "—" : String(serving.latency_ms) + " ms"]]);
  const stages = $("pipeline-list"); clear(stages); (payload.pipeline || []).forEach((item, index) => { const row = make("li"); row.append(make("span", String(index + 1).padStart(2, "0"), "stage-index"), make("span", stageName(item.id)), badge(item.status, statusName(item.status))); stages.append(row); });
  setDetailList("git-details", [["分支", text((payload.git || {}).branch)], ["提交", text((payload.git || {}).commit)], ["提交時間", formatDate((payload.git || {}).commit_time)]]);
  renderArtifacts(payload.artifacts || []);
}
function statusName(value) { return ({ healthy: "健康", degraded: "降級", offline: "離線", unknown: "未知", stale: "已過期", error: "錯誤", ready: "就緒", missing: "未設定", attention: "注意", ok: "正常", canary: "Canary", disabled_canary: "停用 Canary", alive: "存活", dead: "失敗", unverified: "未驗證", passed: "通過", partial: "部分通過", rotating: "輪替", bypass: "直連疑慮", failed: "失敗", queued: "排隊中", running: "執行中", completed: "完成", cancelled: "已取消" })[value] || text(value); }
function stageName(value) { return ({ fetch: "擷取來源", parse: "解析入庫", verify: "節點驗證", emit: "產生輸出", worker: "遠端服務" })[value] || text(value); }
function jobModeName(value) { return ({ endpoint: "端點連通", exit: "出口 IP", purity: "IP 純淨度" })[value] || "IP"; }
function purityGrade(result) {
  const value = String((result || {}).purity_grade ?? (result || {}).grade ?? "").toUpperCase();
  return /^[ABCDF]$/.test(value) ? value : "";
}
function purityGradeName(value) { return ({ A: "A · 純淨", B: "B · 低風險", C: "C · 中風險", D: "D · 高風險", F: "F · 極高風險" })[value] || "未評級"; }
function purityScore(result) {
  const raw = (result || {}).purity_score ?? (result || {}).score;
  if (raw === null || raw === undefined || raw === "") return null;
  const value = Number(raw);
  return Number.isFinite(value) ? Math.round(Math.max(0, Math.min(100, value))) : null;
}
function purityReasons(result) {
  const values = (result || {}).purity_reasons ?? (result || {}).reasons;
  return Array.isArray(values) ? values.filter((value) => typeof value === "string" && value).slice(0, 12) : [];
}
function purityReasonName(value) {
  const key = String(value || "").toLowerCase();
  return ({
    hosting: "資料中心／主機代管", datacenter: "資料中心／主機代管", data_center: "資料中心／主機代管", hosting_provider: "資料中心／主機代管",
    proxy: "已知代理", known_proxy: "已知代理", public_proxy: "公開代理", vpn: "VPN", tor: "Tor 出口", relay: "中繼節點",
    blacklisted: "命中信譽清單", blacklist: "命中信譽清單", reputation_listed: "命中信譽清單",
    abuse: "濫用風險", abuse_reported: "曾有濫用回報", recent_abuse: "近期濫用紀錄", bot: "自動化流量風險", spam: "垃圾訊息紀錄",
    provider_disagreement: "資料來源判定不一致", insufficient_data: "信譽資料不足", limited_provider_coverage: "資料來源覆蓋有限",
    elevated_risk: "風險偏高", moderate_risk: "中度風險", rotating_exit: "出口 IP 輪替",
    direct_match: "出口與本機 IP 相同", direct_bypass: "疑似直連",
  })[key] || "其他信譽訊號";
}
function purityConfidence(result) {
  const raw = (result || {}).purity_confidence ?? (result || {}).confidence;
  if (raw === null || raw === undefined || raw === "") return "";
  const numeric = Number(raw);
  if (Number.isFinite(numeric)) {
    const percentage = numeric <= 1 ? numeric * 100 : numeric;
    return `信心 ${Math.round(Math.max(0, Math.min(100, percentage)))}%`;
  }
  const label = ({ high: "高", medium: "中", low: "低" })[String(raw).toLowerCase()];
  return label ? `信心 ${label}` : "";
}
function purityCoverage(result) {
  const coverage = (result || {}).provider_coverage;
  const ok = Number((coverage || {}).ok); const total = Number((coverage || {}).total);
  return Number.isInteger(ok) && Number.isInteger(total) && ok >= 0 && total > 0 && ok <= total ? `資料源 ${ok}/${total}` : "";
}
function purityBadge(value) {
  const node = make("span", purityGradeName(value), `purity-grade purity-grade-${value.toLowerCase()}`);
  node.setAttribute("aria-label", `純淨度等級 ${purityGradeName(value)}`);
  return node;
}
function purityErrorName(value) {
  return ({
    checker_runtime_unavailable: "檢查工具不可用", invalid_proxy_config: "節點設定驗證失敗", proxy_core_exited: "節點執行程序提前結束", proxy_core_timeout: "節點執行程序啟動逾時",
    all_ip_probes_failed: "出口 IP 查詢失敗", all_reputation_probes_failed: "信譽資料查詢失敗", provider_quota_exhausted: "信譽資料來源今日額度已用完",
    network_error: "網路檢查失敗", unsupported_outbound: "節點協定尚未支援", proxy_runtime_error: "節點執行程序錯誤", timeout: "檢查逾時", cancelled: "檢查已取消",
  })[value] || "檢查未完成";
}
function renderArtifacts(items) {
  const grid = $("artifacts-grid");
  clear(grid);
  items.forEach((item) => {
    const card = make("article", undefined, "artifact");
    const top = make("div", undefined, "artifact-header");
    top.append(make("h2", item.id), badge(item.valid ? "ready" : "failed", item.valid ? "有效" : "無效"));
    card.append(top);
    card.append(make("div", item.count === null ? "—" : item.count, "artifact-count"));
    card.append(make("p", "節點數 / " + formatBytes(item.bytes)));
    card.append(make("p", "更新：" + formatDate(item.updated_at)));
    card.append(make("p", item.error ? "錯誤：" + item.error : "SHA：" + text(item.sha256).slice(0, 14)));
    grid.append(card);
  });
}

function populateSelect(id, values, current) {
  const select = $(id); const prior = current || select.value || "all"; clear(select); select.append(makeOption("all", id === "filter-proto" ? "全部協定" : "全部來源")); values.forEach((value) => select.append(makeOption(value, value))); select.value = Array.from(select.options).some((option) => option.value === prior) ? prior : "all";
}
function makeOption(value, label) { const option = document.createElement("option"); option.value = value; option.textContent = label; return option; }
function currentFilters() { const params = new URLSearchParams(); ["query", "status", "proto", "source", "published"].forEach((key) => { const value = $(`filter-${key}`).value.trim(); if (value && value !== "all") params.set(key, value); }); params.set("offset", String(state.offset)); params.set("limit", String(state.limit)); return params; }
function renderNodes(payload) {
  state.nodes = payload;
  populateSelect("filter-proto", (payload.facets || {}).protocols || []);
  populateSelect("filter-source", (payload.facets || {}).sources || []);
  const body = $("nodes-body"); clear(body);
  const items = payload.items || [];
  items.forEach((item) => { const row = document.createElement("tr"); const check = document.createElement("input"); check.type = "checkbox"; check.checked = state.selected.has(item.id); check.setAttribute("aria-label", `選取 ${item.name}`); check.addEventListener("change", () => toggleNode(item.id, check.checked)); const idCell = document.createElement("td"); idCell.dataset.label = "選取"; idCell.append(check); row.append(idCell);
    const name = make("td"); name.dataset.label = "節點"; name.append(make("span", item.name, "node-name"), make("span", item.short_id, "subline mono")); row.append(name);
    const proto = make("td", item.proto); proto.dataset.label = "協定"; row.append(proto); const endpoint = make("td"); endpoint.dataset.label = "端點"; endpoint.append(make("span", `${item.host}:${item.port}`, "mono"), make("span", item.country || "—", "subline")); row.append(endpoint);
    const stat = make("td"); stat.dataset.label = "狀態"; stat.append(badge(item.status, statusName(item.status))); row.append(stat);
    const latency = make("td", item.latency_ms === null ? "—" : `${item.latency_ms} ms`); latency.dataset.label = "延遲"; row.append(latency);
    row.append(ipCell(item.ip_check));
    row.append(purityCell(item.ip_purity));
    const source = make("td", item.source); source.dataset.label = "來源"; row.append(source); body.append(row);
  });
  if (!items.length) { const row = document.createElement("tr"); const cell = make("td", "沒有符合目前篩選條件的節點。", "muted"); cell.colSpan = 9; row.append(cell); body.append(row); }
  const total = Number(payload.total || 0); const start = total ? Number(payload.offset) + 1 : 0; const end = Math.min(Number(payload.offset) + (payload.items || []).length, total);
  $("nodes-summary").textContent = `共 ${total} 個符合條件的節點`;
  $("pagination-info").textContent = `顯示 ${start}–${end} / ${total}`;
  $("previous-page").disabled = !Number(payload.offset); $("next-page").disabled = Number(payload.offset) + Number(payload.limit) >= total;
  $("select-page").checked = (payload.items || []).length > 0 && payload.items.every((item) => state.selected.has(item.id));
  updateSelection();
}
function ipCell(check) {
  const cell = document.createElement("td"); cell.dataset.label = "連通／出口";
  if (!check) { cell.textContent = "未檢測"; return cell; }
  cell.append(make("span", check.mode === "exit" ? "出口 IP" : "端點連通", "check-kind"));
  cell.append(badge(check.status, statusName(check.status)));
  const detail = check.exit_ip || (check.endpoint_ips || []).join(", ") || check.error;
  if (detail) cell.append(make("span", detail, "subline mono"));
  if (check.checked_at) cell.append(make("span", `檢測：${formatCheckedAt(check.checked_at)}`, "subline"));
  return cell;
}
function purityCell(result) {
  const cell = document.createElement("td"); cell.dataset.label = "最近純淨度";
  if (!result) { cell.textContent = "未檢測"; return cell; }
  const grade = purityGrade(result); const score = purityScore(result); const reasons = purityReasons(result);
  if (!grade && score === null) {
    cell.append(badge(result.status, statusName(result.status)));
    if (result.error) cell.append(make("span", purityErrorName(result.error), "subline"));
    const coverage = purityCoverage(result);
    if (coverage) cell.append(make("span", coverage, "subline"));
    if (result.checked_at) cell.append(make("span", `檢測：${formatCheckedAt(result.checked_at)}`, "subline"));
    return cell;
  }
  const summary = make("span", undefined, "purity-summary");
  if (grade) summary.append(purityBadge(grade));
  if (score !== null) summary.append(make("strong", `純淨分數 ${score}/100`, "purity-score"));
  cell.append(summary);
  const meta = [purityConfidence(result), purityCoverage(result)].filter(Boolean);
  if (result.status && result.status !== "passed") meta.unshift(`檢查狀態：${statusName(result.status)}`);
  if (meta.length) cell.append(make("span", meta.join(" · "), "subline"));
  if (reasons.length) {
    const shown = reasons.slice(0, 2).map(purityReasonName);
    cell.append(make("span", `風險訊號：${shown.join("、")}${reasons.length > shown.length ? ` ＋${reasons.length - shown.length}` : ""}`, "subline purity-reason-summary"));
  } else {
    cell.append(make("span", grade === "A" ? "未發現已知風險訊號" : "未提供風險訊號明細", "subline"));
  }
  if (result.exit_ip) cell.append(make("span", `出口 ${result.exit_ip}`, "subline mono"));
  if (result.checked_at) cell.append(make("span", `檢測：${formatCheckedAt(result.checked_at)}`, "subline"));
  return cell;
}
function toggleNode(id, checked) { if (checked) { if (state.selected.size >= 20) { alert("一次最多選取 20 個節點。"); loadNodes(); return; } state.selected.add(id); } else state.selected.delete(id); updateSelection(); }
function updateSelection() {
  const count = state.selected.size; const checker = (state.status || {}).ip_checker || {};
  const busy = state.startingJob || Boolean(state.job && ["queued", "running"].includes(state.job.status));
  const endpointAllowed = checker.endpoint === true; const exitAllowed = checker.exit_ip === true; const purityAllowed = checker.purity === true;
  $("selection-count").textContent = `已選 ${count} / 20`;
  $("endpoint-check").disabled = count === 0 || busy || !endpointAllowed;
  $("exit-check").disabled = count === 0 || busy || !exitAllowed;
  $("purity-check").disabled = count === 0 || busy || !purityAllowed;
  const base = "純淨度依出口 IP 的信譽訊號評分，與端點連通及出口 IP 驗證分開顯示；分數越高越乾淨。";
  const availability = !state.status ? " 正在讀取檢查能力。" : !purityAllowed ? " 目前純淨度檢查未啟用。" : busy ? " 目前有檢查工作執行中。" : "";
  $("purity-help").textContent = base + availability;
}
function loadNodes() { setConnection("", "更新節點資料…"); return api(`/api/nodes?${currentFilters()}`).then(renderNodes).then(() => setConnection("is-online", "已連線")).catch(showError); }
function loadSources() { return api("/api/sources").then((payload) => { const body = $("sources-body"); clear(body); const items = payload.items || []; items.forEach((item) => { const row = document.createElement("tr"); [item.id, item.origin].forEach((value) => row.append(make("td", value))); const status = make("td"); const isCanary = String(item.status || "").includes("canary"); status.append(badge(item.enabled ? item.status : isCanary ? "attention" : "offline", item.enabled ? statusName(item.status) : isCanary ? "停用 Canary" : "停用")); row.append(status); [item.tier, item.format, formatDate(item.last_fetch_at), item.last_count, item.mirrors].forEach((value) => row.append(make("td", value))); body.append(row); }); if (!items.length) { const row = document.createElement("tr"); const cell = make("td", "尚無來源資料。", "muted"); cell.colSpan = 8; row.append(cell); body.append(row); } $("sources-summary").textContent = `共 ${payload.total || 0} 個來源`; }).catch(showError); }
function scheduleRefresh() { window.clearTimeout(state.refreshTimer); const seconds = Math.max(5, Number((state.status || {}).refresh_seconds) || 30); state.refreshTimer = window.setTimeout(() => { loadStatus().then(() => { if (state.nodes) loadNodes(); }); }, seconds * 1000); }
function loadStatus(force) { setConnection("", "更新系統狀態…"); const options = force ? { headers: { "X-Dashboard-Action": "refresh" } } : undefined; return api(`/api/status${force ? "?force=true" : ""}`, options).then(renderOverview).then(() => { setConnection("is-online", "已連線"); updateSelection(); scheduleRefresh(); }).catch(showError); }
function showError(error) { setConnection("is-error", "連線失敗"); $("generated-at").textContent = `無法更新：${error.message}`; }

function renderJob(job) {
  state.job = job; const panel = $("job-panel"); const active = ["queued", "running"].includes(job.status);
  panel.hidden = false; panel.setAttribute("aria-busy", String(active)); clear(panel);
  const header = make("div", undefined, "job-header"); const heading = make("div");
  const title = make("strong", `${jobModeName(job.mode)}檢查：${statusName(job.status)}`); title.id = "job-title";
  const progress = make("span", `${job.completed} / ${job.total} 已完成`, "subline"); progress.setAttribute("role", "status"); progress.setAttribute("aria-live", "polite");
  heading.append(title, progress); header.append(heading);
  if (["queued", "running"].includes(job.status)) { const cancel = make("button", "取消工作", "button button-quiet"); cancel.type = "button"; cancel.addEventListener("click", cancelJob); header.append(cancel); }
  panel.append(header); const results = make("ul", undefined, "job-results");
  (job.items || []).forEach((item) => {
    const entry = make("li", undefined, job.mode === "purity" ? "job-result purity-result" : "job-result");
    const current = ((state.nodes || {}).items || []).find((node) => node.id === item.node_id);
    entry.append(make("span", current ? `${current.name} · ${current.short_id}` : text(item.node_id).slice(0, 10), "job-result-node"));
    if (job.mode !== "purity") {
      entry.append(badge(item.status, statusName(item.status)));
      const info = item.exit_ip || (item.endpoint_ips || []).join(", ") || item.error;
      if (info) entry.append(make("span", info, "job-result-info mono"));
      results.append(entry); return;
    }
    const grade = purityGrade(item); const score = purityScore(item); const reasons = purityReasons(item);
    if (!grade && score === null) {
      entry.append(badge(item.status, statusName(item.status)));
      if (item.error) entry.append(make("span", purityErrorName(item.error), "job-result-info"));
      const coverage = purityCoverage(item);
      if (coverage) entry.append(make("span", coverage, "job-result-info"));
      results.append(entry); return;
    }
    const summary = make("span", undefined, "purity-summary");
    if (grade) summary.append(purityBadge(grade));
    if (score !== null) summary.append(make("strong", `純淨分數 ${score}/100`, "purity-score"));
    entry.append(summary);
    const meta = [purityConfidence(item), purityCoverage(item)].filter(Boolean);
    if (item.status && item.status !== "passed") meta.unshift(`檢查狀態：${statusName(item.status)}`);
    if (item.exit_ip) meta.push(`出口 ${item.exit_ip}`);
    if (meta.length) entry.append(make("span", meta.join(" · "), "job-result-info mono-break"));
    if (reasons.length) {
      const list = make("ul", undefined, "purity-reasons");
      reasons.forEach((reason) => list.append(make("li", purityReasonName(reason))));
      entry.append(list);
    } else entry.append(make("span", grade === "A" ? "未發現已知風險訊號" : "未提供風險訊號明細", "job-result-info"));
    results.append(entry);
  });
  if (!(job.items || []).length) results.append(make("li", active ? "等待檢查結果…" : "沒有檢查結果。", "job-result muted"));
  panel.append(results); updateSelection();
}
function startJob(mode) {
  if (state.startingJob || (state.job && ["queued", "running"].includes(state.job.status))) return;
  const nodeIds = Array.from(state.selected); state.startingJob = true; updateSelection();
  api("/api/ip-checks", { method: "POST", body: JSON.stringify({ node_ids: nodeIds, mode }) })
    .then((job) => { renderJob(job); pollJob(); })
    .catch((error) => { alert(`無法建立檢查工作：${error.message}`); })
    .finally(() => { state.startingJob = false; updateSelection(); });
}
function pollJob() { window.clearTimeout(state.pollTimer); if (!state.job || !["queued", "running"].includes(state.job.status)) { loadNodes(); return; } state.pollTimer = window.setTimeout(() => api(`/api/ip-checks/${state.job.id}`).then((job) => { renderJob(job); pollJob(); }).catch(showError), 1000); }
function cancelJob() { if (!state.job) return; api(`/api/ip-checks/${state.job.id}/cancel`, { method: "POST", body: "{}" }).then((job) => { renderJob(job); pollJob(); }).catch(showError); }

document.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => { const target = button.dataset.tab; document.querySelectorAll(".tab").forEach((tab) => { const active = tab === button; tab.classList.toggle("is-active", active); tab.setAttribute("aria-selected", String(active)); }); document.querySelectorAll(".panel-view").forEach((panel) => { const active = panel.id === target; panel.classList.toggle("is-active", active); panel.hidden = !active; }); if (target === "nodes" && !state.nodes) loadNodes(); if (target === "sources") loadSources(); }));
$("refresh-button").addEventListener("click", () => { loadStatus(true); if (state.nodes) loadNodes(); });
$("node-filters").addEventListener("submit", (event) => event.preventDefault());
$("node-filters").addEventListener("change", () => { state.offset = 0; loadNodes(); });
$("filter-query").addEventListener("input", (() => { let timer; return () => { window.clearTimeout(timer); timer = window.setTimeout(() => { state.offset = 0; loadNodes(); }, 280); }; })());
$("node-filters").addEventListener("reset", () => { window.setTimeout(() => { state.offset = 0; loadNodes(); }); });
$("select-page").addEventListener("change", (event) => { const items = (state.nodes || {}).items || []; if (event.target.checked) { items.forEach((item) => { if (state.selected.size < 20 || state.selected.has(item.id)) state.selected.add(item.id); }); } else items.forEach((item) => state.selected.delete(item.id)); loadNodes(); });
$("previous-page").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); loadNodes(); });
$("next-page").addEventListener("click", () => { state.offset += state.limit; loadNodes(); });
$("endpoint-check").addEventListener("click", () => startJob("endpoint")); $("exit-check").addEventListener("click", () => startJob("exit")); $("purity-check").addEventListener("click", () => startJob("purity"));
loadStatus().then(() => loadNodes());
