/**
 * Task 06 (G1): Google Apps Script -> Meta Graph/Threads API -> Notion Idempotent Briefing Runner
 * Note: Secret tokens are read strictly from PropertiesService.getScriptProperties() and never logged.
 */
function runMorningBriefingWithTraceability() {
  var startUtc = new Date();
  var runId = "g1_run_" + Utilities.formatDate(startUtc, "GMT", "yyyyMMdd_HHmmss") + "_" + Utilities.getUuid().slice(0, 8);
  var props = PropertiesService.getScriptProperties();
  var metaToken = props.getProperty("META_ACCESS_TOKEN");
  var notionToken = props.getProperty("NOTION_API_TOKEN");
  var notionDbId = props.getProperty("NOTION_LEDGER_DB_ID");

  var logEntry = {
    run_id: runId,
    started_at_utc: Utilities.formatDate(startUtc, "GMT", "yyyy-MM-dd'T'HH:mm:ss'Z'"),
    started_at_kst: Utilities.formatDate(startUtc, "GMT+9", "yyyy-MM-dd'T'HH:mm:ss'+09:00'"),
    finished_at_utc: null,
    finished_at_kst: null,
    status: "RUNNING",
    http_status: 0,
    source_api_call_count: 0,
    snapshot_count: 0,
    retry_count: 0,
    dedup_prevented: false,
    failure_reason: null
  };

  if (!metaToken || !notionToken || !notionDbId) {
    var endFail = new Date();
    logEntry.finished_at_utc = Utilities.formatDate(endFail, "GMT", "yyyy-MM-dd'T'HH:mm:ss'Z'");
    logEntry.finished_at_kst = Utilities.formatDate(endFail, "GMT+9", "yyyy-MM-dd'T'HH:mm:ss'+09:00'");
    logEntry.status = "FAILED_CONFIG_MISSING";
    logEntry.failure_reason = "Missing required ScriptProperties (META_ACCESS_TOKEN / NOTION_API_TOKEN / NOTION_LEDGER_DB_ID)";
    Logger.log(JSON.stringify(logEntry));
    return logEntry;
  }

  // Bounded retry helper (HTTP 429 / 5xx)
  function fetchWithBoundedRetry(url, options, maxRetries) {
    var attempt = 0;
    while (attempt <= maxRetries) {
      logEntry.source_api_call_count += 1;
      var res = UrlFetchApp.fetch(url, Object.assign({ muteHttpExceptions: true }, options));
      var code = res.getResponseCode();
      logEntry.http_status = code;
      if (code >= 200 && code < 300) {
        return { ok: true, code: code, body: res.getContentText() };
      }
      if (code === 429 || code >= 500) {
        attempt += 1;
        logEntry.retry_count += 1;
        if (attempt <= maxRetries) {
          Utilities.sleep(Math.pow(2, attempt) * 1000);
          continue;
        }
      }
      return { ok: false, code: code, body: res.getContentText() };
    }
    return { ok: false, code: 500, body: "Max retries exceeded" };
  }

  var finishUtc = new Date();
  logEntry.finished_at_utc = Utilities.formatDate(finishUtc, "GMT", "yyyy-MM-dd'T'HH:mm:ss'Z'");
  logEntry.finished_at_kst = Utilities.formatDate(finishUtc, "GMT+9", "yyyy-MM-dd'T'HH:mm:ss'+09:00'");
  logEntry.status = "READY_TEMPLATE";
  Logger.log(JSON.stringify(logEntry));
  return logEntry;
}
