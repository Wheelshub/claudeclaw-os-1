# Post-mortem — Cross-process Claude Code SDK session resume crashes the subprocess

**Date:** 2026-05-10
**Severity:** P2 — feature broken, no data loss, immediate user-visible error
**Surface:** Dashboard `/chat` page, sub-agent tabs (research / comms / content / ops)
**Commits involved:** `0f2c8b9` (feature that exposed the bug) → `a4dfb07` (fix)

## TL;DR

Each sub-agent has its own launchd process (`com.claudeclaw.research`, `com.claudeclaw.comms`, ...) running with that agent's cwd, CLAUDE.md, and SDK settings. The main dashboard process is a different process. **Anthropic Claude-Code SDK session IDs created in one process can't be resumed by a different process** — the spawned SDK subprocess exits with code 1.

When per-agent dashboard chat routing landed, the dashboard tried to resume sub-agent sessions from the main process. The SDK subprocess crashed on every sub-agent turn. Main agent chat kept working because the dashboard IS main's process.

Fix: every sub-agent invocation from the dashboard starts a fresh Anthropic session. Conversation continuity comes from `buildMemoryContext()` (retrieval-based recall over `conversation_log`), not from session resume.

This is the same trade-off `src/orchestrator.ts:delegateToAgent` already accepts — it has always passed `sessionId: undefined` for cross-process delegations.

## Timeline

| Time (AEST) | Event |
|---|---|
| ~17:00 | `0f2c8b9` (per-agent chat routing) merged on testbed, cherry-picked to Mac fork as `761a73d` |
| ~18:00 | Operator deploys `761a73d` on `wheelsclaw.com` via `git pull && npm run build && launchctl kickstart -k gui/$UID/com.claudeclaw.app` |
| ~18:10 | Operator clicks "Content" tab in dashboard chat → message sent → reply: "Something went wrong. Check the logs." |
| ~18:15 | Logs reveal `category: "subprocess_crash"`, `originalMsg: "Claude Code process exited with code 1"`, stack pointing at `runAgent` invoked from `processDashboardMessage` |
| ~18:25 | Root cause identified — cross-process session resume |
| ~18:30 | Fix `a4dfb07` committed and pushed to both forks |

## Symptom

User-visible: chat replies for any sub-agent tab returned `Something went wrong. Check the logs.` (the catch-block fallback in `src/bot.ts:processDashboardMessage`). Main agent chat unaffected.

Server log:

```jsonc
{"level":30,"messageLen":43,"source":"dashboard","targetAgent":"content","msg":"Processing dashboard message"}
{"level":30,"sessionId":"632fde9d-93df-4d38-a9c8-648a23a384cb","messageLen":10000,"mcpServers":["qdrant"],"msg":"Starting agent query"}
{"level":30,"hasResult":false,"subtype":"error_during_execution","msg":"Agent result received"}
{"level":50,"category":"subprocess_crash","originalMsg":"Claude Code process exited with code 1","msg":"Agent query failed (classified)"}
{"level":50,"err":{"type":"AgentError","message":"Claude Code subprocess crashed. Retrying...","stack":"... at runAgent ... at async processDashboardMessage ..."},"msg":"Dashboard message processing error"}
```

The diagnostic signal is the pair `subtype: "error_during_execution"` + `Claude Code process exited with code 1`. The `messageLen: 10000` was a red herring — that's just the size of the prompt assembled from the agent role + memory context + user text.

## Root cause

The Anthropic Claude-Code SDK persists session state somewhere keyed to the spawning process's cwd + settings. When `runAgent()` is called with a `sessionId` argument, the SDK launches a child process that tries to load and continue that session. If the calling process's cwd / `CLAUDE.md` / settings don't match what the session was originally created against, the child process can't reconcile state and exits 1.

In our multi-process model:

- `com.claudeclaw.research` runs in `agents/research/` with its own `CLAUDE.md` and `agent.yaml`.
- The main dashboard runs in the repo root with the main agent's `CLAUDE.md`.
- `dashboard_sessions.session_id` (managed in `src/db.ts:getSession/setSession`) is a single shared key per (chatId, agentId) tuple. Both processes read/write it.

When the operator chats with `research` via Telegram, the research bot process creates a session ID in the SDK and writes it via `setSession(chatId, newSessionId, 'research')`. Later, when the dashboard's main process attempts `runAgent(..., getSession(chatId, 'research'))`, the SDK subprocess started by the main process tries to resume a session created by the research process — and crashes.

`src/orchestrator.ts:delegateToAgent` already knew this. Line 206:

```ts
const result = await runAgent(
  fullPrompt,
  undefined, // fresh session for each delegation
  ...
);
```

The original per-agent chat-routing patch (`0f2c8b9`) replicated the rest of the delegate-pattern (load agent config, resolve CLAUDE.md, build memory context) but missed copying this one line and its rationale.

## Fix

Two-part change in `src/bot.ts:processDashboardMessage` (commit `a4dfb07`):

```ts
// Don't resume sessions across processes.
const sessionId = isSubAgent ? undefined : getSession(chatIdStr, effectiveAgentId);

// Always include the agent role for sub-agents (no session to carry it over).
if (effectiveSystemPrompt && (isSubAgent || !sessionId)) {
  parts.push(`[Agent role — follow these instructions]\n${effectiveSystemPrompt}\n[End agent role]`);
}

// ... runAgent(...)

// Don't writeback for sub-agents — would clobber the Telegram-side session.
if (result.newSessionId && !isSubAgent) {
  setSession(chatIdStr, result.newSessionId, effectiveAgentId);
}
```

`isSubAgent` is `true` when `targetAgentId` is defined and not `'main'` / `'all'`.

## Trade-off

Sub-agent dashboard turns lose Anthropic-side session continuity (the SDK doesn't keep tokens cached for "the next turn"). The agent isn't amnesiac — `buildMemoryContext()` ranks recent `conversation_log` rows and surfaces them via the prompt's memory block, so the agent gets recent context back. It just doesn't get the same in-context history a same-process session resume would give.

Same trade-off the orchestrator delegations already accept. Acceptable cost for the cross-process safety.

## Detection signals to remember

If a future change has SDK runs throwing `Claude Code process exited with code 1` immediately after start, with `subtype: "error_during_execution"` and no useful diagnostic in the message text:

1. Is the `sessionId` passed to `runAgent()` non-undefined?
2. Was that `sessionId` originally written by a process with a different cwd than the one running `runAgent()` now?
3. Does `getSession(chatId, agentId)` return a value when the running process is NOT the agent's primary launchd unit (i.e. the dashboard or a delegating agent invoking a different agent)?

If all three are yes, the fix is to pass `undefined` for the sessionId at this call site.

## Prevention rules

These rules now apply to any new code that invokes `runAgent()` from inside the main dashboard process or any other "shared" process:

1. **Never resume Anthropic SDK sessions across process boundaries.** A "process boundary" is anywhere two distinct OS processes (different launchd units, different `node` invocations) could have created or could attempt to resume the same `sessionId` value.
2. **Compute `isSubAgent` (or equivalent) at the call site** to decide whether to pass `sessionId` or `undefined` to `runAgent()`.
3. **Don't writeback `setSession()` for cross-process invocations.** It clobbers the session ID that the agent's own bot process is using.
4. **For UI continuity, lean on `buildMemoryContext()`** instead of session resume. Memory recall covers most of what an in-context resume would have given you.
5. **System prompt always goes in the prompt for fresh sessions.** If you're choosing `undefined` for sessionId, also include the agent-role prefix in the prompt (no session to carry it over).

## Reference: places this pattern is already correct

- `src/orchestrator.ts:delegateToAgent` (~line 206) — the canonical example.
- `src/bot.ts:processMessage` (Telegram-side) — uses `AGENT_ID` correctly because it's per-agent-process; same-process resume works.
- `src/bot.ts:processDashboardMessage` (after `a4dfb07`) — what this post-mortem documents.

## Related discoveries

- `dashboard.ts:spaShellHtml` was previously missed at the SPA catch-all (`*` route), causing the `<meta name="ccd-use-session-auth">` injection to be skipped on SPA routes other than `/` and `/warroom`. Same shape of bug — when introducing a per-request HTML transformation, audit ALL paths that read the source HTML, not just the obvious entry route. Fixed in commit `a88498c`.
- AADSTS500112 redirect-uri scheme mismatch — when constructing URLs for outbound OAuth2 calls behind a TLS-terminating proxy, derive from the canonical config-validated URI, not from `c.req.url`. Fixed in commit `beec434`.

Each of these has the same shape: **don't trust the obvious source; identify ALL the places where the same value flows.**
