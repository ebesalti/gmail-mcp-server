import express, { Request, Response, NextFunction } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { google } from "googleapis";
import { z } from "zod";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { GmailService } from "./gmail-service.js";
import { TokenStore } from "./token-store.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.PORT || "3000", 10);
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD!;
// The MCP endpoint lives at /mcp/<MCP_SECRET>. Claude custom connectors cannot
// send a header, so the secret in the path is what keeps the mailbox private.
const MCP_SECRET = process.env.MCP_SECRET!;

// Refuse to start with a missing secret. An unset ADMIN_PASSWORD used to let
// requests without a password through the admin check.
const missing = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "ADMIN_PASSWORD",
  "MCP_SECRET",
  "ENCRYPTION_KEY",
].filter((k) => !process.env[k]);
if (missing.length) {
  throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
}
if (MCP_SECRET.length < 32) throw new Error("MCP_SECRET must be at least 32 characters");
if (ADMIN_PASSWORD.length < 16) throw new Error("ADMIN_PASSWORD must be at least 16 characters");

const SECURE_COOKIES = SERVER_URL.startsWith("https://");
const SESSION_COOKIE = "gmcp_admin";
const STATE_COOKIE = "gmcp_oauth_state";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/userinfo.email",
];

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

const tokenStore = new TokenStore();

// ---------------------------------------------------------------------------
// Gmail service factory — exchanges stored refresh token for access token
// ---------------------------------------------------------------------------

function makeOAuth2Client() {
  return new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    `${SERVER_URL}/oauth/callback`
  );
}

async function getGmailServiceForAccount(email: string): Promise<GmailService> {
  const refreshToken = tokenStore.getRefreshToken(email);
  if (!refreshToken) {
    throw new Error(
      `Account "${email}" is not connected. Use list_accounts to see connected accounts, or add it via the /setup page.`
    );
  }

  const oauth2 = makeOAuth2Client();
  oauth2.setCredentials({ refresh_token: refreshToken });

  const { token } = await oauth2.getAccessToken();
  if (!token) {
    throw new Error(
      `Failed to get access token for "${email}". The account may need to be re-authorized via /setup.`
    );
  }

  return new GmailService(token);
}

function resolveAccounts(account: string): string[] {
  if (account.toLowerCase() === "all") {
    const all = tokenStore.listAccounts().map((a) => a.email);
    if (all.length === 0) {
      throw new Error("No accounts connected. Add accounts via the /setup page.");
    }
    return all;
  }
  if (!tokenStore.hasAccount(account)) {
    const available = tokenStore.listAccounts().map((a) => a.email);
    throw new Error(
      `Account "${account}" is not connected. Available accounts: ${available.join(", ") || "none"}`
    );
  }
  return [account];
}

// ---------------------------------------------------------------------------
// MCP server factory — registers all tools
// ---------------------------------------------------------------------------

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "gmail-mcp-server",
    version: "1.0.0",
  });

  // ---- list_accounts ----
  server.tool(
    "list_accounts",
    "List all connected Gmail accounts. Use the email addresses returned here as the 'account' parameter in other tools.",
    {},
    async () => {
      const accounts = tokenStore.listAccounts();
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                connected_accounts: accounts,
                usage_hint:
                  "Use any email address as the 'account' parameter, or use 'all' to query every account.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ---- list_emails ----
  server.tool(
    "list_emails",
    "Search and list emails. Supports Gmail search syntax (is:unread, from:, newer_than:7d, etc). Use account='all' to search across all connected accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .optional()
        .describe(
          "Gmail search query (e.g. 'is:unread', 'from:user@example.com newer_than:2d', 'subject:invoice')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to return per account (1-100)"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{ account: string; emails: any[]; error?: string }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.listEmails(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({ account: email, emails: [], error: err?.message ?? String(err) });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(allResults, null, 2),
          },
        ],
      };
    }
  );

  // ---- get_email ----
  server.tool(
    "get_email",
    "Get the full content of a specific email including body, headers, and any unsubscribe links found.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const email = await gmail.getEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...email }, null, 2),
          },
        ],
      };
    }
  );

  // ---- archive_email ----
  server.tool(
    "archive_email",
    "Archive an email by removing it from the inbox. The email remains accessible via search or All Mail.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID to archive"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.archiveEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Email ${message_id} archived successfully.`,
            }),
          },
        ],
      };
    }
  );

  // ---- apply_label ----
  server.tool(
    "apply_label",
    "Apply a label to an email. Creates the label if it does not already exist.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
      label_name: z
        .string()
        .describe(
          "Label name to apply (e.g. 'Receipts', 'Follow Up'). Created automatically if it does not exist."
        ),
    },
    async ({ account, message_id, label_name }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.applyLabel(message_id, label_name);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Label "${label_name}" applied to email ${message_id}.`,
            }),
          },
        ],
      };
    }
  );

  // ---- unsubscribe_email ----
  server.tool(
    "unsubscribe_email",
    "Unsubscribe from a mailing list. May SEND an email from this account (List-Unsubscribe mailto). Uses RFC 8058 one-click POST when offered, else sends the List-Unsubscribe mailto from this account. Returns status: confirmed | sent | needs_manual_click (links in manualLinks) | failed. Only confirmed/sent count as done.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z
        .string()
        .describe("The Gmail message ID to unsubscribe from"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.unsubscribeEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...result }, null, 2),
          },
        ],
      };
    }
  );

  // ---- compose fields shared by create_draft and send_email ----
  const addressList = z
    .array(z.string())
    .optional();
  const composeFields = {
    account: z
      .string()
      .describe("Email address of the connected account to write from (not 'all')"),
    to: addressList.describe(
      "Recipients, e.g. ['jane@example.com', 'Bob <bob@example.com>']. Optional when replying: defaults to the original sender."
    ),
    cc: addressList.describe("Cc recipients"),
    bcc: addressList.describe("Bcc recipients"),
    subject: z
      .string()
      .optional()
      .describe("Subject line. Optional when replying: defaults to 'Re: <original subject>'."),
    body: z.string().describe("Plain text body"),
    html_body: z
      .string()
      .optional()
      .describe("Optional HTML version of the body. The plain text body is still sent as the fallback."),
    reply_to_message_id: z
      .string()
      .optional()
      .describe("Gmail message ID to reply to. Keeps the message in the same thread with proper reply headers."),
    reply_all: z
      .boolean()
      .default(false)
      .describe("When replying without 'to', also include the original To and Cc recipients (except yourself)."),
  };

  const toCompose = (a: any) => ({
    to: a.to,
    cc: a.cc,
    bcc: a.bcc,
    subject: a.subject,
    body: a.body,
    htmlBody: a.html_body,
    replyToMessageId: a.reply_to_message_id,
    replyAll: a.reply_all,
  });

  const singleAccount = (account: string) => {
    if (account.toLowerCase() === "all") {
      throw new Error("Pick one account to write from; 'all' is only for reading.");
    }
    return resolveAccounts(account)[0];
  };

  // ---- create_draft ----
  server.tool(
    "create_draft",
    "Create a draft email in a connected Gmail account. Nothing is sent. The draft appears in that account's Drafts folder, where it can be reviewed, edited or sent (also with send_email and draft_id). Supports replies in a thread via reply_to_message_id.",
    composeFields,
    async (args) => {
      const email = singleAccount(args.account);
      const gmail = await getGmailServiceForAccount(email);
      const draft = await gmail.createDraft(toCompose(args));
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account: email, status: "draft_created", ...draft }, null, 2),
          },
        ],
      };
    }
  );

  // ---- send_email ----
  server.tool(
    "send_email",
    "Send an email from a connected Gmail account. This delivers immediately and cannot be undone. Either compose a new message (to, subject, body) or pass draft_id to send an existing draft as saved. Supports replies in a thread via reply_to_message_id.",
    {
      ...composeFields,
      body: z
        .string()
        .optional()
        .describe("Plain text body. Required unless draft_id is given."),
      draft_id: z
        .string()
        .optional()
        .describe("Send this existing draft exactly as saved. When set, all other compose fields must be left out."),
    },
    async (args) => {
      const email = singleAccount(args.account);
      const gmail = await getGmailServiceForAccount(email);
      let sent;
      if (args.draft_id) {
        const composed = ["to", "cc", "bcc", "subject", "body", "html_body", "reply_to_message_id"].filter(
          (k) => (args as any)[k] !== undefined
        );
        if (composed.length) {
          throw new Error(`draft_id sends the draft as saved; remove ${composed.join(", ")} or edit the draft first.`);
        }
        sent = await gmail.sendDraft(args.draft_id);
      } else {
        if (args.body === undefined) throw new Error("body is required when not sending a draft.");
        sent = await gmail.sendEmail(toCompose(args));
      }
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account: email, status: "sent", ...sent }, null, 2),
          },
        ],
      };
    }
  );

  // ---- batch_process ----
  server.tool(
    "batch_process",
    "Fetch a batch of emails matching a query for triage. Returns structured data so you can decide which actions to take on each email. Use account='all' to scan all accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .describe(
          "Gmail search query (e.g. 'is:unread category:promotions', 'newer_than:7d')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to fetch per account"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{ account: string; emails: any[]; error?: string }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.batchProcess(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({ account: email, emails: [], error: err?.message ?? String(err) });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                total: allResults.reduce((n, r) => n + r.emails.length, 0),
                query,
                results: allResults,
                hint: "Review each email and decide whether to archive, label, unsubscribe, or skip. Use the individual tools with the correct account parameter.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serverless instances do not share memory, so read the accounts fresh.
app.use(async (_req, _res, next) => {
  try {
    await tokenStore.refresh();
    next();
  } catch (err) {
    next(err);
  }
});

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function safeEqual(given: string | undefined, expected: string): boolean {
  if (!given || !expected) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function secretMatches(given: string | undefined): boolean {
  return safeEqual(given, MCP_SECRET);
}

// ---------------------------------------------------------------------------
// Admin session: password is POSTed once, then an HMAC-signed HttpOnly cookie.
// The password never appears in a URL, a log line or the OAuth state.
// ---------------------------------------------------------------------------

function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) {
      return decodeURIComponent(part.slice(i + 1).trim());
    }
  }
  return undefined;
}

function cookieAttrs(maxAgeSeconds: number): string {
  return `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${SECURE_COOKIES ? "; Secure" : ""}`;
}

function sign(value: string): string {
  return createHmac("sha256", `${ADMIN_PASSWORD}|${MCP_SECRET}`).update(value).digest("hex");
}

function makeSession(): string {
  const expires = Date.now() + SESSION_TTL_MS;
  return `${expires}.${sign(`admin:${expires}`)}`;
}

function sessionValid(req: Request): boolean {
  const cookie = readCookie(req, SESSION_COOKIE);
  if (!cookie) return false;
  const [expires, mac] = cookie.split(".");
  if (!expires || !mac || Number(expires) < Date.now()) return false;
  return safeEqual(mac, sign(`admin:${expires}`));
}

function loginPage(res: Response, status: number, error?: string): void {
  res.status(status).send(`
    <html><body style="font-family:system-ui;max-width:400px;margin:80px auto;text-align:center">
      <h2>Admin Login</h2>
      ${error ? `<p style="color:#c00">${escapeHtml(error)}</p>` : ""}
      <form method="POST" action="/setup/login">
        <input type="password" name="password" placeholder="Admin password" autocomplete="current-password" style="padding:8px;width:100%;box-sizing:border-box;margin-bottom:12px" />
        <button type="submit" style="padding:8px 24px">Login</button>
      </form>
    </body></html>
  `);
}

function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!sessionValid(req)) {
    loginPage(res, 401);
    return;
  }
  next();
}

function setupRedirect(res: Response, message: string): void {
  res.redirect(`/setup?message=${encodeURIComponent(message)}`);
}

app.post("/setup/login", (req: Request, res: Response) => {
  if (!safeEqual(req.body?.password, ADMIN_PASSWORD)) {
    loginPage(res, 401, "Wrong password");
    return;
  }
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${makeSession()}; ${cookieAttrs(SESSION_TTL_MS / 1000)}`);
  res.redirect("/setup");
});

app.post("/setup/logout", (_req: Request, res: Response) => {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; ${cookieAttrs(0)}`);
  res.redirect("/setup");
});

// ---------------------------------------------------------------------------
// Setup page — manage connected Gmail accounts
// ---------------------------------------------------------------------------

app.get("/setup", requireAdmin, (_req: Request, res: Response) => {
  const accounts = tokenStore.listAccounts();
  const message = _req.query.message as string | undefined;

  const accountRows = accounts.length > 0
    ? accounts
        .map(
          (a) => `
        <tr>
          <td>${escapeHtml(a.email)}</td>
          <td>${escapeHtml(new Date(a.addedAt).toLocaleDateString())}</td>
          <td>
            <form method="POST" action="/setup/remove" style="display:inline" onsubmit="return confirm('Remove this account?')">
              <input type="hidden" name="email" value="${escapeHtml(a.email)}" />
              <button type="submit" style="color:red;background:none;border:1px solid red;padding:4px 12px;cursor:pointer">Remove</button>
            </form>
          </td>
        </tr>`
        )
        .join("")
    : `<tr><td colspan="3" style="text-align:center;color:#888">No accounts connected yet</td></tr>`;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Gmail MCP — Setup</title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
        h1 { font-size: 1.5rem; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
        th { font-weight: 600; border-bottom: 2px solid #ddd; }
        .btn { display: inline-block; padding: 10px 24px; background: #4285f4; color: white; text-decoration: none; border-radius: 6px; font-size: 14px; }
        .btn:hover { background: #3367d6; }
        .msg { padding: 12px; background: #e8f5e9; border-radius: 6px; margin-bottom: 16px; }
        .msg.error { background: #fce4ec; }
      </style>
    </head>
    <body>
      <h1>Gmail MCP Server — Setup</h1>
      ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ""}
      <table>
        <thead><tr><th>Account</th><th>Added</th><th></th></tr></thead>
        <tbody>${accountRows}</tbody>
      </table>
      <a class="btn" href="/oauth/start">+ Add Gmail Account</a>
      <form method="POST" action="/setup/logout" style="display:inline;margin-left:12px">
        <button type="submit" style="background:none;border:none;color:#888;cursor:pointer">Log out</button>
      </form>
      <hr style="margin-top:40px;border:none;border-top:1px solid #eee" />
      <p style="color:#888;font-size:13px">
        MCP endpoint: <code>${SERVER_URL}/mcp/${MCP_SECRET}</code><br/>
        Connected accounts: ${accounts.length}
      </p>
    </body>
    </html>
  `);
});

app.post("/setup/remove", requireAdmin, async (req: Request, res: Response) => {
  const email = req.body?.email;

  if (email && tokenStore.hasAccount(email)) {
    await tokenStore.removeAccount(email);
    setupRedirect(res, `Removed ${email}`);
  } else {
    setupRedirect(res, "Account not found");
  }
});

// ---------------------------------------------------------------------------
// OAuth flow — server-managed Google auth
// ---------------------------------------------------------------------------

app.get("/oauth/start", requireAdmin, (_req: Request, res: Response) => {
  // One-time random state, bound to this browser by an HttpOnly cookie.
  const state = randomBytes(24).toString("hex");
  res.setHeader("Set-Cookie", `${STATE_COOKIE}=${state}; ${cookieAttrs(600)}`);

  const oauth2 = makeOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state,
  });

  res.redirect(url);
});

app.get("/oauth/callback", async (req: Request, res: Response) => {
  const code = req.query.code as string | undefined;
  const state = req.query.state as string | undefined;
  const error = req.query.error as string | undefined;
  const expectedState = readCookie(req, STATE_COOKIE);
  res.setHeader("Set-Cookie", `${STATE_COOKIE}=; ${cookieAttrs(0)}`);

  // Only a logged-in admin who started this exact flow may add an account.
  if (!sessionValid(req) || !expectedState || !safeEqual(state, expectedState)) {
    res.status(403).send("Invalid or expired OAuth state. Start again from /setup.");
    return;
  }

  if (error) {
    setupRedirect(res, `OAuth error: ${error}`);
    return;
  }

  if (!code) {
    setupRedirect(res, "No authorization code received");
    return;
  }

  try {
    const oauth2 = makeOAuth2Client();
    const { tokens } = await oauth2.getToken(code);

    if (!tokens.refresh_token) {
      setupRedirect(res, "No refresh token received. Try removing the app from your Google account permissions and re-adding.");
      return;
    }

    // Get the user's email address
    oauth2.setCredentials(tokens);
    const oauth2Api = google.oauth2({ version: "v2", auth: oauth2 });
    const userInfo = await oauth2Api.userinfo.get();
    const email = userInfo.data.email;

    if (!email) {
      setupRedirect(res, "Could not determine email address");
      return;
    }

    await tokenStore.addAccount(email, tokens.refresh_token);
    setupRedirect(res, `Successfully connected ${email}`);
  } catch (err: any) {
    console.error("[oauth/callback] Error:", err?.message ?? err);
    setupRedirect(res, `Error: ${err?.message ?? "unknown"}`);
  }
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    accounts: tokenStore.size,
  });
});

// ---------------------------------------------------------------------------
// MCP transport — Streamable HTTP (stateless: each request gets a fresh server)
// ---------------------------------------------------------------------------

app.post("/mcp/:secret", async (req: Request, res: Response) => {
  if (!secretMatches(req.params.secret as string)) {
    res.status(404).send("Not found");
    return;
  }
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless — no session tracking
    });

    const mcpServer = createMcpServer();
    await mcpServer.connect(transport);

    await transport.handleRequest(req, res, req.body);

    // Clean up after response is sent
    res.on("close", () => {
      mcpServer.close().catch(() => {});
      transport.close().catch(() => {});
    });
  } catch (err: any) {
    console.error("[mcp] Error handling request:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: err.message },
        id: null,
      });
    }
  }
});

app.get("/mcp/:secret", async (req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "SSE streams not supported in stateless mode. Use POST." },
    id: null,
  });
});

app.delete("/mcp/:secret", async (req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Session management not used in stateless mode." },
    id: null,
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

export default app;

// Vercel imports the app; anywhere else, listen as before.
if (!process.env.VERCEL) app.listen(PORT, () => {
  console.log(`Gmail MCP server listening on port ${PORT}`);
  console.log(`  MCP endpoint:  ${SERVER_URL}/mcp/<MCP_SECRET>`);
  console.log(`  Setup page:    ${SERVER_URL}/setup`);
  console.log(`  Health check:  ${SERVER_URL}/health`);
  console.log(`  Accounts:      ${tokenStore.size}`);
});
