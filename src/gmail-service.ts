import { marked } from "marked";
import type { GoogleClient } from "./google-client.js";

const GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1/users/me";

/**
 * Gmail search snippet automatically appended to every search query to
 * exclude system / security notifications from Google that have no family
 * value and may leak internal routing details if surfaced to the MCP.
 */
const NOREPLY_GOOGLE_FILTER = "-from:noreply@google.com";

function isNoreplyGoogle(fromHeader: string): boolean {
  return /noreply@google\.com/i.test(fromHeader);
}

// --- Types ---

export interface GmailThreadSummary {
  threadId: string;
  subject: string;
  from: string;
  cc?: string;
  bcc?: string;
  date: string;
  snippet: string;
  messageCount: number;
}

export interface GmailMessage {
  messageId: string;
  from: string;
  to: string;
  cc?: string;
  bcc?: string;
  date: string;
  subject: string;
  body: string;
  attachments: AttachmentMeta[];
}

export interface GmailLabel {
  id: string;
  name: string;
  type: string;
}

// --- Helpers ---

function base64urlDecode(data: string): string {
  const padded = data.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64").toString("utf-8");
}

function base64urlEncode(str: string): string {
  return Buffer.from(str, "utf-8").toString("base64url");
}

function encodeSubject(subject: string): string {
  if (!/[^\x00-\x7F]/.test(subject)) return subject;
  return `=?UTF-8?B?${Buffer.from(subject, "utf-8").toString("base64")}?=`;
}

interface PayloadPart {
  mimeType?: string;
  filename?: string;
  body?: { data?: string; attachmentId?: string; size?: number };
  parts?: PayloadPart[];
}

export interface AttachmentMeta {
  messageId: string;
  attachmentId: string;
  filename: string;
  mimeType: string;
  size: number;
}

function extractTextFromParts(parts: PayloadPart[]): string {
  let text = "";
  for (const part of parts) {
    if (part.mimeType === "text/plain" && part.body?.data) {
      text += base64urlDecode(part.body.data);
    }
    if (part.parts) {
      text += extractTextFromParts(part.parts);
    }
  }
  return text;
}

function extractAttachmentsFromParts(messageId: string, parts: PayloadPart[]): AttachmentMeta[] {
  const attachments: AttachmentMeta[] = [];
  for (const part of parts) {
    if (part.body?.attachmentId && part.filename) {
      attachments.push({
        messageId,
        attachmentId: part.body.attachmentId,
        filename: part.filename,
        mimeType: part.mimeType ?? "application/octet-stream",
        size: part.body.size ?? 0,
      });
    }
    if (part.parts) {
      attachments.push(...extractAttachmentsFromParts(messageId, part.parts));
    }
  }
  return attachments;
}

// --- API Functions ---

// Lightweight: just returns thread IDs from a search query (single API call, no per-thread fetches)
export async function gmailListThreadIds(
  client: GoogleClient,
  query: string,
  maxResults = 10,
): Promise<string[]> {
  const safeQuery = query ? `${query} ${NOREPLY_GOOGLE_FILTER}` : NOREPLY_GOOGLE_FILTER;
  const params = new URLSearchParams({
    q: safeQuery,
    maxResults: String(maxResults),
  });

  const listData = await client.request<{
    threads?: { id: string }[];
  }>("GET", `${GMAIL_BASE}/threads?${params}`);

  return listData.threads?.map((t) => t.id) ?? [];
}

export async function gmailSearch(
  client: GoogleClient,
  query: string,
  maxResults = 10,
): Promise<GmailThreadSummary[]> {
  const safeQuery = query ? `${query} ${NOREPLY_GOOGLE_FILTER}` : NOREPLY_GOOGLE_FILTER;
  const params = new URLSearchParams({
    q: safeQuery,
    maxResults: String(maxResults),
  });

  const listData = await client.request<{
    threads?: { id: string }[];
  }>("GET", `${GMAIL_BASE}/threads?${params}`);

  if (!listData.threads?.length) return [];

  const results = await Promise.all(
    listData.threads.map(async (t) => {
      const params = new URLSearchParams({
        format: "METADATA",
        metadataHeaders: "Subject",
      });
      // Need multiple metadataHeaders - build URL manually
      const url = `${GMAIL_BASE}/threads/${t.id}?format=METADATA&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date&metadataHeaders=Cc&metadataHeaders=Bcc`;

      const thread = await client.request<{
        id: string;
        messages?: {
          snippet?: string;
          payload?: {
            headers?: { name: string; value: string }[];
          };
        }[];
      }>("GET", url);

      const headers = thread.messages?.[0]?.payload?.headers ?? [];
      const get = (name: string) =>
        headers.find((h) => h.name === name)?.value ?? "";

      return {
        threadId: thread.id,
        subject: get("Subject"),
        from: get("From"),
        cc: get("Cc") || undefined,
        bcc: get("Bcc") || undefined,
        date: get("Date"),
        snippet: thread.messages?.[0]?.snippet ?? "",
        messageCount: thread.messages?.length ?? 0,
      };
    }),
  );

  return results;
}

export async function gmailGetThread(
  client: GoogleClient,
  threadId: string,
): Promise<GmailMessage[]> {
  const thread = await client.request<{
    messages?: {
      id: string;
      payload?: {
        headers?: { name: string; value: string }[];
        body?: { data?: string };
        parts?: PayloadPart[];
      };
    }[];
  }>("GET", `${GMAIL_BASE}/threads/${threadId}?format=FULL`);

  return (thread.messages ?? [])
    .filter((msg) => {
      const from = msg.payload?.headers?.find((h) => h.name === "From")?.value ?? "";
      return !isNoreplyGoogle(from);
    })
    .map((msg) => {
    const headers = msg.payload?.headers ?? [];
    const get = (name: string) =>
      headers.find((h) => h.name === name)?.value ?? "";

    let body = "";
    if (msg.payload?.body?.data) {
      body = base64urlDecode(msg.payload.body.data);
    } else if (msg.payload?.parts) {
      body = extractTextFromParts(msg.payload.parts);
    }

    const attachments = msg.payload?.parts
      ? extractAttachmentsFromParts(msg.id, msg.payload.parts)
      : [];

    return {
      messageId: msg.id,
      from: get("From"),
      to: get("To"),
      cc: get("Cc") || undefined,
      bcc: get("Bcc") || undefined,
      date: get("Date"),
      subject: get("Subject"),
      body: body.trim(),
      attachments,
    };
  });
}

export async function gmailCreateDraft(
  client: GoogleClient,
  opts: {
    to: string;
    subject: string;
    body: string;
    cc?: string;
    bcc?: string;
    threadId?: string;
  },
): Promise<{ draftId: string; messageId: string }> {
  sanitizeHeader(opts.to, "to");
  sanitizeHeader(opts.subject, "subject");
  if (opts.cc) sanitizeHeader(opts.cc, "cc");
  if (opts.bcc) sanitizeHeader(opts.bcc, "bcc");

  let headers = `To: ${opts.to}\nSubject: ${encodeSubject(opts.subject)}\nContent-Type: text/plain; charset=utf-8\n`;
  if (opts.cc) headers += `Cc: ${opts.cc}\n`;
  if (opts.bcc) headers += `Bcc: ${opts.bcc}\n`;

  const raw = base64urlEncode(`${headers}\n${opts.body}`);

  const draft = await client.request<{
    id: string;
    message: { id: string };
  }>("POST", `${GMAIL_BASE}/drafts`, {
    message: {
      raw,
      threadId: opts.threadId ?? undefined,
    },
  });

  return {
    draftId: draft.id,
    messageId: draft.message.id,
  };
}

// --- Header injection prevention ---

function sanitizeHeader(field: string, name: string): string {
  if (/[\r\n]/.test(field)) {
    throw new Error(`${name} contains invalid characters`);
  }
  return field;
}

// --- Markdown to HTML (lightweight) ---

function markdownToHtml(md: string): string {
  const html = marked.parse(md, { async: false, breaks: true, gfm: true }) as string;
  return `<html><body>${html}</body></html>`;
}

// --- Send & Forward ---

export async function gmailSend(
  client: GoogleClient,
  opts: {
    to: string;
    subject: string;
    body: string;
    cc?: string;
    bcc?: string;
    threadId?: string;
    inReplyTo?: string;
    references?: string;
  },
): Promise<{ messageId: string; threadId: string }> {
  sanitizeHeader(opts.to, "to");
  sanitizeHeader(opts.subject, "subject");
  if (opts.cc) sanitizeHeader(opts.cc, "cc");
  if (opts.bcc) sanitizeHeader(opts.bcc, "bcc");

  const htmlBody = markdownToHtml(opts.body);
  const boundary = `----=_Part_${Date.now()}`;

  let headers = `To: ${opts.to}\n`;
  headers += `Subject: ${encodeSubject(opts.subject)}\n`;
  if (opts.cc) headers += `Cc: ${opts.cc}\n`;
  if (opts.bcc) headers += `Bcc: ${opts.bcc}\n`;
  if (opts.inReplyTo) headers += `In-Reply-To: ${opts.inReplyTo}\n`;
  if (opts.references) headers += `References: ${opts.references}\n`;
  headers += `MIME-Version: 1.0\n`;
  headers += `Content-Type: multipart/alternative; boundary="${boundary}"\n`;

  const message =
    `${headers}\n` +
    `--${boundary}\n` +
    `Content-Type: text/plain; charset=UTF-8\n\n` +
    `${opts.body}\n` +
    `--${boundary}\n` +
    `Content-Type: text/html; charset=UTF-8\n\n` +
    `${htmlBody}\n` +
    `--${boundary}--`;

  const raw = base64urlEncode(message);

  const result = await client.request<{
    id: string;
    threadId: string;
  }>("POST", `${GMAIL_BASE}/messages/send`, {
    raw,
    threadId: opts.threadId ?? undefined,
  });

  return {
    messageId: result.id,
    threadId: result.threadId,
  };
}

export async function gmailForward(
  client: GoogleClient,
  opts: {
    messageId: string;
    to: string;
  },
): Promise<{ messageId: string; threadId: string }> {
  sanitizeHeader(opts.to, "to");

  // Fetch original message
  const original = await client.request<{
    id: string;
    threadId: string;
    payload?: {
      headers?: { name: string; value: string }[];
      body?: { data?: string };
      parts?: PayloadPart[];
    };
  }>("GET", `${GMAIL_BASE}/messages/${opts.messageId}?format=FULL`);

  const headers = original.payload?.headers ?? [];
  const getHeader = (name: string) =>
    headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? "";

  let originalBody = "";
  if (original.payload?.body?.data) {
    originalBody = base64urlDecode(original.payload.body.data);
  } else if (original.payload?.parts) {
    originalBody = extractTextFromParts(original.payload.parts);
  }

  const fwdBlock =
    `---------- Forwarded message ---------\n` +
    `From: ${getHeader("From")}\n` +
    `Date: ${getHeader("Date")}\n` +
    `Subject: ${getHeader("Subject")}\n` +
    `To: ${getHeader("To")}\n\n` +
    originalBody.trim();

  const subject = getHeader("Subject").startsWith("Fwd:")
    ? getHeader("Subject")
    : `Fwd: ${getHeader("Subject")}`;

  let rawHeaders = `To: ${opts.to}\n`;
  rawHeaders += `Subject: ${encodeSubject(subject)}\n`;
  rawHeaders += `Content-Type: text/plain; charset=UTF-8\n`;

  const raw = base64urlEncode(`${rawHeaders}\n${fwdBlock}`);

  const result = await client.request<{
    id: string;
    threadId: string;
  }>("POST", `${GMAIL_BASE}/messages/send`, {
    raw,
  });

  return {
    messageId: result.id,
    threadId: result.threadId,
  };
}

export async function gmailMarkRead(
  client: GoogleClient,
  opts: {
    message_ids?: string[];
    thread_id?: string;
  },
): Promise<{ markedRead: string[] }> {
  const ids: string[] = [...(opts.message_ids ?? [])];

  // If thread_id provided, fetch all message IDs in the thread
  if (opts.thread_id) {
    const thread = await client.request<{
      messages?: { id: string }[];
    }>("GET", `${GMAIL_BASE}/threads/${opts.thread_id}?format=MINIMAL`);
    for (const msg of thread.messages ?? []) {
      if (!ids.includes(msg.id)) ids.push(msg.id);
    }
  }

  if (ids.length === 0) {
    throw new Error("No message IDs or thread ID provided.");
  }

  await Promise.all(
    ids.map((id) =>
      client.request("POST", `${GMAIL_BASE}/messages/${id}/modify`, {
        removeLabelIds: ["UNREAD"],
      }),
    ),
  );

  return { markedRead: ids };
}

export async function gmailGetAttachment(
  client: GoogleClient,
  messageId: string,
  attachmentId: string,
): Promise<{ data: string; size: number }> {
  const result = await client.request<{ data: string; size: number }>(
    "GET",
    `${GMAIL_BASE}/messages/${messageId}/attachments/${attachmentId}`,
  );
  return { data: result.data, size: result.size };
}

export async function gmailListLabels(
  client: GoogleClient,
): Promise<GmailLabel[]> {
  const data = await client.request<{
    labels?: { id: string; name: string; type: string }[];
  }>("GET", `${GMAIL_BASE}/labels`);

  return (data.labels ?? []).map((l) => ({
    id: l.id,
    name: l.name,
    type: l.type,
  }));
}
