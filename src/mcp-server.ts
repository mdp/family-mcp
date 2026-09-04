import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Env } from "./env.js";
import type { Storage } from "./storage.js";
import { GoogleClient } from "./google-client.js";
import type { GoogleTokens, AuthExtra } from "./types.js";
import {
  resolveTargetAccount,
  assertRecipientsAllowed,
  assertAttendeesAllowed,
  parseAllowedList,
} from "./access-policy.js";
import {
  gmailSearch,
  gmailGetThread,
  gmailGetAttachment,
  gmailCreateDraft,
  gmailSend,
  gmailForward,
  gmailListLabels,
  gmailMarkRead,
  type GmailThreadSummary,
} from "./gmail-service.js";
import {
  calendarList,
  calendarListEvents,
  calendarGetEvent,
  calendarCreateEvent,
  calendarUpdateEvent,
  calendarDeleteEvent,
} from "./calendar-service.js";
import {
  driveListFiles,
  driveSearchFiles,
  driveReadFile,
  driveGetFileBytes,
  driveUploadFile,
  driveCreateFolder,
} from "./drive-service.js";
import { listFamilyMembers, parseFamilyProfiles, type FamilyProfile } from "./family-profiles.js";
import { registerSkillTools } from "./skills/tools.js";
import { SKILL_NAMES, renderSkillMarkdown, skillCatalogSummary, skillIndex, type SkillName } from "./skills/registry.js";

function errorResult(message: string) {
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: message }],
  };
}

function successResult(data: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof data === "string" ? data : JSON.stringify(data, null, 2),
      },
    ],
  };
}

function authEmail(extra: { authInfo?: { extra?: unknown } }): string | undefined {
  return (extra.authInfo?.extra as AuthExtra | undefined)?.email;
}

// ─── GoogleClient cache (KV read reduction) ──────────────────────────────────
// GoogleClient.fromStorage does a KV read per call. Clients are cached in
// isolate memory for a short window; ensureValidToken() still re-checks expiry
// against the cached copy and falls back to a KV read + refresh when stale, so
// caching cannot serve an expired access token for longer than that window.
const CLIENT_CACHE_TTL_MS = 5 * 60_000;
const googleClientCache = new Map<string, { client: GoogleClient; at: number }>();

function cachedClient(email: string): GoogleClient | undefined {
  const key = email.toLowerCase();
  const entry = googleClientCache.get(key);
  if (!entry) return undefined;
  if (Date.now() - entry.at > CLIENT_CACHE_TTL_MS) {
    googleClientCache.delete(key);
    return undefined;
  }
  return entry.client;
}

export interface GmailSearchAllAccountResult {
  account: string;
  name: string | null;
  relationship: string | null;
  timezone: string | null;
  authorized: boolean;
  results: GmailThreadSummary[];
  error?: string;
}

export async function searchAllFamilyGmail(opts: {
  allowedEmails: string[];
  profiles: FamilyProfile[];
  query: string;
  maxResults: number;
  clientFor: (email: string) => Promise<GoogleClient | null>;
}): Promise<GmailSearchAllAccountResult[]> {
  return Promise.all(
    opts.allowedEmails.map(async (account) => {
      const profile = opts.profiles.find((member) => member.email.toLowerCase() === account);
      const base = {
        account,
        name: profile?.name ?? null,
        relationship: profile?.relationship ?? null,
        timezone: profile?.timezone ?? null,
      };
      const client = await opts.clientFor(account);
      if (!client) {
        return {
          ...base,
          authorized: false,
          results: [],
        };
      }
      try {
        return {
          ...base,
          authorized: true,
          results: await gmailSearch(client, opts.query, opts.maxResults),
        };
      } catch (error) {
        return {
          ...base,
          authorized: true,
          error: `Error searching Gmail: ${error}`,
          results: [],
        };
      }
    }),
  );
}

function familyInstructions(): string {
  return [
    "Family MCP. Use this server for shared family Gmail, Calendar, and Drive workflows.",
    "Every authenticated family member can operate on every authorized family account. Pass account when targeting a specific family member.",
    `Static skills are available through skills_get. Available skills: ${skillCatalogSummary()}`,
    "Load the relevant skill before specialized work: about for caller context, family-google for cross-account Google work, email-search before shared Gmail search, and calendar before scheduling or invites.",
  ].join("\n");
}

function registerSkillResources(server: McpServer, callerEmail: string, profiles: FamilyProfile[]): void {
  server.registerResource(
    "Family skill index",
    "skill://family/index.json",
    {
      title: "Family MCP skill index",
      description: "Static skills available through the Family MCP server.",
      mimeType: "application/json",
    },
    (_uri, extra) => {
      const email = authEmail(extra) ?? callerEmail;
      return {
        contents: [
          {
            uri: "skill://family/index.json",
            mimeType: "application/json",
            text: JSON.stringify(skillIndex(email, profiles), null, 2),
          },
        ],
      };
    },
  );

  for (const name of SKILL_NAMES) {
    server.registerResource(
      `Family skill: ${name}`,
      `skill://family/${name}/SKILL.md`,
      {
        title: `Family skill: ${name}`,
        description: `Static Family MCP skill markdown for ${name}.`,
        mimeType: "text/markdown",
      },
      (_uri, extra) => {
        const email = authEmail(extra) ?? callerEmail;
        const rendered = renderSkillMarkdown(name as SkillName, email, profiles);
        if ("error" in rendered) {
          return {
            contents: [
              {
                uri: `skill://family/${name}/SKILL.md`,
                mimeType: "text/plain",
                text: rendered.error,
              },
            ],
          };
        }
        return {
          contents: [
            {
              uri: `skill://family/${name}/SKILL.md`,
              mimeType: "text/markdown",
              text: rendered.markdown,
            },
          ],
        };
      },
    );
  }
}

export function createMcpServer(storage: Storage, env: Env, callerEmail: string): McpServer {
  const familyProfiles = parseFamilyProfiles(env.FAMILY_MEMBERS, env.ALLOWED_EMAILS);
  const server = new McpServer(
    {
      name: "family-mcp",
      version: "1.0.0",
    },
    {
      instructions: familyInstructions(),
    },
  );

  registerSkillResources(server, callerEmail, familyProfiles);
  registerSkillTools(server, callerEmail, familyProfiles);

  // All family members may pass `account` to operate on another member's data.
  const accountField = (description: string) => ({
    account: z.string().email().optional().describe(description),
  });

  async function clientFor(email: string): Promise<GoogleClient | null> {
    const cached = cachedClient(email);
    if (cached) return cached;
    const client = await GoogleClient.fromStorage(
      storage,
      email,
      env.GOOGLE_CLIENT_ID,
      env.GOOGLE_CLIENT_SECRET,
    );
    if (client) googleClientCache.set(email.toLowerCase(), { client, at: Date.now() });
    return client;
  }

  // ── accounts_list ─────────────────────────────────────────────────────────
  server.tool(
    "accounts_list",
    "List family accounts that have authorized this server and are ready to use.",
    {},
    async (_args, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const emails = parseAllowedList(env.ALLOWED_EMAILS);
      const results = await Promise.all(
        emails.map(async (e) => {
          const client = await clientFor(e);
          const profile = listFamilyMembers(familyProfiles).find((member) => member.email.toLowerCase() === e);
          let authorized = client !== null;
          let auth_error: string | null = null;

          // ensureValidToken may refresh in the background (one KV write per
          // interval per account); the snapshot reflects pre- or post-refresh
          // state without extra KV reads.
          let tokens: GoogleTokens | null = client ? client.tokenSnapshot : null;
          if (client) {
            try {
              await client.ensureValidToken();
              tokens = client.tokenSnapshot;
            } catch (error) {
              authorized = false;
              auth_error = String(error);
            }
          }

          const now = Date.now();

          return {
            email: e,
            name: profile?.name ?? null,
            relationship: profile?.relationship ?? null,
            timezone: profile?.timezone ?? null,
            authorized,
            auth_error,
            google_token: tokens
              ? {
                  has_refresh_token: Boolean(tokens.refresh_token),
                  obtained_at: tokens.obtained_at ? new Date(tokens.obtained_at).toISOString() : null,
                  expires_at: new Date(tokens.expiry_date).toISOString(),
                  seconds_until_expiry: Math.floor((tokens.expiry_date - now) / 1000),
                }
              : null,
          };
        }),
      );
      return successResult(results);
    },
  );

  // ── Gmail: gmail_search ────────────────────────────────────────────────────
  server.tool(
    "gmail_search",
    "Search Gmail threads by query. Returns thread summaries with subject, sender, date, and snippet.",
    {
      query: z.string().describe("Gmail search query (same syntax as Gmail search box)"),
      max_results: z.number().optional().default(10).describe("Maximum threads to return (default 10)"),
      ...accountField("Family member email to search (defaults to the authenticated user)."),
    },
    async ({ query, max_results, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await gmailSearch(client, query, max_results));
      } catch (error) {
        return errorResult(`Error searching Gmail: ${error}`);
      }
    },
  );

  // ── Gmail: gmail_search_all ────────────────────────────────────────────────
  server.tool(
    "gmail_search_all",
    "Search Gmail threads across all family accounts. Returns per-account result groups; unauthorized accounts are reported without failing the whole search.",
    {
      query: z.string().describe("Gmail search query (same syntax as Gmail search box)"),
      max_results: z.number().optional().default(10).describe("Maximum threads to return per account (default 10)"),
    },
    async ({ query, max_results }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const results = await searchAllFamilyGmail({
        allowedEmails: parseAllowedList(env.ALLOWED_EMAILS),
        profiles: familyProfiles,
        query,
        maxResults: max_results,
        clientFor,
      });

      return successResult({ query, accounts: results });
    },
  );

  // ── Gmail: gmail_get_thread ────────────────────────────────────────────────
  server.tool(
    "gmail_get_thread",
    "Get the full contents of a Gmail thread including all messages with decoded bodies.",
    {
      thread_id: z.string().describe("Gmail thread ID"),
      ...accountField("Family member email whose thread to read (defaults to the authenticated user)."),
    },
    async ({ thread_id, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await gmailGetThread(client, thread_id));
      } catch (error) {
        return errorResult(`Error fetching thread: ${error}`);
      }
    },
  );

  // ── Gmail: gmail_get_attachment ───────────────────────────────────────────
  server.tool(
    "gmail_get_attachment",
    "Fetch a Gmail message attachment as base64url-encoded bytes.",
    {
      message_id: z.string().describe("Gmail message ID that contains the attachment"),
      attachment_id: z.string().describe("Attachment ID from the message payload"),
      ...accountField("Family member email whose attachment to fetch (defaults to the authenticated user)."),
    },
    async ({ message_id, attachment_id, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await gmailGetAttachment(client, message_id, attachment_id));
      } catch (error) {
        return errorResult(`Error fetching attachment: ${error}`);
      }
    },
  );

  // ── Gmail: gmail_create_draft ──────────────────────────────────────────────
  server.tool(
    "gmail_create_draft",
    "Create a draft email. The draft is NOT sent — it is saved to the Drafts folder for review.",
    {
      to: z.string().describe("Recipient email address"),
      subject: z.string().describe("Email subject"),
      body: z.string().describe("Email body (plain text)"),
      cc: z.string().optional().describe("CC recipients (comma-separated)"),
      bcc: z.string().optional().describe("BCC recipients (comma-separated)"),
      thread_id: z.string().optional().describe("Thread ID to attach draft to (for replies)"),
      ...accountField("Family member email to draft into (defaults to the authenticated user)."),
    },
    async ({ to, subject, body, cc, bcc, thread_id, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        const result = await gmailCreateDraft(client, { to, subject, body, cc, bcc, threadId: thread_id });
        return successResult(result);
      } catch (error) {
        return errorResult(`Error creating draft: ${error}`);
      }
    },
  );

  // ── Gmail: gmail_list_labels ───────────────────────────────────────────────
  server.tool(
    "gmail_list_labels",
    "List all Gmail labels.",
    {
      ...accountField("Family member email to list labels for (defaults to the authenticated user)."),
    },
    async ({ account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await gmailListLabels(client));
      } catch (error) {
        return errorResult(`Error listing labels: ${error}`);
      }
    },
  );

  // ── Gmail: gmail_mark_read ─────────────────────────────────────────────────
  server.tool(
    "gmail_mark_read",
    "Mark Gmail messages as read by removing the UNREAD label. Provide message IDs, a thread ID, or both.",
    {
      message_ids: z.array(z.string()).optional().describe("Gmail message IDs to mark as read"),
      thread_id: z.string().optional().describe("Gmail thread ID — all messages in the thread will be marked as read"),
      ...accountField("Family member email whose messages to mark (defaults to the authenticated user)."),
    },
    async ({ message_ids, thread_id, account }, extra) => {
      if (!message_ids?.length && !thread_id) {
        return errorResult("Provide at least one of message_ids or thread_id.");
      }
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await gmailMarkRead(client, { message_ids, thread_id }));
      } catch (error) {
        return errorResult(`Error marking messages as read: ${error}`);
      }
    },
  );

  // ── Gmail: gmail_send ──────────────────────────────────────────────────────
  server.tool(
    "gmail_send",
    "Send a new email or reply to a thread. Recipients must be family members or on the external allowlist. Body is markdown, sent as both plain text and HTML.",
    {
      to: z.string().describe("Recipient email(s), comma-separated"),
      subject: z.string().describe("Email subject"),
      body: z.string().describe("Email body (markdown — sent as both plain text and HTML)"),
      cc: z.string().optional().describe("CC recipients (comma-separated)"),
      bcc: z.string().optional().describe("BCC recipients (comma-separated)"),
      thread_id: z.string().optional().describe("Thread ID to reply to"),
      in_reply_to: z.string().optional().describe("Message-ID header of the message being replied to"),
      references: z.string().optional().describe("References header for threading"),
      ...accountField("Family member email to send from (defaults to the authenticated user)."),
    },
    async ({ to, subject, body, cc, bcc, thread_id, in_reply_to, references, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      try {
        assertRecipientsAllowed({ to, cc, bcc }, env.ALLOWED_EMAILS, env.ALLOWED_EXTERNAL_RECIPIENTS ?? "");
      } catch (error) {
        return errorResult(`${error instanceof Error ? error.message : String(error)}`);
      }

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        const result = await gmailSend(client, {
          to, subject, body, cc, bcc,
          threadId: thread_id,
          inReplyTo: in_reply_to,
          references,
        });
        return successResult(result);
      } catch (error) {
        return errorResult(`Error sending email: ${error}`);
      }
    },
  );

  // ── Gmail: gmail_forward ───────────────────────────────────────────────────
  server.tool(
    "gmail_forward",
    "Forward an existing Gmail message. Recipient must be a family member or on the external allowlist.",
    {
      message_id: z.string().describe("Gmail message ID to forward"),
      to: z.string().describe("Recipient email address"),
      ...accountField("Family member email to forward from (defaults to the authenticated user)."),
    },
    async ({ message_id, to, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      try {
        assertRecipientsAllowed({ to }, env.ALLOWED_EMAILS, env.ALLOWED_EXTERNAL_RECIPIENTS ?? "");
      } catch (error) {
        return errorResult(`${error instanceof Error ? error.message : String(error)}`);
      }

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        const result = await gmailForward(client, { messageId: message_id, to });
        return successResult(result);
      } catch (error) {
        return errorResult(`Error forwarding message: ${error}`);
      }
    },
  );

  // ── Calendar: calendar_list ────────────────────────────────────────────────
  server.tool(
    "calendar_list",
    "List all accessible Google Calendars.",
    {
      ...accountField("Family member email to list calendars for (defaults to the authenticated user)."),
    },
    async ({ account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await calendarList(client));
      } catch (error) {
        return errorResult(`Error listing calendars: ${error}`);
      }
    },
  );

  // ── Calendar: calendar_list_events ─────────────────────────────────────────
  server.tool(
    "calendar_list_events",
    "List calendar events with full Google Calendar API query support: time range, text search, pagination, recurring event expansion, event type filtering.",
    {
      calendar_id: z.string().optional().default("primary").describe("Calendar ID (default: primary)"),
      time_min: z.string().optional().describe("Start of time range (ISO 8601)"),
      time_max: z.string().optional().describe("End of time range (ISO 8601)"),
      query: z.string().optional().describe("Free-text search"),
      max_results: z.number().optional().default(25).describe("Maximum events (default 25)"),
      updated_min: z.string().optional().describe("Only events modified after this time"),
      show_deleted: z.boolean().optional(),
      show_hidden_invitations: z.boolean().optional(),
      time_zone: z.string().optional(),
      page_token: z.string().optional(),
      event_types: z.array(z.enum(["default", "outOfOffice", "focusTime", "workingLocation"])).optional(),
      ical_uid: z.string().optional(),
      single_events: z.boolean().optional().default(true),
      order_by: z.enum(["startTime", "updated"]).optional(),
      ...accountField("Family member email whose calendar to list (defaults to the authenticated user)."),
    },
    async (args, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, args.account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        const result = await calendarListEvents(client, {
          calendarId: args.calendar_id,
          timeMin: args.time_min,
          timeMax: args.time_max,
          query: args.query,
          maxResults: args.max_results,
          updatedMin: args.updated_min,
          showDeleted: args.show_deleted,
          showHiddenInvitations: args.show_hidden_invitations,
          timeZone: args.time_zone,
          pageToken: args.page_token,
          eventTypes: args.event_types,
          iCalUID: args.ical_uid,
          singleEvents: args.single_events,
          orderBy: args.order_by,
        });
        return successResult(result);
      } catch (error) {
        return errorResult(`Error listing events: ${error}`);
      }
    },
  );

  // ── Calendar: calendar_get_event ───────────────────────────────────────────
  server.tool(
    "calendar_get_event",
    "Get full details of a calendar event including attendees, conference/Meet links, recurrence, reminders.",
    {
      event_id: z.string().describe("Calendar event ID"),
      calendar_id: z.string().optional().default("primary"),
      ...accountField("Family member email whose event to read (defaults to the authenticated user)."),
    },
    async ({ event_id, calendar_id, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await calendarGetEvent(client, { calendarId: calendar_id, eventId: event_id }));
      } catch (error) {
        return errorResult(`Error getting event: ${error}`);
      }
    },
  );

  const attendeeSchema = z.union([
    z.string().email(),
    z.object({
      email: z.string().email(),
      optional: z.boolean().optional(),
      responseStatus: z.enum(["needsAction", "declined", "tentative", "accepted"]).optional(),
    }),
  ]);

  // ── Calendar: calendar_create_event ────────────────────────────────────────
  server.tool(
    "calendar_create_event",
    "Create a new calendar event. Supports Meet links, recurring events, all-day events, reminders, visibility. Attendees must be family members or on the external allowlist. 24h-dedup check.",
    {
      summary: z.string().describe("Event title"),
      start_date_time: z.string().describe("Start time — ISO 8601 datetime or date for all-day events"),
      end_date_time: z.string().describe("End time — ISO 8601 datetime or date"),
      time_zone: z.string().optional().default("UTC"),
      description: z.string().optional(),
      location: z.string().optional(),
      attendees: z.array(attendeeSchema).optional(),
      calendar_id: z.string().optional().default("primary"),
      send_updates: z.enum(["all", "externalOnly", "none"]).optional(),
      create_meet_link: z.boolean().optional(),
      recurrence: z.array(z.string()).optional(),
      reminders: z.object({
        useDefault: z.boolean(),
        overrides: z.array(z.object({
          method: z.enum(["email", "popup"]),
          minutes: z.number(),
        })).optional(),
      }).optional(),
      visibility: z.enum(["default", "public", "private", "confidential"]).optional(),
      transparency: z.enum(["opaque", "transparent"]).optional(),
      color_id: z.string().optional(),
      all_day: z.boolean().optional(),
      guests_can_modify: z.boolean().optional(),
      guests_can_invite_others: z.boolean().optional(),
      guests_can_see_other_guests: z.boolean().optional(),
      ...accountField("Family member email whose calendar to create on (defaults to the authenticated user)."),
    },
    async (args, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, args.account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      try {
        assertAttendeesAllowed(args.attendees, env.ALLOWED_EMAILS, env.ALLOWED_EXTERNAL_RECIPIENTS ?? "");
      } catch (error) {
        return errorResult(`${error instanceof Error ? error.message : String(error)}`);
      }

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        const result = await calendarCreateEvent(client, {
          calendarId: args.calendar_id,
          summary: args.summary,
          description: args.description,
          startDateTime: args.start_date_time,
          endDateTime: args.end_date_time,
          timeZone: args.time_zone,
          location: args.location,
          attendees: args.attendees,
          sendUpdates: args.send_updates,
          createMeetLink: args.create_meet_link,
          recurrence: args.recurrence,
          reminders: args.reminders,
          visibility: args.visibility,
          transparency: args.transparency,
          colorId: args.color_id,
          allDay: args.all_day,
          guestsCanModify: args.guests_can_modify,
          guestsCanInviteOthers: args.guests_can_invite_others,
          guestsCanSeeOtherGuests: args.guests_can_see_other_guests,
        });
        if (result.dedupSkipped) {
          return successResult({ message: result.dedupSkipped, existingEvent: result.event });
        }
        return successResult(result.event);
      } catch (error) {
        return errorResult(`Error creating event: ${error}`);
      }
    },
  );

  // ── Calendar: calendar_update_event ────────────────────────────────────────
  server.tool(
    "calendar_update_event",
    "Update a calendar event. Only provided fields change. Dedup check on title/time changes. If attendees are provided, all must be family members or on the external allowlist.",
    {
      event_id: z.string().describe("Calendar event ID to update"),
      calendar_id: z.string().optional().default("primary"),
      summary: z.string().optional(),
      description: z.string().optional(),
      start_date_time: z.string().optional(),
      end_date_time: z.string().optional(),
      time_zone: z.string().optional().default("UTC"),
      location: z.string().optional(),
      attendees: z.array(attendeeSchema).optional(),
      send_updates: z.enum(["all", "externalOnly", "none"]).optional(),
      create_meet_link: z.boolean().optional(),
      recurrence: z.array(z.string()).optional(),
      reminders: z.object({
        useDefault: z.boolean(),
        overrides: z.array(z.object({
          method: z.enum(["email", "popup"]),
          minutes: z.number(),
        })).optional(),
      }).optional(),
      visibility: z.enum(["default", "public", "private", "confidential"]).optional(),
      transparency: z.enum(["opaque", "transparent"]).optional(),
      color_id: z.string().optional(),
      guests_can_modify: z.boolean().optional(),
      guests_can_invite_others: z.boolean().optional(),
      guests_can_see_other_guests: z.boolean().optional(),
      ...accountField("Family member email whose calendar to update on (defaults to the authenticated user)."),
    },
    async (args, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, args.account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      try {
        assertAttendeesAllowed(args.attendees, env.ALLOWED_EMAILS, env.ALLOWED_EXTERNAL_RECIPIENTS ?? "");
      } catch (error) {
        return errorResult(`${error instanceof Error ? error.message : String(error)}`);
      }

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        const result = await calendarUpdateEvent(client, {
          calendarId: args.calendar_id,
          eventId: args.event_id,
          summary: args.summary,
          description: args.description,
          startDateTime: args.start_date_time,
          endDateTime: args.end_date_time,
          timeZone: args.time_zone,
          location: args.location,
          attendees: args.attendees,
          sendUpdates: args.send_updates,
          createMeetLink: args.create_meet_link,
          recurrence: args.recurrence,
          reminders: args.reminders,
          visibility: args.visibility,
          transparency: args.transparency,
          colorId: args.color_id,
          guestsCanModify: args.guests_can_modify,
          guestsCanInviteOthers: args.guests_can_invite_others,
          guestsCanSeeOtherGuests: args.guests_can_see_other_guests,
        });
        if (result.dedupSkipped) {
          return successResult({ message: result.dedupSkipped, existingEvent: result.event });
        }
        return successResult(result.event);
      } catch (error) {
        return errorResult(`Error updating event: ${error}`);
      }
    },
  );

  // ── Calendar: calendar_delete_event ────────────────────────────────────────
  server.tool(
    "calendar_delete_event",
    "Delete a calendar event by ID. Optionally notify attendees.",
    {
      event_id: z.string().describe("Calendar event ID to delete"),
      calendar_id: z.string().optional().default("primary"),
      send_updates: z.enum(["all", "externalOnly", "none"]).optional(),
      ...accountField("Family member email whose calendar to delete from (defaults to the authenticated user)."),
    },
    async ({ event_id, calendar_id, send_updates, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        await calendarDeleteEvent(client, {
          calendarId: calendar_id,
          eventId: event_id,
          sendUpdates: send_updates,
        });
        return successResult({ deleted: true, eventId: event_id });
      } catch (error) {
        return errorResult(`Error deleting event: ${error}`);
      }
    },
  );

  // ── Drive: drive_list_files ────────────────────────────────────────────────
  server.tool(
    "drive_list_files",
    "List files in a Google Drive folder (default: root).",
    {
      folder_id: z.string().optional().describe("Folder ID (default: root)"),
      max_results: z.number().optional().default(20),
      ...accountField("Family member email whose Drive to list (defaults to the authenticated user)."),
    },
    async ({ folder_id, max_results, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await driveListFiles(client, { folderId: folder_id, maxResults: max_results }));
      } catch (error) {
        return errorResult(`Error listing files: ${error}`);
      }
    },
  );

  // ── Drive: drive_search_files ──────────────────────────────────────────────
  server.tool(
    "drive_search_files",
    "Search Google Drive files using Google Drive query syntax.",
    {
      query: z.string().describe("Google Drive search query"),
      max_results: z.number().optional().default(20),
      ...accountField("Family member email whose Drive to search (defaults to the authenticated user)."),
    },
    async ({ query, max_results, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await driveSearchFiles(client, { query, maxResults: max_results }));
      } catch (error) {
        return errorResult(`Error searching files: ${error}`);
      }
    },
  );

  // ── Drive: drive_read_file ─────────────────────────────────────────────────
  server.tool(
    "drive_read_file",
    "Read the text content of a Drive file (Google Docs → text, Sheets → CSV, Presentations → text). Truncated at 50,000 characters.",
    {
      file_id: z.string().describe("Google Drive file ID"),
      ...accountField("Family member email whose Drive file to read (defaults to the authenticated user)."),
    },
    async ({ file_id, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        const result = await driveReadFile(client, { fileId: file_id });
        if (result.truncated) {
          return successResult({ content: result.content, truncated: true, note: "Content was truncated at 50,000 characters." });
        }
        return successResult(result.content);
      } catch (error) {
        return errorResult(`Error reading file: ${error}`);
      }
    },
  );

  // ── Drive: drive_get_file_bytes ───────────────────────────────────────────
  server.tool(
    "drive_get_file_bytes",
    "Download a Drive file as base64-encoded bytes. Google Docs/Sheets/Slides are exported as text/plain or CSV. Returns { base64, mimeType, name }.",
    {
      file_id: z.string().describe("Google Drive file ID"),
      ...accountField("Family member email whose Drive file to download (defaults to the authenticated user)."),
    },
    async ({ file_id, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await driveGetFileBytes(client, { fileId: file_id }));
      } catch (error) {
        return errorResult(`Error fetching file bytes: ${error}`);
      }
    },
  );

  // ── Drive: drive_upload_file ───────────────────────────────────────────────
  server.tool(
    "drive_upload_file",
    "Create a new file in Google Drive with text content.",
    {
      name: z.string().describe("File name"),
      content: z.string().describe("Text content"),
      mime_type: z.string().describe("MIME type (e.g. text/plain)"),
      folder_id: z.string().optional().describe("Parent folder ID (default: root)"),
      ...accountField("Family member email whose Drive to upload to (defaults to the authenticated user)."),
    },
    async ({ name, content, mime_type, folder_id, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await driveUploadFile(client, { name, content, mimeType: mime_type, folderId: folder_id }));
      } catch (error) {
        return errorResult(`Error uploading file: ${error}`);
      }
    },
  );

  // ── Drive: drive_create_folder ─────────────────────────────────────────────
  server.tool(
    "drive_create_folder",
    "Create a new folder in Google Drive, optionally nested.",
    {
      name: z.string().describe("Folder name"),
      parent_folder_id: z.string().optional().describe("Parent folder ID (default: root)"),
      ...accountField("Family member email whose Drive to create the folder in (defaults to the authenticated user)."),
    },
    async ({ name, parent_folder_id, account }, extra) => {
      const email = authEmail(extra);
      if (!email) return errorResult("Not authenticated.");

      const resolved = resolveTargetAccount(email, account, env.ALLOWED_EMAILS);
      if (!resolved.ok) return errorResult(resolved.error);

      const client = await clientFor(resolved.account);
      if (!client) return errorResult(`No Google credentials for ${resolved.account}.`);
      try {
        return successResult(await driveCreateFolder(client, { name, parentFolderId: parent_folder_id }));
      } catch (error) {
        return errorResult(`Error creating folder: ${error}`);
      }
    },
  );

  return server;
}
