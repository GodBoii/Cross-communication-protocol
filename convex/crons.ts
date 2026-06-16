import { cronJobs } from "convex/server";
import { api } from "./_generated/api";

/**
 * Scheduled jobs for CCP backend maintenance.
 *
 * - purge_expired_messages: every hour, clean up delivered or expired messages
 *   to keep the database lean.
 */
const crons = cronJobs();

crons.hourly(
  "purge expired messages",
  { minuteUTC: 0 },
  api.messages.purgeExpiredMessages
);

export default crons;
