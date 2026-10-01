import { cronJobs } from "convex/server";
import { internal } from "./_generated/api";

/**
 * Scheduled jobs for CCP backend maintenance.
 *
 * - purge expired messages: hourly, delete relay messages past their TTL.
 *   Acked messages are deleted on ack, so only undelivered ones expire here.
 */
const crons = cronJobs();

crons.hourly(
  "purge expired messages",
  { minuteUTC: 0 },
  internal.messages.purgeExpiredMessages
);

export default crons;
