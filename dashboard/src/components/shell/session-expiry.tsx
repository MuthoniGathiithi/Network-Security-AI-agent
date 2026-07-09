import { getSessionSecondsLeft } from "@/lib/server/session";
import { ExpiryTimer } from "./expiry-timer";

/** Reads the session on the server and starts the client-side expiry timer. */
export async function SessionExpiry() {
  return <ExpiryTimer secondsLeft={await getSessionSecondsLeft()} />;
}
