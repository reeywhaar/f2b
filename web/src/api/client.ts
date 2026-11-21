import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";

import { ApiError } from "@app/api/transport";
import { leaveFor } from "@app/leave";

/** Every read is a server read. Query owns what came from the server; the URL owns the rest. */

// One navigation however many requests failed together: everything on screen answers 401 at the
// same moment when a session ends.
let leaving = false;

/**
 * Sends the tab to the sign-in page when its session has ended. Not in transport, which cannot
 * tell that 401 from the sign-in form's own for a wrong password.
 */
function ended(error: unknown) {
  if (leaving || !(error instanceof ApiError) || error.status !== 401) return;
  leaving = true;
  leaveFor("/login");
}

/** The client for an island that requires a session. */
export function sessionClient(): QueryClient {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
    queryCache: new QueryCache({ onError: ended }),
    mutationCache: new MutationCache({ onError: ended }),
  });
}
