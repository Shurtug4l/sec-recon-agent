// Cross-component navigation events. Kept in a leaf module so consumers
// (dashboard page, command palette) don't pull each other into their bundles.

// Fired by the command palette after rewriting ?tab= while already on
// /dashboard; the dashboard page re-reads the query string on this event.
export const DASHBOARD_TAB_EVENT = "sec-recon:dashboard-tab";

// Fired by the command palette's "Show SSVC decision trace" command; the
// trace disclosure (closed by default, so a plain scroll would land on a
// collapsed panel) listens for it to open itself and scroll into view.
export const SSVC_TRACE_EVENT = "sec-recon:ssvc-trace";
