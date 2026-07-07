// Cross-component navigation events. Kept in a leaf module so consumers
// (dashboard page, command palette) don't pull each other into their bundles.

// Fired by the command palette after rewriting ?tab= while already on
// /dashboard; the dashboard page re-reads the query string on this event.
export const DASHBOARD_TAB_EVENT = "sec-recon:dashboard-tab";
