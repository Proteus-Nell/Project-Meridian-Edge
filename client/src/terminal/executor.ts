// Facade for the executor package. The implementation lives in ./executor/:
// index (dispatch + session state), context (shared internals + chrome),
// identity, contacts, trust, messaging, lifecycle, settings, duress, views,
// bench, with records/payload/format as data helpers. Import sites and tests
// reach the public surface through this stable path.

export { Executor } from "./executor/index";
export type { EmblemState, UiChrome } from "./executor/context";
