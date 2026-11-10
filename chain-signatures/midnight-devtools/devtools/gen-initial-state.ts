import { writeFileSync } from "node:fs";
import { initialResponderState } from "./initial-state.js";

// The native publisher's build tests read this as the deployed responder's state.
const bytes = await initialResponderState();
writeFileSync(
  new URL("../../chain-midnight/fixtures/initial-responder-state.mn", import.meta.url),
  bytes,
);
console.log(`wrote initial-responder-state.mn (${bytes.length} bytes)`);
