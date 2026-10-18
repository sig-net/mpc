import { writeFileSync } from "node:fs";
import { initialSingletonState } from "./initial-state.js";

// The native publisher's build tests read this as the deployed singleton's state.
const bytes = await initialSingletonState();
writeFileSync(
  new URL("../../chain-midnight/fixtures/initial-singleton-state.mn", import.meta.url),
  bytes,
);
console.log(`wrote initial-singleton-state.mn (${bytes.length} bytes)`);
