// Print what a run needs as `name=value` lines, for a workflow to size the
// pinger and its funding before starting.
//
//   node loadtests/plan.mjs rps_3 5m >> "$GITHUB_OUTPUT"
import { parseDuration, planFor, strategies } from './strategies.mjs';

const [name, duration = '5m'] = process.argv.slice(2);
if (!name) {
  console.error(
    `Usage: plan.mjs <strategy> [duration]. Known: ${Object.keys(strategies).join(', ')}`
  );
  process.exit(1);
}

const plan = planFor(name, parseDuration(duration));
console.log(`jobs=${plan.jobs}`);
console.log(`address_jobs=${plan.addressJobs}`);
console.log(`paths=${plan.paths}`);
console.log(`total_seconds=${plan.totalSeconds}`);
