const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'k6-bidirectional.js'), 'utf8')
  .replace(/^import .*;\n/gm, '')
  .replace('export const options', 'const options')
  .replace('export function setup', 'function setup')
  .replace('export default function ()', 'function iteration()');

function driver(overrides = {}, replies = []) {
  const metrics = new Map();
  const requests = [];
  let now = 0;
  const response = (status, body) => ({ status, body: JSON.stringify(body), json: key => key ? body[key] : body });
  const next = (method, url, body) => {
    requests.push({ method, url, body });
    assert.ok(replies.length, 'unexpected HTTP call');
    return response(...replies.shift());
  };
  class Metric {
    constructor(name) { this.name = name; metrics.set(name, []); }
    add(value, tags) { metrics.get(this.name).push({ value, tags }); }
  }
  const context = vm.createContext({
    __ENV: { LT_STRATEGY: 'rpm_1', LT_CHAIN_ENV: 'dev', LT_PINGER_API_KEY: 'test-key', ...overrides },
    http: { get: url => next('GET', url), post: (url, body) => next('POST', url, JSON.parse(body)) },
    check: (value, predicates) => Object.values(predicates).every(predicate => predicate(value)),
    fail: message => { throw new Error(message); },
    sleep: seconds => { now += seconds * 1000; },
    Date: { now: () => now },
    console: { log() {}, warn() {}, error() {} },
    Trend: Metric, Rate: Metric, Counter: Metric, Gauge: Metric,
  });
  vm.runInContext(`${source}\nglobalThis.driver = { options, setup, iteration };`, context);
  return { ...context.driver, metrics, requests, elapsed: () => now };
}

const midnight = { LT_SOURCE_CHAIN: 'midnight', LT_CHAIN_ENV: 'stagenet', LT_STRATEGY: 'serial' };
const workers = { workers: [{ path: 'load/0', address: '0x1234', balanceWei: '9000000000000000', underfunded: false }] };

test('Solana retains arrival strategy and thresholds', () => {
  const run = driver();
  assert.equal(run.options.scenarios.bidirectional.rate, 1);
  assert.equal(run.options.scenarios.bidirectional.executor, 'constant-arrival-rate');
  assert.deepEqual(Object.keys(run.options.thresholds), ['bidi_success']);
});

test('Midnight serial configuration bounds concurrency and requires completed work', () => {
  const run = driver(midnight);
  assert.equal(run.options.scenarios.bidirectional.executor, 'constant-vus');
  assert.equal(run.options.scenarios.bidirectional.vus, 1);
  assert.deepEqual(Array.from(run.options.thresholds.bidi_completed), ['count>0']);
  assert.throws(() => driver({ ...midnight, LT_STRATEGY: 'rpm_1' }), /requires/);
  assert.throws(() => driver({ LT_STRATEGY: 'serial' }), /requires/);
  assert.throws(() => driver({ LT_SOURCE_CHAIN: 'unknown' }), /Unknown LT_SOURCE_CHAIN/);
});

test('invalid source/network combinations fail before any HTTP call', () => {
  for (const env of [{ ...midnight, LT_CHAIN_ENV: 'dev' }, { LT_CHAIN_ENV: 'stagenet' }]) {
    const run = driver(env);
    assert.throws(() => run.setup(), /Unsupported environment/);
    assert.equal(run.requests.length, 0);
  }
});

test('Midnight sends source selection, polls completion, and reports service timings', () => {
  const run = driver(midnight, [
    [200, workers], [202, { jobId: 'job-1' }],
    [200, { state: 'responded', durations: { signatureMs: 12000, totalMs: 25000 } }],
  ]);
  run.setup();
  run.iteration();
  assert.match(run.requests[0].url, /workers\?env=stagenet&sourceChain=midnight$/);
  assert.deepEqual(run.requests[1].body, { env: 'stagenet', mode: 'eth_self_transfer', sourceChain: 'midnight' });
  assert.match(run.requests[2].url, /\/sign_bidirectional\/job-1$/);
  assert.deepEqual(run.metrics.get('bidi_success').map(sample => sample.value), [true]);
  assert.equal(run.metrics.get('bidi_signature_seconds')[0].value, 12);
  assert.equal(run.metrics.get('bidi_completed').at(-1).value, 1);
  assert.equal(run.elapsed(), 60000);
});

test('Solana rejection remains separate; Midnight rejection cannot count as completed work', () => {
  for (const env of [{}, midnight]) {
    const run = driver(env, [[429, { limit: 'active_jobs' }]]);
    run.iteration();
    assert.equal(run.metrics.get('bidi_rejected_capacity')[0].value, 1);
    assert.deepEqual(run.metrics.get('bidi_completed').map(sample => sample.value), [0]);
    assert.deepEqual(run.metrics.get('bidi_success').map(sample => sample.value), env === midnight ? [false] : []);
    assert.equal(run.elapsed(), env === midnight ? 60000 : 0);
  }
});

test('Midnight failures and driver timeout are unsuccessful and paced', () => {
  const failed = driver(midnight, [[202, { jobId: 'failed' }], [200, { state: 'failed', failureReason: 'respond_timeout' }]]);
  failed.iteration();
  assert.equal(failed.metrics.get('bidi_success')[0].value, false);
  assert.equal(failed.metrics.get('bidi_failures')[0].tags.reason, 'respond_timeout');
  assert.equal(failed.elapsed(), 60000);
  const timedOut = driver({ ...midnight, LT_JOB_TIMEOUT_SECONDS: '1' }, [[202, { jobId: 'pending' }], [200, { state: 'queued' }]]);
  timedOut.iteration();
  assert.equal(timedOut.metrics.get('bidi_failures')[0].tags.reason, 'driver_timeout');
  assert.equal(timedOut.metrics.get('bidi_completed').at(-1).value, 0);
});

test('worker funding/configuration failures stop before submission', () => {
  for (const reply of [[503, { error: 'source unavailable' }], [200, { workers: [] }]]) {
    const run = driver(midnight, [reply]);
    assert.throws(() => run.setup(), /Could not read worker funding|addresses funded/);
    assert.equal(run.requests.length, 1);
  }
});

test('workflow matrix preserves Solana schedules and gates Midnight independently', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '../.github/workflows/k6-bidirectional-loadtest.yml'), 'utf8');
  const expression = workflow.match(/include: \$\{\{ ([\s\S]*?) \}\}/)[1];
  const resolve = (event, enabled, chain, environment) => JSON.parse(JSON.stringify(vm.runInNewContext(expression, {
    github: { event_name: event }, vars: { LT_MIDNIGHT_ENABLED: enabled },
    inputs: { source_chain: chain, environment }, fromJSON: JSON.parse,
  })));
  const solana = [{ source: 'solana', environment: 'dev' }, { source: 'solana', environment: 'testnet' }];
  assert.deepEqual(resolve('schedule', '', '', ''), solana);
  assert.deepEqual(resolve('schedule', 'true', '', ''), [...solana, { source: 'midnight', environment: 'stagenet' }]);
  assert.deepEqual(resolve('workflow_dispatch', '', 'solana', 'both'), solana);
  for (const environment of ['both', 'dev', 'testnet', 'mainnet', 'stagenet']) {
    for (const chain of ['solana', 'midnight']) {
      const actual = resolve('workflow_dispatch', '', chain, environment);
      const valid = chain === 'midnight' ? ['both', 'stagenet'].includes(environment) : environment !== 'stagenet';
      assert.equal(actual[0].source, valid ? chain : 'unmatched');
      if (chain === 'midnight' && valid) assert.equal(actual[0].environment, 'stagenet');
    }
  }
  assert.match(workflow, /group: k6-bidirectional-\$\{\{ matrix.source \}\}-\$\{\{ matrix.environment \}\}/);
  assert.match(workflow, /--tag source_chain="\$\{LT_SOURCE_CHAIN\}"/);
});

test('Midnight driver allows proving plus the Ethereum finality budget', () => {
  const pending = Array.from({ length: 50 }, () => [200, { state: 'awaiting_signature' }]);
  const run = driver({ ...midnight, LT_POLL_SECONDS: '60' }, [
    [202, { jobId: 'slow-proof' }], ...pending,
    [200, { state: 'responded' }],
  ]);
  run.iteration();
  assert.deepEqual(run.metrics.get('bidi_success').map(sample => sample.value), [true]);
  assert.equal(run.options.scenarios.bidirectional.gracefulStop, '90m');
});
