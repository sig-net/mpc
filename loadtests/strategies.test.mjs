// Run with: node --test loadtests/strategies.test.mjs
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseDuration, planFor, strategies } from './strategies.mjs';

describe('parseDuration', () => {
  it('reads seconds, minutes and hours', () => {
    assert.equal(parseDuration('30s'), 30);
    assert.equal(parseDuration('5m'), 300);
    assert.equal(parseDuration('1h'), 3600);
  });

  it('rejects anything else', () => {
    for (const text of ['5', '5x', 'm', '1.5m', '']) {
      assert.throws(() => parseDuration(text), /Duration must look like/);
    }
  });
});

describe('planFor', () => {
  it('sizes a constant rate from its duration', () => {
    assert.deepEqual(planFor('rps_3', 300), {
      totalSeconds: 300,
      peakPerSecond: 3,
      jobs: 901,
      addressJobs: 8,
      paths: 219,
    });
  });

  it('converts a per-minute rate', () => {
    const plan = planFor('rpm_6', 600);
    assert.ok(Math.abs(plan.peakPerSecond - 0.1) < 1e-9);
    assert.equal(plan.jobs, 61);
  });

  it('sizes a ramp from the area under its stages, whatever the duration', () => {
    // 1 held for 3m, then straight lines to 2, 5 and 10: 180 + 270 + 630 + 1350.
    const plan = planFor('ramp_1_10', 60);
    assert.equal(plan.totalSeconds, 720);
    assert.equal(plan.peakPerSecond, 10);
    assert.equal(plan.jobs, 2431);
    assert.equal(plan.paths, 730);
    assert.deepEqual(planFor('ramp_1_10', 3600), plan);
  });

  it('never expects the busiest address to serve more jobs than there are', () => {
    const plan = planFor('rpm_1', 300);
    assert.equal(plan.jobs, 6);
    assert.equal(plan.addressJobs, 6);
  });

  it('always needs at least one address', () => {
    assert.ok(planFor('rpm_1', 60).paths >= 1);
  });

  it('names the strategies it knows when given one it does not', () => {
    assert.throws(
      () => planFor('rps_99', 60),
      new RegExp(`Known: ${Object.keys(strategies).join(', ')}`)
    );
  });
});
