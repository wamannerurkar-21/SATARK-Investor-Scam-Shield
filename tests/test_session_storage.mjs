import assert from "node:assert/strict";
import test from "node:test";
import {
  readSessionScans,
  syncSessionScans,
} from "../artifacts/satark/components/session_insights/session_history.js";

function createTabSessionStorage() {
  const values = new Map();
  return {
    getItem(key) {
      return values.has(key) ? values.get(key) : null;
    },
    setItem(key, value) {
      values.set(key, String(value));
    },
  };
}

function scan(scanId, riskLevel) {
  return {
    scan_id: scanId,
    timestamp: "2026-10-03T10:00:00+00:00",
    input_type: "text",
    risk_level: riskLevel,
    risk_score: 80,
    indicator_count: 1,
    verification_status: "not checked",
    indicator_keys: ["urgency"],
  };
}

test("fresh tab starts at zero, same-tab refresh persists, and another tab is isolated", () => {
  const firstTab = createTabSessionStorage();

  assert.deepEqual(readSessionScans(firstTab), []);
  assert.equal(syncSessionScans(firstTab, scan("first-1", "HIGH RISK")).length, 1);
  assert.equal(
    syncSessionScans(firstTab, scan("first-2", "LOW CONCERN")).length,
    2,
  );

  // A page refresh keeps the same tab's sessionStorage object.
  assert.equal(readSessionScans(firstTab).length, 2);

  // A distinct browser/tab session receives a distinct sessionStorage area.
  const secondTab = createTabSessionStorage();
  assert.deepEqual(readSessionScans(secondTab), []);
  assert.equal(
    syncSessionScans(secondTab, scan("second-1", "NEEDS VERIFICATION")).length,
    1,
  );
  assert.equal(readSessionScans(secondTab).length, 1);
  assert.equal(readSessionScans(firstTab).length, 2);
});

test("repeated Streamlit renders do not count the same scan twice", () => {
  const storage = createTabSessionStorage();
  const event = scan("same-event", "VERY HIGH RISK");

  assert.equal(syncSessionScans(storage, event).length, 1);
  assert.equal(syncSessionScans(storage, event).length, 1);
});