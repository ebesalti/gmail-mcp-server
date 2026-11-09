// Run: npx tsx test/unsubscribe-parse.test.ts  (no network, no Gmail)
import assert from "node:assert/strict";
import { parseListUnsubscribe, parseMailto } from "../src/gmail-service.js";

const p = parseListUnsubscribe(
  "<mailto:unsub@x.com?subject=unsubscribe%20me>, <https://x.com/u?a=1,b>, <http://y.com/u>"
);
assert.deepEqual(p.https, ["https://x.com/u?a=1,b"]);
assert.deepEqual(p.http, ["http://y.com/u"]);
assert.equal(p.mailto, "mailto:unsub@x.com?subject=unsubscribe%20me");

const m = parseMailto(p.mailto!);
assert.equal(m.to, "unsub@x.com");          // old code put "?subject=..." into To:
assert.equal(m.subject, "unsubscribe me");
assert.equal(m.body, "Unsubscribe");

assert.deepEqual(parseListUnsubscribe(""), { https: [], http: [], mailto: undefined });

// Header injection and multiple recipients must be refused.
assert.throws(() => parseMailto("mailto:a@x.com%0D%0ABcc:victim@y.com"));
assert.throws(() => parseMailto("mailto:a@x.com%0ABcc:victim@y.com"));
assert.throws(() => parseMailto("mailto:a@x.com,victim@y.com"));
assert.throws(() => parseMailto("mailto:a@x.com%2Cvictim@y.com"));
assert.throws(() => parseMailto("mailto:Name%20%3Ca@x.com%3E"));
assert.throws(() => parseMailto("mailto:"));
console.log("unsubscribe parse tests: OK");
