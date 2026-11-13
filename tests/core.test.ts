import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { generateSigningKey, seal, signToken, unseal, verifyToken } from '../src/core/crypto.ts';
import { JsonError, canonicalize, digest, parseStrict } from '../src/core/json.ts';
import { unsupportedKeywords, validate } from '../src/core/schema.ts';
import { RateLimiter, isValidPattern, matchPattern, patternCovered } from '../src/core/util.ts';
import { McpClient } from '../src/mcp/client.ts';
import { validateBundle, DEFAULT_POLICY } from '../src/policy/bundle.ts';
import { validateManifest } from '../src/registry/tools.ts';

test('strict JSON: duplicate keys, lone surrogates, __proto__, depth and trailing data are rejected', () => {
  assert.deepEqual(parseStrict(' {"a":[1,2.5,-3e2,true,null,"x\\n\\u00e9"],"b":{}} '), { a: [1, 2.5, -300, true, null, 'x\n\u00e9'], b: {} });
  for (const bad of [
    '{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"__proto__":{"admin":true}}', '"\\ud800"', '{"a":1}x', '{"a":01}', "{'a':1}",
    '[1,]', '{"a":1,}', '', 'NaN', '1e999', '"unterminated', '"tab\there"', '['.repeat(100) + ']'.repeat(100),
  ]) {
    assert.throws(() => parseStrict(bad), JsonError, bad.slice(0, 30));
  }
  assert.equal(({} as Record<string, unknown>).admin, undefined);
});

test('canonicalization matches the RFC 8785 examples', () => {
  const input = String.raw`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`;
  const expected = String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"` + '\u20ac' + String.raw`$\u000f\nA'B\"\\\\\"/"}`;
  assert.equal(canonicalize(parseStrict(input)), expected);

  const keys = String.raw`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`;
  const order = [...canonicalize(parseStrict(keys)).matchAll(/:"([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(order, ['Carriage Return', 'One', 'Control', 'Latin Small Letter O With Diaeresis', 'Euro Sign', 'Emoji: Grinning Face', 'Hebrew Letter Dalet With Dagesh']);

  assert.equal(digest({ b: 1, a: [2, { d: 4, c: 3 }] }), digest(parseStrict('{"a":[2,{"c":3,"d":4}],"b":1.0}')));
  assert.notEqual(digest({ a: '1' }), digest({ a: 1 }));
  assert.throws(() => canonicalize(Number.NaN), JsonError);
});

test('signed tokens verify only with the right key and type', () => {
  const key = generateSigningKey();
  const token = signToken(key, 'agentshield-permit+jwt', { a: 1 });
  const resolve = (kid: string) => (kid === key.kid ? key.publicKey : undefined);
  assert.deepEqual(verifyToken(token, 'agentshield-permit+jwt', resolve), { a: 1 });
  assert.equal(verifyToken(token, 'other', resolve), null);
  assert.equal(verifyToken(token, 'agentshield-permit+jwt', () => generateSigningKey().publicKey), null);
  const [h, , s] = token.split('.');
  assert.equal(verifyToken(`${h}.${Buffer.from('{"a":2}').toString('base64url')}.${s}`, 'agentshield-permit+jwt', resolve), null);
  const none = `${Buffer.from('{"alg":"none","kid":"' + key.kid + '","typ":"agentshield-permit+jwt"}').toString('base64url')}.${token.split('.')[1]}.`;
  assert.equal(verifyToken(none, 'agentshield-permit+jwt', resolve), null);
  assert.equal(verifyToken('garbage', 'agentshield-permit+jwt', resolve), null);
});

test('vault sealing is bound to its scope', () => {
  const key = Buffer.alloc(32, 7);
  const sealed = seal(key, 'jane@example.com', 'acme\0task\0act\0[EMAIL_1]');
  assert.equal(unseal(key, sealed, 'acme\0task\0act\0[EMAIL_1]'), 'jane@example.com');
  assert.throws(() => unseal(key, sealed, 'globex\0task\0act\0[EMAIL_1]'));
  assert.throws(() => unseal(Buffer.alloc(32, 8), sealed, 'acme\0task\0act\0[EMAIL_1]'));
  assert.notEqual(seal(key, 'x', 'a'), seal(key, 'x', 'a'), 'fresh nonce each time');
});

test('scope patterns: matching and subset checks', () => {
  assert.ok(matchPattern('*', 'anything') && matchPattern('cust_*', 'cust_42') && matchPattern('a', 'a'));
  assert.ok(!matchPattern('cust_*', 'customer') && !matchPattern('a', 'ab'));
  assert.ok(isValidPattern('a*') && isValidPattern('*') && !isValidPattern('a*b') && !isValidPattern('') && !isValidPattern('**'));
  assert.ok(patternCovered('cust_4*', ['cust_*']) && patternCovered('cust_42', ['cust_*']) && patternCovered('x', ['*']) && patternCovered('a*', ['a*']));
  assert.ok(!patternCovered('cust_*', ['cust_4*']) && !patternCovered('*', ['cust_*']) && !patternCovered('customer', ['cust_*']) && !patternCovered('a', []));
});

test('schema validator enforces what it supports and names what it does not', () => {
  const schema = { type: 'object', required: ['kw'], additionalProperties: false, properties: { kw: { type: 'number', minimum: 0, maximum: 50 }, mode: { enum: ['auto', 'manual'] }, tags: { type: 'array', maxItems: 2, items: { type: 'string', maxLength: 3, pattern: '^[a-z]+$' } } } };
  assert.deepEqual(validate(schema, { kw: 30, mode: 'auto', tags: ['ab'] }), []);
  assert.equal(validate(schema, { kw: 500 }).length, 1);
  assert.equal(validate(schema, { kw: 5, extra: 1 }).length, 1);
  assert.equal(validate(schema, {}).length, 1);
  assert.equal(validate(schema, { kw: '5' }).length, 1);
  assert.equal(validate(schema, { kw: 5, mode: 'turbo', tags: ['abcd', 'A', 'x'] }).length, 4);
  assert.equal(validate({ anyOf: [{ type: 'string' }, { type: 'integer' }] }, 1.5).length, 1);
  assert.equal(validate({ oneOf: [{ type: 'number' }, { type: 'integer' }] }, 1).length, 1);
  assert.equal(validate({ not: { type: 'null' } }, null).length, 1);
  assert.deepEqual(unsupportedKeywords({ type: 'object', properties: { a: { $ref: '#/x' }, b: { if: {}, description: 'fine' } }, patternProperties: {} }), ['/properties/a/$ref', '/properties/b/if', '/patternProperties']);
});

test('manifests and policy bundles are validated structurally', () => {
  const base = { tool_id: 't', kind: 'function', owner: 'it', destination_id: 'd', operations: { 'op.x': { class: 'data_read', effect: 'read' } } };
  assert.equal(validateManifest(base).tool_id, 't');
  for (const broken of [
    { ...base, kind: 'shell' }, { ...base, owner: '' }, { ...base, operations: {} }, { ...base, credential_ref: 'sk-live-inline-secret' },
    { ...base, operations: { x: { class: 'a', effect: 'maybe' } } }, { ...base, operations: { x: { class: 'a', effect: 'read', approval: 'never' } } },
    { ...base, kind: 'http' }, { ...base, kind: 'http', endpoint: { base_url: 'https://user:pw@api.example' }, operations: { x: { class: 'a', effect: 'read', http: { method: 'GET', path: '/x' } } } },
    { ...base, kind: 'http', endpoint: { base_url: 'https://api.example' }, operations: { x: { class: 'a', effect: 'read', http: { method: 'GET', path: 'x' } } } },
    { ...base, kind: 'mcp', endpoint: { transport: 'stdio' } },
  ]) {
    assert.throws(() => validateManifest(broken), /Tool manifest rejected/);
  }
  assert.equal(validateBundle(structuredClone(DEFAULT_POLICY)).version, 1);
  for (const mutate of [
    (p: any) => (p.risk.weights.impact = 30), (p: any) => (p.risk.thresholds.high = 10), (p: any) => (p.data_flow.secrets = 'allow'),
    (p: any) => (p.data_flow.external_approval_label = 'TOP'), (p: any) => delete p.default_class, (p: any) => (p.version = 0),
    (p: any) => (p.limits.permit_ttl_seconds = 0), (p: any) => (p.operation_classes.x = { approval: 'sometimes', redaction: 'allow' }),
  ]) {
    const p = structuredClone(DEFAULT_POLICY);
    mutate(p);
    assert.throws(() => validateBundle(p), /Policy bundle rejected/);
  }
});

test('rate limiter refills over time', () => {
  const clock = { t: 0, now: () => clock.t };
  const rl = new RateLimiter(60, 3, clock);
  assert.deepEqual([rl.take('a'), rl.take('a'), rl.take('a'), rl.take('a')], [true, true, true, false]);
  assert.equal(rl.take('b'), true);
  clock.t += 1000;
  assert.deepEqual([rl.take('a'), rl.take('a')], [true, false]);
});

test('MCP client over HTTP: plain JSON and event-stream replies, upstream credential, session id', async () => {
  const seen: { auth?: string; session?: string; method: string }[] = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const c of req) body += c;
    const msg = JSON.parse(body);
    seen.push({ auth: req.headers.authorization, session: req.headers['mcp-session-id'] as string, method: msg.method });
    if (msg.id === undefined) return void res.writeHead(202).end();
    const result =
      msg.method === 'initialize' ? { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'up', version: '1' } }
      : msg.method === 'tools/list' ? (msg.params.cursor ? { tools: [{ name: 'b' }] } : { tools: [{ name: 'a' }], nextCursor: 'p2' })
      : { content: [{ type: 'text', text: `called ${msg.params.name}` }] };
    const reply = JSON.stringify({ jsonrpc: '2.0', id: msg.id, result });
    if (msg.method === 'tools/call') {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end(`event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\nevent: message\ndata: ${reply}\n\n`);
    } else {
      res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': 'sess-1' });
      res.end(reply);
    }
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  try {
    const client = await McpClient.connect({ transport: 'http', url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp` }, 'upstream-cred');
    assert.deepEqual((await client.listTools()).map((t) => t.name), ['a', 'b']);
    assert.deepEqual(await client.callTool('a', {}, 5000), { content: [{ type: 'text', text: 'called a' }] });
    assert.ok(seen.every((s) => s.auth === 'Bearer upstream-cred'));
    assert.equal(seen.at(-1)!.session, 'sess-1');
    client.close();
    await assert.rejects(() => McpClient.connect({ transport: 'http', url: 'http://127.0.0.1:1/mcp' }, null), /unreachable/);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});

test('policies/default.policy.json is the built-in default policy', async () => {
  const { readFileSync } = await import('node:fs');
  const onDisk = parseStrict(readFileSync(new URL('../policies/default.policy.json', import.meta.url), 'utf8'));
  assert.deepEqual(onDisk, JSON.parse(JSON.stringify(DEFAULT_POLICY)));
});
