#!/usr/bin/env node
// Runs the TypeScript sources directly in a checkout, and the compiled build when installed as a package
// (Node does not strip types from files under node_modules).
import { existsSync } from 'node:fs';

const source = new URL('../src/cli.ts', import.meta.url);
const built = new URL('../dist/src/cli.js', import.meta.url);
const installed = import.meta.url.includes('/node_modules/');
await import(!installed && existsSync(source) ? source.href : built.href);
