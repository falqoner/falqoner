#!/usr/bin/env node
/**
 * The `falconer` executable: run one command and exit with its code.
 *
 * Everything else lives in `cli.ts`, which does nothing on import. Setting
 * `exitCode` rather than calling `process.exit` lets buffered output reach a
 * pipe before the process ends.
 */
import { run } from './cli.js';

process.exitCode = await run(process.argv.slice(2));
