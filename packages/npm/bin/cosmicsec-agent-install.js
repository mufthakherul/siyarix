#!/usr/bin/env node

const { installAgent } = require("../lib/installer");

const result = installAgent(true);
process.exitCode = result.ok ? 0 : 1;
