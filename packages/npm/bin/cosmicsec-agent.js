#!/usr/bin/env node

const { runAgentCLI } = require("../lib/installer");

runAgentCLI(process.argv.slice(2));
