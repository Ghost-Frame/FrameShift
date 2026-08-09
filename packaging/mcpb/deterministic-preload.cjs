// Makes the pinned MCPB 2.1.2 packer emit stable ZIP metadata and entry order.

"use strict";

const fs = require("node:fs");
const { syncBuiltinESMExports } = require("node:module");

const OriginalDate = Date;
const originalReaddirSync = fs.readdirSync;

// Supplies the same local calendar fields whenever the packer requests the current time.
class DeterministicDate extends OriginalDate {
  // Constructs caller-specified dates normally and fixes zero-argument construction.
  constructor(...args) {
    if (args.length === 0) {
      super(2000, 0, 1, 0, 0, 0, 0);
      return;
    }
    super(...args);
  }

  // Returns the fixed instant for code that reads the wall clock without construction.
  static now() {
    return OriginalDate.UTC(2000, 0, 1, 0, 0, 0, 0);
  }
}

// Derives a byte-comparable name from strings, buffers, or directory entries.
function entryName(entry) {
  if (Buffer.isBuffer(entry)) {
    return entry;
  }
  if (typeof entry === "string") {
    return Buffer.from(entry, "utf8");
  }
  return Buffer.from(entry.name, "utf8");
}

// Sorts each filesystem directory before MCPB constructs its ZIP entry map.
function deterministicReaddirSync(...args) {
  const entries = originalReaddirSync(...args);
  return entries.sort((left, right) => Buffer.compare(entryName(left), entryName(right)));
}

global.Date = DeterministicDate;
fs.readdirSync = deterministicReaddirSync;
syncBuiltinESMExports();
