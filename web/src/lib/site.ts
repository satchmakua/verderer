// Build-time checks against the files the site actually ships. Never advertise a download
// the deploy didn't produce.

import fs from 'node:fs';
import path from 'node:path';

/** Whether a proof bundle for this source is published (the deploy writes them before the build). */
export function hasBundle(targetId: string): boolean {
  return fs.existsSync(path.resolve(process.cwd(), 'public', 'bundles', `${targetId}.json`));
}
