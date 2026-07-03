import { defineConfig } from 'astro/config';

// The public record is read-heavy and static-leaning — Astro's sweet spot (DESIGN §3).
// The in-browser WASM verifier and search become islands in M5b.
export default defineConfig({
  site: 'https://druid.example',
});
