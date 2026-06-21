import { defineConfig } from "oxfmt";

export default defineConfig({
  printWidth: 80,
  sortImports: true,
  sortPackageJson: true,
  sortTailwindcss: true,
  ignorePatterns: [
    "packages/proto/src/generated",
    "apps/web/src/components/ui",
  ],
});
