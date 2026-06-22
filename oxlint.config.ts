import { defineConfig } from "oxlint";

export default defineConfig({
  jsPlugins: [
    {
      name: "better-tailwindcss",
      specifier: "eslint-plugin-better-tailwindcss",
    },
  ],
  plugins: ["import", "vue"],
  overrides: [
    {
      files: ["apps/web/**/*.{js,jsx,ts,tsx,vue}"],
      rules: {
        "better-tailwindcss/enforce-canonical-classes": [
          "error",
          {
            cwd: "apps/web",
            entryPoint: "src/styles.css",
          },
        ],
      },
    },
  ],
});
