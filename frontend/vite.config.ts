import { defineConfig } from "vite";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";
import babel from "@rolldown/plugin-babel";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [
    react(),
    babel({
      parallel: true,
      presets: [reactCompilerPreset()],
    }),
    tailwindcss(),
  ],
  build: {
    outDir: "../backend/static",
    emptyOutDir: true,
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: "react-vendor",
              test: /node_modules[\\/](react|react-dom|react-router|scheduler)[\\/]/,
            },
            {
              name: "markdown-vendor",
              test: /node_modules[\\/](react-markdown|remark-gfm|lowlight|highlight\.js|micromark|mdast|hast|unified|unist|vfile|devlop|property-information|comma-separated-tokens|space-separated-tokens|decode-named-character-reference|character-entities|bail|trough|is-plain-obj|trim-lines|ccount|escape-string-regexp|markdown-table|longest-streak|zwitch|html-url-attributes)[\\/]/,
            },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
