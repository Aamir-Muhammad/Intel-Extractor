import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/", // served at the root of ioc.threatterminal.com (GitHub Pages custom domain)
});
