import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Tauri serves the built files; the dev server runs on a fixed port the shell expects.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: '127.0.0.1' },
  build: { target: 'es2022', sourcemap: false, outDir: 'dist' },
});
