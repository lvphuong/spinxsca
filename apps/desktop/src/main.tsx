import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles.css';

// The shell injects the sidecar URL and the per-launch token before the page loads; in a browser
// (development) they come from the query string of the dev server URL.
const params = new URLSearchParams(window.location.search);
const connection = window.__SPINXSCA__ ?? {
  baseUrl: params.get('api') ?? 'http://127.0.0.1:8080',
  token: params.get('token') ?? '',
};
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App connection={connection} />
    </StrictMode>,
  );
}
