// frontend/src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 30_000 },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
)

// frontend/src/index.css
/* @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,300;0,400;0,500;1,300&family=Barlow:ital,wght@0,300;0,400;0,500;0,600;1,300&family=Barlow+Condensed:wght@400;500;600;700&display=swap'); */

:root {
  --bg:        #070b0f;
  --surface:   #0e1419;
  --surface2:  #141c24;
  --border:    #1a2535;
  --border2:   #22304a;
  --accent:    #00c8ff;
  --accent2:   #ff6b35;
  --green:     #2ee88a;
  --yellow:    #f5c518;
  --red:       #ff3d57;
  --text:      #a8c0d8;
  --text-dim:  #4a6480;
  --text-bright: #ddeeff;
  --font-mono: 'IBM Plex Mono', monospace;
  --font-ui:   'Barlow', sans-serif;
  --font-cond: 'Barlow Condensed', sans-serif;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-ui);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}

/* Scanline texture overlay */
body::after {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,0.03) 2px,
    rgba(0,0,0,0.03) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--surface); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }

/* Utility classes */
.mono { font-family: var(--font-mono); }
.cond { font-family: var(--font-cond); }
.dim  { color: var(--text-dim); }
.bright { color: var(--text-bright); }
