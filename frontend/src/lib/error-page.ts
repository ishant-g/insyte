/** Static HTML shell for a fatal SSR failure - rendered before React ever
 * mounts, so it cannot depend on the app's own styles or components. */
export function renderErrorPage(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Insyte - This page didn't load</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { font: 15px/1.5 ui-monospace, "SF Mono", Consolas, monospace; background: #0a0e14; color: #e2e8f0; display: grid; place-items: center; min-height: 100vh; margin: 0; padding: 1.5rem; }
      .card { max-width: 28rem; width: 100%; text-align: center; padding: 2rem; }
      .brand { font-size: 0.8rem; letter-spacing: 0.15em; color: #64748b; margin-bottom: 1rem; text-transform: uppercase; }
      h1 { font-size: 1.25rem; margin: 0 0 0.5rem; font-weight: 600; }
      p { color: #94a3b8; margin: 0 0 1.5rem; }
      .actions { display: flex; gap: 0.5rem; justify-content: center; flex-wrap: wrap; }
      a, button { padding: 0.5rem 1rem; border-radius: 0.375rem; font: inherit; cursor: pointer; text-decoration: none; border: 1px solid transparent; }
      .primary { background: #22d3ee; color: #0a0e14; font-weight: 600; }
      .secondary { background: transparent; color: #e2e8f0; border-color: #334155; }
    </style>
  </head>
  <body>
    <div class="card">
      <div class="brand">Insyte</div>
      <h1>This page didn't load</h1>
      <p>Something went wrong rendering this page. Try again or head back to the overview.</p>
      <div class="actions">
        <button class="primary" onclick="location.reload()">Try again</button>
        <a class="secondary" href="/">Go home</a>
      </div>
    </div>
  </body>
</html>`;
}
