/**
 * Independent re-derivation of the deployable surface from the Worker sources.
 *
 * surface.json is hand-maintained, so on its own it proves nothing: someone
 * adds POST /refund, never lists it, and the gate still reports "100%". This
 * module reads the sources and fails when they expose something the inventory
 * does not mention — which is what makes the coverage number mean anything.
 *
 * It is deliberately conservative: it reports what it can prove is missing
 * rather than trying to fully parse TypeScript.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/** Route literals: `url.pathname === '/x'` / `pathname === "/x"`. */
function routesInSource(src) {
  const found = new Set();
  const re = /pathname\s*===\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(src)) !== null) found.add(m[1]);
  return found;
}

/** Stripe event types dispatched in a switch: `case 'invoice.paid':`. */
function webhookCasesInSource(src) {
  const found = new Set();
  const re = /case\s+['"]([a-z_]+(?:\.[a-z_]+)+)['"]\s*:/g;
  let m;
  while ((m = re.exec(src)) !== null) found.add(m[1]);
  return found;
}

export function checkDrift(root, surface) {
  const problems = [];

  for (const [name, spec] of Object.entries(surface.workers)) {
    const entry = join(root, spec.dir, 'src', 'index.ts');
    if (!existsSync(entry)) {
      problems.push(`${name}: source not found at ${spec.dir}/src/index.ts`);
      continue;
    }
    const src = readFileSync(entry, 'utf8');

    // Every route path the source matches on must appear in the inventory.
    const inventoried = new Set(spec.routes.map(r => r.path));
    for (const path of routesInSource(src)) {
      if (!inventoried.has(path)) {
        problems.push(`${name}: source serves "${path}" but surface.json has no entry for it`);
      }
    }

    // Every dispatched webhook event type must be inventoried.
    if (spec.webhook_events) {
      const types = new Set(spec.webhook_events.map(e => e.type));
      for (const t of webhookCasesInSource(src)) {
        if (!types.has(t)) {
          problems.push(`${name}: webhook dispatches "${t}" but surface.json does not list it`);
        }
      }
      for (const t of types) {
        if (!webhookCasesInSource(src).has(t)) {
          problems.push(`${name}: surface.json lists webhook "${t}" that the source no longer handles`);
        }
      }
    }
  }

  // Every front-end page in the inventory must exist on disk, in the source
  // location the app's staging maps from.
  for (const fe of surface.frontends) {
    const app = surface.frontend_apps[fe.app];
    if (!app) { problems.push(`frontend: unknown app "${fe.app}" for ${fe.id}`); continue; }
    const src = app.stage
      ? (app.stage.find(([, dest]) => dest === fe.page) || [])[0]
      : join(app.root, fe.page);
    if (!src || !existsSync(join(root, src))) {
      problems.push(`frontend: ${fe.id} maps to "${src}" which is missing on disk`);
    }
  }

  // The staging lists must still match what the deploy workflows copy. If a
  // workflow starts publishing another file and surface.json does not, the
  // gate would be rendering a layout that no longer ships.
  for (const [name, app] of Object.entries(surface.frontend_apps)) {
    if (!app.stage || !app.workflow) continue;
    const wf = join(root, '.github/workflows', app.workflow);
    if (!existsSync(wf)) { problems.push(`frontend: ${name} references missing ${app.workflow}`); continue; }

    const text = readFileSync(wf, 'utf8');
    // `cp web/x/y  out/z` and `cp -R web/a/. out/b/`
    const re = /^\s*cp\s+(?:-R\s+)?(\S+)\s+(\S+)\s*$/gm;
    const inWorkflow = new Set();
    let m;
    while ((m = re.exec(text)) !== null) {
      const from = m[1].replace(/\/\.$/, '');
      const to = m[2].replace(/^out\//, '').replace(/\/$/, '');
      inWorkflow.add(`${from}->${to}`);
    }
    const inSurface = new Set(app.stage.map(([f, t]) => `${f}->${t}`));

    for (const pair of inWorkflow) {
      if (!inSurface.has(pair)) {
        problems.push(`frontend: ${app.workflow} publishes "${pair}" but surface.json does not stage it`);
      }
    }
    for (const pair of inSurface) {
      if (!inWorkflow.has(pair)) {
        problems.push(`frontend: surface.json stages "${pair}" but ${app.workflow} no longer publishes it`);
      }
    }
  }

  return { ok: problems.length === 0, problems };
}
