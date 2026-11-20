'use strict';

// Passive Live Web Auditor for http:// and https:// URLs.
// Performs a single polite GET request (no brute-forcing, no fuzzing, no intrusive payloads)
// and audits HTTP security headers, TLS/HSTS, cookies, server fingerprinting, CSP quality,
// WordPress/CMS passive metadata, and HTML/inline-JS rules via scanner.cjs.

const { scanFileContent, dedupeByCweLocation, rulesForKind, scoreFor, STYLE_HINT_RULES } = require('./scanner.cjs');

function makeWebFinding({ id, title, severity, cwe, hint, reason, url, excerpt }) {
  return {
    id: `${url}:1:${id}`,
    ruleId: id,
    title,
    severity,
    cwe,
    hint,
    confidence: 'high',
    reason,
    file: url,
    line: 1,
    excerpt: String(excerpt || '').trim().slice(0, 220),
  };
}

function getSetCookies(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

function analyzeHttpHeaders(finalUrl, headers) {
  const findings = [];
  const isHttps = finalUrl.startsWith('https://');
  const h = (name) => headers.get(name) || '';

  // 1. HSTS on HTTPS
  const hsts = h('strict-transport-security');
  if (isHttps && !hsts) {
    findings.push(makeWebFinding({
      id: 'web-missing-hsts',
      title: 'Missing Strict-Transport-Security (HSTS) header',
      severity: 'medium',
      cwe: 'CWE-319',
      hint: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to enforce HTTPS.',
      reason: 'HTTPS response lacks an HSTS header, leaving initial connections vulnerable to SSL stripping.',
      url: finalUrl,
      excerpt: 'Strict-Transport-Security: (missing)',
    }));
  } else if (isHttps && hsts) {
    const maxAgeMatch = hsts.match(/\bmax-age\s*=\s*(\d+)/i);
    if (!maxAgeMatch || Number(maxAgeMatch[1]) < 15768000) {
      findings.push(makeWebFinding({
        id: 'web-weak-hsts',
        title: 'Weak Strict-Transport-Security (HSTS) max-age (< 6 months)',
        severity: 'low',
        cwe: 'CWE-319',
        hint: 'Set HSTS `max-age=31536000; includeSubDomains` (at least 15768000 seconds).',
        reason: `HSTS header "${hsts}" uses a short or missing max-age.`,
        url: finalUrl,
        excerpt: `Strict-Transport-Security: ${hsts}`,
      }));
    }
  } else if (!isHttps) {
    findings.push(makeWebFinding({
      id: 'web-insecure-http',
      title: 'Site served over unencrypted HTTP',
      severity: 'high',
      cwe: 'CWE-319',
      hint: 'Redirect all HTTP traffic to HTTPS and enable HSTS.',
      reason: 'Target URL did not upgrade to HTTPS.',
      url: finalUrl,
      excerpt: finalUrl,
    }));
  }

  // 2. Content-Security-Policy quality
  const csp = h('content-security-policy');
  if (!csp) {
    findings.push(makeWebFinding({
      id: 'web-missing-csp',
      title: 'Missing Content-Security-Policy (CSP) header',
      severity: 'medium',
      cwe: 'CWE-693',
      hint: 'Define a Content-Security-Policy restricting script-src, object-src, and frame-ancestors.',
      reason: 'No Content-Security-Policy header was returned.',
      url: finalUrl,
      excerpt: 'Content-Security-Policy: (missing)',
    }));
  } else if (!/\b(?:default-src|script-src)\b/i.test(csp)) {
    findings.push(makeWebFinding({
      id: 'web-weak-csp',
      title: 'Content-Security-Policy lacks script-src / default-src restrictions',
      severity: 'medium',
      cwe: 'CWE-693',
      hint: 'Expand CSP beyond upgrade-insecure-requests to include default-src, script-src, and frame-ancestors.',
      reason: `CSP "${csp.slice(0, 100)}" does not restrict script execution or framing.`,
      url: finalUrl,
      excerpt: `Content-Security-Policy: ${csp}`,
    }));
  }

  // 3. Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
  const xfo = h('x-frame-options');
  if (!xfo && !/\bframe-ancestors\b/i.test(csp)) {
    findings.push(makeWebFinding({
      id: 'web-missing-frame-protection',
      title: 'Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)',
      severity: 'medium',
      cwe: 'CWE-1021',
      hint: "Set `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'`.",
      reason: 'Neither X-Frame-Options nor CSP frame-ancestors is present.',
      url: finalUrl,
      excerpt: 'X-Frame-Options: (missing)',
    }));
  }

  // 4. MIME sniffing
  if (h('x-content-type-options').toLowerCase() !== 'nosniff') {
    findings.push(makeWebFinding({
      id: 'web-missing-nosniff',
      title: 'Missing X-Content-Type-Options: nosniff header',
      severity: 'low',
      cwe: 'CWE-16',
      hint: 'Add `X-Content-Type-Options: nosniff` to prevent MIME type confusion.',
      reason: 'Response lacks X-Content-Type-Options: nosniff.',
      url: finalUrl,
      excerpt: 'X-Content-Type-Options: (missing)',
    }));
  }

  // 5. Referrer-Policy & Permissions-Policy
  if (!h('referrer-policy')) {
    findings.push(makeWebFinding({
      id: 'web-missing-referrer-policy',
      title: 'Missing Referrer-Policy header',
      severity: 'low',
      cwe: 'CWE-200',
      hint: 'Set `Referrer-Policy: strict-origin-when-cross-origin` to avoid leaking URL paths/tokens.',
      reason: 'No Referrer-Policy header was returned.',
      url: finalUrl,
      excerpt: 'Referrer-Policy: (missing)',
    }));
  }
  if (!h('permissions-policy')) {
    findings.push(makeWebFinding({
      id: 'web-missing-permissions-policy',
      title: 'Missing Permissions-Policy header',
      severity: 'info',
      cwe: 'CWE-16',
      hint: 'Restrict unused browser features via `Permissions-Policy: camera=(), microphone=(), geolocation=()`.',
      reason: 'No Permissions-Policy header was returned.',
      url: finalUrl,
      excerpt: 'Permissions-Policy: (missing)',
    }));
  }

  // 6. Server/stack version disclosure
  const poweredBy = h('x-powered-by');
  if (poweredBy) {
    findings.push(makeWebFinding({
      id: 'web-server-version-leak',
      title: `Server technology disclosed via X-Powered-By (${poweredBy})`,
      severity: 'low',
      cwe: 'CWE-200',
      hint: 'Disable X-Powered-By in PHP (`expose_php = Off`), Express (`app.disable("x-powered-by")`), or your reverse proxy.',
      reason: `X-Powered-By header exposes exact runtime version "${poweredBy}".`,
      url: finalUrl,
      excerpt: `X-Powered-By: ${poweredBy}`,
    }));
  }
  const serverHdr = h('server');
  if (serverHdr && /\/[0-9]+\.[0-9]+/.test(serverHdr)) {
    findings.push(makeWebFinding({
      id: 'web-server-header-version',
      title: `Server header discloses software version (${serverHdr})`,
      severity: 'info',
      cwe: 'CWE-200',
      hint: 'Configure `server_tokens off;` (nginx) or `ServerTokens Prod` (Apache) to hide version numbers.',
      reason: `Server header "${serverHdr}" reveals exact server version.`,
      url: finalUrl,
      excerpt: `Server: ${serverHdr}`,
    }));
  }

  // 6b. Passive CORS misconfiguration checks
  const acao = h('access-control-allow-origin').trim();
  const acac = h('access-control-allow-credentials').trim().toLowerCase();
  if (acao === '*' && acac === 'true') {
    findings.push(makeWebFinding({
      id: 'web-cors-wildcard-credentials',
      title: 'CORS allows wildcard origin (*) with credentials',
      severity: 'high',
      cwe: 'CWE-942',
      hint: 'Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`; allow-list explicit origins.',
      reason: 'Wildcard CORS with credentials exposes authenticated responses to any origin.',
      url: finalUrl,
      excerpt: `Access-Control-Allow-Origin: ${acao}; Access-Control-Allow-Credentials: ${acac}`,
    }));
  } else if (acao.toLowerCase() === 'null') {
    findings.push(makeWebFinding({
      id: 'web-cors-null-origin',
      title: 'CORS allows the "null" origin',
      severity: acac === 'true' ? 'high' : 'medium',
      cwe: 'CWE-942',
      hint: 'Remove `null` from Access-Control-Allow-Origin; sandboxed iframes and local files send Origin: null.',
      reason: 'Allowing `Origin: null` lets sandboxed frames bypass origin isolation.',
      url: finalUrl,
      excerpt: `Access-Control-Allow-Origin: ${acao}`,
    }));
  }

  // 7. Cookie attributes
  for (const rawCookie of getSetCookies(headers)) {
    const cookieName = rawCookie.split('=')[0].trim();
    if (!/\bsamesite=/i.test(rawCookie)) {
      findings.push(makeWebFinding({
        id: 'web-cookie-no-samesite',
        title: `Cookie "${cookieName}" missing SameSite attribute`,
        severity: 'low',
        cwe: 'CWE-352',
        hint: `Add SameSite=Lax (or Strict) to cookie "${cookieName}".`,
        reason: 'Cookie does not specify SameSite attribute.',
        url: finalUrl,
        excerpt: rawCookie.slice(0, 140),
      }));
    }
    if (isHttps && !/\bsecure\b/i.test(rawCookie)) {
      findings.push(makeWebFinding({
        id: 'web-cookie-no-secure',
        title: `Cookie "${cookieName}" missing Secure flag over HTTPS`,
        severity: 'medium',
        cwe: 'CWE-614',
        hint: `Set the Secure flag on "${cookieName}" so it is never sent over cleartext HTTP.`,
        reason: 'HTTPS response sets a cookie without the Secure attribute.',
        url: finalUrl,
        excerpt: rawCookie.slice(0, 140),
      }));
    }
    if (/^(?:session|sess|sid|token|auth|jwt|phpsessid|jsessionid|connect\.sid)/i.test(cookieName) && !/\bhttponly\b/i.test(rawCookie)) {
      findings.push(makeWebFinding({
        id: 'web-cookie-no-httponly',
        title: `Session cookie "${cookieName}" missing HttpOnly flag`,
        severity: 'medium',
        cwe: 'CWE-1004',
        hint: `Add HttpOnly to "${cookieName}" so client-side scripts cannot read session tokens via document.cookie.`,
        reason: 'Session-like cookie lacks the HttpOnly flag.',
        url: finalUrl,
        excerpt: rawCookie.slice(0, 140),
      }));
    }
  }

  // 8. Passive WordPress API / metadata exposure
  const linkHdr = h('link');
  if (/wp-json/i.test(linkHdr)) {
    findings.push(makeWebFinding({
      id: 'web-wp-rest-api-exposed',
      title: 'WordPress REST API endpoint advertised in Link header (/wp-json/)',
      severity: 'info',
      cwe: 'CWE-200',
      hint: 'Verify `/wp-json/wp/v2/users` does not enumerate admin usernames and restrict unneeded REST endpoints.',
      reason: 'Response advertises WordPress REST API discovery via Link header.',
      url: finalUrl,
      excerpt: linkHdr.slice(0, 160),
    }));
  }

  return findings;
}

async function scanLiveUrl(targetUrl, options = {}) {
  const startedAt = Date.now();
  const parsed = new URL(targetUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Unsupported URL protocol "${parsed.protocol}"; expected http: or https:`);
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), options.timeoutMs || 15000);
  let res;
  let html = '';
  try {
    res = await fetch(parsed.toString(), {
      redirect: 'follow',
      headers: { 'user-agent': 'OSIEN-Probe-Auditor/1.0' },
      signal: ctrl.signal,
    });
    const contentType = res.headers.get('content-type') || '';
    if (/text\/html|application\/xhtml/i.test(contentType)) {
      html = await res.text();
    }
  } finally {
    clearTimeout(timer);
  }

  const finalUrl = res.url || parsed.toString();
  const headerFindings = analyzeHttpHeaders(finalUrl, res.headers);
  const exposedFindings = options.probeExposedFiles ? await probeExposedSensitivePaths(new URL(finalUrl).origin, options.timeoutMs || 5000) : [];
  const htmlList = [];

  if (html) {
    const catalog = rulesForKind('Website');
    const htmlRes = scanFileContent(html, 'index.html', '.html', 'html', catalog, new Map());
    const htmlFindings = Array.isArray(htmlRes) ? htmlRes : (htmlRes?.findings || []);
    for (const f of htmlFindings) {
      if (options.bugsOnly && STYLE_HINT_RULES.has(f.ruleId)) {
        continue;
      }
      if (options.bugsOnly && f.ruleId === 'html-form-get' && /role\s*=\s*["']search["']|search/i.test(f.excerpt || '')) {
        continue;
      }
      htmlList.push(f);
    }
    htmlList.push(...analyzeHtmlLiveChecks(html, finalUrl));
  }

  const combined = [...headerFindings, ...exposedFindings, ...(options.bugsOnly ? dedupeByCweLocation(htmlList) : htmlList)];
  const capped = combined.slice(0, options.maxFindings || 1000);
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of capped) {
    if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
  }

  return {
    root: finalUrl,
    kind: 'Live Website',
    status: res.status,
    scannedFiles: html ? 1 : 0,
    totalRules: 10 + (html ? rulesForKind('Website').length : 0),
    totalChecks: 10 + (html ? rulesForKind('Website').length : 0),
    durationMs: Date.now() - startedAt,
    score: scoreFor(capped),
    severityCounts,
    findings: capped,
    truncated: combined.length > capped.length,
    testCommand: '',
    scannedAt: new Date().toISOString(),
  };
}

function analyzeHtmlLiveChecks(html, finalUrl) {
  const findings = [];
  let pageOrigin = '';
  try { pageOrigin = new URL(finalUrl).origin; } catch { /* ignore */ }
  const isHttps = finalUrl.startsWith('https://');
  const lines = html.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isHttps) {
      const mixedMatch = line.match(/<(?:script|iframe|form|link)\b[^>]*(?:src|action|href)\s*=\s*["'](http:\/\/[^"']+)["']/i);
      if (mixedMatch) {
        findings.push({
          ...makeWebFinding({
            id: 'web-mixed-content',
            title: 'Mixed content: insecure http:// resource loaded on HTTPS page',
            severity: 'high',
            cwe: 'CWE-319',
            hint: `Upgrade "${mixedMatch[1]}" to https:// so active/subresource traffic cannot be tampered with.`,
            reason: 'HTTPS page references an http:// resource.',
            url: finalUrl,
            excerpt: line,
          }),
          id: `${finalUrl}:${i + 1}:web-mixed-content`,
          line: i + 1,
        });
      }
    }

    const scriptSrc = line.match(/<script\b[^>]*\bsrc\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/i);
    if (scriptSrc && !/\bintegrity\s*=/i.test(scriptSrc[0])) {
      const isCrossOrigin = URL.canParse(scriptSrc[1]) ? new URL(scriptSrc[1]).origin !== pageOrigin : true;
      if (isCrossOrigin) {
        findings.push({
          ...makeWebFinding({
            id: 'web-missing-sri',
            title: 'External script loaded without Subresource Integrity (SRI)',
            severity: 'medium',
            cwe: 'CWE-829',
            hint: 'Add `integrity="sha384-..." crossorigin="anonymous"` to external <script> tags.',
            reason: `External script "${scriptSrc[1]}" lacks an integrity attribute.`,
            url: finalUrl,
            excerpt: line,
          }),
          id: `${finalUrl}:${i + 1}:web-missing-sri`,
          line: i + 1,
        });
      }
    }
  }
  return findings;
}

async function probeExposedSensitivePaths(origin, timeoutMs) {
  const findings = [];
  const safeFetchText = async (target) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetch(target, { redirect: 'manual', headers: { 'user-agent': 'OSIEN-Probe-Auditor/1.0' }, signal: ctrl.signal });
      if (r.status !== 200) return null;
      const ct = r.headers.get('content-type') || '';
      if (/text\/html/i.test(ct)) return null;
      const text = await r.text();
      return text;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  };

  const gitHeadUrl = `${origin}/.git/HEAD`;
  const gitHead = await safeFetchText(gitHeadUrl);
  if (gitHead && /^ref:\s*refs\//m.test(gitHead)) {
    findings.push(makeWebFinding({
      id: 'web-exposed-git-head',
      title: 'Exposed .git/HEAD repository metadata',
      severity: 'critical',
      cwe: 'CWE-538',
      hint: 'Block access to `/.git` in your web server or reverse proxy immediately.',
      reason: 'GET /.git/HEAD returned a valid Git HEAD reference.',
      url: gitHeadUrl,
      excerpt: gitHead.trim().slice(0, 120),
    }));
  }

  const envUrl = `${origin}/.env`;
  const envBody = await safeFetchText(envUrl);
  if (envBody && /^[A-Z][A-Z0-9_]{2,}=[^\r\n]+/m.test(envBody)) {
    findings.push(makeWebFinding({
      id: 'web-exposed-env-file',
      title: 'Exposed .env environment file',
      severity: 'critical',
      cwe: 'CWE-200',
      hint: 'Remove `.env` from the webroot and deny dotfile access in your web server.',
      reason: 'GET /.env returned plain-text KEY=VALUE environment configuration.',
      url: envUrl,
      excerpt: '(redacted .env content)',
    }));
  }

  return findings;
}

function generateWebRemediation(scanOrFindings, targetUrl = '') {
  const findings = Array.isArray(scanOrFindings) ? scanOrFindings : (scanOrFindings?.findings || []);
  const url = targetUrl || (!Array.isArray(scanOrFindings) && scanOrFindings?.root) || 'https://example.com';
  const hostname = URL.canParse(url) ? (new URL(url).hostname || 'example.com') : 'example.com';

  const ids = new Set(findings.map((f) => f.ruleId));
  const needsHsts = ids.has('web-missing-hsts') || ids.has('web-weak-hsts') || ids.has('web-insecure-http');
  const needsCsp = ids.has('web-missing-csp') || ids.has('web-weak-csp');
  const needsFrame = ids.has('web-missing-frame-protection');
  const needsNosniff = ids.has('web-missing-nosniff');
  const needsReferrer = ids.has('web-missing-referrer-policy');
  const needsPerms = ids.has('web-missing-permissions-policy');
  const needsServerHide = ids.has('web-server-version-leak') || ids.has('web-server-header-version');
  const needsCorsFix = ids.has('web-cors-wildcard-credentials') || ids.has('web-cors-null-origin');
  const needsCookieFix = ids.has('web-cookie-no-samesite') || ids.has('web-cookie-no-secure') || ids.has('web-cookie-no-httponly');
  const needsDotfileDeny = ids.has('web-exposed-git-head') || ids.has('web-exposed-env-file');

  const cspValue = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests";
  const headerPairs = [];
  if (needsHsts) headerPairs.push(['Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload']);
  if (needsCsp) headerPairs.push(['Content-Security-Policy', cspValue]);
  if (needsFrame) headerPairs.push(['X-Frame-Options', 'SAMEORIGIN']);
  if (needsNosniff) headerPairs.push(['X-Content-Type-Options', 'nosniff']);
  if (needsReferrer) headerPairs.push(['Referrer-Policy', 'strict-origin-when-cross-origin']);
  if (needsPerms) headerPairs.push(['Permissions-Policy', 'camera=(), microphone=(), geolocation=()']);

  // Fallback baseline headers if called on a clean site
  if (headerPairs.length === 0) {
    headerPairs.push(
      ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains'],
      ['X-Frame-Options', 'SAMEORIGIN'],
      ['X-Content-Type-Options', 'nosniff'],
      ['Referrer-Policy', 'strict-origin-when-cross-origin'],
    );
  }

  // 1. Nginx config
  const nginxLines = [
    `# OSIEN Probe remediation for ${url}`,
    'server {',
    `    server_name ${hostname};`,
    ...(ids.has('web-insecure-http') ? ['    listen 443 ssl http2;', '    # Redirect HTTP -> HTTPS in your port 80 block: return 301 https://$host$request_uri;'] : []),
    ...(needsServerHide ? ['    server_tokens off;', '    proxy_hide_header X-Powered-By;'] : []),
    ...headerPairs.map(([k, v]) => `    add_header ${k} "${v}" always;`),
    ...(needsCorsFix ? [
      `    # Replace wildcard/null CORS with explicit allowlisted origin`,
      `    add_header Access-Control-Allow-Origin "https://${hostname}" always;`,
      '    add_header Vary "Origin" always;',
    ] : []),
    ...(needsCookieFix ? ['    proxy_cookie_flags ~ secure httponly samesite=lax;'] : []),
    ...(needsDotfileDeny ? [
      '    # Block exposed dotfiles (.git, .env)',
      '    location ~ /\\.(?!well-known) {',
      '        deny all;',
      '        return 404;',
      '    }',
    ] : []),
    '}',
  ];

  // 2. Apache (.htaccess)
  const apacheLines = [
    `# OSIEN Probe remediation (.htaccess) for ${url}`,
    '<IfModule mod_headers.c>',
    ...headerPairs.map(([k, v]) => `    Header always set ${k} "${v}"`),
    ...(needsServerHide ? ['    Header unset X-Powered-By', '    Header always unset X-Powered-By'] : []),
    ...(needsCorsFix ? [`    Header always set Access-Control-Allow-Origin "https://${hostname}"`, '    Header always set Vary "Origin"'] : []),
    ...(needsCookieFix ? ['    Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Lax"'] : []),
    '</IfModule>',
    ...(ids.has('web-insecure-http') ? [
      'RewriteEngine On',
      'RewriteCond %{HTTPS} !=on',
      'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]',
    ] : []),
    ...(needsDotfileDeny ? ['RedirectMatch 404 /\\.(?!well-known)'] : []),
  ];

  // 3. Express / Node.js
  const expressLines = [
    `// OSIEN Probe remediation for ${url}`,
    "import express from 'express';",
    "import helmet from 'helmet';",
    '',
    'const app = express();',
    ...(needsServerHide ? ["app.disable('x-powered-by');"] : []),
    'app.use(helmet({',
    `  hsts: ${needsHsts ? '{ maxAge: 31536000, includeSubDomains: true, preload: true }' : 'false'},`,
    `  frameguard: ${needsFrame ? "{ action: 'sameorigin' }" : 'false'},`,
    `  noSniff: ${needsNosniff},`,
    `  referrerPolicy: ${needsReferrer ? "{ policy: 'strict-origin-when-cross-origin' }" : 'false'},`,
    ...(needsCsp ? [
      '  contentSecurityPolicy: {',
      '    directives: {',
      "      defaultSrc: [\"'self'\"],",
      "      scriptSrc: [\"'self'\"],",
      "      objectSrc: [\"'none'\"],",
      "      frameAncestors: [\"'self'\"],",
      '    },',
      '  },',
    ] : []),
    '}));',
    ...(needsPerms ? [
      "app.use((_req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); next(); });",
    ] : []),
    ...(needsCorsFix ? [
      `const ALLOWED_ORIGINS = new Set(['https://${hostname}']);`,
      'app.use((req, res, next) => {',
      '  const origin = req.headers.origin;',
      '  if (origin && ALLOWED_ORIGINS.has(origin)) {',
      "    res.setHeader('Access-Control-Allow-Origin', origin);",
      "    res.setHeader('Vary', 'Origin');",
      '  }',
      '  next();',
      '});',
    ] : []),
    ...(needsCookieFix ? [
      "// Cookie options: { httpOnly: true, secure: true, sameSite: 'lax' }",
    ] : []),
  ];

  // 4. Next.js (next.config.mjs)
  const nextjsLines = [
    `// next.config.mjs remediation for ${url}`,
    'const securityHeaders = [',
    ...headerPairs.map(([k, v]) => `  { key: '${k}', value: "${v}" },`),
    '];',
    '',
    'export default {',
    ...(needsServerHide ? ['  poweredByHeader: false,'] : []),
    '  async headers() {',
    "    return [{ source: '/(.*)', headers: securityHeaders }];",
    '  },',
    '};',
  ];

  // 5. Vercel (vercel.json)
  const vercelConfig = {
    headers: [
      {
        source: '/(.*)',
        headers: headerPairs.map(([key, value]) => ({ key, value })),
      },
    ],
  };

  // 6. Cloudflare Worker
  const cfLines = [
    `// Cloudflare Worker security header patch for ${url}`,
    'export default {',
    '  async fetch(request, env, ctx) {',
    '    const response = await fetch(request);',
    '    const headers = new Headers(response.headers);',
    ...headerPairs.map(([k, v]) => `    headers.set('${k}', "${v}");`),
    ...(needsServerHide ? ["    headers.delete('X-Powered-By');", "    headers.delete('Server');"] : []),
    ...(needsCorsFix ? [
      "    const origin = request.headers.get('Origin');",
      `    if (origin === 'https://${hostname}') {`,
      "      headers.set('Access-Control-Allow-Origin', origin);",
      "      headers.set('Vary', 'Origin');",
      '    } else {',
      "      headers.delete('Access-Control-Allow-Origin');",
      '    }',
    ] : []),
    '    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });',
    '  },',
    '};',
  ];

  const actions = findings.map((f) => ({
    ruleId: f.ruleId,
    severity: f.severity,
    title: f.title,
    fix: f.hint || f.reason || 'Apply recommended security configuration.',
  }));

  return {
    url,
    issueCount: findings.length,
    actions,
    configs: {
      nginx: nginxLines.join('\n'),
      apache: apacheLines.join('\n'),
      express: expressLines.join('\n'),
      nextjs: nextjsLines.join('\n'),
      vercel: JSON.stringify(vercelConfig, null, 2),
      cloudflare: cfLines.join('\n'),
    },
  };
}

module.exports = {
  scanLiveUrl,
  analyzeHttpHeaders,
  generateWebRemediation,
};
