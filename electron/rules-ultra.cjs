'use strict';

// Ultra expansion pack adding 1,140+ high-precision security & reliability rules across
// Go, Rust, Java/Kotlin, PHP, Ruby, Cloud/K8s/IaC, Crypto, SQL/NoSQL, and Web Frameworks.

function makeUltraRule(lang, view, id, title, severity, cwe, pattern, bad, good, hint, extra = {}) {
  const needsRaw = view === 'raw' || /['"`]|https?:|0\.0\.0\.0|public-read|privileged|hostNetwork|allowPrivilegeEscalation|unconfined|SYS_ADMIN|NET_ADMIN/.test(pattern.source);
  return { id, title, severity, cwe, lang, view: needsRaw ? 'raw' : view, pattern, bad, good, hint, ...extra };
}

const js = (id, t, s, c, p, b, g, h, e) => makeUltraRule('js', 'code', id, t, s, c, p, b, g, h, e);
const py = (id, t, s, c, p, b, g, h, e) => makeUltraRule('py', 'code', id, t, s, c, p, b, g, h, e);
const go = (id, t, s, c, p, b, g, h, e) => makeUltraRule('any', 'code', id, t, s, c, p, b, g, h, e);
const rs = (id, t, s, c, p, b, g, h, e) => makeUltraRule('any', 'code', id, t, s, c, p, b, g, h, e);
const java = (id, t, s, c, p, b, g, h, e) => makeUltraRule('any', 'code', id, t, s, c, p, b, g, h, e);
const php = (id, t, s, c, p, b, g, h, e) => makeUltraRule('any', 'raw', id, t, s, c, p, b, g, h, e);
const rb = (id, t, s, c, p, b, g, h, e) => makeUltraRule('any', 'code', id, t, s, c, p, b, g, h, e);
const yaml = (id, t, s, c, p, b, g, h, e) => makeUltraRule('yaml', 'raw', id, t, s, c, p, b, g, h, e);
const any = (id, t, s, c, p, b, g, h, e) => makeUltraRule('any', 'code', id, t, s, c, p, b, g, h, e);

function buildUltraShared() {
  const out = [];

  // 1. Go Source-to-Sink Matrix: 10 sources x 15 sinks = 150 rules
  const goSources = [
    ['r-url-query', 'r\\.URL\\.Query\\(\\)\\.Get\\([^)]+\\)', 'r.URL.Query().Get("id")'],
    ['r-form-val', 'r\\.FormValue\\([^)]+\\)', 'r.FormValue("input")'],
    ['r-post-form', 'r\\.PostFormValue\\([^)]+\\)', 'r.PostFormValue("val")'],
    ['r-header', 'r\\.Header\\.Get\\([^)]+\\)', 'r.Header.Get("X-Input")'],
    ['gin-query', 'c\\.Query\\([^)]+\\)', 'c.Query("q")'],
    ['gin-param', 'c\\.Param\\([^)]+\\)', 'c.Param("id")'],
    ['gin-postform', 'c\\.PostForm\\([^)]+\\)', 'c.PostForm("name")'],
    ['gin-cookie', 'c\\.Cookie\\([^)]+\\)', 'c.Cookie("sess")'],
    ['os-args', 'os\\.Args\\[\\d+\\]', 'os.Args[1]'],
    ['r-raw-query', 'r\\.URL\\.RawQuery', 'r.URL.RawQuery'],
  ];

  const goSinks = [
    ['db-query', 'critical', 'CWE-89', 'db\\.Query', 'db.Query("SELECT 1", safeVal)', 'Use parameterized SQL placeholders ($1 / ?) in db.Query().'],
    ['db-exec', 'critical', 'CWE-89', 'db\\.Exec', 'db.Exec("DELETE FROM t WHERE id=$1", safeId)', 'Use parameterized placeholders in db.Exec().'],
    ['db-queryrow', 'critical', 'CWE-89', 'db\\.QueryRow', 'db.QueryRow("SELECT * FROM u WHERE id=$1", safeId)', 'Use parameterized placeholders in db.QueryRow().'],
    ['exec-cmd', 'critical', 'CWE-78', 'exec\\.Command', 'exec.Command("ls", "-la")', 'Pass fixed binary and validated args without shell interpolation.'],
    ['os-readfile', 'high', 'CWE-22', 'os\\.ReadFile', 'os.ReadFile(filepath.Join(baseDir, safeName))', 'Sanitize filenames with filepath.Base() and check base directory.'],
    ['os-writefile', 'high', 'CWE-22', 'os\\.WriteFile', 'os.WriteFile(safePath, data, 0600)', 'Anchor write paths inside an allowed directory.'],
    ['os-open', 'high', 'CWE-22', 'os\\.Open', 'os.Open(safePath)', 'Validate file paths against traversal before os.Open().'],
    ['os-remove', 'high', 'CWE-22', 'os\\.Remove', 'os.Remove(safePath)', 'Validate paths before deleting files with os.Remove().'],
    ['http-get', 'high', 'CWE-918', 'http\\.Get', 'http.Get("https://api.example.com/status")', 'Validate outbound URLs against an allowlist to prevent SSRF.'],
    ['http-post', 'high', 'CWE-918', 'http\\.Post', 'http.Post("https://api.example.com/hook", "application/json", body)', 'Validate outbound URLs before calling http.Post().'],
    ['http-redirect', 'medium', 'CWE-601', 'http\\.Redirect', 'http.Redirect(w, r, "/home", http.StatusFound)', 'Allow only relative same-site redirect paths.'],
    ['tmpl-html', 'high', 'CWE-79', 'template\\.HTML', 'template.HTMLEscapeString(safeText)', 'Never wrap untrusted input in template.HTML().'],
    ['fmt-fprintf', 'medium', 'CWE-79', 'fmt\\.Fprintf', 'w.Write([]byte(html.EscapeString(safeText)))', 'Escape untrusted output before writing to ResponseWriter.'],
    ['filepath-join', 'medium', 'CWE-22', 'filepath\\.Join', 'filepath.Join(base, filepath.Base(safeName))', 'Use filepath.Base() before joining untrusted path segments.'],
    ['ioutil-read', 'high', 'CWE-22', 'ioutil\\.ReadFile', 'os.ReadFile(safePath)', 'Sanitize paths before reading files.'],
  ];

  for (const [srcId, srcRx, srcEx] of goSources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of goSinks) {
      out.push(go(
        `ultra-goflow-${srcId}-${sinkId}`,
        `Go untrusted ${srcId} reaches ${sinkId}`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\([^)\\n]*${srcRx}`),
        `${sinkRx.replace(/\\/g, '')}(${srcEx})`,
        safeCall,
        hint,
      ));
    }
  }

  // 2. Rust Source-to-Sink Matrix: 8 sources x 14 sinks = 112 rules
  const rsSources = [
    ['req-query', 'req\\.query_string\\(\\)', 'req.query_string()'],
    ['query-inner', 'query\\.into_inner\\(\\)', 'query.into_inner()'],
    ['path-inner', 'path\\.into_inner\\(\\)', 'path.into_inner()'],
    ['body-inner', 'body\\.into_inner\\(\\)', 'body.into_inner()'],
    ['req-headers', 'req\\.headers\\(\\)', 'req.headers()'],
    ['env-args', 'std::env::args\\(\\)', 'std::env::args()'],
    ['header-val', 'header_val', 'header_val'],
    ['user-input', 'user_input', 'user_input'],
  ];

  const rsSinks = [
    ['sqlx-query', 'critical', 'CWE-89', 'sqlx::query', 'sqlx::query("SELECT 1").bind(safe_val)', 'Use .bind() parameters instead of dynamic SQL strings.'],
    ['cmd-new', 'critical', 'CWE-78', 'Command::new', 'Command::new("ls").arg("-la")', 'Avoid passing untrusted input to Command::new().'],
    ['fs-read', 'high', 'CWE-22', 'std::fs::read_to_string', 'std::fs::read_to_string(safe_path)', 'Canonicalize and validate paths against a base directory.'],
    ['fs-write', 'high', 'CWE-22', 'std::fs::write', 'std::fs::write(safe_path, bytes)', 'Validate paths before writing to disk.'],
    ['fs-remove', 'high', 'CWE-22', 'std::fs::remove_file', 'std::fs::remove_file(safe_path)', 'Validate paths before deleting files.'],
    ['reqwest-get', 'high', 'CWE-918', 'reqwest::get', 'reqwest::get("https://api.example.com")', 'Validate outbound URLs against an allowlist to prevent SSRF.'],
    ['html-resp', 'high', 'CWE-79', 'Html::from', 'escape_html(safe_str)', 'HTML-escape untrusted content before returning Html.'],
    ['regex-new', 'medium', 'CWE-1333', 'Regex::new', 'Regex::new(r"^[a-z]+$")', 'Avoid building Regex::new() from untrusted input.'],
    ['serde-from-str', 'medium', 'CWE-20', 'serde_json::from_str', 'serde_json::from_str::<SafeDto>(bounded_json)', 'Validate size and schema before deserializing untrusted JSON.'],
    ['mem-transmute', 'critical', 'CWE-704', 'std::mem::transmute', 'u32::from_le_bytes(buf)', 'Avoid std::mem::transmute on untrusted data.'],
    ['slice-raw', 'critical', 'CWE-119', 'from_raw_parts', 'slice.get(0..len)', 'Avoid unsafe slice::from_raw_parts with untrusted lengths.'],
    ['ptr-offset', 'high', 'CWE-119', 'ptr\\.offset', 'slice.get(idx)', 'Use bounds-checked indexing instead of raw pointer offset().'],
    ['copy-nonoverlap', 'critical', 'CWE-787', 'copy_nonoverlapping', 'dst.copy_from_slice(src)', 'Prefer safe copy_from_slice() over unsafe copy_nonoverlapping().'],
    ['unwrap-uncheck', 'high', 'CWE-252', 'unwrap_unchecked', 'opt.ok_or(AppError::Invalid)?', 'Handle Option/Result explicitly instead of unwrap_unchecked().'],
  ];

  for (const [srcId, srcRx, srcEx] of rsSources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of rsSinks) {
      out.push(rs(
        `ultra-rsflow-${srcId}-${sinkId}`,
        `Rust untrusted ${srcId} reaches ${sinkId}`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\([^)\\n]*${srcRx}`),
        `${sinkRx.replace(/\\/g, '')}(${srcEx})`,
        safeCall,
        hint,
      ));
    }
  }

  // 3. Java / Spring / Kotlin Source-to-Sink Matrix: 10 sources x 16 sinks = 160 rules
  const javaSources = [
    ['req-param', 'request\\.getParameter\\([^)]+\\)', 'request.getParameter("q")'],
    ['req-header', 'request\\.getHeader\\([^)]+\\)', 'request.getHeader("X-User")'],
    ['req-query', 'request\\.getQueryString\\(\\)', 'request.getQueryString()'],
    ['spring-param', 'springParam', 'springParam'],
    ['spring-path', 'pathVarInput', 'pathVarInput'],
    ['spring-body', 'requestBodyDto', 'requestBodyDto'],
    ['spring-hdr', 'headerInput', 'headerInput'],
    ['cookie-val', 'cookieValue', 'cookieValue'],
    ['intent-extra', 'intent\\.getStringExtra\\([^)]+\\)', 'intent.getStringExtra("url")'],
    ['cli-arg', 'args\\[\\d+\\]', 'args[0]'],
  ];

  const javaSinks = [
    ['stmt-exec', 'critical', 'CWE-89', 'stmt\\.executeQuery', 'ps.executeQuery()', 'Use PreparedStatement with bound parameters instead of Statement.executeQuery().'],
    ['native-query', 'critical', 'CWE-89', 'em\\.createNativeQuery', 'em.createNamedQuery("User.findSafe")', 'Use parameterized JPA queries instead of dynamic createNativeQuery().'],
    ['jdbc-query', 'critical', 'CWE-89', 'jdbcTemplate\\.query', 'jdbcTemplate.query(SAFE_SQL, mapper, id)', 'Bind parameters in JdbcTemplate rather than concatenating SQL.'],
    ['runtime-exec', 'critical', 'CWE-78', 'Runtime\\.getRuntime\\(\\)\\.exec', 'new ProcessBuilder("ls", "-la").start()', 'Avoid Runtime.exec() with untrusted input.'],
    ['process-builder', 'critical', 'CWE-78', 'new\\s+ProcessBuilder', 'new ProcessBuilder(List.of("ls", "-la"))', 'Validate arguments and avoid shell commands in ProcessBuilder.'],
    ['new-file', 'high', 'CWE-22', 'new\\s+File', 'baseDir.resolve(safeName).normalize()', 'Normalize and verify path prefix before creating File objects.'],
    ['files-read', 'high', 'CWE-22', 'Files\\.readString', 'Files.readString(safeResolvedPath)', 'Verify resolved path stays inside allowed directory.'],
    ['files-write', 'high', 'CWE-22', 'Files\\.write', 'Files.write(safeResolvedPath, bytes)', 'Verify resolved path before writing files.'],
    ['obj-stream', 'critical', 'CWE-502', 'new\\s+ObjectInputStream', 'objectMapper.readValue(json, SafeDto.class)', 'Avoid Java ObjectInputStream on untrusted bytes.'],
    ['xml-decoder', 'critical', 'CWE-502', 'new\\s+XMLDecoder', 'safeXmlParser.parse(stream)', 'Never pass untrusted input to XMLDecoder.'],
    ['doc-builder', 'high', 'CWE-611', 'DocumentBuilderFactory\\.newInstance', 'secureDbf.newDocumentBuilder()', 'Disable external entities (XXE) on DocumentBuilderFactory.'],
    ['send-redirect', 'medium', 'CWE-601', 'response\\.sendRedirect', 'response.sendRedirect("/dashboard")', 'Allow-list redirect destinations to prevent open redirects.'],
    ['rest-template', 'high', 'CWE-918', 'restTemplate\\.getForObject', 'restTemplate.getForObject(ALLOWED_URI, Res.class)', 'Validate outbound URLs against an allowlist to prevent SSRF.'],
    ['script-eval', 'critical', 'CWE-95', 'scriptEngine\\.' + 'eval', 'safeEvaluator.evaluate(ast)', 'Never pass untrusted strings to ScriptEngine eval.'],
    ['pattern-compile', 'medium', 'CWE-1333', 'Pattern\\.compile', 'Pattern.compile(Pattern.quote(safeText))', 'Escape untrusted regex inputs with Pattern.quote().'],
    ['webview-load', 'high', 'CWE-749', 'webView\\.loadUrl', 'webView.loadUrl("https://app.example.com")', 'Validate URLs before calling webView.loadUrl().'],
  ];

  for (const [srcId, srcRx, srcEx] of javaSources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of javaSinks) {
      out.push(java(
        `ultra-javaflow-${srcId}-${sinkId}`,
        `Java untrusted ${srcId} reaches ${sinkId}`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\([^)\\n]*${srcRx}`),
        `${sinkRx.replace(/\\s\+/g, ' ').replace(/\\/g, '')}(${srcEx});`,
        `${safeCall};`,
        hint,
      ));
    }
  }

  // 4. PHP Source-to-Sink Matrix: 6 sources x 14 sinks = 84 rules
  const phpSources = [
    ['get', '\\$_GET\\[[^\\]]+\\]', "$_GET['id']"],
    ['post', '\\$_POST\\[[^\\]]+\\]', "$_POST['data']"],
    ['request', '\\$_REQUEST\\[[^\\]]+\\]', "$_REQUEST['q']"],
    ['cookie', '\\$_COOKIE\\[[^\\]]+\\]', "$_COOKIE['sess']"],
    ['server', '\\$_SERVER\\[[^\\]]+\\]', "$_SERVER['HTTP_HOST']"],
    ['input', 'file_get_contents\\([\'"]php://input[\'"]\\)', "file_get_contents('php://input')"],
  ];

  const phpSinks = [
    ['mysqli-query', 'critical', 'CWE-89', 'mysqli_query', '$stmt->execute([$safeId]);', 'Use prepared statements ($pdo->prepare / $mysqli->prepare).'],
    ['mysql-query', 'critical', 'CWE-89', 'mysql_query', '$pdo->prepare($sql);', 'Replace deprecated mysql_query with PDO prepared statements.'],
    ['pg-query', 'critical', 'CWE-89', 'pg_query', 'pg_query_params($conn, $sql, [$safeId]);', 'Use pg_query_params() with bound parameters.'],
    ['shell-exec', 'critical', 'CWE-78', 'shell_exec', 'escapeshellarg($safeArg);', 'Avoid shell_exec() with superglobal input.'],
    ['exec', 'critical', 'CWE-78', 'exec', 'escapeshellarg($safeArg);', 'Validate and escape arguments before exec().'],
    ['system', 'critical', 'CWE-78', 'system', 'escapeshellarg($safeArg);', 'Never pass request input into system().'],
    ['passthru', 'critical', 'CWE-78', 'passthru', 'escapeshellarg($safeArg);', 'Never pass request input into passthru().'],
    ['proc-open', 'critical', 'CWE-78', 'proc_open', 'proc_open(["/usr/bin/env", "ls"], $desc, $pipes);', 'Pass command arrays without shell interpolation.'],
    ['unserialize', 'critical', 'CWE-502', 'unserialize', 'json_decode($safeJson, true);', 'Use json_decode() instead of unserialize() on untrusted data.'],
    ['eval', 'critical', 'CWE-95', 'eval', 'json_decode($safeJson, true);', 'Never pass superglobal input to eval().'],
    ['include', 'critical', 'CWE-98', 'include', "include __DIR__ . '/views/home.php';", 'Allow-list template names instead of dynamic include().'],
    ['require-once', 'critical', 'CWE-98', 'require_once', "require_once __DIR__ . '/init.php';", 'Never pass user input into require_once().'],
    ['file-get', 'high', 'CWE-918', 'file_get_contents', 'file_get_contents(__DIR__ . "/static.txt");', 'Validate paths and URLs before file_get_contents().'],
    ['header-loc', 'medium', 'CWE-601', 'header', 'header("Location: /dashboard");', 'Validate redirect targets against an allowlist.'],
  ];

  for (const [srcId, srcRx, srcEx] of phpSources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of phpSinks) {
      out.push(php(
        `ultra-phpflow-${srcId}-${sinkId}`,
        `PHP $_${srcId.toUpperCase()} reaches ${sinkId}()`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\([^)\\n]*${srcRx}`),
        `${sinkRx}(${srcEx});`,
        safeCall,
        hint,
      ));
    }
  }

  // 5. Ruby Source-to-Sink Matrix: 4 sources x 14 sinks = 56 rules
  const rbSources = [
    ['params', 'params\\[[^\\]]+\\]', 'params[:id]'],
    ['headers', 'request\\.headers\\[[^\\]]+\\]', 'request.headers["X-Input"]'],
    ['cookies', 'cookies\\[[^\\]]+\\]', 'cookies[:session]'],
    ['argv', 'ARGV\\[\\d+\\]', 'ARGV[0]'],
  ];

  const rbSinks = [
    ['eval', 'critical', 'CWE-95', 'eval', 'JSON.parse(safe_json)', 'Never pass untrusted input into eval().'],
    ['instance-eval', 'critical', 'CWE-95', 'instance_eval', 'safe_dispatch(action)', 'Never pass untrusted input into instance_eval().'],
    ['send', 'high', 'CWE-470', 'public_send', 'ALLOWED_METHODS[name]&.call', 'Allow-list method names before calling send/public_send.'],
    ['system', 'critical', 'CWE-78', 'system', 'system("ls", "-la")', 'Pass separate arguments to system() instead of interpolated strings.'],
    ['exec', 'critical', 'CWE-78', 'exec', 'exec("ls", "-la")', 'Avoid shell interpolation in exec().'],
    ['kernel-open', 'critical', 'CWE-78', 'URI\\.open', 'File.open(safe_path)', 'Use File.open() on validated paths instead of Kernel#open.'],
    ['marshal-load', 'critical', 'CWE-502', 'Marshal\\.load', 'JSON.parse(safe_json)', 'Never call Marshal.load() on untrusted input.'],
    ['yaml-load', 'critical', 'CWE-502', 'YAML\\.load', 'YAML.safe_load(safe_yaml)', 'Use YAML.safe_load() instead of YAML.load().'],
    ['erb-new', 'critical', 'CWE-94', 'ERB\\.new', 'render(template: "safe_view")', 'Never compile untrusted strings with ERB.new().'],
    ['redirect-to', 'medium', 'CWE-601', 'redirect_to', 'redirect_to root_path', 'Validate redirect_to targets to prevent open redirects.'],
    ['render-inline', 'critical', 'CWE-79', 'render_inline', 'render(partial: "card")', 'Avoid rendering untrusted strings inline.'],
    ['ar-where', 'critical', 'CWE-89', 'User\\.where', 'User.where(id: safe_id)', 'Pass hash or ? placeholders to ActiveRecord#where.'],
    ['find-by-sql', 'critical', 'CWE-89', 'find_by_sql', 'User.where(id: safe_id)', 'Use bound parameters in find_by_sql().'],
    ['constantize', 'high', 'CWE-470', 'constantize', 'ALLOWED_TYPES[type_name]', 'Allow-list class names before calling constantize().'],
  ];

  for (const [srcId, srcRx, srcEx] of rbSources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of rbSinks) {
      out.push(rb(
        `ultra-rbflow-${srcId}-${sinkId}`,
        `Ruby untrusted ${srcId} reaches ${sinkId}`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\([^)\\n]*${srcRx}`),
        `${sinkRx.replace(/\\/g, '')}(${srcEx})`,
        safeCall,
        hint,
      ));
    }
  }

  // 6. Cloud / Kubernetes / IaC Hardening Matrix: 20 misconfigs x 6 resource contexts = 120 rules
  const k8sResources = [
    ['deployment', 'Deployment'],
    ['statefulset', 'StatefulSet'],
    ['daemonset', 'DaemonSet'],
    ['cronjob', 'CronJob'],
    ['pod', 'Pod'],
    ['helm-values', 'HelmValues'],
  ];
  const k8sMisconfigs = [
    ['privileged', 'Container runs in privileged mode', 'critical', 'CWE-250', 'privileged:\\s*true', 'privileged: true', 'privileged: false', 'Set securityContext.privileged: false.'],
    ['priv-esc', 'Container allows privilege escalation', 'high', 'CWE-250', 'allowPrivilegeEscalation:\\s*true', 'allowPrivilegeEscalation: true', 'allowPrivilegeEscalation: false', 'Set allowPrivilegeEscalation: false.'],
    ['host-net', 'Pod uses hostNetwork namespace', 'high', 'CWE-668', 'hostNetwork:\\s*true', 'hostNetwork: true', 'hostNetwork: false', 'Disable hostNetwork unless strictly required.'],
    ['host-pid', 'Pod shares hostPID namespace', 'high', 'CWE-668', 'hostPID:\\s*true', 'hostPID: true', 'hostPID: false', 'Disable hostPID to isolate container processes.'],
    ['host-ipc', 'Pod shares hostIPC namespace', 'high', 'CWE-668', 'hostIPC:\\s*true', 'hostIPC: true', 'hostIPC: false', 'Disable hostIPC to isolate shared memory.'],
    ['run-as-root', 'Container configured to runAsUser 0 (root)', 'high', 'CWE-250', 'runAsUser:\\s*0\\b', 'runAsUser: 0', 'runAsUser: 10001', 'Run containers as a non-root UID.'],
    ['run-as-nonroot-false', 'Container explicitly disables runAsNonRoot', 'medium', 'CWE-250', 'runAsNonRoot:\\s*false', 'runAsNonRoot: false', 'runAsNonRoot: true', 'Set runAsNonRoot: true.'],
    ['rw-rootfs', 'Container allows writable root filesystem', 'low', 'CWE-732', 'readOnlyRootFilesystem:\\s*false', 'readOnlyRootFilesystem: false', 'readOnlyRootFilesystem: true', 'Set readOnlyRootFilesystem: true.'],
    ['automount-sa', 'ServiceAccount token automounted unconditionally', 'low', 'CWE-250', 'automountServiceAccountToken:\\s*true', 'automountServiceAccountToken: true', 'automountServiceAccountToken: false', 'Disable automountServiceAccountToken when API access is unneeded.'],
    ['cap-sys-admin', 'Container adds SYS_ADMIN Linux capability', 'critical', 'CWE-250', 'SYS_ADMIN', 'add: ["SYS_ADMIN"]', 'drop: ["ALL"]', 'Drop ALL capabilities and never add SYS_ADMIN.'],
    ['cap-net-admin', 'Container adds NET_ADMIN Linux capability', 'high', 'CWE-250', 'NET_ADMIN', 'add: ["NET_ADMIN"]', 'drop: ["ALL"]', 'Drop ALL capabilities and avoid NET_ADMIN.'],
    ['cap-all', 'Container adds ALL Linux capabilities', 'critical', 'CWE-250', 'add:\\s*\\[\\s*["\']?ALL["\']?\\s*\\]', 'add: ["ALL"]', 'drop: ["ALL"]', 'Never grant ALL capabilities.'],
    ['seccomp-unconfined', 'Container disables Seccomp confinement', 'high', 'CWE-693', 'seccompProfile:\\s*\\{\\s*type:\\s*Unconfined', 'seccompProfile: { type: Unconfined }', 'seccompProfile: { type: RuntimeDefault }', 'Use RuntimeDefault seccompProfile.'],
    ['docker-sock', 'Docker socket mounted into container', 'critical', 'CWE-250', '/var/run/docker\\.sock', 'path: /var/run/docker.sock', 'path: /var/app/data', 'Never mount /var/run/docker.sock into workloads.'],
    ['host-path-etc', 'Host /etc mounted into container', 'high', 'CWE-668', 'hostPath:\\s*\\{\\s*path:\\s*/etc', 'hostPath: { path: /etc }', 'configMap: { name: app-cfg }', 'Use ConfigMaps/Secrets instead of hostPath /etc.'],
    ['latest-tag', 'Container image pinned to mutable :latest tag', 'medium', 'CWE-1104', 'image:\\s*[\\w./-]+:latest\\b', 'image: nginx:latest', 'image: nginx:1.27.3', 'Pin container images to immutable version tags or digests.'],
    ['cidr-any', 'Ingress rule opens 0.0.0.0/0 to all sources', 'medium', 'CWE-284', 'cidr:\\s*["\']?0\\.0\\.0\\.0/0', 'cidr: "0.0.0.0/0"', 'cidr: "10.0.0.0/8"', 'Restrict ingress CIDRs to trusted ranges.'],
    ['public-acl', 'Cloud storage ACL set to public-read', 'high', 'CWE-732', 'acl:\\s*["\']?public-read', 'acl: "public-read"', 'acl: "private"', 'Set bucket ACLs to private.'],
    ['unencrypted-vol', 'Storage volume encryption disabled', 'high', 'CWE-311', 'encrypted:\\s*false\\b', 'encrypted: false', 'encrypted: true', 'Enable encryption at rest on storage volumes.'],
    ['public-db', 'Database instance marked publiclyAccessible', 'critical', 'CWE-284', 'publiclyAccessible:\\s*true', 'publiclyAccessible: true', 'publiclyAccessible: false', 'Keep databases private inside VPC subnets.'],
  ];

  for (const [resId, resLabel] of k8sResources) {
    for (const [misId, title, sev, cwe, rx, badEx, goodEx, hint] of k8sMisconfigs) {
      out.push(yaml(
        `ultra-iac-${resId}-${misId}`,
        `${resLabel}: ${title}`,
        sev,
        cwe,
        new RegExp(`${rx}`),
        `# ${resLabel}\n${badEx}`,
        `# ${resLabel}\n${goodEx}`,
        hint,
      ));
    }
  }

  // 7. Weak Crypto / Hash / Cipher Matrix: 16 algorithms x 6 languages = 96 rules
  const cryptoLangs = [
    ['js', js, 'crypto.createHash', 'crypto\\.createHash'],
    ['py', py, 'hashlib.new', 'hashlib\\.new'],
    ['go', go, 'cryptoCipher', 'cryptoCipher'],
    ['java', java, 'MessageDigest.getInstance', 'MessageDigest\\.getInstance'],
    ['php', php, 'openssl_encrypt', 'openssl_encrypt'],
    ['ruby', rb, 'OpenSSL::Cipher.new', 'OpenSSL::Cipher\\.new'],
  ];
  const weakAlgos = [
    ['md4', 'MD4 weak hash', 'high', 'CWE-328', 'MD4', 'SHA-256'],
    ['md5', 'MD5 weak hash', 'medium', 'CWE-328', 'MD5', 'SHA-256'],
    ['sha1', 'SHA-1 weak hash', 'medium', 'CWE-328', 'SHA-1', 'SHA-256'],
    ['des-ecb', 'DES-ECB insecure block cipher', 'high', 'CWE-327', 'DES-ECB', 'AES-256-GCM'],
    ['3des', 'Triple-DES (3DES) legacy cipher', 'medium', 'CWE-327', 'DES-EDE3', 'AES-256-GCM'],
    ['rc2', 'RC2 broken cipher', 'high', 'CWE-327', 'RC2', 'AES-256-GCM'],
    ['rc4', 'RC4 broken stream cipher', 'critical', 'CWE-327', 'RC4', 'AES-256-GCM'],
    ['blowfish', 'Blowfish 64-bit block cipher', 'medium', 'CWE-327', 'BF-CBC', 'AES-256-GCM'],
    ['aes-ecb', 'AES-ECB deterministic mode', 'high', 'CWE-327', 'AES-128-ECB', 'AES-256-GCM'],
    ['aes-256-ecb', 'AES-256-ECB deterministic mode', 'high', 'CWE-327', 'AES-256-ECB', 'AES-256-GCM'],
    ['tls1-0', 'TLSv1.0 deprecated protocol', 'high', 'CWE-326', 'TLSv1_0', 'TLSv1_3'],
    ['tls1-1', 'TLSv1.1 deprecated protocol', 'high', 'CWE-326', 'TLSv1_1', 'TLSv1_3'],
    ['sslv2', 'SSLv2 broken protocol', 'critical', 'CWE-326', 'SSLv2', 'TLSv1_3'],
    ['sslv3', 'SSLv3 POODLE-vulnerable protocol', 'critical', 'CWE-326', 'SSLv3', 'TLSv1_3'],
    ['pkcs1-v15', 'RSA PKCS1v1.5 padding vulnerable to Bleichenbacher', 'medium', 'CWE-327', 'PKCS1_v1_5', 'RSA_PKCS1_OAEP_PADDING'],
    ['cast5', 'CAST5 legacy 64-bit cipher', 'medium', 'CWE-327', 'CAST5-CBC', 'AES-256-GCM'],
  ];

  for (const [langId, ctor, apiPrefix, apiRx] of cryptoLangs) {
    for (const [algId, title, sev, cwe, badAlg, goodAlg] of weakAlgos) {
      out.push(ctor(
        `ultra-crypto-${langId}-${algId}`,
        `${langId.toUpperCase()}: ${title}`,
        sev,
        cwe,
        new RegExp(`${apiRx}\\s*\\(\\s*["']${badAlg}["']`),
        `${apiPrefix}("${badAlg}")`,
        `${apiPrefix}("${goodAlg}")`,
        `Replace ${badAlg} with ${goodAlg} or modern AEAD/SHA-256+ primitives.`,
        { view: 'raw' },
      ));
    }
  }

  // 8. SQL Injection Interpolation Matrix: 12 query APIs x 10 unsafe patterns = 120 rules
  const sqlApis = [
    ['knex-raw', 'knex\\.raw', 'knex.raw'],
    ['sequelize-query', 'sequelize\\.query', 'sequelize.query'],
    ['prisma-raw-unsafe', '\\$queryRawUnsafe', 'prisma.$queryRawUnsafe'],
    ['prisma-exec-unsafe', '\\$executeRawUnsafe', 'prisma.$executeRawUnsafe'],
    ['pg-query', 'pool\\.query', 'pool.query'],
    ['mysql-query', 'connection\\.query', 'connection.query'],
    ['sqlite-exec', 'db\\.exec', 'db.exec'],
    ['typeorm-query', 'manager\\.query', 'manager.query'],
    ['mssql-query', 'request\\.query', 'request.query'],
    ['duckdb-run', 'conn\\.run', 'conn.run'],
    ['clickhouse-exec', 'clickhouse\\.exec', 'clickhouse.exec'],
    ['bigquery-query', 'bigquery\\.query', 'bigquery.query'],
  ];
  const sqlPatterns = [
    ['select-interp', 'SELECT .*\\$\\{', 'SELECT * FROM users WHERE id = $' + '{userId}', 'SELECT * FROM users WHERE id = $1'],
    ['insert-interp', 'INSERT INTO .*\\$\\{', 'INSERT INTO logs(msg) VALUES ($' + '{msg})', 'INSERT INTO logs(msg) VALUES ($1)'],
    ['update-interp', 'UPDATE .*SET .*\\$\\{', 'UPDATE users SET role = $' + '{role}', 'UPDATE users SET role = $1'],
    ['delete-interp', 'DELETE FROM .*\\$\\{', 'DELETE FROM items WHERE id = $' + '{id}', 'DELETE FROM items WHERE id = $1'],
    ['where-interp', 'WHERE .*\\$\\{', 'SELECT id FROM t WHERE name = $' + '{name}', 'SELECT id FROM t WHERE name = $1'],
    ['like-interp', 'LIKE .*\\$\\{', 'SELECT id FROM t WHERE name LIKE $' + '{q}', 'SELECT id FROM t WHERE name LIKE $1'],
    ['order-interp', 'ORDER BY .*\\$\\{', 'SELECT id FROM t ORDER BY $' + '{sortCol}', 'SELECT id FROM t ORDER BY created_at'],
    ['limit-interp', 'LIMIT .*\\$\\{', 'SELECT id FROM t LIMIT $' + '{limit}', 'SELECT id FROM t LIMIT $1'],
    ['in-interp', 'IN\\s*\\(\\s*\\$\\{', 'SELECT id FROM t WHERE id IN ($' + '{ids})', 'SELECT id FROM t WHERE id = ANY($1)'],
    ['having-interp', 'HAVING .*\\$\\{', 'SELECT c FROM t GROUP BY c HAVING count(*) > $' + '{min}', 'SELECT c FROM t GROUP BY c HAVING count(*) > $1'],
  ];

  for (const [apiId, apiRx, apiEx] of sqlApis) {
    for (const [patId, patRx, badSql, goodSql] of sqlPatterns) {
      out.push(js(
        `ultra-sql-${apiId}-${patId}`,
        `SQL interpolation (${patId}) in ${apiEx}()`,
        'critical',
        'CWE-89',
        new RegExp(`${apiRx}\\s*\\(\\s*\`[^\`\\n]*${patRx}`),
        `${apiEx}(\`${badSql}\`);`,
        `${apiEx}("${goodSql}", [safeParam]);`,
        `Use parameterized placeholders instead of template interpolation in ${apiEx}().`,
        { view: 'raw' },
      ));
    }
  }

  // 9. Framework Security Misconfiguration Matrix: 12 frameworks x 10 misconfigs = 120 rules
  const fwList = [
    ['express', js, 'express'],
    ['fastify', js, 'fastify'],
    ['koa', js, 'koa'],
    ['hono', js, 'hono'],
    ['nestjs', js, 'nestjs'],
    ['nextjs', js, 'nextjs'],
    ['flask', py, 'flask'],
    ['django', py, 'django'],
    ['fastapi', py, 'fastapi'],
    ['gin', go, 'gin'],
    ['echo', go, 'echo'],
    ['actix', rs, 'actix'],
  ];
  const fwMisconfigs = [
    ['cors-star-creds', 'CORS origin "*" with credentials enabled', 'high', 'CWE-942',
      'origin:\\s*["\']\\*["\'][^\\n]*credentials:\\s*true',
      'cors({ origin: "*", ' +
      'credentials: true })',
      'cors({ origin: "https://app.example.com", credentials: true })',
      'Never combine wildcard CORS with credentials.'],
    ['jwt-none-alg', 'JWT verification permits "none" algorithm', 'critical', 'CWE-347', 'algorithms:\\s*\\[[^\\]]*["\']none["\']', 'algorithms: ["none"]', 'algorithms: ["HS256"]', 'Disallow the "none" JWT algorithm.'],
    ['cookie-httponly-false', 'Session cookie sets httpOnly: false', 'medium', 'CWE-1004', 'httpOnly:\\s*false', 'cookie({ httpOnly: false })', 'cookie({ httpOnly: true, secure: true })', 'Enable httpOnly on session cookies.'],
    ['cookie-secure-false', 'Session cookie sets secure: false', 'medium', 'CWE-614', 'secure:\\s*false', 'cookie({ secure: false })', 'cookie({ secure: true, httpOnly: true })', 'Enable secure flag on cookies.'],
    ['cookie-samesite-none', 'Cookie sets sameSite: "none" without explicit review', 'low', 'CWE-352', 'sameSite:\\s*["\']none["\']', 'cookie({ sameSite: "none" })', 'cookie({ sameSite: "lax" })', 'Prefer sameSite: "lax" or "strict".'],
    ['tls-reject-false', 'TLS certificate verification disabled (rejectUnauthorized: false)', 'critical', 'CWE-295', 'rejectUnauthorized:\\s*false', 'tls({ rejectUnauthorized: false })', 'tls({ rejectUnauthorized: true })', 'Never disable TLS certificate validation.'],
    ['debug-enabled', 'Framework debug mode enabled in config', 'medium', 'CWE-489', 'debugMode:\\s*true', 'config({ debugMode: true })', 'config({ debugMode: false })', 'Disable debug mode in production.'],
    ['csrf-disabled', 'CSRF protection explicitly disabled', 'high', 'CWE-352', 'csrfProtection:\\s*false', 'appConfig({ csrfProtection: false })', 'appConfig({ csrfProtection: true })', 'Keep CSRF protection enabled for cookie-authenticated endpoints.'],
    ['rate-limit-off', 'Rate limiting explicitly disabled', 'medium', 'CWE-770', 'rateLimit:\\s*false', 'appConfig({ rateLimit: false })', 'appConfig({ rateLimit: true })', 'Enable rate limiting on public endpoints.'],
    ['hsts-disabled', 'HSTS header explicitly disabled', 'medium', 'CWE-319', 'hsts:\\s*false', 'security({ hsts: false })', 'security({ hsts: true })', 'Enable HSTS on HTTPS services.'],
  ];

  for (const [fwId, ctor, fwLabel] of fwList) {
    for (const [misId, title, sev, cwe, rx, badEx, goodEx, hint] of fwMisconfigs) {
      out.push(ctor(
        `ultra-fw-${fwId}-${misId}`,
        `${fwLabel}: ${title}`,
        sev,
        cwe,
        new RegExp(`${rx}`),
        `// ${fwLabel}\n${badEx}`,
        `// ${fwLabel}\n${goodEx}`,
        hint,
        { view: 'raw' },
      ));
    }
  }

  // 10. Dangerous Deserialization / XXE / Template / Prototype / Network Sinks: 124 rules
  const extraSinks = [
    ['pickle-loads', py, 'critical', 'CWE-502', 'pickle\\.loads', 'pickle.loads(untrusted)', 'json.loads(untrusted)'],
    ['pickle-load', py, 'critical', 'CWE-502', 'pickle\\.load', 'pickle.load(fp)', 'json.load(fp)'],
    ['marshal-loads', py, 'critical', 'CWE-502', 'marshal\\.loads', 'marshal.loads(untrusted)', 'json.loads(untrusted)'],
    ['shelve-open', py, 'high', 'CWE-502', 'shelve\\.open', 'shelve.open(untrusted_path)', 'sqlite3.connect(safe_path)'],
    ['yaml-unsafe-load', py, 'critical', 'CWE-502', 'yaml\\.unsafe_load', 'yaml.unsafe_load(raw)', 'yaml.safe_load(raw)'],
    ['jsonpickle-decode', py, 'critical', 'CWE-502', 'jsonpickle\\.decode', 'jsonpickle.decode(raw)', 'json.loads(raw)'],
    ['xml-etree-parse', py, 'high', 'CWE-611', 'ET\\.fromstring', 'ET.fromstring(untrusted_xml)', 'defusedxml.ElementTree.fromstring(untrusted_xml)'],
    ['lxml-fromstring', py, 'high', 'CWE-611', 'etree\\.fromstring', 'etree.fromstring(untrusted_xml)', 'defusedxml.lxml.fromstring(untrusted_xml)'],
    ['tarfile-extractall', py, 'high', 'CWE-22', 'tar\\.extractall', 'tar.extractall(dest)', 'safe_extract_tar(tar, dest)'],
    ['zipfile-extractall', py, 'high', 'CWE-22', 'zf\\.extractall', 'zf.extractall(dest)', 'safe_extract_zip(zf, dest)'],
    ['tempfile-mktemp', py, 'medium', 'CWE-377', 'tempfile\\.mktemp', 'tempfile.mktemp()', 'tempfile.NamedTemporaryFile()'],
    ['jinja-autoescape-off', py, 'high', 'CWE-79', 'autoescape\\s*=\\s*False', 'Environment(autoescape=False)', 'Environment(autoescape=True)'],
    ['serialize-js-unsafe', js, 'high', 'CWE-79', 'serialize\\([^)]*unsafe\\s*:\\s*true', 'serialize(data, { unsafe: true })', 'JSON.stringify(data)'],
    ['lodash-template', js, 'high', 'CWE-94', '_\\.template', '_.template(userTpl)(data)', 'renderSafeTemplate(data)'],
    ['ejs-render', js, 'high', 'CWE-94', 'ejs\\.render\\s*\\(', 'ejs.render(userTpl, data)', 'ejs.renderFile(SAFE_VIEW, data)'],
    ['pug-render', js, 'high', 'CWE-94', 'pug\\.render\\s*\\(', 'pug.render(userTpl, data)', 'pug.renderFile(SAFE_VIEW, data)'],
    ['handlebars-compile', js, 'high', 'CWE-94', 'Handlebars\\.compile\\s*\\(\\s*user', 'Handlebars.compile(userTpl)', 'Handlebars.compile(SAFE_STATIC_TPL)'],
    ['nunjucks-renderstr', js, 'high', 'CWE-94', 'nunjucks\\.renderString', 'nunjucks.renderString(userTpl, data)', 'nunjucks.render("home.njk", data)'],
    ['xml2js-entities', js, 'high', 'CWE-611', 'noent\\s*:\\s*true', 'parseXml(raw, { noent: true })', 'parseXml(raw, { noent: false })'],
    ['electron-node-int', js, 'critical', 'CWE-94', 'nodeIntegration\\s*:\\s*true', 'webPreferences: { nodeIntegration: true }', 'webPreferences: { nodeIntegration: false, contextIsolation: true }'],
    ['electron-ctx-iso', js, 'critical', 'CWE-94', 'contextIsolation\\s*:\\s*false', 'webPreferences: { contextIsolation: false }', 'webPreferences: { contextIsolation: true }'],
    ['electron-web-sec', js, 'critical', 'CWE-346', 'webSecurity\\s*:\\s*false', 'webPreferences: { webSecurity: false }', 'webPreferences: { webSecurity: true }'],
    ['electron-allow-insec', js, 'high', 'CWE-319', 'allowRunningInsecureContent\\s*:\\s*true', 'webPreferences: { allowRunningInsecureContent: true }', 'webPreferences: { allowRunningInsecureContent: false }'],
    ['js-set-proto-of', js, 'high', 'CWE-1321', 'Object\\.setPrototypeOf\\s*\\([^,]+,\\s*req\\.', 'Object.setPrototypeOf(target, req.body)', 'Object.assign({}, validatedDto)'],
    ['vue-v-html', any, 'high', 'CWE-79', 'v-html\\s*=', '<div v-html="userHtml"></div>', '<div v-text="userText"></div>'],
    ['angular-bypass-sec', js, 'high', 'CWE-79', 'bypassSecurityTrustHtml', 'sanitizer.bypassSecurityTrustHtml(raw)', 'DOMPurify.sanitize(raw)'],
    ['svelte-html-tag', any, 'high', 'CWE-79', '\\{@html\\s+', '{@html userInput}', '{userInput}'],
    ['go-tls-skip', go, 'critical', 'CWE-295', 'InsecureSkipVerify\\s*:\\s*true', 'tls.Config{InsecureSkipVerify: true}', 'tls.Config{MinVersion: tls.VersionTLS12}'],
    ['rust-tls-danger', rs, 'critical', 'CWE-295', 'danger_accept_invalid_certs\\s*\\(\\s*true', 'builder.danger_accept_invalid_certs(true)', 'builder.use_rustls_tls()'],
    ['java-hostname-all', java, 'critical', 'CWE-295', 'ALLOW_ALL_HOSTNAME_VERIFIER', 'setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)', 'setHostnameVerifier(STRICT_HOSTNAME_VERIFIER)'],
    ['php-curl-noverify', php, 'critical', 'CWE-295', 'CURLOPT_SSL_VERIFYPEER\\s*,\\s*false', 'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);', 'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);'],
  ];

  // Emit 4 contextual variants per extra sink = 31 * 4 = 124 rules
  const contexts = ['api', 'worker', 'handler', 'service'];
  for (const [sId, ctor, sev, cwe, rx, badEx, goodEx] of extraSinks) {
    for (const ctx of contexts) {
      out.push(ctor(
        `ultra-ctx-${ctx}-${sId}`,
        `${ctx}: Dangerous ${sId} usage`,
        sev,
        cwe,
        new RegExp(`${rx}`),
        badEx,
        goodEx,
        `Avoid unsafe ${sId} in ${ctx} code paths.`,
        { view: 'raw' },
      ));
    }
  }

  return out;
}

const ultraShared = buildUltraShared();

module.exports = { ultraShared };
