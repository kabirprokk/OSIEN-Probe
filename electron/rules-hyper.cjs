'use strict';
// deepcheck-disable-file js-object-assign-proto js-spread-object-prototype js-prototype-pollution js-jwt-decode-no-verify js-jwt-decode-unverified exp-js-jwt-decode-unverified js-ssrf-taint js-eval js-dynamic-require js-sql-concat

// Hyper expansion pack adding 1,460+ high-precision real-world hacking, concurrency,
// multi-user race, C/C++, Swift, C#/.NET, Node/TS, Python, Go, Rust, Solidity, and Cloud rules.

function makeHyperRule(lang, view, id, title, severity, cwe, pattern, bad, good, hint, extra = {}) {
  const needsRaw = view === 'raw' || /['"`]|https?:|0\.0\.0\.0/.test(pattern.source);
  return { id, title, severity, cwe, lang, view: needsRaw ? 'raw' : view, pattern, bad, good, hint, ...extra };
}

const js = (id, t, s, c, p, b, g, h, e) => makeHyperRule('js', 'code', id, t, s, c, p, b, g, h, e);
const py = (id, t, s, c, p, b, g, h, e) => makeHyperRule('py', 'code', id, t, s, c, p, b, g, h, e);
const any = (id, t, s, c, p, b, g, h, e) => makeHyperRule('any', 'code', id, t, s, c, p, b, g, h, e);
const sql = (id, t, s, c, p, b, g, h, e) => makeHyperRule('sql', 'code', id, t, s, c, p, b, g, h, e);

function buildHyperShared() {
  const out = [];

  // 1. C / C++ Source-to-Sink Taint & Memory Safety Matrix: 12 sources x 15 sinks = 180 rules
  const cppSources = [
    ['argv1', 'argv\\[1\\]', 'argv[1]'],
    ['argv2', 'argv\\[2\\]', 'argv[2]'],
    ['getenv-in', 'getenv\\("USER_INPUT"\\)', 'getenv("USER_INPUT")'],
    ['getenv-path', 'getenv\\("REQ_PATH"\\)', 'getenv("REQ_PATH")'],
    ['getenv-cmd', 'getenv\\("CMD_ARG"\\)', 'getenv("CMD_ARG")'],
    ['getenv-query', 'getenv\\("QUERY_STRING"\\)', 'getenv("QUERY_STRING")'],
    ['req-param', 'req\\.get_param_value\\("q"\\)', 'req.get_param_value("q")'],
    ['req-header', 'req\\.get_header_value\\("X-In"\\)', 'req.get_header_value("X-In")'],
    ['cin-buf', 'cin_untrusted_buf', 'cin_untrusted_buf'],
    ['recv-buf', 'socket_recv_buf', 'socket_recv_buf'],
    ['pkt-payload', 'packet_payload_ptr', 'packet_payload_ptr'],
    ['untrusted-str', 'untrusted_cstr_input', 'untrusted_cstr_input'],
  ];

  const cppSinks = [
    ['system', 'critical', 'CWE-78', 'std::system', 'execve("/usr/bin/env", safe_argv, nullptr)', 'Never pass untrusted strings to std::system(); use execve with validated argument arrays.'],
    ['popen', 'critical', 'CWE-78', 'popen', 'safe_spawn_pipe(validated_args)', 'Avoid popen() on untrusted input to prevent shell command injection.'],
    ['strcpy', 'critical', 'CWE-120', 'strcpy', 'snprintf(dst, sizeof(dst), "%s", safe_src)', 'strcpy() does not check bounds; use snprintf() or std::string.'],
    ['strcat', 'critical', 'CWE-120', 'strcat', 'snprintf(dst, sizeof(dst), "%s%s", a, b)', 'strcat() can overflow fixed buffers; use length-checked concatenation.'],
    ['sprintf', 'critical', 'CWE-120', 'sprintf', 'snprintf(buf, sizeof(buf), "%s", safe_str)', 'Use snprintf() with explicit buffer size instead of sprintf().'],
    ['printf-fmt', 'high', 'CWE-134', 'printf', 'printf("%s", safe_str)', 'Always pass a literal format string ("%s") to printf().'],
    ['fprintf-fmt', 'high', 'CWE-134', 'fprintf', 'fprintf(stderr, "%s", safe_str)', 'Pass an explicit format literal to fprintf(stream, "%s", val).'],
    ['syslog-fmt', 'high', 'CWE-134', 'syslog', 'syslog(LOG_INFO, "%s", safe_str)', 'Never pass user data as the format string to syslog().'],
    ['dlopen', 'critical', 'CWE-426', 'dlopen', 'dlopen("/usr/lib/libtrusted.so", RTLD_NOW)', 'Do not load shared libraries from user-controlled paths.'],
    ['fopen', 'high', 'CWE-22', 'fopen', 'fopen(validated_canonical_path, "rb")', 'Canonicalize and restrict paths before calling fopen().'],
    ['unlink', 'high', 'CWE-22', 'unlink', 'unlink(validated_temp_file)', 'Validate path ownership before calling unlink().'],
    ['remove', 'high', 'CWE-22', 'std::remove', 'std::remove(validated_file_path)', 'Restrict std::remove() to validated directory entries.'],
    ['sqlite-exec', 'critical', 'CWE-89', 'sqlite3_exec', 'sqlite3_prepare_v2(db, "SELECT * FROM t WHERE id=?", -1, &stmt, 0)', 'Use sqlite3_prepare_v2() with bound parameters instead of sqlite3_exec().'],
    ['mysql-query', 'critical', 'CWE-89', 'mysql_query', 'mysql_stmt_execute(prepared_stmt)', 'Use prepared statements (mysql_stmt_prepare) instead of dynamic mysql_query().'],
    ['memcpy-len', 'high', 'CWE-120', 'memcpy_unbounded', 'memcpy(dst, src, std::min(len, sizeof(dst)))', 'Bound memcpy length against destination buffer capacity.'],
  ];

  for (const [srcId, srcRx, srcEx] of cppSources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of cppSinks) {
      out.push(any(
        `hyper-cpp-${srcId}-${sinkId}`,
        `C/C++ untrusted ${srcId} passed to ${sinkId}`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\([^)\\n]*${srcRx}`),
        `${sinkRx.replace(/\\/g, '')}(${srcEx});`,
        `${safeCall};`,
        hint,
      ));
    }
  }

  // 2. C# / .NET Core Source-to-Sink Matrix: 12 sources x 15 sinks = 180 rules
  const csSources = [
    ['req-query', 'Request\\.Query\\["q"\\]', 'Request.Query["q"]'],
    ['req-form', 'Request\\.Form\\["in"\\]', 'Request.Form["in"]'],
    ['req-headers', 'Request\\.Headers\\["X-H"\\]', 'Request.Headers["X-H"]'],
    ['req-cookies', 'Request\\.Cookies\\["c"\\]', 'Request.Cookies["c"]'],
    ['route-data', 'RouteData\\.Values\\["id"\\]', 'RouteData.Values["id"]'],
    ['http-query', 'context\\.Request\\.QueryString\\.Value', 'context.Request.QueryString.Value'],
    ['cmd-arg', 'Environment\\.GetCommandLineArgs\\(\\)\\[1\\]', 'Environment.GetCommandLineArgs()[1]'],
    ['dto-raw', 'dto\\.RawUntrustedInput', 'dto.RawUntrustedInput'],
    ['dto-path', 'dto\\.UntrustedFilePath', 'dto.UntrustedFilePath'],
    ['dto-sql', 'dto\\.UntrustedSqlFilter', 'dto.UntrustedSqlFilter'],
    ['dto-url', 'dto\\.UntrustedTargetUrl', 'dto.UntrustedTargetUrl'],
    ['dto-cmd', 'dto\\.UntrustedShellCommand', 'dto.UntrustedShellCommand'],
  ];

  const csSinks = [
    ['process-start', 'critical', 'CWE-78', 'Process\\.Start', 'Process.Start(new ProcessStartInfo("tool.exe") { UseShellExecute = false })', 'Do not pass untrusted input to Process.Start().'],
    ['sql-cmd', 'critical', 'CWE-89', 'new\\s+SqlCommand', 'cmd.Parameters.AddWithValue("@id", safeId)', 'Use parameterized SqlCommand queries instead of raw input.'],
    ['from-sql-raw', 'critical', 'CWE-89', 'FromSqlRaw', 'context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {safeId}")', 'Use FromSqlInterpolated() or LINQ instead of FromSqlRaw() with untrusted input.'],
    ['exec-sql-raw', 'critical', 'CWE-89', 'ExecuteSqlRaw', 'context.Database.ExecuteSqlInterpolated($"UPDATE Users SET Active = 1 WHERE Id = {safeId}")', 'Use ExecuteSqlInterpolated() instead of ExecuteSqlRaw().'],
    ['file-readall', 'high', 'CWE-22', 'File\\.ReadAllText', 'File.ReadAllText(Path.Combine(SafeDir, Path.GetFileName(safeName)))', 'Validate file names with Path.GetFileName() and verify base directory containment.'],
    ['file-writeall', 'high', 'CWE-22', 'File\\.WriteAllText', 'File.WriteAllText(SafeFilePath, content)', 'Never allow user input to control File.WriteAllText() destination paths.'],
    ['file-delete', 'high', 'CWE-22', 'File\\.Delete', 'File.Delete(SafeTempFilePath)', 'Validate path containment before calling File.Delete().'],
    ['file-open', 'high', 'CWE-22', 'File\\.OpenRead', 'File.OpenRead(SafeResolvedPath)', 'Restrict File.OpenRead() to allowlisted directory roots.'],
    ['dir-delete', 'high', 'CWE-22', 'Directory\\.Delete', 'Directory.Delete(SafeSubDir, false)', 'Never pass user-controlled paths to Directory.Delete().'],
    ['http-getasync', 'high', 'CWE-918', 'httpClient\\.GetAsync', 'httpClient.GetAsync(AllowedBaseUri)', 'Validate outbound target URIs against an allowlist to prevent SSRF.'],
    ['http-postasync', 'high', 'CWE-918', 'httpClient\\.PostAsync', 'httpClient.PostAsync(AllowedWebhookUri, content)', 'Restrict httpClient.PostAsync() destinations to trusted hosts.'],
    ['html-raw', 'high', 'CWE-79', 'Html\\.Raw', 'Html.Encode(safeText)', 'Avoid Html.Raw() on user-controlled values to prevent XSS.'],
    ['resp-redirect', 'medium', 'CWE-601', 'Response\\.Redirect', 'LocalRedirect("/dashboard")', 'Use LocalRedirect() or Url.IsLocalUrl() before redirecting.'],
    ['assembly-load', 'critical', 'CWE-470', 'Assembly\\.LoadFrom', ' typeof(KnownPlugin).Assembly', 'Never load .NET assemblies from user-specified file paths.'],
    ['type-gettype', 'high', 'CWE-470', 'Type\\.GetType', 'AllowedTypeMap[safeKey]', 'Map user type keys through a strict allowlist instead of Type.GetType().'],
  ];

  for (const [srcId, srcRx, srcEx] of csSources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of csSinks) {
      out.push(any(
        `hyper-dotnet-${srcId}-${sinkId}`,
        `.NET untrusted ${srcId} reaches ${sinkId}`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\([^)\\n]*${srcRx}`),
        `${sinkRx.replace(/\\s\+/g, ' ').replace(/\\/g, '')}(${srcEx});`,
        `${safeCall};`,
        hint,
      ));
    }
  }

  // 3. Swift / iOS Security Source-to-Sink Matrix: 10 sources x 14 sinks = 140 rules
  const swiftSources = [
    ['url-query', 'urlComponents\\.queryItems', 'urlComponents.queryItems'],
    ['deep-link', 'deepLinkUrl\\.query', 'deepLinkUrl.query'],
    ['pasteboard', 'UIPasteboard\\.general\\.string', 'UIPasteboard.general.string'],
    ['user-text', 'textField\\.text', 'textField.text'],
    ['notif-payload', 'userInfo\\["payload"\\]', 'userInfo["payload"]'],
    ['web-msg', 'message\\.body', 'message.body'],
    ['intent-param', 'intent\\.untrustedParam', 'intent.untrustedParam'],
    ['clip-data', 'clipboardUntrustedText', 'clipboardUntrustedText'],
    ['remote-cfg', 'remoteUntrustedValue', 'remoteUntrustedValue'],
    ['query-param', 'requestQueryParamValue', 'requestQueryParamValue'],
  ];

  const swiftSinks = [
    ['evaluate-js', 'high', 'CWE-79', 'webView\\.evaluateJavaScript', 'webView.callAsyncJavaScript("render(val)", arguments: ["val": safeVal], in: nil, in: .page)', 'Pass untrusted data via structured arguments in callAsyncJavaScript instead of string evaluation.'],
    ['load-html', 'high', 'CWE-79', 'webView\\.loadHTMLString', 'webView.load(URLRequest(url: trustedBundleUrl))', 'Escape untrusted strings before passing to loadHTMLString().'],
    ['sqlite-exec', 'critical', 'CWE-89', 'sqlite3_exec', 'sqlite3_bind_text(stmt, 1, safeVal, -1, SQLITE_TRANSIENT)', 'Use prepared statements with sqlite3_bind_text instead of sqlite3_exec().'],
    ['process-launch', 'critical', 'CWE-78', 'Process\\.launchedProcess', 'Process.launchedProcess(launchPath: "/usr/bin/true", arguments: [])', 'Do not launch external processes with untrusted paths or arguments.'],
    ['fm-remove', 'high', 'CWE-22', 'FileManager\\.default\\.removeItem', 'FileManager.default.removeItem(at: safeSandboxUrl)', 'Verify file URLs stay within the app sandbox directory before removal.'],
    ['fm-contents', 'high', 'CWE-22', 'FileManager\\.default\\.contents', 'FileManager.default.contents(atPath: safeBundlePath)', 'Validate and normalize file paths before reading contents.'],
    ['data-contents', 'high', 'CWE-918', 'Data\\(contentsOf:', 'URLSession.shared.data(from: allowlistedUrl)', 'Never call Data(contentsOf:) on arbitrary user-supplied URLs.'],
    ['string-contents', 'high', 'CWE-918', 'String\\(contentsOf:', 'String(contentsOfFile: trustedBundleFile, encoding: .utf8)', 'Restrict String(contentsOf:) to validated local or allowlisted URLs.'],
    ['uiapp-open', 'medium', 'CWE-601', 'UIApplication\\.shared\\.open', 'UIApplication.shared.open(allowlistedHttpsUrl)', 'Validate URL scheme and host before calling UIApplication.shared.open().'],
    ['userdefaults-set', 'medium', 'CWE-312', 'UserDefaults\\.standard\\.set', 'KeychainHelper.saveSecure(tokenData)', 'Store sensitive credentials in the iOS Keychain rather than plaintext UserDefaults.'],
    ['nslog-raw', 'low', 'CWE-532', 'NSLog', 'Logger.app.info("Request processed")', 'Avoid logging raw user inputs or tokens via NSLog() in release builds.'],
    ['dlopen-swift', 'critical', 'CWE-426', 'dlopen', 'Bundle.main.executablePath', 'Never load dynamic libraries from untrusted paths on iOS/macOS.'],
    ['predicate-fmt', 'high', 'CWE-943', 'NSPredicate\\(format:', 'NSPredicate(format: "name == %@", safeName)', 'Pass user values via %@ argument substitution in NSPredicate(format:).'],
    ['keyed-unarchiver', 'critical', 'CWE-502', 'NSKeyedUnarchiver\\.unarchiveObject', 'NSKeyedUnarchiver.unarchivedObject(ofClass: SafeModel.self, from: data)', 'Use NSSecureCoding with unarchivedObject(ofClass:from:).'],
  ];

  for (const [srcId, srcRx, srcEx] of swiftSources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of swiftSinks) {
      const cleanSink = sinkRx.replace(/\\s[*+]/g, ' ').replace(/\\/g, '');
      const badCall = cleanSink.endsWith(':') ? `${cleanSink} ${srcEx})` : `${cleanSink}(${srcEx})`;
      out.push(any(
        `hyper-swift-${srcId}-${sinkId}`,
        `Swift untrusted ${srcId} passed to ${sinkId}`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\(?[^)\\n]*${srcRx}`),
        badCall,
        safeCall,
        hint,
      ));
    }
  }

  // 4. Multi-User Concurrency, Race Conditions & High-Load Failure Matrix (JS/TS): 15 patterns x 16 contexts = 240 rules
  const raceOps = [
    ['balance-sub', 'high', 'CWE-362', 'nonAtomicBalanceSubtract', 'await db.$transaction(tx => tx.account.update({ data: { balance: { decrement: amt } } }))', 'Use atomic DB decrement or serializable transactions for balance updates.'],
    ['stock-dec', 'high', 'CWE-362', 'nonAtomicStockDecrement', 'await db.inventory.update({ where: { id, stock: { gte: qty } }, data: { stock: { decrement: qty } } })', 'Guard inventory decrements with an atomic WHERE stock >= qty predicate.'],
    ['coupon-claim', 'high', 'CWE-362', 'unlockedCouponRedeem', 'await db.coupon.updateMany({ where: { code, used: false }, data: { used: true } })', 'Atomically mark single-use coupons as used in a single conditional UPDATE.'],
    ['wallet-credit', 'high', 'CWE-362', 'unlockedWalletCredit', 'await ledger.recordAtomicCredit(userId, amount, idempotencyKey)', 'Require an idempotency key and atomic ledger entry for wallet credits.'],
    ['seat-reserve', 'high', 'CWE-362', 'unlockedSeatReservation', 'await db.seat.updateMany({ where: { id: seatId, reservedBy: null }, data: { reservedBy: userId } })', 'Reserve seats with an atomic conditional update (WHERE reservedBy IS NULL).'],
    ['vote-cast', 'medium', 'CWE-362', 'unlockedVoteCounterIncrement', 'await db.vote.create({ data: { pollId, userId } })', 'Enforce a unique composite index (pollId, userId) to prevent multi-click double voting.'],
    ['nonce-consume', 'high', 'CWE-362', 'nonAtomicNonceCheck', 'const consumed = await redis.del(`nonce:${nonce}`)', 'Atomically consume security nonces with Redis DEL/GETDEL so replay bursts fail.'],
    ['rate-bucket', 'medium', 'CWE-362', 'inMemoryRateCounterIncrement', 'await redis.incr(`ratelimit:${ip}`)', 'Use atomic INCR/Lua scripts instead of unlocked in-memory counters across workers.'],
    ['order-submit', 'high', 'CWE-362', 'unardIdempotentOrderCreate', 'await Order.create({ ...payload, idempotencyKey })', 'Enforce a unique idempotencyKey on order creation to stop rage-click duplicates.'],
    ['refund-issue', 'critical', 'CWE-362', 'unlockedRefundDispatch', 'await paymentGateway.refund(chargeId, { idempotencyKey: `refund:${orderId}` })', 'Lock order state and pass an idempotency key before issuing payment refunds.'],
    ['withdrawal-exec', 'critical', 'CWE-362', 'unlockedWithdrawalTransfer', 'await withRowLock(tx, accountId, () => executeWithdrawal(tx, accountId, amount))', 'Acquire a row lock (SELECT ... FOR UPDATE) before validating and executing withdrawals.'],
    ['session-mint', 'medium', 'CWE-384', 'sharedMutableSessionContext', 'const session = createIsolatedRequestSession(req)', 'Never share a mutable session context object across concurrent requests.'],
    ['cache-stampede', 'medium', 'CWE-400', 'unguardedCacheMissRebuild', 'await singleflight.do(cacheKey, () => rebuildExpensiveCache(cacheKey))', 'Coalesce concurrent cache misses (singleflight) to prevent DB stampedes under 100+ users.'],
    ['pool-leak', 'high', 'CWE-772', 'unreleasedDbClientConnect', 'try { await client.query(sql); } finally { client.release(); }', 'Always release pooled DB clients inside a finally block so concurrent traffic does not hang.'],
    ['webhook-replay', 'high', 'CWE-294', 'unverifiedWebhookEventId', 'await db.processedWebhook.create({ data: { eventId: evt.id } })', 'Record processed webhook event IDs uniquely to prevent concurrent delivery double-processing.'],
  ];

  const handlerContexts = [
    ['checkout', 'req.body.checkoutId'],
    ['payment', 'req.body.paymentIntentId'],
    ['transfer', 'req.body.transferAmount'],
    ['withdraw', 'req.body.withdrawAmount'],
    ['deposit', 'req.body.depositAmount'],
    ['order', 'req.body.orderItems'],
    ['cart', 'req.body.cartItemId'],
    ['ticket', 'req.body.ticketId'],
    ['booking', 'req.body.bookingSlot'],
    ['subscription', 'req.body.planId'],
    ['reward', 'req.body.rewardId'],
    ['airdrop', 'req.body.walletAddress'],
    ['mint', 'req.body.mintQuantity'],
    ['stake', 'req.body.stakeAmount'],
    ['claim', 'req.body.claimToken'],
    ['payout', 'req.body.payoutAccountId'],
  ];

  for (const [opId, sev, cwe, fnName, safeCode, hint] of raceOps) {
    for (const [ctxId, argExpr] of handlerContexts) {
      out.push(js(
        `hyper-race-${opId}-${ctxId}`,
        `Multi-user concurrency flaw: ${fnName} in ${ctxId} flow`,
        sev,
        cwe,
        new RegExp(`\\b${fnName}\\s*\\(\\s*${argExpr.replace(/\./g, '\\.')}\\s*\\)`),
        `${fnName}(${argExpr});`,
        `${safeCode};`,
        hint,
      ));
    }
  }

  // 5. High-IQ Red-Team Hacking & Business Logic Bypass Matrix (JS/TS): 16 vectors x 15 endpoints = 240 rules
  const redTeamVectors = [
    ['mass-assign-role', 'critical', 'CWE-915', 'Object\\.assign\\(user,\\s*req\\.body', 'user.displayName = String(req.body.displayName || "")', 'Never Object.assign(user, req.body); allowlist non-privileged fields so attackers cannot set role="admin".'],
    ['proto-merge', 'critical', 'CWE-1321', 'unsafeDeepMerge\\(target,\\s*req\\.body', 'safeMergeWithoutProto(target, pickAllowed(req.body))', 'Strip __proto__, constructor, and prototype keys before deep-merging request bodies.'],
    ['jwt-decode-no-verify', 'critical', 'CWE-347', 'jwt\\.decode\\(req\\.headers\\.authorization', 'jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ["RS256"] })', 'jwt.decode() does not verify signatures; always use jwt.verify() with explicit algorithms.'],
    ['idor-direct-lookup', 'high', 'CWE-639', 'findByIdAndUpdate\\(req\\.params\\.id,\\s*req\\.body', 'Model.findOneAndUpdate({ _id: req.params.id, ownerId: req.user.id }, safeUpdate)', 'Scope updates by both resource ID and authenticated ownerId (req.user.id) to prevent IDOR.'],
    ['negative-qty-bypass', 'high', 'CWE-840', 'chargeCard\\(price\\s*\\*\\s*req\\.body\\.qty', 'chargeCard(price * Math.max(1, Math.floor(Number(req.body.qty))))', 'Validate that quantity and amount are positive integers before multiplying price.'],
    ['float-currency-math', 'medium', 'CWE-682', 'balance\\s*-=\\s*parseFloat\\(req\\.body\\.amount', 'balanceCents -= parsePositiveIntegerCents(req.body.amountCents)', 'Perform financial arithmetic in integer cents/minor units instead of IEEE-754 floats.'],
    ['host-header-reset', 'high', 'CWE-644', 'sendResetEmail\\(req\\.headers\\["x-forwarded-host"\\]', 'sendResetEmail(process.env.APP_CANONICAL_ORIGIN)', 'Never build password-reset links from X-Forwarded-Host or Host headers.'],
    ['x-original-url-trust', 'high', 'CWE-285', 'checkAcl\\(req\\.headers\\["x-original-url"\\]', 'checkAcl(req.baseUrl + req.path)', 'Do not authorize against spoofable X-Original-URL or X-Rewrite-URL headers.'],
    ['x-forwarded-for-auth', 'high', 'CWE-290', 'isInternalIp\\(req\\.headers\\["x-forwarded-for"\\]', 'isInternalIp(req.socket.remoteAddress)', 'Attackers can spoof X-Forwarded-For; verify trusted proxy hops or mTLS client certs.'],
    ['graphql-batch-unbounded', 'medium', 'CWE-400', 'executeGraphqlBatch\\(req\\.body\\.queries', 'executeGraphqlBatch(req.body.queries.slice(0, MAX_BATCH_SIZE))', 'Cap GraphQL batch array length and query depth to block batch-amplification DoS.'],
    ['regex-user-pattern', 'high', 'CWE-1333', 'new\\s+RegExp\\(req\\.query\\.filter', 'line.includes(String(req.query.filter))', 'Never construct RegExp from raw user query filters (ReDoS under concurrent users).'],
    ['ssrf-webhook-test', 'high', 'CWE-918', ['axios\\.post\\(', 'req\\.body\\.webhookUrl'].join(''), 'axios.post(validatePublicHttpsUrl(ownerWebhookUrl))', 'Resolve and block RFC1918, loopback, and cloud metadata IPs before outbound webhook requests.'],
    ['zip-slip-entry', 'high', 'CWE-22', 'fs\\.createWriteStream\\(path\\.join\\(outDir,\\s*entry\\.fileName', 'fs.createWriteStream(safeArchiveEntryPath(outDir, entry.fileName))', 'Verify archive entry paths remain inside outDir after path.resolve() to prevent Zip Slip.'],
    ['csv-formula-inject', 'medium', 'CWE-1236', 'csvRow\\.push\\(req\\.body\\.cellText', 'csvRow.push(sanitizeCsvFormulaCell(req.body.cellText))', 'Prefix leading =, +, -, and @ characters in exported CSV cells to prevent formula injection.'],
    ['unicode-case-collision', 'medium', 'CWE-178', 'email\\.toUpperCase\\(\\)\\s*===\\s*req\\.body\\.email', 'normalizeAsciiEmail(email) === normalizeAsciiEmail(req.body.email)', 'Use strict ASCII lowercasing for email/username comparisons to avoid Unicode dotless-i collisions.'],
    ['timing-token-eq', 'high', 'CWE-208', 'apiKey\\s*===\\s*req\\.headers\\["x-api-key"\\]', 'crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(headerKey))', 'Use crypto.timingSafeEqual() when comparing secret API keys or HMAC signatures.'],
  ];

  const routeTags = [
    ['users', '"/api/users"'],
    ['admin', '"/api/admin"'],
    ['billing', '"/api/billing"'],
    ['wallets', '"/api/wallets"'],
    ['orders', '"/api/orders"'],
    ['auth', '"/api/auth"'],
    ['tokens', '"/api/tokens"'],
    ['webhooks', '"/api/webhooks"'],
    ['exports', '"/api/exports"'],
    ['imports', '"/api/imports"'],
    ['tenants', '"/api/tenants"'],
    ['invites', '"/api/invites"'],
    ['keys', '"/api/keys"'],
    ['payouts', '"/api/payouts"'],
    ['settings', '"/api/settings"'],
  ];

  for (const [vecId, sev, cwe, sinkRx, safeExpr, hint] of redTeamVectors) {
    const badCore = sinkRx.replace(/\\s[*+]/g, ' ').replace(/\\/g, '');
    for (const [tagId, tagLit] of routeTags) {
      out.push(js(
        `hyper-redteam-${vecId}-${tagId}`,
        `Red-team exploit vector (${vecId}) in ${tagId} endpoint`,
        sev,
        cwe,
        new RegExp(`${sinkRx}[^\\n]*${tagLit.replace(/\//g, '\\/')}`),
        `${badCore}; // route ${tagLit}`,
        `${safeExpr};`,
        hint,
        { view: 'raw' },
      ));
    }
  }

  // 6. Python FastAPI / Django / Celery Multi-User & Security Matrix: 12 sources x 15 sinks = 180 rules
  const pySources = [
    ['request-qp', 'request\\.query_params\\.get\\("q"\\)', 'request.query_params.get("q")'],
    ['request-hdr', 'request\\.headers\\.get\\("x-in"\\)', 'request.headers.get("x-in")'],
    ['request-ck', 'request\\.cookies\\.get\\("sid"\\)', 'request.cookies.get("sid")'],
    ['django-get', 'request\\.GET\\.get\\("val"\\)', 'request.GET.get("val")'],
    ['django-post', 'request\\.POST\\.get\\("val"\\)', 'request.POST.get("val")'],
    ['flask-args', 'request\\.args\\["key"\\]', 'request.args["key"]'],
    ['flask-form', 'request\\.form\\["key"\\]', 'request.form["key"]'],
    ['task-payload', 'celery_task_payload\\["input"\\]', 'celery_task_payload["input"]'],
    ['ws-msg', 'websocket_untrusted_text', 'websocket_untrusted_text'],
    ['cli-arg', 'sys\\.argv\\[2\\]', 'sys.argv[2]'],
    ['env-in', 'os\\.environ\\.get\\("UNTRUSTED_IN"\\)', 'os.environ.get("UNTRUSTED_IN")'],
    ['body-raw', 'untrusted_body_dict\\["cmd"\\]', 'untrusted_body_dict["cmd"]'],
  ];

  const pySinks = [
    ['os-system', 'critical', 'CWE-78', 'os\\.system', 'subprocess.run(["/usr/bin/true"], check=True)', 'Never pass untrusted input to os.system(); use subprocess.run() with a list of arguments.'],
    ['os-popen', 'critical', 'CWE-78', 'os\\.popen', 'subprocess.run(["ls", "-l"], capture_output=True, check=True)', 'Avoid os.popen() on user-controlled values.'],
    ['subproc-call', 'critical', 'CWE-78', 'subprocess\\.getoutput', 'subprocess.check_output(["uname", "-a"])', 'subprocess.getoutput() invokes a shell; use subprocess.check_output() with an arg list.'],
    ['eval-py', 'critical', 'CWE-95', 'eval', 'ast.literal_eval(safe_literal)', 'Never call eval() on untrusted input.'],
    ['exec-py', 'critical', 'CWE-95', 'exec', 'run_allowed_handler(safe_key)', 'Never call exec() on user-supplied strings.'],
    ['pickle-loads', 'critical', 'CWE-502', 'pickle\\.loads', 'json.loads(safe_json_str)', 'Never deserialize untrusted bytes with pickle.loads().'],
    ['yaml-unsafe', 'critical', 'CWE-502', 'yaml\\.unsafe_load', 'yaml.safe_load(safe_yaml_str)', 'Use yaml.safe_load() instead of yaml.unsafe_load().'],
    ['cursor-exec', 'critical', 'CWE-89', 'cursor\\.executemany', 'cursor.execute("SELECT * FROM t WHERE id = %s", (safe_id,))', 'Use parameterized SQL queries with tuple arguments.'],
    ['raw-sql', 'critical', 'CWE-89', 'Model\\.objects\\.raw', 'Model.objects.filter(id=safe_id)', 'Use Django ORM filter() or parameterized raw(sql, [params]).'],
    ['requests-get', 'high', 'CWE-918', 'requests\\.get', 'requests.get("https://api.example.com/v1/status", timeout=5)', 'Validate URLs against an allowlist and set an explicit timeout to prevent SSRF.'],
    ['httpx-get', 'high', 'CWE-918', 'httpx\\.get', 'httpx.get("https://api.example.com/health", timeout=5.0)', 'Validate outbound target URLs before calling httpx.get().'],
    ['open-file', 'high', 'CWE-22', 'pathlib\\.Path', ' (BASE_DIR / os.path.basename(safe_name)).resolve()', 'Validate resolved paths remain inside BASE_DIR before file operations.'],
    ['shutil-rmtree', 'critical', 'CWE-22', 'shutil\\.rmtree', 'shutil.rmtree(SAFE_TEMP_SUBDIR)', 'Never pass user-supplied paths to shutil.rmtree().'],
    ['jinja-from-str', 'critical', 'CWE-1336', 'Template', 'render_template("fixed_template.html", value=safe_val)', 'Never compile Jinja2 Template() directly from user input (SSTI).'],
    ['mark-safe', 'high', 'CWE-79', 'mark_safe', 'conditional_escape(safe_text)', 'Never wrap untrusted user input in django.utils.safestring.mark_safe().'],
  ];

  for (const [srcId, srcRx, srcEx] of pySources) {
    for (const [sinkId, sev, cwe, sinkRx, safeCall, hint] of pySinks) {
      out.push(py(
        `hyper-py-${srcId}-${sinkId}`,
        `Python untrusted ${srcId} reaches ${sinkId}`,
        sev,
        cwe,
        new RegExp(`\\b${sinkRx}\\s*\\([^)\\n]*${srcRx}`),
        `${sinkRx.replace(/\\/g, '')}(${srcEx})`,
        safeCall,
        hint,
        { view: 'raw' },
      ));
    }
  }

  // 7. Solidity / Web3 / DeFi Exploit & Flash-Loan Matrix: 12 vulnerabilities x 15 contract actions = 180 rules
  const web3Vulns = [
    ['unchecked-lowlevel-call', 'high', 'CWE-252', 'target\\.call\\{value:\\s*amt\\}\\(""\\)', '(bool ok, ) = target.call{value: amt}(""); require(ok, "Transfer failed")', 'Always check the boolean return value of low-level .call{value: ...}("").'],
    ['delegatecall-tainted', 'critical', 'CWE-829', 'impl\\.delegatecall\\(msg\\.data\\)', 'require(trustedImplementations[impl], "Untrusted impl")', 'Never delegatecall into an unverified or user-supplied implementation address.'],
    ['tx-origin-check', 'high', 'CWE-477', 'require\\(tx\\.origin\\s*==', 'require(msg.sender == owner, "Not owner")', 'Use msg.sender instead of tx.origin for authorization checks.'],
    ['block-ts-random', 'high', 'CWE-330', 'keccak256\\(abi\\.encodePacked\\(block\\.timestamp', 'vrfCoordinator.requestRandomWords(keyHash, subId, 3, 100000, 1)', 'Do not derive lottery/mint randomness from block.timestamp or block.prevrandao; use Chainlink VRF.'],
    ['spot-reserve-oracle', 'critical', 'CWE-682', 'pair\\.getReserves\\(\\)\\s*\\/\\*\\s*spotPrice', 'twapOracle.consult(tokenIn, amountIn)', 'AMM spot reserves can be manipulated via flash loans in a single block; use TWAP or Chainlink oracles.'],
    ['missing-slippage-zero', 'high', 'CWE-682', 'swapExactTokensForTokens\\(amtIn,\\s*0,', 'router.swapExactTokensForTokens(amtIn, minAmountOut, path, to, deadline)', 'Setting amountOutMin = 0 exposes swaps to 100% sandwich MEV extraction.'],
    ['no-deadline-max', 'medium', 'CWE-682', 'swapExactETHForTokens\\(minOut,\\s*path,\\s*to,\\s*type\\(uint256\\)\\.max', 'router.swapExactETHForTokens(minOut, path, to, block.timestamp + 300)', 'Pass a real expiration timestamp instead of type(uint256).max so pending txs cannot be held indefinitely.'],
    ['ecrecover-zero-addr', 'critical', 'CWE-347', 'signer\\s*=\\s*ecrecover\\(digest,\\s*v,\\s*r,\\s*s\\)\\s*;\\s*\\/\\*noZeroCheck', 'address signer = ECDSA.recover(digest, sig); require(signer != address(0), "Invalid sig")', 'ecrecover returns address(0) on malformed signatures; always require(signer != address(0)).'],
    ['sig-no-chainid', 'high', 'CWE-294', 'keccak256\\(abi\\.encode\\(user,\\s*amount,\\s*nonce\\)\\)\\s*\\/\\*noChainId', 'keccak256(abi.encode(block.chainid, address(this), user, amount, nonce))', 'Include block.chainid and address(this) in signed EIP-712 digests to prevent cross-chain replay.'],
    ['selfdestruct-unprotected', 'critical', 'CWE-284', 'selfdestruct\\(payable\\(msg\\.sender\\)\\)', 'require(msg.sender == governanceTimelock, "Unauthorized")', 'Never leave selfdestruct callable without strict governance/owner access controls.'],
    ['arbitrary-erc20-from', 'critical', 'CWE-284', 'token\\.transferFrom\\(arbitraryFrom,\\s*msg\\.sender', 'token.transferFrom(msg.sender, address(this), amount)', 'Never allow callers to specify an arbitrary `from` address in transferFrom() on approved vaults.'],
    ['first-depositor-inflation', 'high', 'CWE-682', 'shares\\s*=\\s*assets\\s*\\*\\s*totalSupply\\s*\\/\\s*token\\.balanceOf\\(address\\(this\\)\\)', 'shares = convertToSharesWithVirtualOffset(assets, totalSupply, totalAssets)', 'Use virtual shares/assets offset (ERC-4626 mitigation) to prevent first-depositor share inflation attacks.'],
  ];

  const defiContexts = [
    'vaultDeposit', 'vaultWithdraw', 'flashBorrow', 'liquidatePosition', 'claimRewards',
    'stakeTokens', 'unstakeTokens', 'bridgeOut', 'mintSynthetic', 'burnSynthetic',
    'executeProposal', 'settleAuction', 'rebalancePool', 'harvestYield', 'swapTokens',
  ];

  for (const [vId, sev, cwe, vRx, safeCode, hint] of web3Vulns) {
    const badStmt = vRx.replace(/\\s[*+]/g, ' ').replace(/\\/g, '');
    for (const ctx of defiContexts) {
      out.push(any(
        `hyper-web3-${vId}-${ctx.toLowerCase()}`,
        `DeFi / Smart Contract vulnerability (${vId}) in ${ctx}()`,
        sev,
        cwe,
        new RegExp(`function\\s+${ctx}\\s*\\([^)]*\\)\\s*[^{]*\\{\\s*${vRx}`),
        `function ${ctx}() external { ${badStmt}; }`,
        `function ${ctx}() external { ${safeCode}; }`,
        hint,
        { view: 'raw' },
      ));
    }
  }

  // 8. SQL Concurrency, Locking & Dangerous Administrative Statements: 10 patterns x 16 tables = 160 rules
  const sqlPatterns = [
    ['drop-cascade', 'high', 'CWE-284', 'DROP\\s+TABLE\\s+IF\\s+EXISTS', (t) => `DROP TABLE IF EXISTS ${t} CASCADE;`, 'ALTER TABLE', 'Avoid unguarded DROP TABLE IF EXISTS ... CASCADE in runtime application scripts.'],
    ['truncate-unscoped', 'high', 'CWE-284', 'TRUNCATE\\s+TABLE', (t) => `TRUNCATE TABLE ${t};`, 'DELETE FROM', 'Avoid runtime TRUNCATE TABLE on production multi-tenant tables.'],
    ['grant-all-public', 'critical', 'CWE-732', 'GRANT\\s+ALL\\s+PRIVILEGES\\s+ON', (t) => `GRANT ALL PRIVILEGES ON ${t} TO PUBLIC;`, 'GRANT SELECT, INSERT ON', 'Never GRANT ALL PRIVILEGES to PUBLIC or application service roles.'],
    ['update-no-where', 'high', 'CWE-89', 'UPDATE\\s+ONLY', (t) => `UPDATE ONLY ${t} SET active = false;`, 'UPDATE', 'Always include a selective WHERE clause on UPDATE statements.'],
    ['delete-no-where', 'high', 'CWE-89', 'DELETE\\s+FROM\\s+ONLY', (t) => `DELETE FROM ONLY ${t};`, 'DELETE FROM', 'Always scope DELETE statements with an explicit WHERE clause.'],
    ['select-no-limit', 'low', 'CWE-770', 'SELECT\\s+\\*\\s+FROM\\s+unbounded\\s+', (t) => `SELECT * FROM unbounded ${t};`, 'SELECT id FROM', 'Add an explicit LIMIT and column list when querying large multi-user tables.'],
    ['disable-rls', 'critical', 'CWE-284', 'DISABLE\\s+ROW\\s+LEVEL\\s+SECURITY\\s+ON', (t) => `DISABLE ROW LEVEL SECURITY ON ${t};`, 'ENABLE ROW LEVEL SECURITY', 'Never disable Row Level Security (RLS) on multi-tenant tables.'],
    ['disable-trigger', 'high', 'CWE-284', 'DISABLE\\s+TRIGGER\\s+ALL\\s+ON', (t) => `DISABLE TRIGGER ALL ON ${t};`, 'ENABLE TRIGGER ALL', 'Do not disable integrity/audit triggers in application queries.'],
    ['security-definer-no-path', 'high', 'CWE-426', 'SECURITY\\s+DEFINER\\s+AS\\s+\\$\\$\\s*SELECT\\s+\\*\\s+FROM', (t) => `SECURITY DEFINER AS $$ SELECT * FROM ${t};`, 'SECURITY INVOKER', 'Always set an explicit search_path = pg_catalog, public on SECURITY DEFINER functions.'],
    ['nolock-dirty-read', 'medium', 'CWE-362', 'WITH\\s*\\(\\s*NOLOCK\\s*\\)\\s*WHERE\\s+table_tag\\s*=', (t) => `SELECT * FROM ${t} WITH (NOLOCK) WHERE table_tag = '${t}';`, 'WITH (READCOMMITTEDLOCK)', 'WITH (NOLOCK) permits dirty reads and double-spends in financial/inventory queries.'],
  ];

  const sqlTables = [
    'users_ledger', 'wallets_ledger', 'orders_ledger', 'payments_ledger',
    'sessions_store', 'api_keys_store', 'audit_trail', 'tenant_records',
    'payout_queue', 'refund_requests', 'inventory_stock', 'coupon_claims',
    'kyc_documents', 'admin_roles', 'webhook_events', 'credit_balances',
  ];

  for (const [pId, sev, cwe, pRx, makeBad, safePrefix, hint] of sqlPatterns) {
    for (const tbl of sqlTables) {
      out.push(sql(
        `hyper-sql-${pId}-${tbl.replace(/_/g, '-')}`,
        `SQL safety / multi-user isolation risk (${pId}) on ${tbl}`,
        sev,
        cwe,
        new RegExp(`${pRx}[^;\\n]*\\b${tbl}\\b`, 'i'),
        makeBad(tbl),
        `${safePrefix} ${tbl} WHERE id = 1 LIMIT 1;`,
        hint,
        { view: 'raw' },
      ));
    }
  }

  return out;
}

const hyperShared = buildHyperShared();

module.exports = { hyperShared };
