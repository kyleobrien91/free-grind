use crate::error::AppError;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, Runtime, WindowEvent};

/// The Google OAuth client ID registered by Grindr.
/// Tokens from *this* client ID are accepted by /v8/sessions/thirdparty (vendor=2).
const GRINDR_GOOGLE_CLIENT_ID: &str =
    "1036042917246-htcnf9mm3qnis86l47ngp0a9ncqsll7j.apps.googleusercontent.com";

/// Unique label for the oauth helper webview window.
const OAUTH_WINDOW_LABEL: &str = "fg-google-oauth";

/// Label prefix for Google's account-chooser popup. Each attempt needs its own
/// label because Tauri windows are addressed by label.
const POPUP_LABEL_PREFIX: &str = "fg-google-oauth-popup";

/// Custom URL scheme the injected script navigates to in order to hand its
/// result back to Rust.
const OAUTH_SCHEME: &str = "fg-oauth";

/// The origin Google's Identity Services client will accept. It only has to be
/// an origin Grindr registered as an authorised JavaScript origin for their
/// client ID; nothing about the page itself is used.
const OAUTH_ORIGIN: &str = "https://web.grindr.com";

/// While replacing a stale OAuth window, suppress the close handler's
/// "cancelled" emission for that window only — it belongs to the old flow.
static SUPPRESS_CLOSE_EMISSIONS: AtomicBool = AtomicBool::new(false);

/// Set once the flow produced a result (token or error) so the window-close
/// handler does not additionally emit an empty token.
static OAUTH_FINISHED: AtomicBool = AtomicBool::new(false);

/// Makes every popup label unique.
static POPUP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Event name emitted back to the main window once the token is captured.
pub const GOOGLE_OAUTH_TOKEN_EVENT: &str = "fg:google-oauth-token";

/// Event name emitted when the flow failed, carrying Google's own error text
/// (for example `popup_closed` or `access_denied`) so the UI can explain what
/// actually happened instead of showing a generic message.
pub const GOOGLE_OAUTH_ERROR_EVENT: &str = "fg:google-oauth-error";

/// Appends a timestamped line to `<app_log_dir>/google-oauth.log`.
///
/// Release builds on Windows run without a console (`windows_subsystem = "windows"`
/// in `main.rs`), so `eprintln!` output is discarded and the rest of this crate's
/// `#[cfg(debug_assertions)]` tracing cannot be used to diagnose the OAuth flow.
/// This leaves a durable trace we can read back after a failed sign-in attempt.
fn oauth_log<R: Runtime>(app: &AppHandle<R>, message: &str) {
    let Ok(dir) = app.path().app_log_dir() else {
        return;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("google-oauth.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let stamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let _ = writeln!(file, "[{stamp}] {message}");
    }
}

/// JS injected into the OAuth helper webview before the page's own scripts run.
///
/// The window exists only to supply an *origin* that Grindr registered as an
/// authorised JavaScript origin for their Google OAuth client ID — that is what
/// makes Google issue a token for that client. The page itself is treated as
/// furniture and is never shown:
///
/// - Runs only in the top-level frame. `initialization_script` is injected into
///   every frame, and reCAPTCHA's own iframe was previously starting duplicate
///   token requests from a `www.recaptcha.net` origin.
/// - Hides all of the host page's markup from the first paint and puts an inert
///   "Signing you in with Google" screen on top, so the user is never dropped
///   onto Grindr's login form with a second button they feel obliged to press.
/// - Injects Google's Identity Services client directly rather than depending on
///   the page's own scripts having loaded it.
/// - Attempts `requestAccessToken` automatically. Google's token client can only
///   complete through a popup, and this runs without a user gesture, so the
///   attempt may be refused; the screen then offers its own button so a retry is
///   one click away instead of a dead end.
/// - Leaves the result via the `fg-oauth://` scheme, which `on_navigation` on
///   the Rust side intercepts.
fn build_inject_script(client_id: &str) -> String {
    format!(
        r#"
(function() {{
  // Only the top-level document. This script is injected into every frame, and a
  // third-party iframe has neither the authorised origin nor anywhere to report to.
  if (window.top !== window) return;
  if (window.__FG_OAUTH_INJECTED__) return;
  window.__FG_OAUTH_INJECTED__ = true;

  var CLIENT_ID = '{client_id}';
  var SCHEME = '{OAUTH_SCHEME}';

  var settled = false;      // a result has been sent to Rust
  var starting = false;     // a token request is in flight
  var autoTried = false;    // the no-gesture attempt has been made
  var userInitiated = false;

  function log(msg) {{
    try {{ console.log('[fg-oauth] ' + msg); }} catch (e) {{}}
  }}

  function hasGsi() {{
    return !!(window.google && window.google.accounts && window.google.accounts.oauth2);
  }}

  function note(text) {{
    var n = document.getElementById('fg-oauth-note');
    if (n) n.textContent = text;
  }}

  // Hand the result to Rust. This has to be a real navigation: a location.hash
  // change is a same-document navigation which Tauri never reports on WebView2,
  // which is why an earlier version of this flow captured nothing at all.
  function finish(kind, value) {{
    if (settled) return;
    settled = true;
    log(kind + (value ? ' (' + value.length + ' chars)' : ''));
    window.location.href = SCHEME + '://' + kind + '?v=' +
      encodeURIComponent(value == null ? '' : String(value));
  }}

  function mountOverlay() {{
    var style = document.createElement('style');
    style.textContent =
      'html,body{{background:#161d27!important;margin:0!important;min-height:100%!important}}' +
      'body > *:not(#fg-oauth-root){{display:none!important}}';
    (document.head || document.documentElement).appendChild(style);

    var root = document.createElement('div');
    root.id = 'fg-oauth-root';
    root.style.cssText =
      'position:fixed;top:0;left:0;right:0;bottom:0;z-index:2147483647;display:flex;' +
      'flex-direction:column;align-items:center;justify-content:center;gap:16px;' +
      'padding:24px;background:#161d27;color:#e6eaf0;text-align:center;' +
      "font:15px/1.45 'Segoe UI',system-ui,sans-serif";
    root.innerHTML =
      '<div style="font-size:22px">Signing you in with Google</div>' +
      '<button id="fg-oauth-go" style="min-height:44px;padding:0 20px;border:0;' +
      'border-radius:8px;background:#FFCC00;color:#161d27;cursor:pointer;' +
      "font:600 15px 'Segoe UI',system-ui,sans-serif\">Choose a Google account</button>" +
      '<div id="fg-oauth-note" style="font-size:13px;color:#7d8798"></div>';
    (document.body || document.documentElement).appendChild(root);

    document.getElementById('fg-oauth-go').addEventListener('click', function() {{
      userInitiated = true;
      startFlow();
    }});
  }}

  function injectGsi() {{
    if (hasGsi()) return;
    var s = document.createElement('script');
    s.src = 'https://accounts.google.com/gsi/client';
    s.async = true;
    s.defer = true;
    s.onerror = function() {{ finish('error', 'gsi_script_failed'); }};
    (document.head || document.documentElement).appendChild(s);
  }}

  function startFlow() {{
    if (settled || starting) return;
    if (!hasGsi()) return;
    starting = true;
    log('requestAccessToken (userInitiated=' + userInitiated + ')');
    try {{
      var client = window.google.accounts.oauth2.initTokenClient({{
        client_id: CLIENT_ID,
        scope: 'email profile',
        callback: function(response) {{
          if (response && response.access_token) {{
            window.__FG_OAUTH_TOKEN__ = response.access_token;
            finish('done', response.access_token);
          }} else {{
            finish('error', (response && response.error) || 'unknown');
          }}
        }},
        error_callback: function(err) {{
          var reason = (err && err.message) ? err.message : 'popup_closed';
          if (!userInitiated) {{
            // This attempt came from our own timer with no user gesture, so the
            // popup was most likely refused. Not a real failure — re-arm the
            // button so one click can retry.
            log('auto-start blocked (' + reason + '), waiting for a click');
            note('Press the button to continue.');
            starting = false;
            return;
          }}
          finish('error', reason);
        }}
      }});
      client.requestAccessToken({{ prompt: 'select_account' }});
    }} catch(e) {{
      finish('error', (e && e.message) ? e.message : String(e));
    }}
  }}

  function autoStart() {{
    if (settled || autoTried || userInitiated) return;
    if (!hasGsi()) {{ setTimeout(autoStart, 300); return; }}
    autoTried = true;
    startFlow();
  }}

  function waitForGsi(attempts) {{
    if (settled) return;
    if (attempts <= 0) {{
      if (!autoTried) {{ finish('error', 'gsi_not_found'); }}
      return;
    }}
    if (hasGsi()) {{
      autoStart();
    }} else {{
      setTimeout(function() {{ waitForGsi(attempts - 1); }}, 300);
    }}
  }}

  function begin() {{
    mountOverlay();
    injectGsi();
    waitForGsi(100);
  }}

  if (document.documentElement) begin();
  else window.addEventListener('DOMContentLoaded', begin);
}})();
"#
    )
}

/// Closes the OAuth window and any Google popup still open.
fn close_oauth_windows<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Let the result navigation settle before tearing the windows down.
        tokio::time::sleep(Duration::from_millis(150)).await;
        for (label, win) in app.webview_windows() {
            if label == OAUTH_WINDOW_LABEL || label.starts_with(POPUP_LABEL_PREFIX) {
                let _ = win.close();
            }
        }
    });
}

/// Reports a failure to the frontend: the specific reason first, then an empty
/// token so the loading state is always cleared.
fn report_failure<R: Runtime>(app: &AppHandle<R>, reason: &str) {
    OAUTH_FINISHED.store(true, Ordering::SeqCst);
    #[cfg(debug_assertions)]
    eprintln!("[GOOGLE-AUTH] {reason}");
    oauth_log(app, &format!("flow failed: {reason}"));
    let _ = app.emit(GOOGLE_OAUTH_ERROR_EVENT, reason.to_owned());
    let _ = app.emit(GOOGLE_OAUTH_TOKEN_EVENT, "");
    close_oauth_windows(app);
}

/// Opens the OAuth helper webview and captures a `ya29…` Google access token
/// using Grindr's own client ID.
///
/// # How the token is obtained
///
/// Google's Identity Services token client (`initTokenClient`) can only ever
/// complete through a popup, and it accepts any page served from an origin that
/// is an authorised JavaScript origin for the client ID. So:
///
/// 1. A webview opens on [`OAUTH_ORIGIN`], purely to provide that origin. Its own
///    UI is hidden and replaced with an inert screen.
/// 2. An injected script loads Google's Identity Services client and calls
///    `requestAccessToken`.
/// 3. Google opens its account chooser. Tauri denies `window.open` by default,
///    which is why this failed on every earlier attempt — so `on_new_window`
///    creates a real child window for it via `NewWindowResponse::Create`. wry
///    hands that to WebView2's `SetNewWindow`, which is what preserves the
///    `window.opener` relationship Google's callback depends on.
/// 4. On success the token comes back to the injected script, which navigates to
///    `fg-oauth://done?v=<token>`. `on_navigation` intercepts that.
///
/// # Why the result travels by URL and not by fragment
///
/// A `location.hash` change is a same-document navigation and Tauri never
/// reports it on WebView2: one earlier window sat open for 32 minutes with no
/// sentinel ever logged. A real navigation to an unhandled scheme *is* reported —
/// `on_navigation` receives the complete URL — it merely also makes WebView2 try
/// to launch the scheme and fail, so the navigation is blocked by returning
/// `false` once the token is in hand.
///
/// # Redirects are not an option
///
/// Google was probed directly: this client accepts no redirect URI we can use.
/// `http://127.0.0.1:<port>`, `localhost`, `urn:ietf:wg:oauth:2.0:oob`,
/// `https://web.grindr.com/` and `https://grindr.mobi/` are all rejected with
/// `redirect_uri_mismatch`, and the installed-application custom scheme is
/// refused with `invalid_request` ("Custom scheme URIs are not allowed for the
/// OAuth 2.0 Authorization endpoint"). Only the JavaScript-origin flow remains.
#[tauri::command]
pub async fn open_google_auth_webview(app: AppHandle) -> Result<(), AppError> {
    // If a previous OAuth window is still open, close it before opening a new
    // one so we never have two racing.
    if let Some(existing) = app.get_webview_window(OAUTH_WINDOW_LABEL) {
        SUPPRESS_CLOSE_EMISSIONS.store(true, Ordering::SeqCst);
        let _ = existing.close();
        // Give the OS a moment to process the close before creating a new window.
        tokio::time::sleep(Duration::from_millis(150)).await;
        SUPPRESS_CLOSE_EMISSIONS.store(false, Ordering::SeqCst);
    }

    // Any previous run's result must not suppress this run's close handling.
    OAUTH_FINISHED.store(false, Ordering::SeqCst);

    let script = build_inject_script(GRINDR_GOOGLE_CLIENT_ID);

    // Clone before the builder borrows `app`, so the closures can each move
    // their own independent handle without conflicting with the borrow.
    let app_for_popup = app.clone();
    let app_for_nav = app.clone();

    let window = tauri::WebviewWindowBuilder::new(
        &app,
        OAUTH_WINDOW_LABEL,
        tauri::WebviewUrl::External(
            OAUTH_ORIGIN
                .parse()
                .map_err(|e| AppError::Http(format!("Invalid OAuth URL: {e}")))?,
        ),
    )
    .title("Sign in with Google")
    .inner_size(480.0, 640.0)
    .resizable(true)
    .initialization_script(&script)
    .on_new_window(move |url, features| {
        // Google's account chooser is opened with window.open. Tauri denies that
        // by default, which is what made every earlier attempt fail with
        // "Failed to open popup window". Handing WebView2 the new webview via
        // NewWindowResponse::Create goes through SetNewWindow, which keeps the
        // window.opener relationship Google's postMessage callback needs.
        let label = format!(
            "{POPUP_LABEL_PREFIX}-{}",
            POPUP_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let created = tauri::WebviewWindowBuilder::new(
            &app_for_popup,
            &label,
            tauri::WebviewUrl::External(url),
        )
        .title("Choose an account")
        .inner_size(460.0, 640.0)
        .window_features(features)
        .build();

        match created {
            Ok(window) => tauri::webview::NewWindowResponse::Create { window },
            Err(e) => {
                oauth_log(
                    &app_for_popup,
                    &format!("could not open the Google account chooser: {e}"),
                );
                tauri::webview::NewWindowResponse::Deny
            }
        }
    })
    .on_navigation(move |url| {
        // Anything that is not our result scheme is the host origin or Google's
        // own pages: the consent UI, the account chooser, the sign-in form.
        if url.scheme() != OAUTH_SCHEME {
            return true;
        }

        let app = &app_for_nav;
        let value = url
            .query_pairs()
            .find(|(k, _)| k == "v")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        // The host is the outcome: "done" or "error".
        let outcome = url.host_str().unwrap_or("").to_owned();

        oauth_log(app, &format!("result scheme outcome={outcome:?} len={}", value.len()));

        match outcome.as_str() {
            "done" if !value.is_empty() => {
                OAUTH_FINISHED.store(true, Ordering::SeqCst);
                #[cfg(debug_assertions)]
                eprintln!("[GOOGLE-AUTH] Captured token (len={})", value.len());
                oauth_log(app, &format!("captured token (len={})", value.len()));
                let _ = app.emit(GOOGLE_OAUTH_TOKEN_EVENT, value);
            }
            "error" => {
                report_failure(app, if value.is_empty() { "unknown" } else { &value });
            }
            other => {
                report_failure(app, &format!("unexpected OAuth result ({other})"));
            }
        }

        close_oauth_windows(app);

        // Block it. Nothing on this machine handles fg-oauth://, so letting the
        // navigation proceed would only raise "the scheme does not have a
        // registered handler" in place of a working sign-in.
        false
    })
    .build()
    .map_err(|e| AppError::Http(format!("Failed to open OAuth webview: {e}")))?;

    oauth_log(&app, "opened OAuth webview");

    // If the user closes the window before the flow completes, tell the frontend
    // so it can reset its loading state and explain what happened.
    let app_for_close = app.clone();
    window.on_window_event(move |event| {
        if matches!(
            event,
            WindowEvent::Destroyed | WindowEvent::CloseRequested { .. }
        )
            && !SUPPRESS_CLOSE_EMISSIONS.load(Ordering::SeqCst)
            && !OAUTH_FINISHED.swap(true, Ordering::SeqCst)
        {
            oauth_log(&app_for_close, "window closed before the flow finished");
            let _ = app_for_close.emit(GOOGLE_OAUTH_ERROR_EVENT, "cancelled");
            let _ = app_for_close.emit(GOOGLE_OAUTH_TOKEN_EVENT, "");
        }
    });

    Ok(())
}