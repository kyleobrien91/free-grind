use crate::error::AppError;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Emitter, Manager, Runtime, WindowEvent};

/// The Google OAuth client ID registered by Grindr.
/// Tokens from *this* client ID are accepted by /v8/sessions/thirdparty (vendor=2).
const GRINDR_GOOGLE_CLIENT_ID: &str =
    "1036042917246-htcnf9mm3qnis86l47ngp0a9ncqsll7j.apps.googleusercontent.com";

/// Unique label for the oauth helper webview window.
const OAUTH_WINDOW_LABEL: &str = "fg-google-oauth";

/// Custom URL scheme the injected script navigates to in order to hand its
/// result back to Rust.
///
/// This deliberately does **not** use a `location.hash` sentinel. A same-document
/// fragment change never reaches `on_navigation` on WebView2, so the original
/// implementation captured nothing at all — confirmed on device across two runs,
/// one of which sat open for 32 minutes without the sentinel ever appearing.
const OAUTH_SCHEME: &str = "fg-oauth";

/// While replacing a stale OAuth window, suppress the close handler's
/// "cancelled" emission for that window only — it belongs to the old flow.
static SUPPRESS_CLOSE_EMISSIONS: AtomicBool = AtomicBool::new(false);

/// Set once the flow produced a result (token or error) so the window-close
/// handler does not additionally emit an empty token.
static OAUTH_FINISHED: AtomicBool = AtomicBool::new(false);

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

/// The minimal page served in response to the `fg-oauth://` hand-off. The window
/// is closed almost immediately, so this only needs to avoid looking broken if the
/// close is delayed. `message` is interpolated as a JS string literal so Google's
/// own error text can be shown without an HTML-injection path.
fn result_page<R: Runtime>(app: &AppHandle<R>, message: &str) -> tauri::http::Response<Vec<u8>> {
    let literal = serde_json::to_string(message).unwrap_or_else(|_| "\"Done\"".to_owned());
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Sign in with Google</title>\
<body style=\"margin:0;height:100vh;display:grid;place-items:center;background:#161d27;\
color:#e6eaf0;font:15px 'Segoe UI',system-ui,sans-serif\">\
<div id=fg-msg style=\"text-align:center;padding:24px\"></div>\
<script>document.getElementById('fg-msg').textContent={literal};</script>"
    );
    oauth_log(app, &format!("served result page: {message}"));
    tauri::http::Response::builder()
        .status(200)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(body.into_bytes())
        .unwrap_or_else(|_| tauri::http::Response::new(Vec::new()))
}

/// Handles `fg-oauth://done?v=<token>` and `fg-oauth://error?v=<reason>`, which
/// the injected script navigates to the moment Google's token client resolves.
///
/// Registered in `lib.rs` with `register_uri_scheme_protocol`. Using a real
/// navigation (rather than a fragment change) is what makes the hand-off
/// reliable: unlike a fragment, this is guaranteed to be dispatched to us.
pub fn handle_oauth_scheme<R: Runtime>(
    ctx: tauri::UriSchemeContext<'_, R>,
    request: tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Vec<u8>> {
    let app = ctx.app_handle();
    let from_label = ctx.webview_label().to_owned();

    let parsed = tauri::Url::parse(&request.uri().to_string()).ok();
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    let value = parsed
        .as_ref()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "v")
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default();

    oauth_log(
        app,
        &format!(
            "scheme host={host:?} len={} from={from_label}",
            value.len()
        ),
    );

    // Only ever trust our own OAuth window.
    if from_label != OAUTH_WINDOW_LABEL {
        return result_page(app, "Ignored: unexpected webview.");
    }

    match host.as_str() {
        "done" => {
            OAUTH_FINISHED.store(true, Ordering::SeqCst);
            #[cfg(debug_assertions)]
            eprintln!("[GOOGLE-AUTH] Captured token (len={})", value.len());
            oauth_log(app, &format!("captured token (len={})", value.len()));

            let _ = app.emit(GOOGLE_OAUTH_TOKEN_EVENT, value);
            close_oauth_window(app);
            result_page(app, "Signed in. Returning to Free Grind\u{2026}")
        }
        "error" => {
            OAUTH_FINISHED.store(true, Ordering::SeqCst);
            #[cfg(debug_assertions)]
            eprintln!("[GOOGLE-AUTH] OAuth error: {value}");
            oauth_log(app, &format!("flow error: {value}"));

            // The reason is Google's own; hand it to the frontend so it can say
            // something specific. The token event is still emitted (empty) so the
            // loading state is always cleared.
            let _ = app.emit(GOOGLE_OAUTH_ERROR_EVENT, value.clone());
            let _ = app.emit(GOOGLE_OAUTH_TOKEN_EVENT, "");
            close_oauth_window(app);
            result_page(app, &format!("Sign-in failed: {value}"))
        }
        other => {
            oauth_log(app, &format!("ignoring unknown scheme host {other:?}"));
            result_page(app, "Nothing to do.")
        }
    }
}

/// Closes the OAuth helper window shortly after a result arrives, so the
/// `fg-oauth://` response can finish loading first.
fn close_oauth_window<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        if let Some(win) = app.get_webview_window(OAUTH_WINDOW_LABEL) {
            let _ = win.close();
        }
    });
}

/// JS injected into the OAuth helper webview before the page's own scripts run.
///
/// The window exists only to supply an *origin* that Grindr registered as an
/// authorised JavaScript origin for their Google OAuth client ID — that is what
/// makes Google accept a token request for that client. The page itself is
/// treated as furniture and is never shown:
///
/// - All of the host page's own markup is hidden from the first paint and an
///   inert "Signing you in with Google" screen is put on top, so the user is
///   never dropped onto Grindr's login form with a button they feel obliged to
///   press.
/// - Google's Identity Services client is injected directly, so we never depend
///   on the page's own scripts having loaded it.
/// - `requestAccessToken` is attempted automatically. Because that happens
///   without a user gesture, Chromium may refuse to open Google's popup; when
///   that happens the screen re-arms its own button instead of failing, so one
///   extra click is available only if it is actually needed.
/// - The result leaves via the `fg-oauth://` scheme (see `handle_oauth_scheme`).
fn build_inject_script(client_id: &str) -> String {
    format!(
        r#"
(function() {{
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

  // Hand the result to Rust with a real navigation. A location.hash change is
  // a same-document navigation and never reaches Tauri on WebView2, which is
  // why the earlier version of this flow silently captured nothing.
  function finish(kind, value) {{
    if (settled) return;
    settled = true;
    log(kind + (value ? ' (' + value.length + ' chars)' : ''));
    window.location.href = SCHEME + '://' + kind + '?v=' +
      encodeURIComponent(value == null ? '' : String(value));
  }}

  // The host page is only an origin. Hide everything it renders and show our
  // own inert screen instead, so there is never a Grindr login button to click.
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
            // This attempt came from our own timer, with no user gesture, so
            // Chromium most likely refused to open the popup. That is not a
            // real failure — re-arm the button so one click can retry. The
            // attempt is still logged, and a failure after a real click is
            // reported to Rust as normal.
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

/// Opens a secondary webview window to `https://web.grindr.com`, injects the
/// Google OAuth token client, and emits the resulting `ya29…` token back to the
/// main window via the `fg:google-oauth-token` event.
///
/// The page is only ever a host for the injected script — it needs to be a real
/// HTML document on an origin that Grindr registered as an authorised
/// JavaScript origin for their Google OAuth client ID, because that is what
/// makes Google accept the implicit token request. It does *not* need to be a
/// usable (or subscription-gated) Grindr session, and its own UI is hidden.
///
/// This previously pointed at `https://grindr.mobi`, chosen for being ungated.
/// That origin now answers 404, so nothing ever defined
/// `google.accounts.oauth2` and the flow sat on a dead page until it timed out.
/// It then moved to `web.grindr.com` while still relying on the page's own
/// scripts, which left the user staring at Grindr's real login form.
#[tauri::command]
pub async fn open_google_auth_webview(app: AppHandle) -> Result<(), AppError> {
    // If a previous OAuth window is still open, close it before opening a new
    // one so we never have two racing.
    if let Some(existing) = app.get_webview_window(OAUTH_WINDOW_LABEL) {
        SUPPRESS_CLOSE_EMISSIONS.store(true, Ordering::SeqCst);
        let _ = existing.close();
        // Give the OS a moment to process the close before creating a new window.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        SUPPRESS_CLOSE_EMISSIONS.store(false, Ordering::SeqCst);
    }

    // Any previous run's result must not suppress this run's close handling.
    OAUTH_FINISHED.store(false, Ordering::SeqCst);

    let script = build_inject_script(GRINDR_GOOGLE_CLIENT_ID);

    // Clone before the builder borrows `app`, so the on_navigation closure can
    // move its own independent handle without conflicting with the borrow.
    let app_for_nav = app.clone();

    let window = tauri::WebviewWindowBuilder::new(
        &app,
        OAUTH_WINDOW_LABEL,
        tauri::WebviewUrl::External(
            "https://web.grindr.com"
                .parse()
                .map_err(|e| AppError::Http(format!("Invalid OAuth URL: {e}")))?,
        ),
    )
    .title("Sign in with Google")
    .inner_size(480.0, 640.0)
    .resizable(true)
    .initialization_script(&script)
    .on_navigation(move |url| {
        // Results arrive via the fg-oauth:// scheme, not here — a fragment change
        // is a same-document navigation and is not reported on WebView2. This
        // handler only traces, so we can tell "the page never loaded" apart from
        // "the flow ran but the hand-off did not arrive".
        let traced: String = url.to_string().chars().take(160).collect();
        oauth_log(&app_for_nav, &format!("nav url={traced}"));
        true
    })
    .build()
    .map_err(|e| AppError::Http(format!("Failed to open OAuth webview: {e}")))?;

    oauth_log(&app, "opened OAuth webview");

    // If the user closes the window before the flow completes, emit an empty
    // token so the frontend can reset its loading state and show an error
    // instead of spinning forever.
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
            let _ = app_for_close.emit(GOOGLE_OAUTH_TOKEN_EVENT, "");
        }
    });

    Ok(())
}