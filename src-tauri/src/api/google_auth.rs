use crate::error::AppError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

/// The Google OAuth client ID registered by Grindr.
/// Tokens from *this* client ID are accepted by /v8/sessions/thirdparty (vendor=2).
const GRINDR_GOOGLE_CLIENT_ID: &str =
    "1036042917246-htcnf9mm3qnis86l47ngp0a9ncqsll7j.apps.googleusercontent.com";

/// Unique label for the oauth helper webview window.
const OAUTH_WINDOW_LABEL: &str = "fg-google-oauth";

/// While replacing a stale OAuth window, suppress the close handler's
/// "cancelled" emission for that window only — it belongs to the old flow.
static SUPPRESS_CLOSE_EMISSIONS: AtomicBool = AtomicBool::new(false);

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
fn oauth_log(app: &AppHandle, message: &str) {
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

/// JS injected into web.grindr.com after the page loads.
/// - Waits for `google.accounts.oauth2` to become available (it is loaded by
///   the page's own scripts unconditionally — no membership check on load).
/// - Calls `initTokenClient` with Grindr's own client ID so Google accepts the
///   origin and returns a valid ya29 token.
/// - On success, stores the token in `window.__FG_OAUTH_TOKEN__` and navigates
///   to a sentinel fragment so the Rust `on_navigation` handler can detect it.
/// - On error, navigates to a different sentinel fragment so Rust can surface
///   the failure.
///
/// NOTE: The fragment-based sentinel avoids any dependency on Tauri IPC being
/// available in an external-origin webview.
fn build_inject_script(client_id: &str) -> String {
    format!(
        r#"
(function() {{
  // Guard: only run once per page load.
  if (window.__FG_OAUTH_INJECTED__) return;
  window.__FG_OAUTH_INJECTED__ = true;

  function waitForGsi(attempts) {{
    if (attempts <= 0) {{
      window.location.hash = 'fg-oauth-error=gsi_not_found';
      return;
    }}
    if (typeof window.google !== 'undefined' &&
        window.google.accounts &&
        window.google.accounts.oauth2) {{
      startFlow();
    }} else {{
      setTimeout(function() {{ waitForGsi(attempts - 1); }}, 300);
    }}
  }}

  function startFlow() {{
    try {{
      var client = window.google.accounts.oauth2.initTokenClient({{
        client_id: '{client_id}',
        scope: 'email profile',
        callback: function(response) {{
          if (response && response.access_token) {{
            window.__FG_OAUTH_TOKEN__ = response.access_token;
            window.location.hash = 'fg-oauth-done=' + response.access_token;
          }} else {{
            var err = (response && response.error) ? response.error : 'unknown';
            window.location.hash = 'fg-oauth-error=' + err;
          }}
        }},
        error_callback: function(err) {{
          var msg = (err && err.message) ? err.message : 'popup_closed';
          window.location.hash = 'fg-oauth-error=' + msg;
        }}
      }});
      client.requestAccessToken({{ prompt: 'select_account' }});
    }} catch(e) {{
      window.location.hash = 'fg-oauth-error=' + encodeURIComponent(String(e));
    }}
  }}

  // Give the page's own scripts up to 30 s to load the GSI library.
  waitForGsi(100);
}})();
"#,
        client_id = client_id,
    )
}

/// Opens a secondary webview window to `https://grindr.mobi`, injects the
/// Google OAuth token client after the page loads, and emits the resulting
/// `ya29…` token back to the main window via the `fg:google-oauth-token` event.
///
/// We use `grindr.mobi` (the mobile web origin) because it is accessible to
/// **all users** with no membership gate — unlike `web.grindr.com` which may
/// require a paid subscription. Grindr has registered `grindr.mobi` as an
/// authorised JavaScript origin for their Google OAuth client ID, so Google
/// accepts the implicit token request from that origin.
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

    let script = build_inject_script(GRINDR_GOOGLE_CLIENT_ID);

    // Clone before the builder borrows `app`, so the on_navigation closure
    // can move its own independent handle without conflicting with the borrow.
    let app_for_nav = app.clone();

    // Set to true once the token/error has been emitted, so the
    // on_window_event handler knows the close was expected and does not
    // emit a spurious empty-token "cancelled" signal.
    let finished = Arc::new(AtomicBool::new(false));
    let finished_for_nav = finished.clone();
    let finished_for_close = finished.clone();

    let window = tauri::WebviewWindowBuilder::new(
        &app,
        OAUTH_WINDOW_LABEL,
        tauri::WebviewUrl::External(
            "https://grindr.mobi"
                .parse()
                .map_err(|e| AppError::Http(format!("Invalid OAuth URL: {e}")))?,
        ),
    )
    .title("Sign in with Google")
    .inner_size(480.0, 640.0)
    .resizable(true)
    .initialization_script(&script)
    .on_navigation(move |url| {
        let app = &app_for_nav;
        let fragment = url.fragment().unwrap_or("").to_owned();

        // Trace every navigation so we can tell "the injected script never set
        // the sentinel" apart from "the sentinel was set but never reached us".
        // Truncated because Google's popup URLs carry long query strings.
        let traced = format!("{url}");
        let traced = traced.chars().take(160).collect::<String>();
        oauth_log(app, &format!("nav fragment={fragment:?} url={traced}"));

        if let Some(rest) = fragment.strip_prefix("fg-oauth-done=") {
            let token = rest.to_owned();
            finished_for_nav.store(true, Ordering::SeqCst);
            #[cfg(debug_assertions)]
            eprintln!("[GOOGLE-AUTH] Captured token (len={})", token.len());
            oauth_log(&app, &format!("captured token (len={})", token.len()));

            // Emit the token to the main window.
            let _ = app.emit(GOOGLE_OAUTH_TOKEN_EVENT, token);

            // Close the oauth window via a short-lived task so we don't
            // block the navigation callback.
            let app_clone = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if let Some(win) = app_clone.get_webview_window(OAUTH_WINDOW_LABEL) {
                    let _ = win.close();
                }
            });

            // Allow the final navigation so the page can settle before close.
            return true;
        }

        if let Some(err) = fragment.strip_prefix("fg-oauth-error=") {
            finished_for_nav.store(true, Ordering::SeqCst);
            #[cfg(debug_assertions)]
            eprintln!("[GOOGLE-AUTH] OAuth error: {err}");

            // The fragment carries Google's own reason; hand it to the frontend
            // so it can show something specific. The token event is still
            // emitted (empty) so the loading state is always cleared.
            oauth_log(&app, &format!("flow error: {err}"));
            let _ = app.emit(GOOGLE_OAUTH_ERROR_EVENT, err.to_owned());
            let _ = app.emit(GOOGLE_OAUTH_TOKEN_EVENT, "");

            let app_clone = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if let Some(win) = app_clone.get_webview_window(OAUTH_WINDOW_LABEL) {
                    let _ = win.close();
                }
            });

            return true;
        }

        // Allow all other navigations (Google popup, redirect pages, etc.).
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
            && !finished_for_close.swap(true, Ordering::SeqCst)
        {
            oauth_log(&app_for_close, "window closed before the flow finished");
            let _ = app_for_close.emit(GOOGLE_OAUTH_TOKEN_EVENT, "");
        }
    });

    Ok(())
}
