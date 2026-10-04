import { useState, useEffect, useRef, type InputHTMLAttributes, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../../contexts/useAuth";
import { AuthShell } from "../../components/ui/auth-shell";
import { Button } from "../../components/ui/button";
import { BugReportButton } from "../../components/ui/BugReportButton";
import type { SignInMethod } from "../../types/auth";
import { useTranslation } from "react-i18next";
import { Mail, Lock, KeyRound, AlertCircle, ExternalLink, Eye, EyeOff } from "lucide-react";
import { cn } from "../../utils/cn";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

function AuthMethodTab({
	active,
	icon,
	label,
	onClick,
}: {
	active: boolean;
	icon: ReactNode;
	label: string;
	onClick: () => void;
}) {
	return (
		<button
			type="button"
			onClick={onClick}
			className={cn(
				"flex flex-1 items-center justify-center gap-1.5 rounded-[10px] py-2 text-sm font-medium transition-all duration-200 active:scale-[0.97]",
				active
					? "bg-[var(--accent)] text-[var(--accent-contrast)] shadow-md shadow-[var(--accent)]/25"
					: "text-[var(--text-muted)] hover:text-[var(--text)]",
			)}
		>
			{icon}
			{label}
		</button>
	);
}

function IconInput({
	icon,
	className,
	rightSlot,
	...inputProps
}: { icon: ReactNode; rightSlot?: ReactNode } & InputHTMLAttributes<HTMLInputElement>) {
	return (
		<div className="group relative">
			<span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] transition-colors duration-150 group-focus-within:text-[var(--accent)]">
				{icon}
			</span>
			<input {...inputProps} className={cn("input-field pl-9", rightSlot && "pr-10", className)} />
			{rightSlot ? (
				<span className="absolute right-3 top-1/2 -translate-y-1/2">{rightSlot}</span>
			) : null}
		</div>
	);
}

function AuthSubmitSection({
	error,
	loading,
	disabled,
	loadingLabel,
	label,
}: {
	error: string | null;
	loading: boolean;
	disabled: boolean;
	loadingLabel: string;
	label: string;
}) {
	return (
		<>
			{error ? (
				<div className="flex items-center gap-2 rounded-xl border border-[color-mix(in_srgb,var(--border)_60%,#f87171_40%)] bg-[color-mix(in_srgb,var(--surface)_88%,#f87171_12%)] px-3 py-2.5 text-sm text-[var(--text)]">
					<AlertCircle className="h-4 w-4 shrink-0 text-[#f87171]" />
					<span>{error}</span>
				</div>
			) : null}
			<div className="pt-1">
				<Button
					type="submit"
					variant="primary"
					loading={loading}
					disabled={disabled}
					className="w-full"
				>
					{loading ? loadingLabel : label}
				</Button>
			</div>
		</>
	);
}

export function SignInPage() {
	const { t } = useTranslation();
	const [searchParams] = useSearchParams();
	const addProfileMode = searchParams.get("mode") === "add-profile";
	const [method, setMethod] = useState<SignInMethod>("password");

	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [showPassword, setShowPassword] = useState(false);
	const [isPasswordLoading, setIsPasswordLoading] = useState(false);

	const [jwtToken, setJwtToken] = useState("");
	const [isTokenLoading, setIsTokenLoading] = useState(false);
	const [isGoogleLoading, setIsGoogleLoading] = useState(false);
	const [googleError, setGoogleError] = useState<string | null>(null);
	// Tracks whether a Google OAuth flow we initiated is still in flight.
	// Used to (a) ignore stray emissions and (b) guarantee the loading
	// spinner is reset exactly once, even if the webview is closed early.
	const googleFlowActive = useRef(false);

	const { login, loginWithJwt, error } = useAuth();
	const navigate = useNavigate();

	const isPasswordFormValid = email.trim().length > 0 && password.trim().length > 0;
	const isTokenFormValid = jwtToken.trim().length > 0;

	const handlePasswordSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setIsPasswordLoading(true);
		try {
			await login(email, password);
			navigate("/");
		} catch {
			// AuthContext updates `error`, which is rendered in the form.
		} finally {
			setIsPasswordLoading(false);
		}
	};

	const handleTokenSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setIsTokenLoading(true);
		try {
			await loginWithJwt(jwtToken.trim());
			navigate("/");
		} catch {
			// AuthContext updates `error`, which is rendered in the form.
		} finally {
			setIsTokenLoading(false);
		}
	};

	// Listen for the ya29 token emitted by the Rust google_auth webview.
	// The event payload is:
	//   - a non-empty token string → valid Google access token → auto-login
	//   - an empty string          → cancelled / failed / window closed early
	// Registered once on mount so the listener is always attached before
	// handleGoogleSignIn invokes the Rust command.
	useEffect(() => {
		const unlisten = listen<string>("fg:google-oauth-token", async (event) => {
			if (!googleFlowActive.current) return;
			googleFlowActive.current = false;
			setIsGoogleLoading(false);

			const token = event.payload ?? "";
			if (!token) {
				setGoogleError(
					t("auth.sign_in.google_sign_in_error", {
						defaultValue: "Google sign-in was cancelled or failed. Please try again.",
					}),
				);
				return;
			}
			setGoogleError(null);
			try {
				await loginWithJwt(token);
				navigate("/");
			} catch {
				// AuthContext already set the error state.
			}
		});

		return () => {
			void unlisten.then((fn) => fn());
		};
	}, [loginWithJwt, navigate, t]);

	const handleGoogleSignIn = async () => {
		setGoogleError(null);
		googleFlowActive.current = true;
		setIsGoogleLoading(true);
		try {
			await invoke("open_google_auth_webview");
			// The fg:google-oauth-token event (handled above) ends the flow.
			// If the user closes the webview early, Rust emits an empty token.
		} catch {
			// Webview failed to open entirely.
			googleFlowActive.current = false;
			setIsGoogleLoading(false);
		}
	};

	return (
		<AuthShell
			title={addProfileMode ? t("auth.sign_in.add_profile_title", { defaultValue: "Add Profile" }) : t("auth.sign_in.title")}
			subtitle={addProfileMode ? t("auth.sign_in.add_profile_subtitle", { defaultValue: "Sign in with the account you want to add." }) : t("auth.sign_in.subtitle")}
			footer={
				addProfileMode ? (
					<div className="flex flex-col items-center gap-3">
						<button
							type="button"
							onClick={() => navigate(-1)}
							className="text-sm text-[var(--text-muted)] hover:text-[var(--text)]"
						>
							{t("common.cancel", { defaultValue: "Cancel" })}
						</button>
					</div>
				) : (
					<div className="flex flex-col items-center gap-3">
						<span className="text-sm text-[var(--text-muted)]">
							{t("auth.sign_in.no_account_label")}{" "}
							<Link
								to="/auth/sign-up"
								className="font-bold underline hover:text-[var(--text)]"
							>
								{t("auth.sign_in.no_account_action")}
							</Link>
						</span>
						<BugReportButton />
					</div>
				)
			}
		>
			{/* Method selector */}
			<div className="mb-6 flex gap-1 rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--surface-2)] p-1 shadow-sm">
				<AuthMethodTab
					active={method === "password"}
					icon={<Lock className="h-3.5 w-3.5" />}
					label={t("auth.sign_in.method_password")}
					onClick={() => setMethod("password")}
				/>
				<AuthMethodTab
					active={method === "token"}
					icon={<KeyRound className="h-3.5 w-3.5" />}
					label={t("auth.sign_in.method_token")}
					onClick={() => setMethod("token")}
				/>
			</div>

			{method === "password" ? (
				<form key="password" onSubmit={handlePasswordSubmit} className="animate-fade-in space-y-3">
					<IconInput
						icon={<Mail className="h-4 w-4" />}
						type="email"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						required
						autoFocus
						placeholder={t("auth.common.email")}
					/>
					<IconInput
						icon={<Lock className="h-4 w-4" />}
						type={showPassword ? "text" : "password"}
						value={password}
						onChange={(e) => setPassword(e.target.value)}
						required
						placeholder={t("auth.common.password")}
						rightSlot={
							<button
								type="button"
								onClick={() => setShowPassword((prev) => !prev)}
								className="flex items-center p-0 text-[var(--text-muted)] hover:text-[var(--text)]"
								tabIndex={-1}
								aria-label={
									showPassword
										? t("auth.common.hide_password")
										: t("auth.common.show_password")
								}
							>
								{showPassword ? (
									<EyeOff className="h-4 w-4" />
								) : (
									<Eye className="h-4 w-4" />
								)}
							</button>
						}
					/>
					<AuthSubmitSection
						error={error}
						loading={isPasswordLoading}
						disabled={!isPasswordFormValid}
						loadingLabel={t("auth.sign_in.signing_in")}
						label={t("auth.sign_in.submit")}
					/>
				</form>
			) : (
				<form key="token" onSubmit={handleTokenSubmit} className="animate-fade-in space-y-3">
					{/* ── Sign in with Google ── */}
					<Button
						type="button"
						variant="secondary"
						className="flex w-full items-center justify-center gap-2"
						loading={isGoogleLoading}
						disabled={isGoogleLoading || isTokenLoading}
						onClick={handleGoogleSignIn}
					>
						{!isGoogleLoading && (
							/* Google "G" icon */
							<svg width="16" height="16" viewBox="0 0 48 48" aria-hidden="true">
								<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
								<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
								<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
								<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.35-8.16 2.35-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
								<path fill="none" d="M0 0h48v48H0z"/>
							</svg>
						)}
						{isGoogleLoading
							? t("auth.sign_in.google_sign_in_opening", { defaultValue: "Opening Google sign-in…" })
							: t("auth.sign_in.google_sign_in_button", { defaultValue: "Sign in with Google" })}
					</Button>

					{/* ── Divider ── */}
					<div className="flex items-center gap-3">
						<div className="h-px flex-1 bg-[var(--border)]" />
						<span className="text-xs text-[var(--text-muted)]">
							{t("auth.sign_in.google_sign_in_or", { defaultValue: "or paste a token manually" })}
						</span>
						<div className="h-px flex-1 bg-[var(--border)]" />
					</div>

					{/* ── Manual token input ── */}
					<div>
						<a
							href="https://freegrinddocs.imaoreo.dev/guide/login"
							target="_blank"
							rel="noreferrer"
							className="mb-2 flex items-start gap-1.5 text-xs font-medium leading-relaxed text-[var(--accent)] hover:underline"
						>
							<ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0" />
							<span>{t("auth.sign_in.token_help")}</span>
						</a>
						<IconInput
							icon={<KeyRound className="h-4 w-4" />}
							type="text"
							value={jwtToken}
							onChange={(e) => setJwtToken(e.target.value)}
							autoFocus
							placeholder={t("auth.sign_in.token_placeholder", {
								defaultValue: "ya29... or eyJhbGciOi...",
							})}
							autoComplete="off"
						/>
						<p className="mt-1.5 text-xs text-[var(--text-muted)]">
							{t("auth.sign_in.token_helper", {
								defaultValue:
									"Accepts Google OAuth tokens (ya29...) and Grindr Web session JWTs (eyJ...).",
							})}
						</p>
					</div>
					<AuthSubmitSection
						error={googleError ?? error}
						loading={isTokenLoading}
						disabled={!isTokenFormValid || isGoogleLoading}
						loadingLabel={t("auth.sign_in.signing_in")}
						label={t("auth.sign_in.submit")}
					/>
				</form>
			)}
		</AuthShell>
	);
}
