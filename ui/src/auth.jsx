import React, { useCallback, useEffect, useState } from "react";
import { KeyRound, LogOut, ShieldCheck, UserPlus, Users, X } from "lucide-react";

// Every state-changing /api request carries X-AEGIS-Request (the server refuses it otherwise,
// which blocks cross-site requests), and a 401 from the API brings back the sign-in screen.
const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function installFetchGuard() {
  if (window.__aegisFetchGuard) return;
  window.__aegisFetchGuard = true;
  const original = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    const sameOrigin = url.startsWith("/") || url.startsWith(window.location.origin);
    const method = String(init.method || (typeof input === "string" ? "GET" : input.method) || "GET").toUpperCase();
    if (sameOrigin && UNSAFE.has(method)) {
      const headers = new Headers(init.headers || (typeof input === "string" ? undefined : input.headers));
      headers.set("X-AEGIS-Request", "1");
      init = { ...init, headers };
    }
    const response = await original(input, init);
    if (sameOrigin && response.status === 401 && url.includes("/api/") && !url.includes("/api/auth/login")) {
      window.dispatchEvent(new Event("aegis-unauthorized"));
    }
    return response;
  };
}

async function api(path, method = "GET", body) {
  const response = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await response.json(); } catch { /* empty body */ }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function SignIn({ onSignedIn, usersExist, signupEnabled }) {
  const [mode, setMode] = useState("signin");          // "signin" | "signup"
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const signup = mode === "signup";

  async function submit(event) {
    event.preventDefault();
    if (signup && password !== repeat) { setError("The passwords do not match."); return; }
    setBusy(true);
    setError("");
    try {
      onSignedIn(signup
        ? await api("/api/auth/register", "POST", { email, password, display_name: name })
        : await api("/api/auth/login", "POST", { email, password }));
    } catch (failure) {
      setError(failure.message);
    } finally {
      setBusy(false);
      setPassword("");
      setRepeat("");
    }
  }

  function switchMode(next) {
    setMode(next);
    setError("");
    setPassword("");
    setRepeat("");
  }

  return (
    <main className="auth-page">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-brand"><div className="brand-mark">AE</div><div>
          <strong>Aegis Enrichment</strong><span>{signup ? "Create your account" : "Sign in to continue"}</span></div></div>
        {usersExist === false && !signup && (
          <p className="auth-note">No users exist yet. An administrator creates the first account on the
            server: <code>python -m aegis_auth create-user you@example.com --role ADMIN</code></p>
        )}
        {signup && (
          <p className="auth-note">A new account starts empty: you see only the uploads and runs you start.
            Earlier runs are visible to administrators only.</p>
        )}
        {signup && <label>Name (optional)<input type="text" autoComplete="name" value={name} maxLength={255}
          onChange={(event) => setName(event.target.value)} /></label>}
        <label>E-mail<input type="email" autoComplete="username" value={email} required
          onChange={(event) => setEmail(event.target.value)} /></label>
        <label>{signup ? "Password (12+ characters)" : "Password"}<input type="password"
          autoComplete={signup ? "new-password" : "current-password"} value={password} required
          minLength={signup ? 12 : undefined} onChange={(event) => setPassword(event.target.value)} /></label>
        {signup && <label>Repeat password<input type="password" autoComplete="new-password" value={repeat} required
          onChange={(event) => setRepeat(event.target.value)} /></label>}
        {error && <p className="auth-error" role="alert">{error}</p>}
        <button className="button button-primary" disabled={busy}>
          {busy ? (signup ? "Creating account…" : "Signing in…") : (signup ? "Create account" : "Sign in")}</button>
        {signupEnabled && (
          <p className="auth-switch">
            {signup
              ? <>Already have an account? <button type="button" className="link-button" onClick={() => switchMode("signin")}>Sign in</button></>
              : <>New here? <button type="button" className="link-button" onClick={() => switchMode("signup")}>Create an account</button></>}
          </p>
        )}
      </form>
    </main>
  );
}

function ChangePassword({ required, onDone, onCancel }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    if (next !== repeat) { setError("The new passwords do not match."); return; }
    setBusy(true);
    setError("");
    try {
      await api("/api/auth/password", "POST", { current_password: current, new_password: next });
      onDone();
    } catch (failure) {
      setError(failure.message);
    } finally {
      setBusy(false);
    }
  }

  const form = (
    <form className="auth-card" onSubmit={submit}>
      <h2><KeyRound size={18} /> {required ? "Choose a new password" : "Change password"}</h2>
      {required && <p className="auth-note">Your account has a temporary password. Choose your own to continue.</p>}
      <label>Current password<input type="password" autoComplete="current-password" value={current} required
        onChange={(event) => setCurrent(event.target.value)} /></label>
      <label>New password (12+ characters)<input type="password" autoComplete="new-password" value={next} required
        minLength={12} onChange={(event) => setNext(event.target.value)} /></label>
      <label>Repeat new password<input type="password" autoComplete="new-password" value={repeat} required
        onChange={(event) => setRepeat(event.target.value)} /></label>
      {error && <p className="auth-error" role="alert">{error}</p>}
      <div className="auth-actions">
        {onCancel && <button type="button" className="button button-ghost" onClick={onCancel}>Cancel</button>}
        <button className="button button-primary" disabled={busy}>{busy ? "Saving…" : "Save password"}</button>
      </div>
    </form>
  );
  return required ? <main className="auth-page">{form}</main>
    : <div className="modal-backdrop" role="dialog" aria-modal="true">{form}</div>;
}

function AdminUsers({ me, onClose }) {
  const [data, setData] = useState({ users: [], roles: [], statuses: [] });
  const [runs, setRuns] = useState([]);
  const [message, setMessage] = useState("");
  const [draft, setDraft] = useState({ email: "", display_name: "", user_role: "ANALYST", temporary_password: "" });

  const load = useCallback(async () => {
    try {
      setData(await api("/api/admin/users"));
      setRuns((await api("/api/admin/runs")).runs || []);
    } catch (failure) {
      setMessage(failure.message);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function act(action, success) {
    setMessage("");
    try {
      await action();
      setMessage(success);
      await load();
    } catch (failure) {
      setMessage(failure.message);
    }
  }

  function resetPassword(user) {
    const temporary = window.prompt(`Temporary password for ${user.email} (12+ characters). They must change it at sign-in.`);
    if (temporary) {
      act(() => api(`/api/admin/users/${user.user_id}/password`, "POST", { temporary_password: temporary }),
        `Password reset for ${user.email}; their sessions were signed out.`);
    }
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Users">
      <section className="modal-card admin-card">
        <div className="admin-head">
          <h2><Users size={18} /> Users and sessions</h2>
          <button className="button button-ghost button-small" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>
        {message && <p className="auth-note">{message}</p>}
        <table className="admin-table">
          <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Sessions</th><th>Last sign-in</th><th /></tr></thead>
          <tbody>
            {data.users.map((user) => (
              <tr key={user.user_id}>
                <td><strong>{user.display_name || user.email}</strong><small>{user.email}</small>
                  {user.must_change_password && <small className="admin-flag">must change password</small>}</td>
                <td><select value={user.user_role} onChange={(event) => act(
                  () => api(`/api/admin/users/${user.user_id}`, "PATCH", { user_role: event.target.value }),
                  `${user.email} is now ${event.target.value}.`)}>
                  {data.roles.map((role) => <option key={role}>{role}</option>)}</select></td>
                <td><select value={user.status} onChange={(event) => act(
                  () => api(`/api/admin/users/${user.user_id}`, "PATCH", { status: event.target.value }),
                  `${user.email} is now ${event.target.value}.`)}>
                  {data.statuses.map((status) => <option key={status}>{status}</option>)}</select></td>
                <td>{user.active_sessions}</td>
                <td>{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "—"}</td>
                <td className="admin-row-actions">
                  <button className="button button-ghost button-small" onClick={() => resetPassword(user)}>Reset password</button>
                  <button className="button button-ghost button-small" disabled={!user.active_sessions}
                    onClick={() => act(() => api(`/api/admin/users/${user.user_id}/sessions/revoke`, "POST"),
                      `Signed out ${user.email}${user.user_id === me.user_id ? " (other sessions)" : ""}.`)}>
                    Sign out</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <form className="admin-create" onSubmit={(event) => {
          event.preventDefault();
          act(() => api("/api/admin/users", "POST", draft), `Created ${draft.email}; they must change the temporary password.`)
            .then(() => setDraft({ email: "", display_name: "", user_role: "ANALYST", temporary_password: "" }));
        }}>
          <h3><UserPlus size={16} /> Add a user</h3>
          <input placeholder="E-mail" type="email" required value={draft.email}
            onChange={(event) => setDraft({ ...draft, email: event.target.value })} />
          <input placeholder="Name" value={draft.display_name}
            onChange={(event) => setDraft({ ...draft, display_name: event.target.value })} />
          <select value={draft.user_role} onChange={(event) => setDraft({ ...draft, user_role: event.target.value })}>
            {(data.roles.length ? data.roles : ["ANALYST"]).map((role) => <option key={role}>{role}</option>)}</select>
          <input placeholder="Temporary password (12+)" type="password" required minLength={12} autoComplete="new-password"
            value={draft.temporary_password} onChange={(event) => setDraft({ ...draft, temporary_password: event.target.value })} />
          <button className="button button-primary button-small">Create</button>
        </form>
        {!!runs.length && (
          <details className="admin-runs"><summary>Recent runs ({runs.length})</summary>
            <table className="admin-table"><thead><tr><th>File</th><th>Started by</th><th>Status</th><th>Started</th></tr></thead>
              <tbody>{runs.slice(0, 30).map((run) => (
                <tr key={run.run_id}><td>{run.source_file_name || "—"}</td>
                  <td>{run.initiated_by || "—"}</td><td>{run.status}</td>
                  <td>{run.started_at ? new Date(run.started_at).toLocaleString() : "—"}</td></tr>))}</tbody></table>
          </details>
        )}
      </section>
    </div>
  );
}

function AuthBar({ me, onSignOut, onPassword, onUsers }) {
  if (!me.auth_enabled) {
    return <div className="auth-bar auth-bar-warning">Sign-in is disabled (AEGIS_AUTH=off): anyone who can reach this server can use it.</div>;
  }
  return (
    <div className="auth-bar">
      <ShieldCheck size={14} />
      <span>{me.user.display_name || me.user.email}</span>
      <span className="auth-role">{me.user.user_role}</span>
      {me.user.user_role === "ADMIN" && (
        <button className="button button-ghost button-small" onClick={onUsers}><Users size={14} /> Users</button>)}
      <button className="button button-ghost button-small" onClick={onPassword}><KeyRound size={14} /> Password</button>
      <button className="button button-ghost button-small" onClick={onSignOut}><LogOut size={14} /> Sign out</button>
    </div>
  );
}

export default function AuthGate({ children }) {
  const [state, setState] = useState({ phase: "loading" });
  const [dialog, setDialog] = useState(null);
  const stateRef = React.useRef("loading");
  stateRef.current = state.phase;

  const refresh = useCallback(async () => {
    try {
      const me = await api("/api/auth/me");
      setState({ phase: me.must_change_password ? "change" : "ready", me });
    } catch {
      let usersExist = null;
      let signupEnabled = false;
      try {
        const status = await api("/api/auth/status");
        usersExist = status.users_exist;
        signupEnabled = Boolean(status.signup_enabled);
      } catch { /* offline */ }
      setState({ phase: "signin", usersExist, signupEnabled });
    }
  }, []);

  useEffect(() => {
    refresh();
    const onUnauthorized = () => { if (stateRef.current === "ready") refresh(); };
    window.addEventListener("aegis-unauthorized", onUnauthorized);
    return () => window.removeEventListener("aegis-unauthorized", onUnauthorized);
  }, [refresh]);

  async function signOut() {
    try { await api("/api/auth/logout", "POST"); } catch { /* already signed out */ }
    setDialog(null);
    refresh();
  }

  if (state.phase === "loading") return <main className="auth-page"><p className="auth-note">Loading…</p></main>;
  if (state.phase === "signin") {
    return <SignIn usersExist={state.usersExist} signupEnabled={state.signupEnabled}
      onSignedIn={(me) => setState({ phase: me.must_change_password ? "change" : "ready", me })} />;
  }
  if (state.phase === "change") return <ChangePassword required onDone={refresh} />;
  return (
    <>
      <AuthBar me={state.me} onSignOut={signOut} onPassword={() => setDialog("password")} onUsers={() => setDialog("users")} />
      {children}
      {dialog === "password" && <ChangePassword onDone={() => setDialog(null)} onCancel={() => setDialog(null)} />}
      {dialog === "users" && <AdminUsers me={state.me.user} onClose={() => setDialog(null)} />}
    </>
  );
}
