import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

// Light / dark theme. With no saved choice the system setting decides (theme-tokens.css);
// the toggle saves the user's choice in this browser and sets <html data-theme>.
const KEY = "aegis-theme";

function saved() {
  try {
    const value = window.localStorage.getItem(KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

function systemTheme() {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

// Called before the first render so the page never flashes the wrong theme.
export function applySavedTheme() {
  const value = saved();
  if (value) document.documentElement.dataset.theme = value;
}

export function ThemeToggle() {
  const [theme, setTheme] = useState(() => saved() || systemTheme());

  useEffect(() => {
    if (saved()) return undefined;
    // No saved choice: follow the system when it changes.
    const query = window.matchMedia?.("(prefers-color-scheme: dark)");
    const follow = (event) => setTheme(event.matches ? "dark" : "light");
    query?.addEventListener?.("change", follow);
    return () => query?.removeEventListener?.("change", follow);
  }, []);

  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.dataset.theme = next;
    try { window.localStorage.setItem(KEY, next); } catch { /* private mode: not remembered */ }
  }

  const dark = theme === "dark";
  return (
    <button type="button" className="theme-toggle" onClick={toggle}
      aria-label={dark ? "Switch to light mode" : "Switch to dark mode"} title={dark ? "Light mode" : "Dark mode"}>
      {dark ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}
