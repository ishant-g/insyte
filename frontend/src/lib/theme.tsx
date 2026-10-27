/**
 * Theme state on two independent axes:
 *
 *   mode:  "light" | "dark"      - the color scheme (white vs. dark)
 *   style: "minimal" | "refined" - the visual treatment
 *
 * Both are applied as classes on <html> (`dark`, `style-minimal` /
 * `style-refined`) and persisted to localStorage. A tiny inline script in
 * the document head (see `themeInitScript`) applies the stored choice before
 * React hydrates, so there is no light-on-dark flash on load.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type ThemeMode = "light" | "dark";
export type ThemeStyle = "minimal" | "refined";

const MODE_KEY = "insyte.theme.mode";
const STYLE_KEY = "insyte.theme.style";

interface ThemeContextValue {
  mode: ThemeMode;
  style: ThemeStyle;
  setMode: (mode: ThemeMode) => void;
  toggleMode: () => void;
  setStyle: (style: ThemeStyle) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

/** Inline, self-contained script executed in <head> before first paint. */
export const themeInitScript = `(function(){try{
  var m=localStorage.getItem("${MODE_KEY}");
  if(m!=="light"&&m!=="dark"){m=window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";}
  var s=localStorage.getItem("${STYLE_KEY}");
  if(s!=="minimal"&&s!=="refined"){s="refined";}
  var el=document.documentElement;
  el.classList.toggle("dark",m==="dark");
  el.classList.remove("style-minimal","style-refined");
  el.classList.add("style-"+s);
  el.style.colorScheme=m;
}catch(e){}})();`;

function applyToDocument(mode: ThemeMode, style: ThemeStyle) {
  if (typeof document === "undefined") return;
  const el = document.documentElement;
  // Briefly enable cross-fade transitions so the theme change feels smooth
  // instead of snapping (see .theme-anim in styles.css).
  el.classList.add("theme-anim");
  window.setTimeout(() => el.classList.remove("theme-anim"), 400);
  el.classList.toggle("dark", mode === "dark");
  el.classList.remove("style-minimal", "style-refined");
  el.classList.add(`style-${style}`);
  el.style.colorScheme = mode;
}

function readStored<T extends string>(key: string, allowed: T[], fallback: T): T {
  if (typeof localStorage === "undefined") return fallback;
  try {
    const v = localStorage.getItem(key) as T | null;
    return v && allowed.includes(v) ? v : fallback;
  } catch {
    return fallback;
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  // SSR renders the default; the inline script has already set the real
  // classes on <html>, and the effect below re-syncs after hydration.
  const [mode, setModeState] = useState<ThemeMode>("light");
  const [style, setStyleState] = useState<ThemeStyle>("refined");

  useEffect(() => {
    const initialMode = readStored<ThemeMode>(MODE_KEY, ["light", "dark"], "light");
    const initialStyle = readStored<ThemeStyle>(STYLE_KEY, ["minimal", "refined"], "refined");
    setModeState(initialMode);
    setStyleState(initialStyle);
    applyToDocument(initialMode, initialStyle);
  }, []);

  const setMode = useCallback(
    (next: ThemeMode) => {
      setModeState(next);
      applyToDocument(next, style);
      try {
        localStorage.setItem(MODE_KEY, next);
      } catch {
        /* storage disabled */
      }
    },
    [style],
  );

  const setStyle = useCallback(
    (next: ThemeStyle) => {
      setStyleState(next);
      applyToDocument(mode, next);
      try {
        localStorage.setItem(STYLE_KEY, next);
      } catch {
        /* storage disabled */
      }
    },
    [mode],
  );

  const toggleMode = useCallback(() => {
    setMode(mode === "dark" ? "light" : "dark");
  }, [mode, setMode]);

  const value = useMemo<ThemeContextValue>(
    () => ({ mode, style, setMode, toggleMode, setStyle }),
    [mode, style, setMode, toggleMode, setStyle],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within <ThemeProvider>");
  return ctx;
}
