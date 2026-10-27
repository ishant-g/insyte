import { useNavigate } from "@tanstack/react-router";
import { Check, LogOut, Moon, Palette, Sun, User as UserIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/lib/auth";
import { useTheme, type ThemeStyle } from "@/lib/theme";

const STYLES: { value: ThemeStyle; label: string; hint: string }[] = [
  { value: "minimal", label: "Minimal", hint: "Monochrome, flat, tight" },
  { value: "refined", label: "Vibrant", hint: "Accented, rounded, soft" },
];

export function ThemeControls() {
  const { mode, style, toggleMode, setStyle } = useTheme();

  return (
    <div className="flex items-center gap-1">
      <Button
        variant="ghost"
        size="icon"
        className="h-8 w-8"
        onClick={toggleMode}
        aria-label={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        title={mode === "dark" ? "Light mode" : "Dark mode"}
      >
        {mode === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </Button>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="Change style" title="Style">
            <Palette className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          <DropdownMenuLabel>Interface style</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {STYLES.map((s) => (
            <DropdownMenuItem
              key={s.value}
              onClick={() => setStyle(s.value)}
              className="flex items-start gap-2"
            >
              <Check
                className={`mt-0.5 h-4 w-4 shrink-0 ${style === s.value ? "opacity-100" : "opacity-0"}`}
              />
              <span className="flex flex-col">
                <span className="text-sm">{s.label}</span>
                <span className="text-xs text-muted-foreground">{s.hint}</span>
              </span>
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

export function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const initials = (user?.display_name || user?.email || "?")
    .slice(0, 2)
    .toUpperCase();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 rounded-full bg-muted text-xs font-semibold"
          aria-label="Account menu"
        >
          {initials}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="flex flex-col gap-0.5">
          <span className="flex items-center gap-1.5 text-sm">
            <UserIcon className="h-3.5 w-3.5" />
            {user?.display_name || "Account"}
          </span>
          <span className="truncate text-xs font-normal text-muted-foreground">{user?.email}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => navigate({ to: "/settings" })}>Settings</DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => {
            logout();
            navigate({ to: "/login" });
          }}
          className="text-destructive focus:text-destructive"
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
