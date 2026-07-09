"use client";

import { Moon, Sun } from "lucide-react";

import { useTheme } from "@/hooks/use-theme";

// Both icons are always in the DOM and CSS on [data-theme] decides which one
// shows, so the prerendered HTML is theme-agnostic and hydration never
// mismatches regardless of what the pre-paint script stamped.
export function ThemeToggle() {
  const { toggleTheme } = useTheme();
  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label="Toggle color theme"
      className="ml-1 inline-flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
    >
      <Sun className="hidden h-4 w-4 [[data-theme=light]_&]:block" />
      <Moon className="h-4 w-4 [[data-theme=light]_&]:hidden" />
    </button>
  );
}
