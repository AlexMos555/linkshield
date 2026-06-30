import { PLATFORMS, type Platform } from "@/lib/install-urls";

/**
 * Honest multi-platform install row.
 *
 * Live platforms render as clickable green CTAs.
 * Pending platforms render as muted status pills with the queue position
 * ("In review", "Coming this week", etc.) — NEVER as dead links to a store
 * search page that doesn't have us listed yet.
 */
export function InstallButtons({
  platforms = ["chrome", "firefox", "edge", "safari"] as Platform[],
  size = "md",
}: {
  platforms?: Platform[];
  size?: "sm" | "md" | "lg";
}) {
  const sizeClass =
    size === "lg"
      ? "px-6 py-3 text-base"
      : size === "sm"
        ? "px-3 py-1.5 text-xs"
        : "px-5 py-2 text-sm";

  return (
    <div className="flex flex-wrap items-center justify-center gap-2">
      {platforms.map((p) => {
        const info = PLATFORMS[p];
        if (info.available) {
          return (
            <a
              key={p}
              href={info.href}
              className={`${sizeClass} bg-green-500 text-green-950 font-bold rounded-lg hover:bg-green-400 transition`}
            >
              {info.label}
            </a>
          );
        }
        return (
          <span
            key={p}
            aria-disabled="true"
            title={info.status}
            className={`${sizeClass} bg-slate-800 text-slate-400 font-semibold rounded-lg border border-slate-700 cursor-not-allowed flex items-center gap-1.5`}
          >
            <span>{info.label}</span>
            <span className="text-[10px] uppercase tracking-wide text-slate-500">
              {info.status}
            </span>
          </span>
        );
      })}
    </div>
  );
}
