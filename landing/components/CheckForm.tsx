"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, type CSSProperties, type FormEvent } from "react";

import { toCheckHost } from "@/lib/check-host";
import { localePath } from "@/lib/locale-path";

/**
 * The "is this site safe?" box on /check and under every scorecard.
 *
 * The browser reduces whatever was typed or pasted to the site's name
 * (lib/check-host.ts) and goes straight to /check/<name>: a pasted link's
 * path, query and whatever they carry never leave the device, which is what
 * the hero, the FAQ and the privacy policy promise.
 *
 * So the form must never submit natively. A GET form with a named input sent
 * the whole link as `?q=` whenever someone pressed the button before the page
 * hydrated — on a slow phone connection, easily. The input has no name, the
 * form no action, and the button stays disabled (which also blocks Enter)
 * until React has attached the handler.
 *
 * Labels come in as props, so this adds no namespace to the client bundle.
 */
interface CheckFormProps {
  readonly locale: string;
  readonly placeholder: string;
  readonly label: string;
  readonly submit: string;
  /** Shown when the input holds no site name. */
  readonly invalid: string;
  /** The page was opened with a `?q=` that holds no site name. */
  readonly initiallyInvalid?: boolean;
  readonly variant?: "large" | "compact";
  readonly autoFocus?: boolean;
}

const INPUT: Record<"large" | "compact", CSSProperties> = {
  large: { flex: 1, minWidth: 0, padding: "14px 18px", borderRadius: 10, border: "1px solid #334155", background: "#1e293b", color: "#e2e8f0", fontSize: 16, outline: "none" },
  compact: { flex: 1, minWidth: 0, padding: "10px 14px", borderRadius: 8, border: "1px solid #334155", background: "#0f172a", color: "#e2e8f0", fontSize: 14, outline: "none" },
};

const BUTTON: Record<"large" | "compact", CSSProperties> = {
  large: { background: "#22c55e", color: "#052e16", border: "none", padding: "14px 24px", borderRadius: 10, fontWeight: 700, fontSize: 16, cursor: "pointer" },
  compact: { background: "#3b82f6", color: "white", border: "none", padding: "10px 20px", borderRadius: 8, fontWeight: 600, cursor: "pointer" },
};

const FORM: Record<"large" | "compact", CSSProperties> = {
  large: { display: "flex", gap: 8 },
  compact: { display: "flex", gap: 8, maxWidth: 400, margin: "0 auto" },
};

export default function CheckForm({
  locale,
  placeholder,
  label,
  submit,
  invalid,
  initiallyInvalid = false,
  variant = "large",
  autoFocus = false,
}: CheckFormProps) {
  const router = useRouter();
  const input = useRef<HTMLInputElement>(null);
  const [ready, setReady] = useState(false);
  const [showInvalid, setShowInvalid] = useState(initiallyInvalid);

  useEffect(() => setReady(true), []);

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const host = toCheckHost(input.current?.value);
    setShowInvalid(host === null);
    if (host) router.push(localePath(locale, `/check/${host}`));
  };

  return (
    <div>
      <form onSubmit={onSubmit} style={FORM[variant]}>
        {/* aria-label: placeholder text alone disappears on focus and isn't
            read by some screen readers. No `name`: nothing here is ever
            submitted as a form field. */}
        <input
          ref={input}
          placeholder={placeholder}
          aria-label={label}
          aria-invalid={showInvalid}
          autoFocus={autoFocus}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          inputMode="url"
          style={INPUT[variant]}
        />
        <button type="submit" disabled={!ready} style={{ ...BUTTON[variant], opacity: ready ? 1 : 0.6 }}>
          {submit}
        </button>
      </form>
      {showInvalid && (
        <p role="alert" data-testid="check-invalid" style={{ color: "#fbbf24", fontSize: 14, margin: "10px 0 0" }}>
          {invalid}
        </p>
      )}
    </div>
  );
}
