import type { ReactNode } from "react";

/**
 * Layout shared by the privacy policy and the terms: a back link, a title,
 * a date, then numbered sections read straight from the locale's strings
 * (`sections` arrays in landing.privacy_policy / landing.terms), so the text
 * lives in packages/i18n-strings like every other user-facing sentence.
 */
export interface LegalSection {
  /**
   * Stable name for a section a page attaches content to ("privacy",
   * "contact"). Positions differ the moment one locale gains or loses a
   * section; ids don't. scripts/test-landing-honesty.mjs checks every locale
   * has the same sections with the same ids.
   */
  id?: string;
  title: string;
  paragraphs?: string[];
  items?: string[];
  after?: string[];
}

interface LegalDocumentProps {
  backHref: string;
  backLabel: string;
  backArrow: string;
  title: string;
  updated: string;
  intro?: string;
  sections: LegalSection[];
  /** Extra content rendered inside the section with this id (e.g. contact details). */
  slots?: Readonly<Record<string, ReactNode>>;
}

const body: React.CSSProperties = { fontSize: 15, lineHeight: 1.8, color: "#94a3b8" };

export function LegalDocument({ backHref, backLabel, backArrow, title, updated, intro, sections, slots = {} }: LegalDocumentProps) {
  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh" }}>
      <main style={{ maxWidth: 760, margin: "0 auto", padding: "60px 24px" }}>
        <a href={backHref} style={{ color: "#60a5fa", fontSize: 14, textDecoration: "none" }}>
          {backArrow} {backLabel}
        </a>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: "#f8fafc", margin: "24px 0 8px" }}>{title}</h1>
        <p style={{ color: "#64748b", marginBottom: intro ? 20 : 40 }}>{updated}</p>
        {intro && <p style={{ ...body, marginBottom: 40 }}>{intro}</p>}

        {sections.map((section) => (
          <section key={section.title} id={section.id} style={{ marginBottom: 32 }}>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: "#f8fafc", marginBottom: 12 }}>{section.title}</h2>
            <div style={body}>
              {section.paragraphs?.map((text) => <p key={text} style={{ margin: "0 0 12px" }}>{text}</p>)}
              {section.items && section.items.length > 0 && (
                <ul style={{ paddingInlineStart: 20, margin: "0 0 12px" }}>
                  {section.items.map((text) => <li key={text} style={{ marginBottom: 4 }}>{text}</li>)}
                </ul>
              )}
              {section.after?.map((text) => <p key={text} style={{ margin: "0 0 12px" }}>{text}</p>)}
              {section.id ? slots[section.id] : null}
            </div>
          </section>
        ))}
      </main>
    </div>
  );
}
