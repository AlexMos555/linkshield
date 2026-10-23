/**
 * "Data sources": the credit the open data asks for (CC BY: who made it, the
 * licence, a link, and that we changed it). The app's Settings → About and the
 * transparency report link here by DATA_SOURCES_ANCHOR. The list itself is
 * landing/lib/data-sources.ts.
 */
import {
  DATA_SOURCES_ANCHOR,
  PHISHING_SOURCES,
  POPULARITY_SOURCES,
  THIRD_PARTY_FEEDS_URL,
  type DataSource,
} from "@/lib/data-sources";

type Translate = (key: string, values?: Record<string, string | number>) => string;

const link: React.CSSProperties = { color: "#60a5fa", textDecoration: "underline" };

// Each Latin name sits in <bdi>, so on the Arabic page the parentheses of
// "crux-top-lists (Zakir Durumeric)" and the separators stay where they belong.
function SourceList({ sources, t }: { sources: readonly DataSource[]; t: Translate }) {
  return (
    <ul style={{ paddingInlineStart: 22 }}>
      {sources.map((source) => (
        <li key={source.id}>
          <bdi><a href={source.url} style={link}>{source.name}</a></bdi>
          {source.by ? <>, <bdi>{source.by}</bdi></> : null}
          {" — "}
          <bdi><a href={source.licenceUrl} style={link}>{source.licence ?? t("sources_terms")}</a></bdi>
          {source.via ? (
            <>
              {` (${t("sources_via")} `}
              <bdi><a href={source.via.url} style={link}>{source.via.name}</a></bdi>
              {")"}
            </>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function DataSources({ t, h2, h3 }: { t: Translate; h2: React.CSSProperties; h3: React.CSSProperties }) {
  return (
    <section id={DATA_SOURCES_ANCHOR} style={{ marginBottom: 36, scrollMarginTop: 24 }}>
      <h2 style={h2}>{t("sources_heading")}</h2>
      <p>{t("sources_intro")}</p>
      <h3 style={h3}>{t("sources_popularity_heading")}</h3>
      {/* Three sentences: the ranking and what we changed in it, the apps'
          lists (from their next releases), the model and its own changes. */}
      <p>
        {t("sources_popularity_body")} {t("sources_popularity_apps")} {t("sources_popularity_model")}
      </p>
      <SourceList sources={POPULARITY_SOURCES} t={t} />
      <h3 style={h3}>{t("sources_phishing_heading")}</h3>
      <p>{t("sources_phishing_body")}</p>
      <SourceList sources={PHISHING_SOURCES} t={t} />
      <p style={{ marginTop: 12 }}>
        {t("sources_full_list")}{" "}
        <a href={THIRD_PARTY_FEEDS_URL} style={link}>docs/THIRD_PARTY_FEEDS.md</a>
      </p>
    </section>
  );
}
