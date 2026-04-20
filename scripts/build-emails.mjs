#!/usr/bin/env node
/**
 * Pre-render all transactional email templates × 10 locales into static HTML + plaintext.
 *
 * Why pre-render:
 *   - Backend (Python FastAPI) never executes React — it reads the pre-baked files
 *   - CI snapshot tests assert rendered output is stable
 *   - No Node.js runtime needed in the email-sending container
 *
 * Output:
 *   packages/email-templates/out/{template_key}/{locale}.html
 *   packages/email-templates/out/{template_key}/{locale}.txt
 *   packages/email-templates/out/manifest.json  — {subject, preheader, vars} per template
 *
 * Usage: node scripts/build-emails.mjs
 */
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import { render } from "@react-email/render";
import React from "react";

import { TEMPLATES, SUPPORTED_LOCALES } from "../packages/email-templates/src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const OUT_DIR = resolve(__dirname, "../packages/email-templates/out");

// Fixture props — realistic values so rendered HTML is representative.
// Real sends use per-user props; these are for CI snapshots + dev preview.
const FIXTURES = {
  welcome: {
    firstName: "Alex",
    scanInboxUrl: "https://linkshield.example/scan",
    unsubscribeUrl: "https://linkshield.example/u/abc123",
    viewInBrowserUrl: "https://linkshield.example/emails/welcome/abc123",
  },
  receipt: {
    firstName: "Alex",
    planLabel: "Personal (Monthly)",
    amountFormatted: "$4.99",
    nextBillingDate: "May 16, 2026",
    invoiceUrl: "https://linkshield.example/invoices/inv_abc",
    unsubscribeUrl: "https://linkshield.example/u/abc123",
  },
  weekly_report: {
    firstName: "Alex",
    blocksCount: 7,
    checksCount: 1247,
    percentile: 89,
    fullReportUrl: "https://linkshield.example/report/abc",
    unsubscribeUrl: "https://linkshield.example/u/abc123",
  },
  family_invite: {
    inviterName: "Maria",
    acceptUrl: "https://linkshield.example/family/accept/tok_xyz",
    unsubscribeUrl: "https://linkshield.example/u/abc123",
  },
  breach_alert: {
    firstName: "Alex",
    affectedSite: "Acme Cloud (disclosed 2026-03-15)",
    changePasswordUrl: "https://linkshield.example/breach/details",
    unsubscribeUrl: "https://linkshield.example/u/abc123",
  },
  subscription_cancel: {
    firstName: "Alex",
    activeUntil: "June 1, 2026",
    reactivateUrl: "https://linkshield.example/reactivate",
    unsubscribeUrl: "https://linkshield.example/u/abc123",
  },
  granny_mode_invite: {
    familyAdminName: "Alex",
    setupUrl: "https://linkshield.example/setup",
    unsubscribeUrl: "https://linkshield.example/u/abc123",
  },
};

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const manifest = {};
  let written = 0;

  for (const [templateKey, meta] of Object.entries(TEMPLATES)) {
    const fixture = FIXTURES[templateKey];
    if (!fixture) throw new Error(`No fixture for ${templateKey}`);

    manifest[templateKey] = {
      subjects: {},
      fixture_props: fixture,
    };

    for (const locale of SUPPORTED_LOCALES) {
      const props = { locale, ...fixture };
      const element = React.createElement(meta.component, props);

      const html = await render(element, { pretty: true });
      const text = await render(element, { plainText: true });
      const subject = meta.subject(locale, props);

      const templateDir = resolve(OUT_DIR, templateKey);
      await mkdir(templateDir, { recursive: true });

      await writeFile(resolve(templateDir, `${locale}.html`), html);
      await writeFile(resolve(templateDir, `${locale}.txt`), text);

      manifest[templateKey].subjects[locale] = subject;
      written += 2;
    }
  }

  await writeFile(
    resolve(OUT_DIR, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n",
  );

  console.log(`✓ Rendered ${Object.keys(TEMPLATES).length} templates × ${SUPPORTED_LOCALES.length} locales`);
  console.log(`  ${written} HTML+text files → ${OUT_DIR}/`);
  console.log(`  manifest.json written`);
}

main().catch((err) => {
  console.error("build-emails failed:", err);
  process.exit(1);
});
