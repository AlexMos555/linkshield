// TypeScript 6 turns on `noUncheckedSideEffectImports` by default, so a bare
// `import "./globals.css"` must resolve to a declaration. Next's own types
// only declare `*.module.css`; the bundler handles plain stylesheets.
declare module "*.css";
