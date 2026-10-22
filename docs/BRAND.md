# Brand guide

## Identity

**Name:** MCP Maintainer Tools  
**Package and repository:** `mcp-maintainer-tools`  
**Tagline:** Evidence, within reach.  
**Short description:** Source-aware vulnerability and package research for maintainers.

The audience is an open-source maintainer or developer using an MCP client to investigate a dependency or advisory. The identity should feel useful at a terminal, legible in a repository, and careful about what the evidence can establish.

The visual idea is an **evidence frame**: two brackets around three offset records. Brackets provide boundaries; the records represent distinct sources and pieces of context. The symbol communicates collection and inspection. It is not a shield, a certification mark, or a promise of a safe release.

## Original assets

The editable visual sources are self-contained SVG files. They contain vector geometry and system-font text, with accessible `title` and `desc` elements. There are no embedded fonts, external images, scripts, or remote resources. PNG exports of the banner and social card are also supplied. [brand-tokens.json](assets/brand-tokens.json) provides the palette, typography, and naming as reusable values.

| Asset | Size | Use |
| --- | --- | --- |
| [GitHub banner](assets/github-banner.svg) | 1600 × 720 | Repository introduction; dark background. |
| [GitHub banner PNG](assets/github-banner.png) | 1600 × 720 | Raster export for destinations that do not accept SVG. |
| [Dark wordmark](assets/wordmark-dark.svg) | 1040 × 256 | Presentations or documentation on dark surfaces. |
| [Light wordmark](assets/wordmark-light.svg) | 1040 × 256 | Presentations or documentation on light surfaces. |
| [Dark icon](assets/icon-dark.svg) | 192 × 192 | Avatar, navigation, or compact product signature. |
| [Light icon](assets/icon-light.svg) | 192 × 192 | Compact signature on light surfaces. |
| [Social card](assets/social-card.svg) | 1280 × 640 | Editable source for a sharing preview or announcement. |
| [Social card PNG](assets/social-card.png) | 1280 × 640 | Ready-to-upload raster export of the social card. |

The social card is an asset, not evidence that a repository social preview or any external profile has been configured. Use the supplied PNG when a platform does not accept SVG; retain the SVG as the editable source.

## Palette

| Token | Hex | Role |
| --- | --- | --- |
| Ink | `#102025` | Primary background and text on light surfaces. |
| Paper | `#F6F5EE` | Primary light surface and text on Ink. |
| Teal | `#52C6B7` | Structure, labels, and emphasis on Ink. |
| Deep Teal | `#126B65` | Accent text and symbol details on Paper. |
| Lime | `#DCEB88` | Sparse emphasis, used for a record or callout. |
| Muted | `#A5B9B6` | Secondary copy on Ink. |

Computed sRGB contrast ratios for the intended text pairings are: Paper/Ink **15.31:1**, Teal/Ink **8.06:1**, Muted/Ink **8.14:1**, Deep Teal/Paper **5.79:1**, and Ink/Lime **12.97:1**. These are color-pair measurements, not an accessibility certification of every downstream composition.

Use Deep Teal for small text on Paper; the brighter Teal is intended for dark backgrounds. Keep Lime subordinate. Color should reinforce labels, not be the only way to distinguish a successful, failed, or incomplete result.

## Typography and composition

The SVG assets use `Arial, Helvetica, sans-serif` for display and body text, with `DejaVu Sans Mono, Liberation Mono, monospace` for technical labels. These are system-font stacks, so no font files are distributed. Exact glyph rendering may vary by platform.

Keep the project name in title case. Use sentence case for prose and uppercase only for short technical labels. Keep commands, identifiers, paths, and output fields in monospace.

Use a clear hierarchy: project name, a single purpose statement, then supporting evidence. The GitHub banner leaves generous space around its three-line record motif. Avoid crowding the symbol with badges, provider logos, or a second illustration.

## Size and spacing

The symbol is drawn on a 96-unit grid, using 6-unit strokes. Preserve its proportions and the horizontal offsets of its three internal records. Use at least one quarter of the symbol width as clear space when placing it beside unrelated content.

Use the icon at **24 px or larger**. Use the complete wordmark at **520 px or wider** so the tagline remains readable; in smaller layouts, use the icon with a live-text project name. Scale the SVG uniformly. Do not stretch it, redraw its brackets as checkmarks, or apply shadows, gradients, or outlines.

The banner's supporting labels are secondary. In narrow mobile views, the adjacent README text must retain the complete meaning without depending on tiny text inside the image.

## Voice and claims

Write like a careful maintainer: name the source, explain what was returned, and state what remains unknown. Prefer concrete verbs such as query, retrieve, compare, validate, and inspect.

| Prefer | Avoid |
| --- | --- |
| “Seven read-only MCP tools for vulnerability and package research.” | “A complete security platform.” |
| “No matching record was returned by this provider.” | “This package is safe.” |
| “The catalog did not include this CVE at retrieval time.” | “This CVE is not exploited.” |
| “The test suite passed for this revision.” | “Certified secure” or “unhackable.” |
| “Uses public data from OSV, NVD, CISA KEV, FIRST EPSS, and deps.dev.” | Any suggestion that those providers endorse this project. |

Do not use OpenAI, MCP, or provider logos as part of the project mark. The name describes protocol compatibility; it does not imply official affiliation. Do not invent usage, download, contributor, customer, compliance, or audit claims.

## Reuse

Original assets in this repository are distributed under the [MIT License](../LICENSE), alongside the code. Preserve the applicable license notice. This guide does not grant rights to third-party trademarks or data, and does not constitute trademark clearance of the project name.
