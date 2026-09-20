// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// Deployed under the marketing site at /palisade/docs/ on GitHub Pages.
export default defineConfig({
  site: "https://arpankernel.github.io",
  base: "/palisade/docs",
  trailingSlash: "always",
  outDir: "./dist",
  integrations: [
    starlight({
      title: "Palisade",
      description:
        "Applied agentic-safety infrastructure - detects, evaluates, and gates untrusted-input → model → dangerous-capability paths in Python and JS/TS.",
      tagline: "Applied agentic-safety infrastructure.",
      logo: { src: "./src/assets/logo.svg", replacesTitle: false },
      social: { github: "https://github.com/arpankernel/palisade" },
      customCss: ["./src/styles/theme.css"],
      editLink: {
        baseUrl: "https://github.com/arpankernel/palisade/edit/main/docs-site/",
      },
      components: {
        SiteTitle: "./src/components/SiteTitle.astro",
      },
      sidebar: [
        { label: "Start here", items: [
          { label: "Overview", link: "/" },
          { label: "Getting started", slug: "getting-started" },
          { label: "End-to-end tutorial", slug: "tutorial" },
        ]},
        { label: "Reference", items: [
          { label: "Architecture", slug: "architecture" },
          { label: "CLI reference", slug: "cli-reference" },
          { label: "Rules reference", slug: "rules-reference" },
        ]},
        { label: "Going further", items: [
          { label: "For AI agents", slug: "agents" },
          { label: "Proof scans", slug: "proof-scans" },
          { label: "Roadmap", slug: "roadmap" },
        ]},
      ],
    }),
  ],
});
