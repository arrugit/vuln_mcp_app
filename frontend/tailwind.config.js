/** Tailwind config — dark-first security-engineering aesthetic (UX-001..005).
 * Design tokens adapt the AEGIS foundation: purple accent for primary actions,
 * semantic severity colors (UX-003), Raleway + monospace typography (UX-002).
 * This is a *supporting* UI (UX-007), not a commercial SaaS look.
 */
/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Semantic severity tokens (UX-003)
        severity: {
          critical: "#FF4D5E",
          high: "#FF8A3D",
          medium: "#E6B84A",
          low: "#56A8E8",
          info: "#8C97BE",
        },
        // Team accent colors (UX-004)
        team: {
          red: "#FF5A6A",
          blue: "#56A8E8",
          purple: "#9971B4",
        },
        // Dark-first surface palette
        surface: {
          base: "#0d0b16",
          raised: "#151125",
          border: "#2a2340",
        },
      },
      fontFamily: {
        sans: ["Raleway", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "'Fira Code'", "ui-monospace", "monospace"],
      },
      backgroundImage: {
        "purple-gradient": "linear-gradient(135deg, #9971B4 0%, #6d4a99 100%)",
      },
    },
  },
  plugins: [],
};
