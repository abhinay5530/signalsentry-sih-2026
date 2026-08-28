/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["IBM Plex Sans", "ui-sans-serif", "system-ui"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      colors: {
        soc: {
          bg: "#070b12",
          panel: "#0d1522",
          border: "#1c2a3d",
          muted: "#8aa0b8",
          cyan: "#3ee0d4",
        },
      },
    },
  },
  plugins: [],
};
