/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyberBlack: '#050505',
        cyberCyan: '#00ffff',
        cyberPink: '#ff007f',
        cyberYellow: '#fcee0a',
      },
    },
  },
  plugins: [],
}