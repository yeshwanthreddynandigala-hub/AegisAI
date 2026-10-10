/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0a0d14',
          card: '#111726',
          border: '#1e293b',
          muted: '#64748b',
          accent: '#0284c7',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
          highlight: '#38bdf8'
        }
      }
    },
  },
  plugins: [],
}
