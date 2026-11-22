/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#05070C',
          card: 'rgba(17, 24, 39, 0.7)',
          border: 'rgba(51, 65, 85, 0.3)',
          glow: '#00F0FF',
          accent: '#F000FF',
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444'
        }
      },
    },
  },
  plugins: [],
}
