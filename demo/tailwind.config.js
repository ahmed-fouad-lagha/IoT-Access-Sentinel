/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                sentinel: {
                    dark: '#0f172a',
                    card: '#1e293b',
                    accent: '#3b82f6',
                    success: '#10b981',
                    warning: '#f59e0b',
                    danger: '#ef4444',
                    text: '#f8fafc',
                    muted: '#94a3b8'
                }
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
            }
        },
    },
    plugins: [],
}
