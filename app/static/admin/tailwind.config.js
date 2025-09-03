// Tailwind CSS Configuration for Admin Dashboard
tailwind.config = {
    theme: {
        extend: {
            colors: {
                'notion-bg': '#0f0f0f',
                'notion-card': '#1a1a1a',
                'notion-border': '#2a2a2a',
                'notion-text': '#f1f1f1',
                'notion-text-secondary': '#9ca3af',
                'notion-accent': '#1e90ff',
                'notion-accent-hover': '#0066cc',
                'notion-input': '#2a2a2a',
                'notion-hover': '#252525'
            },
            fontFamily: {
                'title': ['Space Grotesk', 'sans-serif'],
                'content': ['Sora', 'sans-serif']
            },
            animation: {
                'fade-in': 'fadeIn 0.3s ease-out',
                'slide-up': 'slideUp 0.4s ease-out',
                'scale-in': 'scaleIn 0.2s ease-out'
            }
        }
    }
};
