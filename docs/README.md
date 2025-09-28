# GitHub Pages Website

This directory contains the GitHub Pages website for the AdGuard DNS Kakao AdBlock Filter project.

## Setup Instructions

1. **Enable GitHub Pages**:
   - Go to repository Settings → Pages
   - Source: Deploy from a branch
   - Branch: `main` or `develop`
   - Folder: `/docs`
   - Save settings

2. **Access the Website**:
   - URL: `https://seonghobae.github.io/AdGuardDNS_KakaoAdBlock/`
   - Custom domain can be configured in Settings → Pages

## Files Structure

- `index.html` - Main landing page with bilingual support (Korean/English)
- `404.html` - Custom 404 error page
- `manifest.json` - PWA manifest for mobile app-like experience
- `robots.txt` - Search engine crawling instructions
- `sitemap.xml` - SEO sitemap for search engines

## Features

- ✅ **Responsive Design**: Mobile-first approach with Tailwind CSS
- ✅ **Dark/Light Mode**: Toggle with system preference detection
- ✅ **Korean/English Support**: Complete bilingual interface
- ✅ **Copy-to-Clipboard**: Easy filter URL copying
- ✅ **SEO Optimized**: Meta tags, Open Graph, structured data
- ✅ **PWA Ready**: Manifest file for mobile installation
- ✅ **Accessible**: WCAG compliance with proper ARIA labels
- ✅ **Fast Loading**: CDN resources, optimized images
- ✅ **Modern Design**: Glass morphism, animations, clean typography

## Content Sections

1. **Hero Section**: Project title, filter URL, quick stats
2. **How It Works**: 4-step explanation with icons
3. **Protected Services**: Categorized list of safe domains
4. **Contributing**: Report domains and feature requests
5. **Footer**: Links, statistics, contact information

## Technical Details

- **Framework**: Vanilla HTML/CSS/JS with Tailwind CSS
- **Icons**: Heroicons (inline SVG)
- **Fonts**: Noto Sans KR for Korean text support
- **Animations**: CSS keyframes with Intersection Observer
- **Theme**: Persistent dark mode with localStorage
- **SEO**: Complete meta tags, structured data, sitemap

## Local Development

```bash
# Serve locally
python3 -m http.server 8000 --directory docs

# Visit: http://localhost:8000
```

## Performance Features

- Lazy loading animations
- Optimized images and SVG icons
- Minimal JavaScript footprint
- CDN resources for fast loading
- Progressive enhancement approach

---

**Last Updated**: 2025-09-28
**Version**: 1.0
**License**: MIT