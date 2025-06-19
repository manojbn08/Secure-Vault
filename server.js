// server.js
const express = require('express');
const path = require('path');
const helmet = require('helmet'); // Import helmet

const app = express();
const port = 3000;

// Use Helmet for security headers with a custom Content Security Policy (CSP)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"], // Allow resources from the same origin by default
            scriptSrc: ["'self'", "https://cdn.tailwindcss.com"], // Allow scripts from self and Tailwind CDN
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"], // Allow styles from self, inline styles (for Tailwind's dynamic styles), and Google Fonts CDN
            fontSrc: ["'self'", "https://fonts.gstatic.com"], // Allow fonts from self and Google Fonts CDN (often used by Google Fonts)
            imgSrc: ["'self'", "data:"], // Allow images from self and data URIs (e.g., SVG icons)
            connectSrc: ["'self'"], // Allow connections from self
            objectSrc: ["'none'"], // Disallow <object>, <embed>, and <applet> elements
            upgradeInsecureRequests: [], // Automatically upgrade insecure HTTP requests to HTTPS
        },
    },
    // Disable HSTS only if you are running locally without HTTPS.
    // For production, you should enable HSTS and serve over HTTPS.
    hsts: false, // You might need to set this to false for local development without HTTPS
}));


// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Fallback for any other route to serve index.html (useful for single-page apps)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log('Open your browser and navigate to this address to access the password manager.');
    console.log('If you still see a white screen, check your browser console (F12) for errors.');
});

// Basic error handling for server side
app.on('error', (err) => {
    console.error('Server error:', err);
});

