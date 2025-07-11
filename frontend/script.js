// Add GSAP library
document.addEventListener('DOMContentLoaded', function() {
    // Load GSAP library
    const gsapScript = document.createElement('script');
    gsapScript.src = 'https://cdnjs.cloudflare.com/ajax/libs/gsap/3.11.4/gsap.min.js';
    gsapScript.onload = function() {
        initCircleAnimation();
    };
    document.head.appendChild(gsapScript);

    // Add this to your script.js file
    window.addEventListener('load', function() {
        const headshot = new Image();
        headshot.onload = function() {
            document.querySelector('.picture-resume img').src = this.src;
        };
        headshot.src = '/headshot.jpeg';
    });
    
    // Initialize the visitor counter
    initVisitorCounter();
});

// Function to initialize circle animation
function initCircleAnimation() {
    // Make sure GSAP is loaded
    if (typeof gsap === 'undefined') {
        console.error('GSAP library not loaded');
        return;
    }
    
    function randomBetween(min, max) {
        var number = Math.floor(Math.random() * (max - min + 1) + min);
        return number !== 0 ? number : 0.5;
    }
    
    const timeline = gsap.timeline();
    
    // Animate each bubble
    for (let i = 0; i < 10; i++) {
        const bubble = document.querySelector('.bubble' + i);
        if (bubble) {
            const tween = gsap.to(bubble, {
                x: randomBetween(12, 15) * (randomBetween(-1, 1)),
                y: randomBetween(12, 15) * (randomBetween(-1, 1)),
                duration: randomBetween(1, 1.5),
                repeat: -1,
                repeatDelay: randomBetween(0.2, 0.5),
                yoyo: true,
                ease: "elastic.out(1,0.5)"
            });
            
            timeline.add(tween, (i + 1) / 0.6);
        }
    }
    
    timeline.seek(50);
}

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Load the Inter font
    const fontLink = document.createElement('link');
    fontLink.href = 'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap';
    fontLink.rel = 'stylesheet';
    document.head.appendChild(fontLink);
    
    // Set the intro text
    const aboutDiv = document.getElementById('mainDiv');
    if (aboutDiv) {
        aboutDiv.textContent = 'Data & Marketing Technology Leader';
    }
    
    // Add smooth scrolling effect
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 40,
                    behavior: 'smooth'
                });
            }
        });
    });
    
    // Add intersection observer for fade-in effect
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1
    });
    
    // Apply fade-in to section headers and company names
    document.querySelectorAll('.section_header, .company_name').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
        observer.observe(el);
    });
    
    // Add the CSS for the visible class
    const style = document.createElement('style');
    style.textContent = `
        .visible {
            opacity: 1 !important;
            transform: translateY(0) !important;
        }
    `;
    document.head.appendChild(style);
    
    // Detect and highlight skills
    const skillTerms = ['SQL', 'Python', 'AWS', 'GCP', 'CDP', 'CMS', 'ESP', 'CRM'];
    
    // Create tooltip functionality
    const tooltip = document.createElement('div');
    tooltip.style.cssText = `
        position: absolute;
        background-color: #000;
        color: white;
        padding: 10px 15px;
        border-radius: 3px;
        font-size: 0.85rem;
        opacity: 0;
        transform: translateY(10px);
        transition: opacity 0.3s ease, transform 0.3s ease;
        pointer-events: none;
        z-index: 100;
        max-width: 250px;
    `;
    document.body.appendChild(tooltip);
    
    function showTooltip(text, event) {
        tooltip.textContent = text;
        tooltip.style.opacity = '1';
        tooltip.style.transform = 'translateY(0)';
        
        const rect = event.target.getBoundingClientRect();
        const tooltipHeight = tooltip.offsetHeight;
        
        tooltip.style.left = `${rect.left}px`;
        tooltip.style.top = `${rect.top - tooltipHeight - 10 + window.scrollY}px`;
    }
    
    function hideTooltip() {
        tooltip.style.opacity = '0';
        tooltip.style.transform = 'translateY(10px)';
    }
    
    // Process document text nodes to find and highlight skills
    function processNode(node) {
        if (node.nodeType === Node.TEXT_NODE) {
            let replaced = false;
            let html = node.nodeValue;
            
            skillTerms.forEach(term => {
                const regex = new RegExp(`\\b${term}\\b`, 'g');
                if (regex.test(html)) {
                    html = html.replace(regex, `<span class="highlight-skill" data-skill="${term}">${term}</span>`);
                    replaced = true;
                }
            });
            
            if (replaced) {
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = html;
                
                const fragment = document.createDocumentFragment();
                while (tempDiv.firstChild) {
                    fragment.appendChild(tempDiv.firstChild);
                }
                
                node.parentNode.replaceChild(fragment, node);
            }
        } else if (node.nodeType === Node.ELEMENT_NODE && 
                  node.tagName !== 'SCRIPT' && 
                  node.tagName !== 'STYLE' && 
                  !node.classList.contains('highlight-skill')) {
            Array.from(node.childNodes).forEach(child => processNode(child));
        }
    }
    
    // Process all text in the body
    Array.from(document.body.childNodes).forEach(node => {
        processNode(node);
    });
    
    // Add event listeners to highlighted skills
    document.querySelectorAll('.highlight-skill').forEach(el => {
        el.addEventListener('mouseenter', (e) => {
            const skill = e.target.getAttribute('data-skill');
            showTooltip(getSkillDescription(skill), e);
        });
        
        el.addEventListener('mouseleave', hideTooltip);
    });
});

// Function to handle button click
function buttonClicked() {
    // Create modal overlay
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: rgba(0, 0, 0, 0.8);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
        opacity: 0;
        transition: opacity 0.3s ease;
    `;
    
    // Create modal content
    const modalContent = document.createElement('div');
    modalContent.style.cssText = `
        background-color: white;
        padding: 40px;
        max-width: 500px;
        text-align: center;
        transform: translateY(20px);
        transition: transform 0.3s ease;
    `;
    
    // Add content to modal
    modalContent.innerHTML = `
        <h3 style="margin-top: 0; font-size: 24px;">Thank You!</h3>
        <p style="margin-bottom: 25px;">Thank you for viewing my resume. Feel free to contact me at ricardo@ricardot.com</p>
        <button id="close-modal" style="background-color: #000; color: white; border: none; padding: 10px 20px; cursor: pointer;">Close</button>
    `;
    
    // Add modal to body
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
    
    // Force reflow before adding opacity for smooth animation
    var reflow = modal.offsetHeight;
    modal.style.opacity = '1';
    modalContent.style.transform = 'translateY(0)';
    
    // Add close functionality
    document.getElementById('close-modal').addEventListener('click', function() {
        modal.style.opacity = '0';
        modalContent.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            document.body.removeChild(modal);
        }, 300);
    });
}

// Helper function to get skill descriptions
function getSkillDescription(skill) {
    const descriptions = {
        'SQL': 'Database query language used for data analysis and management',
        'Python': 'Programming language for data processing and automation',
        'AWS': 'Amazon Web Services cloud platform for scalable infrastructure',
        'GCP': 'Google Cloud Platform for cloud computing and data analytics',
        'CDP': 'Customer Data Platform for unified customer data management',
        'CMS': 'Content Management System for digital experience delivery',
        'ESP': 'Email Service Provider for marketing automation',
        'CRM': 'Customer Relationship Management system for customer journey optimization'
    };
    
    return descriptions[skill] || `${skill} - Key technical skill`;
}

// AWS-based visitor counter implementation
function initVisitorCounter() {
    const countElement = document.getElementById('visitor-count');
    if (!countElement) return;

    // API Gateway endpoint
    const API_GATEWAY_URL = 'https://jvv54kkyj7.execute-api.us-east-1.amazonaws.com/prod/counter';
    
    // Show loading state
    countElement.textContent = 'Loading...';
    
    // Fetch and update visitor count from AWS
    fetchVisitorCount();
    
    async function fetchVisitorCount() {
        try {
            // Make POST request to increment and get count
            const response = await fetch(API_GATEWAY_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({})
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('API Response:', data); // Debug logging
            
            // Handle double-wrapped response from API Gateway
            let count;
            if (data.body) {
                // API Gateway is wrapping the response
                const innerData = JSON.parse(data.body);
                count = innerData.count;
            } else if (data.count !== undefined) {
                // Direct response from Lambda
                count = data.count;
            } else {
                throw new Error('Invalid response format');
            }
            
            // Update the counter display
            if (count !== undefined) {
                countElement.textContent = formatNumber(count);
            } else {
                throw new Error('Count not found in response');
            }
            
        } catch (error) {
            console.error('Error fetching visitor count:', error);
            countElement.textContent = 'Error loading count';
            
            // Optional: Retry after 5 seconds
            setTimeout(() => {
                countElement.textContent = 'Retrying...';
                fetchVisitorCount();
            }, 5000);
        }
    }
    
    // Function to format the number with commas for thousands
    function formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
}