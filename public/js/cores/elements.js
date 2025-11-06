//Scroll link
class ScrollLink extends HTMLElement {
    connectedCallback() {
        this.style.cursor = 'pointer'; // Make it look clickable
        this.addEventListener('click', this.scrollToTarget);

        // Highlight active link when clicked
        this.addEventListener('click', () => {
            this.highlightLink();
        });
    }

    scrollToTarget() {
        const targetId = this.getAttribute('target');
        const timer = parseInt(this.getAttribute('timer'), 10) || 500; // Default to 500ms if not provided
        const offset = parseInt(this.getAttribute('offset'), 10) || 0; // Default to 0 if not provided
        const targetElement = document.getElementById(targetId);
        // alert(offset);
        if (targetElement) {
            //History
            let currentUrl = window.location.href.split('#')[0];
    
    		// Use pushState to update the URL with the new anchor
    		window.history.pushState(null, '', `${currentUrl}#${targetId}`);

            //Get offset
			const header = document.getElementById('header');
            const backMenu = document.querySelector('.back-menu');  // Select the back-menu class
            let offset = 0;

            if (header) {
                offset += header.offsetHeight;
            }

            if (backMenu) {
                offset += backMenu.offsetHeight;
            }

            // alert(offset);

            const startPosition = window.scrollY;
            const targetPosition = targetElement.getBoundingClientRect().top + startPosition - offset;
            const startTime = performance.now();

            const animateScroll = (currentTime) => {
                const elapsedTime = currentTime - startTime;
                const progress = Math.min(elapsedTime / timer, 1);

                window.scrollTo(0, startPosition + (targetPosition - startPosition) * progress);

                if (elapsedTime < timer) {
                    requestAnimationFrame(animateScroll);
                }
            };

            requestAnimationFrame(animateScroll);
        }
    }

    highlightLink() {
        // Remove active class from all scroll-links
        document.querySelectorAll('scroll-link').forEach((link) => {
            link.classList.remove('active');
        });

        // Add active class to this link
        this.classList.add('active');
    }
}

// Define the custom element
customElements.define('scroll-link', ScrollLink);

// Observe sections for manual scrolling
document.addEventListener('DOMContentLoaded', () => {
    const sections = document.querySelectorAll('[id]'); // All sections with an ID
    const links = document.querySelectorAll('scroll-link');

    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    const visibleSectionId = entry.target.id;
                    console.log('here::'+visibleSectionId);
                    // Highlight the corresponding scroll-link
                    links.forEach((link) => {
                        if (link.getAttribute('target') === visibleSectionId) {
                            link.classList.add('active');
                        } else {
                            link.classList.remove('active');
                        }
                    });
                }
            });
        },
        {
            threshold: 0.6, // Adjust this value for when a section is considered "visible"
        }
    );

    sections.forEach((section) => observer.observe(section));
});


//SrollIndicator
class ScrollIndicator extends HTMLElement {
    connectedCallback() {
        this.style.position = 'fixed';
        this.style.top = 0;
        this.style.left = 0;
        this.style.width = '0%';
        this.style.height = '4px';
        this.style.backgroundColor = '#3498db';
        this.style.transition = 'width 0.25s ease';

        window.addEventListener('scroll', () => {
            const scrollTop = window.scrollY;
            const docHeight = document.documentElement.scrollHeight - window.innerHeight;
            const scrolled = (scrollTop / docHeight) * 100;
            this.style.width = scrolled + '%';
        });
    }
}

customElements.define('scroll-indicator', ScrollIndicator);
