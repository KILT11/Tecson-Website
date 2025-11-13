// Favorites functionality for EMINA anime website
(function() {
    'use strict';

    // All anime data - must be kept in sync with the anime cards in your HTML
    // NOTE: This list needs to include ALL anime titles and their paths across your pages.
    const animeData = [
        // TV Series - FIX APPLIED: img value changed to filename only
        { title: 'Attack on Titan', url: '{{ url_for("Attack") }}', img: 'attack.jpg' },
        { title: 'Naruto', url: '{{ url_for("Naruto") }}', img: 'naruto.jpg' },
        { title: 'One Piece', url: '{{ url_for("OnePiece") }}', img: 'One.jpg' },
        { title: 'Demon Slayer', url: '{{ url_for("Demon") }}', img: 'demon.jpg' },
        { title: 'Fullmetal Alchemist', url: '{{ url_for("Metal") }}', img: 'metal.jpg' },
        { title: 'Bleach', url: '{{ url_for("Bleach") }}', img: 'bleach.jpg' },
        // Movies
        { title: 'Dragon Ball Super: Broly', url: '{{ url_for("Broly") }}', img: 'dragon.jpg' },
        { title: 'Dragon Ball Super: Super Hero', url: '{{ url_for("SuperHero") }}', img: 'Drag.jpg' },
        { title: 'Demon Slayer: Kimetsu no Yaiba - The Movie: Mugen Train', url: '{{ url_for("Mugen") }}', img: 'Mdemon.jpg' }
        // Add all your anime here with their correct Flask routes
    ];

    // Notification helper
    function showNotification(message, isSuccess = true) {
        const notification = document.getElementById('notification');
        if (!notification) return;

        notification.textContent = message;
        notification.className = 'notification'; // Reset classes
        notification.classList.add(isSuccess ? 'success' : 'error');
        notification.style.display = 'block';
        notification.style.opacity = '1';

        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => {
                notification.style.display = 'none';
            }, 500);
        }, 3000);
    }

    // Main initialization function
    function init() {
        const dataElement = document.getElementById('favorite-titles-data');
        // Parse favorite titles passed from Flask
        const currentFavorites = dataElement ? JSON.parse(dataElement.textContent) : [];

        // --- Logic for Content Pages (Home, Most, Movie, Series) ---
        const animeCards = document.querySelectorAll('.anime-grid-item');
        animeCards.forEach(card => {
            // Find the anchor element containing the title (usually the last 'a' element)
            const linkElement = card.querySelector('a:last-of-type');
            if (!linkElement) return;

            const title = linkElement.textContent.trim();
            const anime = animeData.find(a => a.title === title);

            if (anime) {
                // 1. Create the favorite button (+)
                const btn = document.createElement('button');
                btn.className = 'favorite-btn';
                btn.innerHTML = '+';
                btn.setAttribute('data-title', anime.title);
                btn.setAttribute('data-url', anime.url);
                // The JS now passes the simple filename
                btn.setAttribute('data-image', anime.img);

                // 2. Check if it's already a favorite and set initial state
                if (currentFavorites.includes(anime.title)) {
                    btn.classList.add('favorited');
                    btn.innerHTML = '★';
                }

                // 3. Attach event listener
                btn.addEventListener('click', (e) => toggleFavorite(e, btn));

                // 4. Append button to the card
                card.appendChild(btn);
            }
        });

        // --- Logic for Profile Page (Remove functionality) ---
        setupRemoveFavoriteListeners();
    }

    // Toggles favorite status on content pages
    async function toggleFavorite(e, btn) {
        e.preventDefault();
        const title = btn.getAttribute('data-title');
        const url = btn.getAttribute('data-url');
        // This is now the simple filename (e.g., 'naruto.jpg')
        const imageFilename = btn.getAttribute('data-image');

        const isFavorited = btn.classList.contains('favorited');
        const apiEndpoint = isFavorited ? '/favorites/remove' : '/favorites/add';
        const method = 'POST';

        // Optimistic UI update
        if (isFavorited) {
            btn.classList.remove('favorited');
            btn.innerHTML = '+';
        } else {
            btn.classList.add('favorited');
            btn.innerHTML = '★';
        }

        try {
            const response = await fetch(apiEndpoint, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                // Send the image FILENAME to app.py
                body: JSON.stringify({ title: title, url: url, image: imageFilename })
            });
            const data = await response.json();

            if (!data.success) {
                // Revert UI on error
                if (isFavorited) {
                    btn.classList.add('favorited');
                    btn.innerHTML = '★';
                } else {
                    btn.classList.remove('favorited');
                    btn.innerHTML = '+';
                }
            }

            showNotification(data.message, data.success);

        } catch (error) {
            console.error('Error toggling favorite:', error);
            showNotification('A network error occurred. Please try again.', false);
             // Revert UI on network error
            if (isFavorited) {
                btn.classList.add('favorited');
                btn.innerHTML = '★';
            } else {
                btn.classList.remove('favorited');
                btn.innerHTML = '+';
            }
        }
    }

    // Setup remove buttons on the profile page
    function setupRemoveFavoriteListeners() {
        const removeButtons = document.querySelectorAll('.remove-favorite-btn');
        removeButtons.forEach(btn => {
            btn.addEventListener('click', async function(e) {
                e.preventDefault();
                const favoriteId = this.getAttribute('data-id');
                const itemElement = document.getElementById(`favorite-${favoriteId}`);

                try {
                    const response = await fetch('/favorites/remove', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ id: favoriteId }) // Remove by ID for Profile page
                    });
                    const data = await response.json();

                    if (data.success) {
                        // Optimistic UI update for profile page
                        itemElement.style.opacity = '0';
                        itemElement.style.transform = 'scale(0.9)';

                        setTimeout(() => {
                            itemElement.remove();

                            // Update count dynamically
                            const countElement = document.querySelector('.favorites-section h3');
                            if (countElement) {
                                const match = countElement.textContent.match(/\d+/);
                                if (match) {
                                    const currentCount = parseInt(match[0]);
                                    countElement.textContent = '⭐ My Favorite Anime (' + (currentCount - 1) + ')';
                                }
                            }

                            // If the grid is empty, prompt a reload to show "No favorites"
                            const favoritesGrid = document.querySelector('.favorites-grid');
                            if (favoritesGrid && favoritesGrid.children.length === 0) {
                                location.reload();
                            }
                        }, 300);

                        showNotification(data.message);
                    } else {
                        showNotification(data.message, false);
                    }
                } catch (error) {
                    console.error('Error removing favorite:', error);
                    showNotification('A network error occurred. Please try again.', false);
                }
            });
        });
    }

    // Wait for DOM to be fully loaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();