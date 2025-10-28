// Search functionality for EMINA anime website
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('search-input');
    const searchButton = document.getElementById('search-button');

    if (!searchInput || !searchButton) return;

    // All anime data with Flask template URLs
    const animeData = [
        { title: 'Attack on Titan', url: '/attack.html', img: '/static/attack.jpg' },
        { title: 'Naruto', url: '/naruto.html', img: '/static/naruto.jpg' },
        { title: 'One Piece', url: '/onepiece.html', img: '/static/One.jpg' },
        { title: 'Demon Slayer', url: '/demon.html', img: '/static/demon.jpg' },
        { title: 'Fullmetal Alchemist', url: '/metal.html', img: '/static/metal.jpg' },
        { title: 'Bleach', url: '/bleach.html', img: '/static/bleach.jpg' },
        { title: 'Dragon Ball Super: Broly', url: '/broly.html', img: '/static/dragon.jpg' },
        { title: 'Dragon Ball Super: Super Hero', url: '/superhero.html', img: '/static/Drag.jpg' },
        { title: 'Demon Slayer: Mugen Train', url: '/mugen.html', img: '/static/Mdemon.jpg' }
    ];

    // Check if we're on home page or episode page
    const animeGrid = document.querySelector('.anime-grid');
    const isHomePage = animeGrid !== null && animeGrid.children.length > 0;

    if (isHomePage) {
        // HOME PAGE SEARCH
        const searchResults = document.getElementById('search-results');
        const noResults = document.getElementById('no-results');

        function performHomeSearch() {
            const query = searchInput.value.toLowerCase().trim();
            if (query === '') {
                animeGrid.style.display = 'grid';
                searchResults.style.display = 'none';
                noResults.style.display = 'none';
                return;
            }

            const results = animeData.filter(anime =>
                anime.title.toLowerCase().includes(query)
            );

            animeGrid.style.display = 'none';

            if (results.length > 0) {
                searchResults.innerHTML = '';
                searchResults.style.display = 'grid';
                noResults.style.display = 'none';

                results.forEach(anime => {
                    const item = document.createElement('div');
                    item.className = 'anime-grid-item';
                    item.innerHTML = `
                        <a href="${anime.url}"><img src="${anime.img}" alt="${anime.title}"></a>
                        <a href="${anime.url}">${anime.title}</a>
                    `;
                    searchResults.appendChild(item);
                });
            } else {
                searchResults.style.display = 'none';
                noResults.style.display = 'block';
            }
        }

        searchButton.addEventListener('click', performHomeSearch);
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') performHomeSearch();
        });
        searchInput.addEventListener('input', performHomeSearch);

    } else {
        // EPISODE PAGE SEARCH (with overlay)
        let searchOverlay = document.getElementById('search-overlay');
        if (!searchOverlay) {
            searchOverlay = document.createElement('div');
            searchOverlay.className = 'search-overlay';
            searchOverlay.id = 'search-overlay';
            searchOverlay.innerHTML = `
                <span class="close-search" id="close-search">&times;</span>
                <div class="search-overlay-content">
                    <h2 style="color: white; text-align: center;">Search Results</h2>
                    <div class="search-results" id="search-results"></div>
                    <p class="no-results" id="no-results">No results found.</p>
                </div>
            `;
            document.body.appendChild(searchOverlay);
        }

        const closeSearch = document.getElementById('close-search');
        const searchResults = document.getElementById('search-results');
        const noResults = document.getElementById('no-results');

        function performOverlaySearch() {
            const query = searchInput.value.toLowerCase().trim();
            if (query === '') return;

            const results = animeData.filter(anime =>
                anime.title.toLowerCase().includes(query)
            );

            searchOverlay.classList.add('active');
            document.body.style.overflow = 'hidden';

            if (results.length > 0) {
                searchResults.innerHTML = '';
                noResults.classList.remove('show');

                results.forEach(anime => {
                    const item = document.createElement('div');
                    item.className = 'anime-grid-item';
                    item.innerHTML = `
                        <a href="${anime.url}"><img src="${anime.img}" alt="${anime.title}"></a>
                        <a href="${anime.url}">${anime.title}</a>
                    `;
                    searchResults.appendChild(item);
                });
            } else {
                searchResults.innerHTML = '';
                noResults.classList.add('show');
            }
        }

        function closeSearchOverlay() {
            searchOverlay.classList.remove('active');
            document.body.style.overflow = 'auto';
            searchInput.value = '';
            noResults.classList.remove('show');
        }

        searchButton.addEventListener('click', performOverlaySearch);
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') performOverlaySearch();
        });

        closeSearch.addEventListener('click', closeSearchOverlay);
        searchOverlay.addEventListener('click', function(e) {
            if (e.target === searchOverlay) closeSearchOverlay();
        });

        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && searchOverlay.classList.contains('active')) {
                closeSearchOverlay();
            }
        });
    }
});