// Comment System for EMINA Anime Website
(function() {
    'use strict';

    let currentEpisodeId = null;
    let editingCommentId = null;

    // Initialize comment system
    function initComments() {
        // Get episode ID from the page (you'll need to set this in your HTML)
        currentEpisodeId = document.body.getAttribute('data-episode-id');

        if (!currentEpisodeId) {
            console.warn('No episode ID found on page');
            return;
        }

        // Set up event listeners
        setupEventListeners();

        // Load comments
        loadComments();
    }

    // Set up all event listeners
    function setupEventListeners() {
        const commentForm = document.getElementById('comment-form');
        const commentTextarea = document.getElementById('comment-textarea');
        const submitBtn = document.getElementById('submit-comment-btn');

        if (commentForm) {
            commentForm.addEventListener('submit', handleCommentSubmit);
        }

        if (commentTextarea) {
            commentTextarea.addEventListener('input', updateCharacterCount);
        }
    }

    // Load all comments for the current episode
    async function loadComments() {
        const commentsList = document.getElementById('comments-list');
        const commentsCount = document.getElementById('comments-count');

        if (!commentsList) return;

        // Show loading state
        commentsList.innerHTML = '<div class="comments-loading"><div class="loading-spinner"></div><p>Loading comments...</p></div>';

        try {
            const response = await fetch(`/api/comments/${currentEpisodeId}`);
            const data = await response.json();

            if (data.success) {
                displayComments(data.comments);

                if (commentsCount) {
                    commentsCount.textContent = data.comments.length;
                }
            } else {
                showNotification('Failed to load comments', 'error');
            }
        } catch (error) {
            console.error('Error loading comments:', error);
            commentsList.innerHTML = '<div class="comments-empty"><p>Error loading comments. Please refresh the page.</p></div>';
        }
    }

    // Display comments in the list
    function displayComments(comments) {
        const commentsList = document.getElementById('comments-list');

        if (!commentsList) return;

        if (comments.length === 0) {
            commentsList.innerHTML = `
                <div class="comments-empty">
                    <div class="comments-empty-icon">💬</div>
                    <h4>No comments yet</h4>
                    <p>Be the first to share your thoughts about this episode!</p>
                </div>
            `;
            return;
        }

        commentsList.innerHTML = comments.map(comment => createCommentHTML(comment)).join('');

        // Attach event listeners to comment action buttons
        attachCommentEventListeners();
    }

    // Create HTML for a single comment
    function createCommentHTML(comment) {
        const isOwnComment = comment.user_id === parseInt(document.body.getAttribute('data-user-id'));
        const initials = comment.user_name.charAt(0).toUpperCase();
        const editedBadge = comment.is_edited ? '<span class="comment-edited">(edited)</span>' : '';

        return `
            <div class="comment-item" data-comment-id="${comment.id}">
                <div class="comment-header">
                    <div class="comment-author">
                        <div class="comment-author-icon">${initials}</div>
                        <div>
                            <span class="comment-author-name">${escapeHtml(comment.user_name)}</span>
                            ${isOwnComment ? '<span class="comment-author-badge">YOU</span>' : ''}
                        </div>
                    </div>
                    <div>
                        <span class="comment-date">${comment.created_at}</span>
                        ${editedBadge}
                    </div>
                </div>
                <div class="comment-content" id="comment-content-${comment.id}">
                    ${escapeHtml(comment.content)}
                </div>
                <div class="comment-edit-form" id="comment-edit-form-${comment.id}" style="display: none;">
                    <textarea id="comment-edit-textarea-${comment.id}">${escapeHtml(comment.content)}</textarea>
                    <div class="comment-edit-actions">
                        <button class="comment-btn" onclick="saveCommentEdit(${comment.id})">Save</button>
                        <button class="comment-btn comment-btn-secondary" onclick="cancelCommentEdit(${comment.id})">Cancel</button>
                    </div>
                </div>
                ${isOwnComment ? `
                    <div class="comment-actions">
                        <button class="comment-action-btn edit" data-comment-id="${comment.id}" data-action="edit">
                            ✏️ Edit
                        </button>
                        <button class="comment-action-btn delete" data-comment-id="${comment.id}" data-action="delete">
                            🗑️ Delete
                        </button>
                    </div>
                ` : ''}
            </div>
        `;
    }

    // Handle comment submission
    async function handleCommentSubmit(e) {
        e.preventDefault();

        const textarea = document.getElementById('comment-textarea');
        const submitBtn = document.getElementById('submit-comment-btn');
        const content = textarea.value.trim();

        if (!content) {
            showNotification('Please enter a comment', 'error');
            return;
        }

        if (content.length > 1000) {
            showNotification('Comment is too long (max 1000 characters)', 'error');
            return;
        }

        // Disable form during submission
        submitBtn.disabled = true;
        submitBtn.textContent = 'Posting...';

        try {
            const response = await fetch(`/api/comments/${currentEpisodeId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content })
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Comment posted successfully!', 'success');
                textarea.value = '';
                updateCharacterCount({ target: textarea });
                loadComments(); // Reload all comments
            } else {
                showNotification(data.message || 'Failed to post comment', 'error');
            }
        } catch (error) {
            console.error('Error posting comment:', error);
            showNotification('Error posting comment. Please try again.', 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Post Comment';
        }
    }

    // Attach event listeners to comment action buttons
    function attachCommentEventListeners() {
        const actionButtons = document.querySelectorAll('.comment-action-btn');

        actionButtons.forEach(btn => {
            btn.addEventListener('click', handleCommentAction);
        });
    }

    // Handle comment actions (edit/delete)
    async function handleCommentAction(e) {
        const commentId = e.currentTarget.getAttribute('data-comment-id');
        const action = e.currentTarget.getAttribute('data-action');

        if (action === 'edit') {
            showEditForm(commentId);
        } else if (action === 'delete') {
            if (confirm('Are you sure you want to delete this comment?')) {
                await deleteComment(commentId);
            }
        }
    }

    // Show edit form for a comment
    function showEditForm(commentId) {
        const contentDiv = document.getElementById(`comment-content-${commentId}`);
        const editForm = document.getElementById(`comment-edit-form-${commentId}`);

        if (contentDiv && editForm) {
            contentDiv.style.display = 'none';
            editForm.style.display = 'block';
            editingCommentId = commentId;
        }
    }

    // Cancel comment edit
    window.cancelCommentEdit = function(commentId) {
        const contentDiv = document.getElementById(`comment-content-${commentId}`);
        const editForm = document.getElementById(`comment-edit-form-${commentId}`);

        if (contentDiv && editForm) {
            contentDiv.style.display = 'block';
            editForm.style.display = 'none';
            editingCommentId = null;
        }
    };

    // Save comment edit
    window.saveCommentEdit = async function(commentId) {
        const textarea = document.getElementById(`comment-edit-textarea-${commentId}`);
        const content = textarea.value.trim();

        if (!content) {
            showNotification('Comment cannot be empty', 'error');
            return;
        }

        if (content.length > 1000) {
            showNotification('Comment is too long (max 1000 characters)', 'error');
            return;
        }

        try {
            const response = await fetch(`/api/comments/${commentId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content })
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Comment updated successfully!', 'success');
                editingCommentId = null;
                loadComments();
            } else {
                showNotification(data.message || 'Failed to update comment', 'error');
            }
        } catch (error) {
            console.error('Error updating comment:', error);
            showNotification('Error updating comment. Please try again.', 'error');
        }
    };

    // Delete comment
    async function deleteComment(commentId) {
        try {
            const response = await fetch(`/api/comments/${commentId}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Comment deleted successfully!', 'success');
                loadComments();
            } else {
                showNotification(data.message || 'Failed to delete comment', 'error');
            }
        } catch (error) {
            console.error('Error deleting comment:', error);
            showNotification('Error deleting comment. Please try again.', 'error');
        }
    }

    // Update character count
    function updateCharacterCount(e) {
        const textarea = e.target;
        const count = textarea.value.length;
        const maxCount = 1000;
        const countElement = document.getElementById('character-count');

        if (countElement) {
            countElement.textContent = `${count}/${maxCount}`;

            if (count > maxCount) {
                countElement.classList.add('error');
                countElement.classList.remove('warning');
            } else if (count > maxCount * 0.9) {
                countElement.classList.add('warning');
                countElement.classList.remove('error');
            } else {
                countElement.classList.remove('warning', 'error');
            }
        }
    }

    // Show notification
    function showNotification(message, type = 'success') {
        let notification = document.getElementById('comment-notification');

        if (!notification) {
            notification = document.createElement('div');
            notification.id = 'comment-notification';
            notification.className = 'comment-notification';
            document.body.appendChild(notification);
        }

        notification.textContent = message;
        notification.className = `comment-notification ${type} show`;

        setTimeout(() => {
            notification.classList.remove('show');
        }, 3000);
    }

    // Escape HTML to prevent XSS
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initComments);
    } else {
        initComments();
    }

})();