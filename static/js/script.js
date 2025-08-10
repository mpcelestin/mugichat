// Socket.IO setup
const socket = io();

// Connect to the user's room when authenticated
if (document.getElementById('current-user-id')) {
    const userId = document.getElementById('current-user-id').value;
    socket.emit('join', { userId: userId });
}

// Handle incoming messages
socket.on('message', (data) => {
    // Check if we're on the chat page with this user
    if (window.location.pathname.includes('/chat/' + data.sender_id)) {
        // Add message to chat
        addMessageToChat(data);
        
        // Scroll to bottom
        const chatContainer = document.querySelector('.chat-messages');
        chatContainer.scrollTop = chatContainer.scrollHeight;
    } else {
        // Show notification
        showMessageNotification(data);
    }
});

// Chat functionality
function addMessageToChat(message) {
    const chatMessages = document.querySelector('.chat-messages');
    const messageElement = document.createElement('div');
    messageElement.className = message.sender_id === currentUserId ? 'message sent' : 'message received';
    messageElement.innerHTML = `
        <div class="message-content">${message.content}</div>
        <div class="message-time">${new Date(message.timestamp).toLocaleTimeString()}</div>
    `;
    chatMessages.appendChild(messageElement);
}

function showMessageNotification(message) {
    // Implement notification UI
    console.log('New message from:', message.sender_id);
}

// Form submission for chat
const chatForm = document.getElementById('chat-form');
if (chatForm) {
    chatForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const messageInput = document.getElementById('message-input');
        const message = messageInput.value.trim();
        
        if (message) {
            // Get recipient ID from the page URL or hidden input
            const recipientId = document.getElementById('recipient-id').value;
            
            // Emit message via Socket.IO
            socket.emit('message', {
                sender_id: currentUserId,
                recipient_id: recipientId,
                content: message
            });
            
            // Add message to chat UI immediately
            addMessageToChat({
                sender_id: currentUserId,
                content: message,
                timestamp: new Date()
            });
            
            // Clear input
            messageInput.value = '';
        }
    });
}

// Dark mode toggle
const darkModeToggle = document.getElementById('dark-mode-toggle');
if (darkModeToggle) {
    darkModeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
    });
    
    // Check for saved preference
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
    }
}

// Image preview for uploads
function previewImage(input, previewId) {
    const preview = document.getElementById(previewId);
    const file = input.files[0];
    const reader = new FileReader();
    
    reader.onloadend = function() {
        preview.src = reader.result;
        preview.style.display = 'block';
    }
    
    if (file) {
        reader.readAsDataURL(file);
    } else {
        preview.src = '';
        preview.style.display = 'none';
    }
}

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Infinite scroll for posts
let loading = false;
window.addEventListener('scroll', function() {
    if ((window.innerHeight + window.scrollY) >= document.body.offsetHeight - 500 && !loading) {
        loading = true;
        const lastPostId = document.querySelector('.post-card:last-child').id.split('-')[1];
        loadMorePosts(lastPostId);
    }
});

function loadMorePosts(lastPostId) {
    fetch(`/load_more_posts?last_post_id=${lastPostId}`)
        .then(response => response.json())
        .then(data => {
            if (data.posts.length > 0) {
                appendPosts(data.posts);
            }
            loading = false;
        });
}

function appendPosts(posts) {
    const postsContainer = document.getElementById('posts-container');
    posts.forEach(post => {
        const postElement = createPostElement(post);
        postsContainer.appendChild(postElement);
    });
}

// This is a simplified version - you would need to implement createPostElement based on your post HTML structure
// Handle likes
document.querySelectorAll('.like-btn').forEach(button => {
    button.addEventListener('click', async function(e) {
        e.preventDefault();
        const postId = this.dataset.postId;
        
        try {
            const response = await fetch(`/post/${postId}/like`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            const data = await response.json();
            
            if (data.status === 'liked') {
                this.innerHTML = `<i class="bi bi-heart-fill"></i> ${data.likes_count}`;
            } else {
                this.innerHTML = `<i class="bi bi-heart"></i> ${data.likes_count}`;
            }
        } catch (error) {
            console.error('Error:', error);
        }
    });
});

// Handle comment submission
document.querySelectorAll('.comment-form').forEach(form => {
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        const postId = this.dataset.postId;
        const formData = new FormData(this);
        
        try {
            const response = await fetch(`/post/${postId}/comment`, {
                method: 'POST',
                body: formData
            });
            
            if (response.ok) {
                window.location.reload(); // Refresh to show new comment
            }
        } catch (error) {
            console.error('Error:', error);
        }
    });
});


document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.like-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            const postId = this.dataset.postId;
            const reaction = this.dataset.reaction || 'like';
            
            fetch(`/post/${postId}/like`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ reaction: reaction })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // Update UI
                    const likeBtn = document.querySelector(`.like-btn[data-post-id="${postId}"]`);
                    const countSpan = likeBtn.querySelector('.likes-count');
                    
                    countSpan.textContent = data.likes_count;
                    
                    if (data.action === 'unliked') {
                        likeBtn.querySelector('.current-reaction')?.remove();
                    } else {
                        let reactionSpan = likeBtn.querySelector('.current-reaction');
                        if (!reactionSpan) {
                            reactionSpan = document.createElement('span');
                            reactionSpan.className = 'current-reaction';
                            likeBtn.prepend(reactionSpan);
                        }
                        reactionSpan.textContent = data.current_reaction;
                    }
                    
                    // Close reaction options if open
                    const container = likeBtn.closest('.reactions-container');
                    container?.classList.remove('show-options');
                }
            });
        });
    });
    
    // Show reaction options on hover
    document.querySelectorAll('.like-btn').forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            const container = this.closest('.reactions-container');
            container?.classList.add('show-options');
        });
        
        btn.addEventListener('mouseleave', function() {
            const container = this.closest('.reactions-container');
            if (!container?.matches(':hover')) {
                container?.classList.remove('show-options');
            }
        });
    });
});

// Add to likes.js
socket.on('update_likes', function(data) {
    const likeBtns = document.querySelectorAll(`.like-btn[data-post-id="${data.post_id}"]`);
    likeBtns.forEach(btn => {
        const countSpan = btn.querySelector('.likes-count');
        if (countSpan) {
            countSpan.textContent = data.likes_count;
        }
    });
});

// Add this to your script.js
document.addEventListener('DOMContentLoaded', function() {
    // Handle like button clicks
    document.querySelectorAll('.like-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            const postId = this.dataset.postId;
            likePost(postId);
        });
    });

    // Handle reaction selection
    document.querySelectorAll('.reaction-option').forEach(option => {
        option.addEventListener('click', function(e) {
            e.stopPropagation();
            const postId = this.closest('.reactions-container').querySelector('.like-btn').dataset.postId;
            const reaction = this.dataset.reaction;
            likePost(postId, reaction);
        });
    });

    // Handle share button clicks
    document.querySelectorAll('.share-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const postId = this.dataset.postId;
            sharePost(postId);
        });
    });
});

function likePost(postId, reaction = 'like') {
    fetch(`/post/${postId}/like`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrf_token') // Add CSRF protection
        },
        body: JSON.stringify({ reaction: reaction })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Update like button
            const likeBtn = document.querySelector(`.like-btn[data-post-id="${postId}"]`);
            const countSpan = likeBtn.querySelector('.likes-count');
            
            countSpan.textContent = data.likes_count;
            
            // Update reaction display
            let reactionSpan = likeBtn.querySelector('.current-reaction');
            if (data.action === 'unliked') {
                if (reactionSpan) reactionSpan.remove();
            } else {
                if (!reactionSpan) {
                    reactionSpan = document.createElement('span');
                    reactionSpan.className = 'current-reaction';
                    likeBtn.prepend(reactionSpan);
                }
                reactionSpan.textContent = data.current_reaction;
            }
            
            // Emit socket event to update other clients
            socket.emit('like_post', { post_id: postId });
        }
    });
}

function sharePost(postId) {
    // You can implement different sharing methods here
    const postUrl = `${window.location.origin}/post/${postId}`;
    
    // For now, just copy to clipboard
    navigator.clipboard.writeText(postUrl).then(() => {
        alert('Post link copied to clipboard!');
    });
}

// Helper function to get CSRF token
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}