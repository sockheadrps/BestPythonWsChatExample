// State management
let socket = null;
let currentUsername = '';
let token = null;
let keyPair = null;
let userPublicKeys = new Map();
let isPanelHidden = true;

// PM Session Management
const pmSessions = new Map(); // key: username, value: array of messages
const unreadCounts = new Map(); // key: username, value: number of unread messages
let currentPmUser = null;
let latestUserList = [];

// DOM elements - cached for performance
const elements = {
  messages: document.getElementById('messages'),
  form: document.getElementById('chat-form'),
  input: document.getElementById('message-input'),
  onlineUsers: document.getElementById('online-users'),
  connectingOverlay: document.getElementById('connecting-overlay'),
  logoutBtn: document.getElementById('logout-btn'),
  privateChatContainer: document.getElementById('private-chat-container'),
  privateChatBox: document.getElementById('private-chat-box'),
  privateChatMaximize: document.getElementById('maximize-private-chat'),
  privateChatMinimize: document.getElementById('minimize-private-chat'),
  privateChatDisconnect: document.getElementById('disconnect-private-chat'),
  privateInput: document.getElementById('private-input'),
  privateSendBtn: document.getElementById('private-send-btn'),
  privateChatFooter: document.getElementById('private-chat-footer'),
  usersToggle: document.getElementById('users-toggle'),
  usersPanel: document.getElementById('users-panel'),
  mainContainer: document.querySelector('.main-container'),
  aboutBtn: document.getElementById('about-btn'),
  aboutModal: document.getElementById('about-modal'),
  closeAboutModal: document.getElementById('close-about-modal'),
};

// Utility functions
const utils = {
  parseJwt: (token) => {
    try {
      return JSON.parse(atob(token.split('.')[1]));
    } catch {
      return null;
    }
  },

  getTokenFromCookie: (name) => {
    const match = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
    return match ? match[2] : null;
  },

  createElement: (tag, className, textContent = '') => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (textContent) element.textContent = textContent;
    return element;
  },

  scrollToBottom: (element) => {
    element.scrollTop = element.scrollHeight;
  },

  // Simplified DOM helper
  getElement: (id) => document.getElementById(id),

  // Create PM button with consistent logic
  createPmButton: (user, hasActiveSession) => {
    return hasActiveSession
      ? `<button class="pm-button" disabled title="Already have a PM session with this user">PM</button>`
      : `<button class="pm-button" onclick="sendPmInvite('${user}')">PM</button>`;
  },

  // Create notification toast (consolidated pattern)
  createToast: (type, content, actions = '') => {
    const toastContainer = utils.getElement('invite-toast-container');
    if (!toastContainer) {
      console.error('Toast container not found!');
      return null;
    }

    const toast = utils.createElement('div', `invite-toast ${type}`);
    toast.innerHTML = content + actions;
    toastContainer.appendChild(toast);

    // Auto-remove after delay
    const timeout =
      type === 'decline-notification' || type === 'disconnect-notification' ? 4000 : 15000;
    setTimeout(() => toast.remove(), timeout);
    return toast;
  },

  // Check if Web Crypto API is available
  isCryptoAvailable: () => {
    return (
      window.crypto &&
      window.crypto.subtle &&
      typeof window.crypto.subtle.generateKey === 'function'
    );
  },

  // RSA Encryption functions
  generateKeyPair: async () => {
    if (!utils.isCryptoAvailable()) {
      throw new Error(
        'Web Crypto API is not available. Private messages require HTTPS or localhost.'
      );
    }

    keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
    console.log('RSA key pair generated successfully');
    return keyPair;
  },

  exportPublicKey: async (publicKey) => {
    if (!utils.isCryptoAvailable()) {
      throw new Error('Web Crypto API is not available');
    }
    if (!publicKey) {
      throw new Error('No public key provided');
    }
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    const exportedAsString = utils.arrayBufferToBase64(exported);
    return exportedAsString;
  },

  importPublicKey: async (publicKeyString) => {
    if (!utils.isCryptoAvailable()) {
      throw new Error('Web Crypto API is not available');
    }
    if (!publicKeyString) {
      throw new Error('No public key string provided');
    }
    const publicKeyBuffer = utils.base64ToArrayBuffer(publicKeyString);
    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
    return publicKey;
  },

  encrypt: async (message, recipientUsername) => {
    if (!utils.isCryptoAvailable()) {
      throw new Error(
        'Web Crypto API is not available. Private messages require HTTPS or localhost.'
      );
    }

    if (!keyPair) {
      throw new Error('No key pair available for encryption');
    }

    if (!userPublicKeys.has(recipientUsername)) {
      throw new Error(`No public key found for ${recipientUsername}`);
    }

    const publicKey = userPublicKeys.get(recipientUsername);
    if (!publicKey) {
      throw new Error(`Invalid public key for ${recipientUsername}`);
    }

    const encodedMessage = new TextEncoder().encode(message);
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      encodedMessage
    );

    return utils.arrayBufferToBase64(encrypted);
  },

  decrypt: async (ciphertext) => {
    if (!utils.isCryptoAvailable()) {
      throw new Error('Web Crypto API is not available. Cannot decrypt private messages.');
    }

    if (!keyPair) {
      throw new Error('No key pair available for decryption');
    }

    const encryptedBuffer = utils.base64ToArrayBuffer(ciphertext);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      keyPair.privateKey,
      encryptedBuffer
    );

    return new TextDecoder().decode(decrypted);
  },

  // Helper functions for base64 conversion
  arrayBufferToBase64: (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  base64ToArrayBuffer: (base64) => {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  },
};

// Message handling
const messageHandler = {
  addMessage: (container, user, message, className = '') => {
    // Automatically determine if message is from current user
    let messageClass = className;
    if (!className) {
      if (user === currentUsername) {
        messageClass = 'user';
      } else if (user === 'System') {
        messageClass = 'system';
      } else {
        messageClass = 'other';
      }
    }

    const msgDiv = utils.createElement('div', `message ${messageClass}`);
    msgDiv.innerHTML = `
      <span class="user-name">${user}</span>
      <span class="message-text">${message}</span>
    `;
    container.appendChild(msgDiv);
    utils.scrollToBottom(container);
  },

  addSystemMessage: (container, message) => {
    const msgDiv = utils.createElement('div', 'message system');
    msgDiv.innerHTML = message;
    container.appendChild(msgDiv);
    utils.scrollToBottom(container);
  },
};

// Simplified PM management
const pmManager = {
  // Create or update PM tab with simplified logic
  ensureTab: (user, status) => {
    const footer = utils.getElement('pm-footer');
    if (!footer) return;

    const tabId = `pm-tab-${user}`;
    let tab = utils.getElement(tabId);

    // Remove tab for declined invites
    if (status === 'declined' && tab) {
      tab.remove();
      return;
    }

    // Create new tab if needed
    if (!tab && status !== 'declined') {
      tab = utils.createElement('div', 'pm-tab');
      tab.id = tabId;

      // Add status dot
      const statusDot = utils.createElement('div', 'status-dot');
      tab.appendChild(statusDot);

      // Add click handler
      tab.addEventListener('click', () => pmManager.toggleChat(user));
      footer.appendChild(tab);
    }

    // Update tab appearance
    if (tab) {
      pmManager.updateTabStatus(tab, user, status);
    }
  },

  // Simplified tab status update
  updateTabStatus: (tab, user, status) => {
    // Remove old status classes
    tab.classList.remove('pending', 'accepted', 'disconnected');

    // Add new status
    tab.classList.add(status);

    // Update text content
    const statusText = {
      pending: `${user} (pending)`,
      accepted: user,
      disconnected: user,
    };
    tab.textContent = statusText[status] || user;

    // Re-add status dot after text update
    if (!tab.querySelector('.status-dot')) {
      const statusDot = utils.createElement('div', 'status-dot');
      tab.appendChild(statusDot);
    }
  },

  // Toggle chat visibility
  toggleChat: (user) => {
    const isHidden = elements.privateChatContainer.classList.contains('hidden');

    if (isHidden) {
      pmManager.openChat(user);
    } else {
      pmManager.closeChat();
    }

    // Update active tab state
    document.querySelectorAll('.pm-tab').forEach((t) => t.classList.remove('active'));
    if (!isHidden) {
      utils.getElement(`pm-tab-${user}`)?.classList.add('active');
    }
  },

  // Open chat for specific user
  openChat: (user) => {
    currentPmUser = user;
    elements.privateChatContainer.dataset.user = user;
    elements.privateChatContainer.classList.remove('hidden');
    elements.privateChatContainer.style.display = 'flex';

    // Clear unread count
    unreadCounts.set(user, 0);
    pmManager.updateUnreadIndicator(user);

    // Update header
    const chatUserName = utils.getElement('chat-user-name');
    if (chatUserName) {
      chatUserName.textContent = `with ${user}`;
    }

    // Load messages
    pmManager.loadMessages(user);

    // Set enabled state based on connection status
    const tab = utils.getElement(`pm-tab-${user}`);
    const isDisconnected = tab?.classList.contains('disconnected');
    pmManager.setChatEnabled(!isDisconnected);

    if (isDisconnected) {
      elements.privateChatMinimize.style.display = 'none';
      elements.privateChatDisconnect.title = 'Close';
      elements.privateChatDisconnect.onclick = pmManager.closeChat;
    } else {
      elements.privateChatMinimize.style.display = 'inline-block';
      elements.privateChatDisconnect.title = 'Disconnect';
      elements.privateChatDisconnect.onclick = pmManager.disconnect;
    }
  },

  // Close chat
  closeChat: () => {
    elements.privateChatContainer.classList.add('hidden');
    const chatUserName = utils.getElement('chat-user-name');
    if (chatUserName) {
      chatUserName.textContent = 'with Username';
    }
    currentPmUser = null;
    document.querySelectorAll('.pm-tab').forEach((t) => t.classList.remove('active'));
  },

  // Load messages for user
  loadMessages: (user) => {
    elements.privateChatBox.innerHTML = '';
    const messages = pmSessions.get(user) || [];

    if (messages.length === 0) {
      messageHandler.addSystemMessage(
        elements.privateChatBox,
        `Private chat with <b>${user}</b> started.`
      );
    } else {
      messages.forEach(({ from, text }) => {
        messageHandler.addMessage(elements.privateChatBox, from, text);
      });
    }
  },

  // Set chat enabled/disabled state
  setChatEnabled: (enabled) => {
    elements.privateInput.disabled = !enabled;
    elements.privateSendBtn.disabled = !enabled;
    elements.privateInput.placeholder = enabled
      ? 'Type a private message...'
      : 'Private chat disconnected';
  },

  // Update unread message indicator
  updateUnreadIndicator: (username) => {
    const tab = utils.getElement(`pm-tab-${username}`);
    if (!tab) return;

    const unreadCount = unreadCounts.get(username) || 0;

    // Remove existing badge
    const existingBadge = tab.querySelector('.unread-badge');
    if (existingBadge) {
      existingBadge.remove();
    }

    if (unreadCount > 0) {
      tab.classList.add('has-unread');
      const badge = utils.createElement('span', 'unread-badge');
      badge.textContent = unreadCount > 99 ? '99+' : unreadCount.toString();
      tab.appendChild(badge);
    } else {
      tab.classList.remove('has-unread');
    }
  },

  // Disconnect from current PM
  disconnect: () => {
    const user = elements.privateChatContainer.dataset.user;
    if (!user) return;

    // Send disconnect notification
    socket.send(
      JSON.stringify({
        type: 'pm_disconnect',
        to: user,
      })
    );

    // Clean up local state
    const tab = utils.getElement(`pm-tab-${user}`);
    if (tab) tab.remove();

    pmSessions.delete(user);
    if (currentPmUser === user) currentPmUser = null;

    messageHandler.addSystemMessage(
      elements.privateChatBox,
      'You have disconnected the private chat.'
    );

    pmManager.closeChat();
    pmManager.setChatEnabled(false);
    refreshPmButtonStates();
  },

  // Handle incoming PM message
  handleMessage: async (data) => {
    const { from, ciphertext } = data;

    try {
      const msg = await utils.decrypt(ciphertext);

      if (!pmSessions.has(from)) {
        pmSessions.set(from, []);
        pmManager.ensureTab(from, 'accepted');
      }

      pmSessions.get(from).push({ from, text: msg });

      if (currentPmUser === from && !elements.privateChatContainer.classList.contains('hidden')) {
        // Message is for the current active PM user and chat is visible
        messageHandler.addMessage(elements.privateChatBox, from, msg);
      } else {
        // Increment unread count and update indicator
        const currentUnread = unreadCounts.get(from) || 0;
        unreadCounts.set(from, currentUnread + 1);
        pmManager.updateUnreadIndicator(from);

        // Play notification sound
        playMessageAlert();

        // If this is the current PM user but chat is minimized, still add the message
        if (currentPmUser === from) {
          messageHandler.addMessage(elements.privateChatBox, from, msg);
        }
      }
    } catch (error) {
      console.error('Error handling PM message:', error);
      if (currentPmUser === from) {
        messageHandler.addMessage(
          elements.privateChatBox,
          from,
          '[Encrypted message - decryption failed]'
        );
      }
    }
  },
};

// WebSocket message handlers
const socketHandlers = {
  chat_message: (data) => {
    if (elements.messages) {
      messageHandler.addMessage(elements.messages, data.user, data.message);
    } else {
      console.error('Messages element not found!');
    }
  },

  user_list: (data) => {
    if (!elements.onlineUsers) return;

    // Filter out current user and use the proper updateOnlineUsers function
    const filteredUsers = data.users.filter((user) => user !== currentUsername);
    updateOnlineUsers(filteredUsers);

    // Add staggered animation if panel is visible
    if (!isPanelHidden) {
      const userItems = elements.onlineUsers.querySelectorAll('.online-user');
      userItems.forEach((li, index) => {
        li.style.animationDelay = `${0.4 + index * 0.1}s`;
      });
    }
  },

  pm_message: pmManager.handleMessage,

  pubkey_request: (data) => {
    sendPublicKey(data.from);
  },

  pubkey_response: async (data) => {
    try {
      const publicKey = await utils.importPublicKey(data.public_key);
      userPublicKeys.set(data.from, publicKey);
      console.log(`Stored public key for ${data.from}`);
    } catch (error) {
      console.error(`Error storing public key for ${data.from}:`, error);
    }
  },

  pm_invite: (data) => {
    showPmInviteToast(data.from);
  },

  pm_accept: (data) => {
    const fromUser = data.from;
    pmManager.ensureTab(fromUser, 'accepted');
    messageHandler.addSystemMessage(
      elements.privateChatBox,
      `${fromUser} accepted the private chat.`
    );
    pmManager.openChat(fromUser);
    refreshPmButtonStates();
  },

  pm_decline: (data) => {
    const fromUser = data.from;
    pmManager.ensureTab(fromUser, 'declined');
    showPmDeclineNotification(fromUser);
    refreshPmButtonStates();
  },

  pm_disconnect: (data) => {
    const fromUser = data.from;

    // Always show toast notification for disconnect
    const content = `<span><b>${fromUser}</b> has disconnected from your private chat</span>`;
    utils.createToast('disconnect-notification', content);

    // Add disconnect message if we had an active session and chat is open
    if (currentPmUser === fromUser && !elements.privateChatContainer.classList.contains('hidden')) {
      messageHandler.addSystemMessage(
        elements.privateChatBox,
        `${fromUser} has disconnected from the private chat.`
      );

      pmManager.setChatEnabled(false);
      elements.privateChatMinimize.style.display = 'none';

      // Change disconnect button to close button
      elements.privateChatDisconnect.title = 'Close';
      elements.privateChatDisconnect.onclick = pmManager.closeChat;
    }

    // Clean up the PM session and remove the tab
    pmSessions.delete(fromUser);
    unreadCounts.delete(fromUser);

    const tab = utils.getElement(`pm-tab-${fromUser}`);
    if (tab) {
      tab.remove();
    }

    // If this was the current PM user, close the chat
    if (currentPmUser === fromUser) {
      currentPmUser = null;
      pmManager.closeChat();
    }

    refreshPmButtonStates();
  },
};

// WebSocket setup
function setupSocket() {
  socket = new WebSocket(`ws://localhost:8080/ws?token=${token}`);

  socket.addEventListener('open', () => {
    elements.form.style.pointerEvents = 'auto';
    elements.form.style.opacity = '1';
    elements.connectingOverlay?.classList.add('hidden');
  });

  socket.addEventListener('message', (event) => {
    try {
      const data = JSON.parse(event.data);

      const handler = socketHandlers[data.event] || socketHandlers[data.type];
      if (handler) {
        handler(data.data || data);
      } else {
        // Try to handle as a fallback message
        if (typeof data === 'string') {
          messageHandler.addMessage(elements.messages, 'System', data, 'bot');
        }
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
      console.log('Raw message that failed to parse:', event.data);

      // Handle non-JSON messages (like "Unknown message type")
      if (typeof event.data === 'string') {
        messageHandler.addMessage(elements.messages, 'System', event.data, 'bot');
      }
    }
  });

  socket.addEventListener('error', () => {
    elements.connectingOverlay.innerHTML =
      '<div class="username-form"><h2>Connection failed. Try again.</h2></div>';
  });
}

function updateOnlineUsers(userList) {
  if (!elements.onlineUsers) return;
  latestUserList = userList; // Store for later refresh
  elements.onlineUsers.innerHTML = '';

  userList.forEach((user) => {
    if (user !== currentUsername) {
      const li = utils.createElement('li', 'online-user');
      const hasActiveSession = pmSessions.has(user) || utils.getElement(`pm-tab-${user}`);

      li.innerHTML = `
        <span class="user-name">${user}</span>
        ${utils.createPmButton(user, hasActiveSession)}
      `;
      elements.onlineUsers.appendChild(li);
    }
  });
}

// Helper function to refresh PM button states
function refreshPmButtonStates() {
  if (latestUserList.length > 0) {
    updateOnlineUsers(latestUserList);
  }
}

// Simplified notification functions using utils.createToast
function showPmInviteToast(fromUser) {
  const content = `
    <div class="invite-content">
      <div class="invite-icon">💬</div>
      <div class="invite-message">
        <div class="invite-title">Private Chat Invitation</div>
        <div class="invite-subtitle"><strong>${fromUser}</strong> wants to chat privately</div>
      </div>
    </div>
  `;

  const actions = `
    <div class="invite-actions">
      <button class="accept-btn" onclick="acceptPmInvite('${fromUser}', this.closest('.invite-toast'))">
        <span>✓</span> Accept
      </button>
      <button class="decline-btn" onclick="declinePmInvite('${fromUser}', this.closest('.invite-toast'))">
        <span>✕</span> Decline
      </button>
    </div>
  `;

  utils.createToast('', content, actions);
}

function showPmDeclineNotification(fromUser) {
  const content = `<span><b>${fromUser}</b> declined your private chat request</span>`;
  utils.createToast('decline-notification', content);
}

function declinePmInvite(user, toast) {
  socket.send(JSON.stringify({ type: 'pm_decline', to: user }));
  toast.remove();
}

function sendPmInvite(user) {
  pmManager.ensureTab(user, 'pending');
  socket.send(JSON.stringify({ type: 'pm_invite', to: user }));
  requestPublicKey(user);
  refreshPmButtonStates();
}

async function requestPublicKey(username) {
  socket.send(
    JSON.stringify({
      type: 'pubkey_request',
      to: username,
    })
  );
}

async function sendPublicKey(username) {
  try {
    if (!utils.isCryptoAvailable() || !keyPair) {
      throw new Error('Cannot send public key - crypto not available or no key pair');
    }

    const publicKeyString = await utils.exportPublicKey(keyPair.publicKey);
    socket.send(
      JSON.stringify({
        type: 'pubkey_response',
        to: username,
        public_key: publicKeyString,
      })
    );
    console.log(`Sent public key to ${username}`);
  } catch (error) {
    console.error(`Error sending public key to ${username}:`, error);
  }
}

function acceptPmInvite(user, toast) {
  socket.send(JSON.stringify({ type: 'pm_accept', to: user }));
  pmManager.ensureTab(user, 'accepted');
  pmManager.openChat(user);
  toast.remove();
  requestPublicKey(user);
  refreshPmButtonStates();
}

// Simplified chat window functions
function minimizePrivateChat() {
  elements.privateChatContainer.classList.add('hidden');
}

function maximizePrivateChat() {
  const container = elements.privateChatContainer;
  const button = elements.privateChatMaximize;
  const svg = button.querySelector('svg');

  if (container.classList.contains('maximized')) {
    // Restore to normal size
    container.classList.remove('maximized');
    button.title = 'Maximize';
    // Update SVG for maximize icon (you may need to adjust this)
  } else {
    // Maximize
    container.classList.add('maximized');
    button.title = 'Restore';
    // Update SVG for restore icon (you may need to adjust this)
  }
}

async function sendPrivateMessage() {
  const msg = elements.privateInput.value.trim();
  const to = elements.privateChatContainer.dataset.user;

  if (msg && to) {
    try {
      const ciphertext = await utils.encrypt(msg, to);
      socket.send(
        JSON.stringify({
          type: 'pm_message',
          to,
          ciphertext,
        })
      );

      // Add message to chat display
      messageHandler.addMessage(elements.privateChatBox, currentUsername, msg);

      // Store the sent message in the session
      if (!pmSessions.has(to)) {
        pmSessions.set(to, []);
      }
      pmSessions.get(to).push({ from: currentUsername, text: msg });

      elements.privateInput.value = '';
    } catch (error) {
      console.error('Error sending private message:', error);
      alert('Failed to send private message: ' + error.message);
    }
  }
}

function handlePrivateInputKeyPress(event) {
  if (event.key === 'Enter') {
    event.preventDefault();
    sendPrivateMessage();
  }
}

function playMessageAlert() {
  try {
    const audio = new Audio('/static/message_alert.mp3');
    audio.volume = 0.3;
    audio.play().catch((error) => {
      console.warn('Failed to play message alert sound:', error);
    });
  } catch (error) {
    console.warn('Error creating audio element:', error);
  }
}

// Simplified users panel toggle
function toggleUsersPanel() {
  isPanelHidden = !isPanelHidden;

  if (isPanelHidden) {
    elements.usersPanel.classList.add('hidden');
    elements.mainContainer.classList.add('panel-hidden');
    elements.usersToggle.classList.add('panel-hidden');
    elements.usersToggle.textContent = '👥';
    elements.usersToggle.title = 'Show Users Panel';
  } else {
    // Add loading class temporarily to trigger fade-in
    elements.usersPanel.classList.add('panel-loading');
    elements.usersPanel.classList.remove('hidden');
    elements.mainContainer.classList.remove('panel-hidden');
    elements.usersToggle.classList.remove('panel-hidden');
    elements.usersToggle.textContent = '◀';
    elements.usersToggle.title = 'Hide Users Panel';

    // Remove loading class after a brief delay to trigger fade-in
    setTimeout(() => {
      elements.usersPanel.classList.remove('panel-loading');

      // Stagger the fade-in animations for user items
      setTimeout(() => {
        const userItems = document.querySelectorAll('.online-user');
        userItems.forEach((item, index) => {
          item.style.animationDelay = `${0.4 + index * 0.1}s`;
          item.style.animation = 'none';
          // Force reflow
          item.offsetHeight;
          item.style.animation = 'fadeInUser 0.4s ease forwards';
        });
      }, 50);
    }, 50);
  }
}

// About modal functions
function openAboutModal() {
  elements.aboutModal?.classList.remove('hidden');
}

function closeAboutModal() {
  elements.aboutModal?.classList.add('hidden');
}

// Simplified initialization
function initializeApp() {
  // Authentication
  token = utils.getTokenFromCookie('access_token');
  if (!token) {
    window.location.href = '/login';
    return;
  }

  const payload = utils.parseJwt(token);
  if (!payload?.sub) {
    console.error('Invalid token');
    window.location.href = '/login';
    return;
  }

  currentUsername = payload.sub;

  // Update header with username
  const userDisplay = utils.getElement('current-user');
  if (userDisplay) {
    userDisplay.textContent = currentUsername;
  }

  // Initialize panel as hidden
  elements.usersPanel.classList.add('hidden');
  elements.mainContainer.classList.add('panel-hidden');
  elements.usersToggle.classList.add('panel-hidden');
  elements.usersToggle.textContent = '👥';
  elements.usersToggle.title = 'Show Users Panel';
}

function setupEventListeners() {
  // Authentication
  elements.logoutBtn?.addEventListener('click', () => {
    document.cookie = 'access_token=; Max-Age=0';
    window.location.href = '/login';
  });

  // Private chat controls
  elements.privateSendBtn.addEventListener('click', sendPrivateMessage);
  elements.privateChatMaximize.addEventListener('click', maximizePrivateChat);
  elements.privateChatMinimize.addEventListener('click', minimizePrivateChat);
  // Note: disconnect handler is set dynamically in pmManager.openChat based on connection state
  elements.privateInput.addEventListener('keypress', handlePrivateInputKeyPress);

  // Users panel toggle
  elements.usersToggle?.addEventListener('click', toggleUsersPanel);

  // About modal
  elements.aboutBtn?.addEventListener('click', openAboutModal);
  elements.closeAboutModal?.addEventListener('click', closeAboutModal);
  elements.aboutModal?.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
      closeAboutModal();
    }
  });

  // Chat form submission
  elements.form.addEventListener('submit', (e) => {
    e.preventDefault();

    if (!socket || socket.readyState !== WebSocket.OPEN) {
      console.warn('Socket is not connected.');
      return;
    }

    const message = elements.input.value.trim();
    if (message && currentUsername) {
      socket.send(
        JSON.stringify({
          type: 'chat_message',
          data: { message },
        })
      );
      elements.input.value = '';
    }
  });
}

// Main initialization
window.addEventListener('DOMContentLoaded', () => {
  initializeApp();
  setupEventListeners();

  // Generate RSA key pair for encryption
  utils
    .generateKeyPair()
    .then(() => {
      console.log('RSA key pair generated successfully - private messages will be encrypted');
    })
    .catch((error) => {
      console.error('Failed to generate RSA key pair:', error);
      console.error('Private messages will not work without HTTPS or localhost');
    });

  // Connect to WebSocket
  elements.connectingOverlay?.classList.remove('hidden');
  setupSocket();

  // Remove loading class to trigger fade-in animations
  setTimeout(() => {
    elements.usersPanel?.classList.remove('panel-loading');
  }, 100);
});
