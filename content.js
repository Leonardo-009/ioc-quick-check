(function () {
  // Improved regexes to extract IOCs (more precise)
  const R = {
    // IP regex - improved to avoid matching version numbers
    ip: /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b(?!\d)/g,
    // URL regex - improved to capture more URL formats
    url: /\bhttps?:\/\/(?:[-\w.])+(?::[0-9]+)?(?:\/(?:[\w\/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?/gi,
    // Email regex - improved RFC 5322 compliant
    email: /\b[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b/g,
    // Hash regex - improved to match MD5 (32), SHA1 (40), SHA256 (64)
    hash: /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g,
    // Domain regex - improved to exclude IPs and URLs
    domain: /\b(?!(?:https?:\/\/|www\.|ftp:\/\/))(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b(?![:\/])/g
  };

  let isActive = false;
  let observer = null;
  let selectionMode = false; // false = auto, true = manual selection
  let selectedText = '';
  
  // Load active state from storage
  async function loadActiveState(){
    try {
      const result = await chrome.storage.local.get('ioc_quick_active_state');
      if(result.ioc_quick_active_state !== undefined){
        isActive = result.ioc_quick_active_state;
      }
    } catch(e) {
      console.log('Could not load active state:', e);
    }
  }
  
  // Save active state to storage
  async function saveActiveState(active){
    try {
      await chrome.storage.local.set({ 'ioc_quick_active_state': active });
      isActive = active;
    } catch(e) {
      console.error('Could not save active state:', e);
    }
  }
  
  // Initialize state on load
  loadActiveState();

  function unique(arr){ return Array.from(new Set(arr || [])); }

  // Check if text contains any IOC pattern
  function containsIOC(text){
    if (!text || !text.trim()) return false;
    // Create new regex instances to avoid global flag issues
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b/;
    const urlRegex = /\bhttps?:\/\/[^\s<>"']+/i;
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
    const hashRegex = /\b[a-fA-F0-9]{32,64}\b/;
    const domainRegex = /\b(?!https?:\/\/)([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b/;
    return ipRegex.test(text) || urlRegex.test(text) || emailRegex.test(text) || hashRegex.test(text) || domainRegex.test(text);
  }

  // Get only text from elements that contain IOCs (focused approach)
  function getIOCFocusedText(){
    const elementsWithIOCs = [];
    const processed = new WeakSet();
    
    // Function to check element and its children
    function checkElement(el){
      if (!el || processed.has(el)) return;
      processed.add(el);
      
      // Skip script, style, noscript, template
      const tagName = el.tagName?.toLowerCase();
      if (['script', 'style', 'noscript', 'template', 'meta', 'link', 'head'].includes(tagName)) {
        return;
      }
      
      // Skip if hidden
      try {
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || style.height === '0px') {
          return;
        }
      } catch(e) {
        return;
      }
      
      // Get text content of this element (without children)
      const directText = Array.from(el.childNodes)
        .filter(n => n.nodeType === Node.TEXT_NODE)
        .map(n => n.textContent)
        .join(' ')
        .trim();
      
      // Get full text including children for IOC detection
      const fullText = el.textContent || el.innerText || '';
      
      // If this element or its direct text contains IOCs, add it
      if (containsIOC(fullText)) {
        // Prefer direct text if it has IOCs, otherwise use full text
        const textToAdd = containsIOC(directText) ? directText : fullText;
        if (textToAdd && textToAdd.trim()) {
          elementsWithIOCs.push(textToAdd);
          // Don't process children if parent already has IOCs (avoid duplicates)
          return;
        }
      }
      
      // Recursively check children
      if (el.children && el.children.length > 0) {
        Array.from(el.children).forEach(child => checkElement(child));
      }
    }
    
    // Start checking from body
    if (document.body) {
      checkElement(document.body);
    }
    
    // Join all found texts
    return elementsWithIOCs.join(' ');
  }

  function extractIOCs(text){
    const ips = unique((text.match(R.ip)||[]).map(s=>s.trim()).filter(ip => {
      // Additional validation: exclude common false positives like version numbers
      const parts = ip.split('.');
      return parts.length === 4 && parts.every(p => parseInt(p) >= 0 && parseInt(p) <= 255);
    }));
    
    const urls = unique((text.match(R.url)||[]).map(s=>s.trim()).filter(url => {
      // Validate URL format
      try {
        new URL(url);
        return true;
      } catch(e) {
        return false;
      }
    }));
    
    const emails = unique((text.match(R.email)||[]).map(s=>s.trim()).filter(email => {
      // Additional validation: exclude common false positives
      return !email.includes('..') && email.split('@').length === 2;
    }));
    
    const hashes = unique((text.match(R.hash)||[]).map(s=>s.trim()).filter(hash => {
      // Only accept standard hash lengths
      return [32, 40, 64].includes(hash.length);
    }));
    
    let domains = unique((text.match(R.domain)||[]).map(s=>s.trim()).filter(domain => {
      // Exclude single words, IP addresses, and common false positives
      if(domain.split('.').length < 2) return false;
      if(/^\d/.test(domain)) return false; // Don't start with number
      if(domain.length < 4) return false; // Too short
      return true;
    }));

    // remove domain duplicates that are part of urls
    const urlHosts = urls.map(u=>{ try{ return (new URL(u)).hostname }catch(e){return null}}).filter(Boolean);
    domains = domains.filter(d=>!urlHosts.includes(d));

    return { ips, urls, emails, hashes, domains };
  }

  function scanAndSend(customText = null){
    if (!isActive) return;
    
    try{
      // Use selected text if in manual mode, otherwise use auto detection
      const text = customText || (selectionMode ? selectedText : getIOCFocusedText());
      if (!text || !text.trim()) {
        chrome.runtime.sendMessage({ type: 'IOC_NONE' });
        return;
      }
      
      const iocs = extractIOCs(text);
      const total = iocs.ips.length + iocs.urls.length + iocs.emails.length + iocs.hashes.length + iocs.domains.length;
      if(total>0){
        chrome.runtime.sendMessage({ type: 'IOC_DISCOVERED', data: iocs });
      } else {
        chrome.runtime.sendMessage({ type: 'IOC_NONE' });
      }
    }catch(e){
      console.error('IOC scan error', e);
    }
  }

  // Handle text selection
  function handleTextSelection(){
    const selection = window.getSelection();
    if (selection && selection.toString().trim()) {
      selectedText = selection.toString().trim();
      // Don't scan automatically on selection - only when Scan button is pressed
    }
  }

  // Add selection listener
  document.addEventListener('mouseup', handleTextSelection);
  document.addEventListener('keyup', (e) => {
    if (e.key === 'Escape') {
      window.getSelection().removeAllRanges();
      selectedText = '';
    }
  });

  // Control is now in popup - no floating button needed

  // Listen for rescan requests from popup (removed automatic scan)
  // Scans are now only triggered manually via MANUAL_SCAN message

  // Listen for messages from background/popup
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    // Ping/Pong for checking if script is loaded
    if (msg && msg.type === 'PING') {
      sendResponse({ status: 'pong', active: isActive });
      return true;
    }
    
    // Get status
    if (msg && msg.type === 'GET_STATUS') {
      sendResponse({ active: isActive });
      return true;
    }
    
    if (msg && (msg.type === 'FORCE_SCAN' || msg.type === 'MANUAL_SCAN')) {
      if (!isActive) {
        sendResponse({ status: 'error', message: 'Extensão não está ativa. Clique em "Ativar" no popup.' });
        return true;
      }
      try {
        // Use selected text if in selection mode, otherwise use auto detection
        const text = selectionMode && selectedText ? selectedText : null;
        scanAndSend(text);
        sendResponse({ status: 'ok' });
      } catch(e) {
        console.error('Scan error in content script:', e);
        sendResponse({ status: 'error', message: 'Erro ao executar scan: ' + e.message });
      }
      return true; // Keep channel open for async response
    }
    if (msg && msg.type === 'TOGGLE_ACTIVE') {
      const newState = !isActive;
      saveActiveState(newState).then(() => {
        sendResponse({ status: 'ok', active: newState });
      }).catch(() => {
        isActive = newState;
        sendResponse({ status: 'ok', active: newState });
      });
      return true;
    }
    return false;
  });
})();