/*
 background.js - orchestrates API checks, caching, badge updates.
 Replace API keys in options page (options.html) or set via chrome.storage.local.
*/

const STATE_KEY = 'ioc_qc_state_v3';
const KEYS_STORE = 'ioc_qc_keys_v3';
const APIS_STORE = 'ioc_qc_apis_v3';
const HISTORY_STORE = 'ioc_qc_history_v3';
const CACHE_TTL = 1000 * 60 * 60; // 1 hour
const CACHE = {}; // simple in-memory cache during session
const MAX_HISTORY_ENTRIES = 50; // Maximum history entries to keep

// Clear cache function
function clearCache(){
  Object.keys(CACHE).forEach(key => delete CACHE[key]);
  console.log('Cache cleared');
}

// helper
function now(){ return Date.now(); }
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// load api keys from storage
async function loadKeys(){
  const s = await chrome.storage.local.get(KEYS_STORE);
  return s[KEYS_STORE] || {};
}

// load active APIs from storage
async function loadActiveAPIs(){
  const s = await chrome.storage.local.get(APIS_STORE);
  return s[APIS_STORE] || {
    abuseipdb: true,
    virustotal: true,
    talos: true,
    urlscan: true,
    hibp: true
  };
}

// store last state
async function saveState(state){
  await chrome.storage.local.set({ [STATE_KEY]: state });
}
async function loadState(){
  const s = await chrome.storage.local.get(STATE_KEY);
  return s[STATE_KEY] || { lastScan: 0, pageIOCs: {}, results: [] };
}

// badge helpers
function setBadge(count, color='#d9534f'){
  try{
    if(count && count>0){
      chrome.action.setBadgeText({ text: String(count) });
      chrome.action.setBadgeBackgroundColor({ color });
    } else {
      chrome.action.setBadgeText({ text: '' });
    }
  }catch(e){ console.warn('badge',e); }
}

// fetch wrapper with timeout
async function fetchTimeout(resource, options = {}, timeout = 12000){
  const controller = new AbortController();
  const id = setTimeout(()=>controller.abort(), timeout);
  options.signal = controller.signal;
  try{
    const resp = await fetch(resource, options);
    clearTimeout(id);
    return resp;
  }catch(e){
    clearTimeout(id);
    throw e;
  }
}

// caching helper
function cacheKey(type, ioc){ return `${type}::${ioc}`; }
function isCachedFresh(k){ return CACHE[k] && (now() - CACHE[k].ts) < CACHE_TTL; }

// Check if provider has relevant data (classification/reports)
function hasRelevantData(provider, providerName){
  if(!provider || !providerName) return false;
  // Check if provider response has an error
  if(provider.error) return false;
  try{
    if(providerName === 'AbuseIPDB'){
      // Has score > 0 or reports > 0 (exclude 0% scores)
      return (provider.abuseConfidenceScore !== undefined && provider.abuseConfidenceScore > 0) || 
             (provider.totalReports !== undefined && provider.totalReports > 0);
    }
    if(providerName === 'VirusTotal'){
      // VirusTotal always returns data structure, so if we got a response, it's relevant
      if(provider && provider.data) {
        const attrs = provider.data.attributes;
        // If we have attributes, it's valid data
        if(attrs) {
          return true; // VirusTotal data is always relevant if we got a response
        }
        // If we have data but no attributes, still consider it (might be URL submission response)
        if(provider.data.id || provider.data.type) {
          return true;
        }
      }
      return false;
    }
    if(providerName === 'Talos'){
      // Has reputation data
      return provider.reputation && (
        provider.reputation.risk_score !== undefined ||
        provider.reputation.category ||
        provider.reputation.description
      );
    }
    if(providerName === 'URLScan'){
      // Has results
      return provider.total !== undefined && provider.total > 0;
    }
    if(providerName === 'HIBP'){
      // Has breach data (even if empty array, it's a result)
      return Array.isArray(provider);
    }
  }catch(e){
    console.warn('hasRelevantData error', e);
  }
  return false;
}

// Minimal heuristics: returns { malicious: bool, reasons: [string], providers: {}, errors: [] }
function aggregateResults(type, ioc, providerResponses){
  const agg = { ioc, type, malicious: false, reasons: [], providers: {}, hasRelevantData: false, errors: [] };
  providerResponses.forEach(r=>{
    if(!r) return;
    
    // Track errors separately
    if(r.error) {
      agg.errors.push({ provider: r.provider, error: r.error });
      return;
    }
    
    // Only include providers with relevant data
    if(hasRelevantData(r.data, r.provider)){
      agg.providers[r.provider] = r.data;
      agg.hasRelevantData = true;
      
      try{
        if(r.provider === 'AbuseIPDB' && r.data.abuseConfidenceScore && r.data.abuseConfidenceScore>10){
          agg.malicious = true;
          agg.reasons.push(`AbuseIPDB score ${r.data.abuseConfidenceScore}`);
        }
        if(r.provider === 'VirusTotal'){
          const attrs = r.data?.data?.attributes;
          if(attrs && attrs.last_analysis_stats && attrs.last_analysis_stats.malicious && attrs.last_analysis_stats.malicious>0){
            agg.malicious = true;
            agg.reasons.push('VirusTotal positives');
          }
        }
        if(r.provider === 'Talos' && r.data && r.data.reputation && r.data.reputation.risk_score && r.data.reputation.risk_score>50){
          agg.malicious = true;
          agg.reasons.push(`Talos risk ${r.data.reputation.risk_score}`);
        }
        if(r.provider === 'URLScan' && r.data && r.data.total && r.data.total>0){
          agg.malicious = true;
          agg.reasons.push(`URLScan hits ${r.data.total}`);
        }
        if(r.provider === 'HIBP' && Array.isArray(r.data) && r.data.length>0){
          agg.malicious = true;
          agg.reasons.push(`HIBP breaches: ${r.data.length}`);
        }
      }catch(e){
        console.warn('aggreg parse', e);
      }
    }
  });
  return agg;
}

// API modules inline (simple)
// AbuseIPDB
async function apiAbuseIPDB(ip, keys){
  if(!keys.abuseipdb) {
    return { provider: 'AbuseIPDB', error: 'API key not configured' };
  }
  // Validate IP format
  if(!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    return { provider: 'AbuseIPDB', error: 'Invalid IP format' };
  }
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
  try{
    const res = await fetchTimeout(url, { headers: { 'Key': keys.abuseipdb, 'Accept':'application/json' } }, 6000);
    if(!res.ok) {
      const errorText = await res.text();
      return { provider: 'AbuseIPDB', error: `API error: ${res.status} ${errorText.substring(0, 100)}` };
    }
    const j = await res.json();
    if(j && j.data) {
      return { provider: 'AbuseIPDB', data: j.data };
    }
    return { provider: 'AbuseIPDB', error: 'Invalid response format' };
  }catch(e){
    return { provider: 'AbuseIPDB', error: e.name === 'AbortError' ? 'Request timeout' : `Network error: ${e.message}` };
  }
}

// VirusTotal
async function apiVirusTotal(ioc, type, keys){
  if(!keys.virustotal) return { provider: 'VirusTotal', error: 'API key not configured' };
  
  const headers = { 
    'x-apikey': keys.virustotal, 
    'Accept': 'application/json'
  };
  
  try{
    if(type==='ip') {
      if(!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ioc)) {
        return { provider: 'VirusTotal', error: 'Invalid IP format' };
      }
      const url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`;
      const res = await fetchTimeout(url, { headers }, 6000);
      if(!res.ok) {
        const errorText = await res.text();
        return { provider: 'VirusTotal', error: `API error: ${res.status} ${errorText.substring(0, 100)}` };
      }
      const j = await res.json();
      if(j && j.data) {
        return { provider: 'VirusTotal', data: j };
      }
      return { provider: 'VirusTotal', error: 'Invalid response format' };
    }
    if(type==='domain'){
      const url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`;
      const res = await fetchTimeout(url, { headers }, 6000);
      if(!res.ok) {
        const errorText = await res.text();
        return { provider: 'VirusTotal', error: `API error: ${res.status} ${errorText.substring(0, 100)}` };
      }
      const j = await res.json();
      if(j && j.data) {
        return { provider: 'VirusTotal', data: j };
      }
      return { provider: 'VirusTotal', error: 'Invalid response format' };
    }
    if(type==='hash'){
      const hashRegex = /^[a-fA-F0-9]{32,64}$/;
      if(!hashRegex.test(ioc)) {
        return { provider: 'VirusTotal', error: 'Invalid hash format' };
      }
      const url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`;
      const res = await fetchTimeout(url, { headers }, 8000);
      if(!res.ok) {
        const errorText = await res.text();
        return { provider: 'VirusTotal', error: `API error: ${res.status} ${errorText.substring(0, 100)}` };
      }
      const j = await res.json();
      if(j && j.data) {
        return { provider: 'VirusTotal', data: j };
      }
      return { provider: 'VirusTotal', error: 'Invalid response format' };
    }
    if(type==='url'){
      try {
        new URL(ioc); // Validate URL format
      } catch(e) {
        return { provider: 'VirusTotal', error: 'Invalid URL format' };
      }
      const url = `https://www.virustotal.com/api/v3/urls`;
      const body = new URLSearchParams(); 
      body.append('url', ioc);
      const res = await fetchTimeout(url, { method:'POST', headers, body }, 8000);
      if(!res.ok) {
        const errorText = await res.text();
        return { provider: 'VirusTotal', error: `API error: ${res.status} ${errorText.substring(0, 100)}` };
      }
      const j = await res.json();
      if(j && j.data) {
        return { provider: 'VirusTotal', data: j };
      }
      return { provider: 'VirusTotal', error: 'Invalid response format' };
    }
  }catch(e){
    return { provider: 'VirusTotal', error: e.name === 'AbortError' ? 'Request timeout' : `Network error: ${e.message}` };
  }
  return { provider: 'VirusTotal', error: 'Unsupported IOC type' };
}

// Talos
async function apiTalos(ip, keys){
  if(!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    return { provider: 'Talos', error: 'Invalid IP format' };
  }
  try{
    const url = `https://talosintelligence.com/sb_api/query_lookup?query=${encodeURIComponent(ip)}&query_type=ip`;
    const res = await fetchTimeout(url, {}, 6000);
    if(!res.ok) {
      const errorText = await res.text();
      return { provider: 'Talos', error: `API error: ${res.status} ${errorText.substring(0, 100)}` };
    }
    const j = await res.json();
    return { provider: 'Talos', data: j };
  }catch(e){
    return { provider: 'Talos', error: e.name === 'AbortError' ? 'Request timeout' : `Network error: ${e.message}` };
  }
}

// URLScan
async function apiURLScan(urlToCheck, keys){
  try {
    new URL(urlToCheck); // Validate URL format
  } catch(e) {
    return { provider: 'URLScan', error: 'Invalid URL format' };
  }
  try{
    const q = encodeURIComponent(urlToCheck);
    const url = `https://urlscan.io/api/v1/search/?q=${q}`;
    const res = await fetchTimeout(url, {}, 6000);
    if(!res.ok) {
      const errorText = await res.text();
      return { provider: 'URLScan', error: `API error: ${res.status} ${errorText.substring(0, 100)}` };
    }
    const j = await res.json();
    return { provider: 'URLScan', data: j };
  }catch(e){
    return { provider: 'URLScan', error: e.name === 'AbortError' ? 'Request timeout' : `Network error: ${e.message}` };
  }
}

// HIBP
async function apiHIBP(email, keys){
  if(!keys.hibp) return { provider: 'HIBP', error: 'API key not configured' };
  // Validate email format
  const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
  if(!emailRegex.test(email)) {
    return { provider: 'HIBP', error: 'Invalid email format' };
  }
  const headers = { 'hibp-api-key': keys.hibp, 'Accept': 'application/json' };
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=true`;
  try{
    const res = await fetchTimeout(url, { headers }, 6000);
    if(res.status===404) return { provider: 'HIBP', data: [] };
    if(!res.ok) {
      const errorText = await res.text();
      return { provider: 'HIBP', error: `API error: ${res.status} ${errorText.substring(0, 100)}` };
    }
    const j = await res.json();
    return { provider: 'HIBP', data: j };
  }catch(e){
    return { provider: 'HIBP', error: e.name === 'AbortError' ? 'Request timeout' : `Network error: ${e.message}` };
  }
}

// main orchestration: process discovered IOCs
async function processIOCs(iocs){
  const keys = await loadKeys();
  const activeAPIs = await loadActiveAPIs();
  
  const results = [];
  const flat = [];

  (iocs.ips||[]).forEach(v=>flat.push({ioc:v,type:'ip'}));
  (iocs.domains||[]).forEach(v=>flat.push({ioc:v,type:'domain'}));
  (iocs.urls||[]).forEach(v=>flat.push({ioc:v,type:'url'}));
  (iocs.hashes||[]).forEach(v=>flat.push({ioc:v,type:'hash'}));
  (iocs.emails||[]).forEach(v=>flat.push({ioc:v,type:'email'}));

  // limit to first 50 to be safe (or unlimited for manual analysis)
  const limited = flat.length > 50 && !iocs.manual ? flat.slice(0,50) : flat;
  
  // Process in batches of 10 for better performance
  const batchSize = 10;
  for(let i = 0; i < limited.length; i += batchSize){
    const batch = limited.slice(i, i + batchSize);
    
    // Process batch in parallel
    const batchPromises = batch.map(async (item) => {
      const key = cacheKey(item.type, item.ioc);
      
      // gather provider promises based on type and active APIs
      const checks = [];
      if(item.type==='ip'){
        if(activeAPIs.abuseipdb && keys.abuseipdb) {
          checks.push(apiAbuseIPDB(item.ioc, keys));
        }
        if(activeAPIs.virustotal && keys.virustotal) {
          checks.push(apiVirusTotal(item.ioc, 'ip', keys));
        }
        if(activeAPIs.talos) {
          checks.push(apiTalos(item.ioc, keys));
        }
      } else if(item.type==='domain'){
        if(activeAPIs.virustotal && keys.virustotal) {
          checks.push(apiVirusTotal(item.ioc, 'domain', keys));
        }
      } else if(item.type==='url'){
        if(activeAPIs.urlscan) {
          checks.push(apiURLScan(item.ioc, keys));
        }
        if(activeAPIs.virustotal && keys.virustotal) {
          checks.push(apiVirusTotal(item.ioc, 'url', keys));
        }
      } else if(item.type==='hash'){
        if(activeAPIs.virustotal && keys.virustotal) {
          checks.push(apiVirusTotal(item.ioc, 'hash', keys));
        }
      } else if(item.type==='email'){
        if(activeAPIs.hibp && keys.hibp) {
          checks.push(apiHIBP(item.ioc, keys));
        }
      }

      // run checks in parallel (protected)
      const settled = await Promise.allSettled(checks);
      const providerResponses = settled.map((s) => {
        if(s.status === 'fulfilled' && s.value) {
          return s.value;
        }
        if(s.status === 'rejected') {
          console.warn('Provider check rejected:', s.reason);
        }
        return null;
      }).filter(Boolean);
      
      const agg = aggregateResults(item.type, item.ioc, providerResponses);
      CACHE[key] = { value: agg, ts: now() };
      return agg;
    });
    
    // Wait for batch to complete
    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults);
    
    // Minimal delay between batches
    if(i + batchSize < limited.length) {
      await sleep(50);
    }
  }

  // save to storage and update badge
  const state = await loadState();
  state.lastScan = now();
  state.pageIOCs = iocs;
  state.results = results;
  await saveState(state);
  
  // Save to history
  await saveToHistory(state);

  const malCount = results.filter(r=>r.malicious).length;
  setBadge(malCount, malCount>0 ? '#d9534f' : '#2e7d32');
}

// History management
async function saveToHistory(state) {
  try {
    const history = await loadHistory();
    const entry = {
      timestamp: state.lastScan,
      summary: {
        totalIOCs: Object.values(state.pageIOCs || {}).reduce((acc, arr) => (acc + (arr ? arr.length : 0)), 0),
        maliciousCount: (state.results || []).filter(r => r.malicious).length,
        cleanCount: (state.results || []).filter(r => !r.malicious).length
      },
      url: (await chrome.tabs.query({active: true, currentWindow: true}))[0]?.url || 'unknown'
    };
    
    // Add to beginning of history
    history.unshift(entry);
    
    // Keep only last MAX_HISTORY_ENTRIES
    if(history.length > MAX_HISTORY_ENTRIES) {
      history.splice(MAX_HISTORY_ENTRIES);
    }
    
    await chrome.storage.local.set({ [HISTORY_STORE]: history });
  } catch(e) {
    console.warn('Failed to save history:', e);
  }
}

async function loadHistory() {
  try {
    const s = await chrome.storage.local.get(HISTORY_STORE);
    return s[HISTORY_STORE] || [];
  } catch(e) {
    return [];
  }
}

// listen for content script
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if(msg && msg.type === 'IOC_DISCOVERED'){
    // Clear cache for fresh scan
    clearCache();
    processIOCs(msg.data).catch(e=>console.error('processIOCs',e));
  }
  if(msg && msg.type === 'IOC_NONE'){
    // clear badge if nothing
    setBadge(0);
  }
  // allow popup to request current state
  if(msg && msg.type === 'GET_STATE'){
    loadState().then(st=> sendResponse({ status: 'ok', state: st })).catch(e=> sendResponse({ status:'err' }));
    return true; // will respond asynchronously
  }
  // clear state
  if(msg && msg.type === 'CLEAR_STATE'){
    const emptyState = { lastScan: 0, pageIOCs: {}, results: [] };
    clearCache(); // Clear cache when clearing state
    saveState(emptyState).then(async () => {
      // Also clear active state from storage
      await chrome.storage.local.remove('ioc_quick_active_state');
      setBadge(0);
      sendResponse({ status: 'ok' });
    }).catch(e => {
      console.error('Clear state error', e);
      sendResponse({ status: 'err' });
    });
    return true; // will respond asynchronously
  }
  // get history
  if(msg && msg.type === 'GET_HISTORY'){
    loadHistory().then(h => sendResponse({ status: 'ok', history: h })).catch(e => sendResponse({ status: 'err' }));
    return true;
  }
  // analyze manual IOC
  if(msg && msg.type === 'ANALYZE_MANUAL_IOC'){
    // Process in background - don't wait for completion
    processIOCs(msg.data.iocs).catch(e => {
      console.error('Manual IOC processing error:', e);
    });
    // Send immediate response to keep port open
    sendResponse({ status: 'ok', message: 'Processing started' });
    return true; // will respond asynchronously
  }
});