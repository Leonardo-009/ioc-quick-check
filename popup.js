// popup.js - displays stored state as dashboard cards
function friendly(ts){ if(!ts) return '-'; return new Date(ts).toLocaleString(); }

let isExtensionActive = false;

async function getState(){
  return new Promise((resolve)=>{
    chrome.runtime.sendMessage({ type: 'GET_STATE' }, function(resp){
      if(resp && resp.status==='ok') resolve(resp.state);
      else resolve({ lastScan:0, results:[], pageIOCs:{} });
    });
  });
}

async function getHistory(){
  return new Promise((resolve)=>{
    chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, function(resp){
      if(resp && resp.status==='ok') resolve(resp.history || []);
      else resolve([]);
    });
  });
}

// Check if extension is active on current tab
async function checkExtensionStatus(){
  const tabs = await chrome.tabs.query({active:true,currentWindow:true});
  if(!tabs[0]) return false;
  
  try {
    const response = await chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_STATUS' });
    return response && response.active === true;
  } catch(e) {
    // Content script might not be loaded yet, try to inject it
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabs[0].id },
        files: ['content.js']
      });
      await new Promise(resolve => setTimeout(resolve, 300));
      const response = await chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_STATUS' });
      return response && response.active === true;
    } catch(e2) {
      return false;
    }
  }
}

// Update toggle button state
function updateToggleButton(active){
  isExtensionActive = active;
  const toggleBtn = document.getElementById('toggle-active');
  const toggleText = document.getElementById('toggle-text');
  const statusIndicator = document.getElementById('status-indicator');
  const scanBtn = document.getElementById('scan');
  
  if(active){
    toggleBtn.classList.add('active');
    toggleBtn.style.background = '#2e7d32';
    toggleText.textContent = 'Desativar';
    statusIndicator.classList.add('active');
    scanBtn.disabled = false;
  } else {
    toggleBtn.classList.remove('active');
    toggleBtn.style.background = '#dc2626';
    toggleText.textContent = 'Ativar';
    statusIndicator.classList.remove('active');
    scanBtn.disabled = true;
  }
}

// Get provider link based on type and IOC
function getProviderLink(provider, ioc, type, uuid = null){
  const encoded = encodeURIComponent(ioc);
  switch(provider){
    case 'AbuseIPDB':
      return `https://www.abuseipdb.com/check/${encoded}`;
    case 'VirusTotal':
      if(type === 'ip') return `https://www.virustotal.com/gui/ip-address/${encoded}`;
      if(type === 'domain') return `https://www.virustotal.com/gui/domain/${encoded}`;
      if(type === 'url') return `https://www.virustotal.com/gui/url/${encoded}`;
      if(type === 'hash') return `https://www.virustotal.com/gui/file/${encoded}`;
      return `https://www.virustotal.com/gui/search/${encoded}`;
    case 'Talos':
      return `https://talosintelligence.com/reputation_center/lookup?search=${encoded}`;
    case 'URLScan':
      if(uuid){
        return `https://urlscan.io/result/${uuid}`;
      }
      return `https://urlscan.io/search/#${encoded}`;
    case 'Have I Been Pwned':
      return `https://haveibeenpwned.com/unifiedsearch/${encoded}`;
    default:
      return null;
  }
}

// Format provider data for better visualization
function formatProviderData(providers, ioc, type){
  if(!providers || Object.keys(providers).length === 0) return null;
  
  const formatted = [];
  
  // AbuseIPDB
  if(providers.AbuseIPDB){
    const d = providers.AbuseIPDB;
    const items = [];
    if(d.abuseConfidenceScore !== undefined) items.push(`Score: ${d.abuseConfidenceScore}%`);
    if(d.usageType) items.push(`Tipo: ${d.usageType}`);
    if(d.isp) items.push(`ISP: ${d.isp}`);
    if(d.countryCode) items.push(`País: ${d.countryCode}`);
    if(d.isWhitelisted !== undefined) items.push(`Whitelist: ${d.isWhitelisted ? 'Sim' : 'Não'}`);
    if(items.length > 0) formatted.push({ 
      name: 'AbuseIPDB', 
      items, 
      score: d.abuseConfidenceScore || 0,
      link: getProviderLink('AbuseIPDB', ioc, type)
    });
  }
  
  // VirusTotal
  if(providers.VirusTotal){
    const d = providers.VirusTotal;
    const attrs = d?.data?.attributes;
    if(attrs){
      const items = [];
      if(attrs.last_analysis_stats){
        const stats = attrs.last_analysis_stats;
        items.push(`Maliciosos: ${stats.malicious || 0}`);
        items.push(`Suspensos: ${stats.suspicious || 0}`);
        items.push(`Limpos: ${stats.harmless || 0}`);
        items.push(`Total: ${stats.undetected + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0)}`);
      }
      if(attrs.reputation !== undefined) items.push(`Reputação: ${attrs.reputation}`);
      if(attrs.country) items.push(`País: ${attrs.country}`);
      if(items.length > 0) formatted.push({ 
        name: 'VirusTotal', 
        items, 
        score: attrs.last_analysis_stats?.malicious || 0,
        link: getProviderLink('VirusTotal', ioc, type)
      });
    }
  }
  
  // Talos
  if(providers.Talos){
    const d = providers.Talos;
    if(d.reputation){
      const items = [];
      if(d.reputation.risk_score !== undefined) items.push(`Risk Score: ${d.reputation.risk_score}`);
      if(d.reputation.category) items.push(`Categoria: ${d.reputation.category}`);
      if(d.reputation.description) items.push(`Descrição: ${d.reputation.description}`);
      if(items.length > 0) formatted.push({ 
        name: 'Talos', 
        items, 
        score: d.reputation.risk_score || 0,
        link: getProviderLink('Talos', ioc, type)
      });
    }
  }
  
  // URLScan
  if(providers.URLScan){
    const d = providers.URLScan;
    const items = [];
    if(d.total !== undefined) items.push(`Total de resultados: ${d.total}`);
    if(d.results && d.results.length > 0){
      const first = d.results[0];
      if(first.task) items.push(`URL: ${first.task.url}`);
      if(first.task?.screenshot) items.push(`Screenshot disponível`);
      if(first.uuid) items.push(`UUID: ${first.uuid}`);
    }
      const uuid = d.results?.[0]?.uuid;
      if(items.length > 0) formatted.push({ 
        name: 'URLScan', 
        items, 
        score: d.total || 0,
        link: getProviderLink('URLScan', ioc, type, uuid),
        uuid: uuid
      });
  }
  
  // HIBP (Have I Been Pwned)
  if(providers.HIBP){
    const d = providers.HIBP;
    if(Array.isArray(d) && d.length > 0){
      const items = [];
      items.push(`Vazamentos encontrados: ${d.length}`);
      d.slice(0, 3).forEach(breach => {
        if(breach.Name) items.push(`• ${breach.Name}${breach.BreachDate ? ` (${breach.BreachDate})` : ''}`);
      });
      if(d.length > 3) items.push(`... e mais ${d.length - 3}`);
      formatted.push({ 
        name: 'Have I Been Pwned', 
        items, 
        score: d.length,
        link: getProviderLink('Have I Been Pwned', ioc, type)
      });
    } else if(Array.isArray(d) && d.length === 0){
      formatted.push({ 
        name: 'Have I Been Pwned', 
        items: ['Nenhum vazamento encontrado'], 
        score: 0,
        link: getProviderLink('Have I Been Pwned', ioc, type)
      });
    }
  }
  
  return formatted;
}

function createCard(item){
  const wrap = document.createElement('div'); wrap.className='card';
  const top = document.createElement('div'); top.className='top';
  const left = document.createElement('div'); left.innerHTML = `<div class="ioc">${item.ioc}</div><div style="font-size:12px;color:var(--muted)">${item.type}</div>`;
  const right = document.createElement('div');
  const badge = document.createElement('div'); badge.className='badge';
  if(item.malicious) badge.className += ' bad-danger'; else badge.className += ' bad-ok';
  badge.innerText = item.malicious ? 'MALICIOUS' : 'CLEAN';
  right.appendChild(badge);
  top.appendChild(left); top.appendChild(right);
  wrap.appendChild(top);

  // Format providers data
  const providerData = formatProviderData(item.providers, item.ioc, item.type);
  if(providerData && providerData.length > 0){
    const providersContainer = document.createElement('div'); 
    providersContainer.className='providers-container';
    
    providerData.forEach(provider => {
      const providerCard = document.createElement('div');
      providerCard.className='provider-card';
      
      const providerHeader = document.createElement('div');
      providerHeader.className='provider-header';
      
      const headerLeft = document.createElement('div');
      headerLeft.style.display = 'flex';
      headerLeft.style.alignItems = 'center';
      headerLeft.style.gap = '8px';
      headerLeft.innerHTML = `<strong>${provider.name}</strong>`;
      
      if(provider.link){
        const linkBtn = document.createElement('a');
        linkBtn.href = provider.link;
        linkBtn.target = '_blank';
        linkBtn.rel = 'noopener noreferrer';
        linkBtn.className = 'provider-link';
        linkBtn.innerHTML = '🔗 Ver mais';
        linkBtn.title = 'Abrir no site do provider';
        linkBtn.style.cssText = 'font-size:11px;color:var(--accent);text-decoration:none;padding:2px 6px;border-radius:4px;background:rgba(255,184,107,0.1);';
        headerLeft.appendChild(linkBtn);
      }
      
      providerHeader.appendChild(headerLeft);
      providerCard.appendChild(providerHeader);
      
      const providerItems = document.createElement('div');
      providerItems.className='provider-items';
      provider.items.forEach(itemText => {
        const itemEl = document.createElement('div');
        itemEl.className='provider-item';
        itemEl.textContent = itemText;
        providerItems.appendChild(itemEl);
      });
      providerCard.appendChild(providerItems);
      
      providersContainer.appendChild(providerCard);
    });
    
    wrap.appendChild(providersContainer);
  } else {
    const noData = document.createElement('div');
    noData.className='providers-empty';
    noData.textContent = 'Nenhum dado de provider disponível';
    wrap.appendChild(noData);
  }

  if(item.reasons && item.reasons.length){
    const r = document.createElement('div'); 
    r.className='reasons';
    r.innerHTML = `<strong>⚠️ Alertas:</strong> ${item.reasons.join(' • ')}`;
    wrap.appendChild(r);
  }

  return wrap;
}

function renderProviderDashboards(results){
  // Group results by provider
  const providerGroups = {
    'AbuseIPDB': [],
    'VirusTotal': [],
    'Talos': [],
    'URLScan': [],
    'Have I Been Pwned': []
  };

  // Group IOCs by provider (only MALICIOUS)
  results.forEach(result => {
    if(!result.providers || !result.malicious) return; // Only malicious IOCs
    
    Object.keys(result.providers).forEach(providerName => {
      if(!providerGroups[providerName]) return;
      
      const provider = result.providers[providerName];
      // Only include if has relevant data
      if(hasRelevantProviderData(provider, providerName)){
        // Get UUID for URLScan if available
        let uuid = null;
        if(providerName === 'URLScan' && provider.results && provider.results.length > 0){
          uuid = provider.results[0].uuid;
        }
        
        providerGroups[providerName].push({
          ioc: result.ioc,
          type: result.type,
          malicious: result.malicious,
          provider: provider,
          link: getProviderLink(providerName, result.ioc, result.type, uuid)
        });
      }
    });
  });

  const statsEl = document.getElementById('provider-stats');
  statsEl.innerHTML = '';

  const providerLinks = {
    'AbuseIPDB': 'https://www.abuseipdb.com',
    'VirusTotal': 'https://www.virustotal.com',
    'Talos': 'https://talosintelligence.com',
    'URLScan': 'https://urlscan.io',
    'Have I Been Pwned': 'https://haveibeenpwned.com'
  };

  Object.keys(providerGroups).forEach(providerName => {
    const iocs = providerGroups[providerName];
    if(iocs.length === 0) return; // Skip providers with no data

    const dashboardCard = document.createElement('div');
    dashboardCard.className = 'provider-dashboard-card';
    
    const header = document.createElement('div');
    header.className = 'provider-dashboard-header';
    header.style.cursor = 'pointer';
    
    const headerLeft = document.createElement('div');
    headerLeft.style.display = 'flex';
    headerLeft.style.alignItems = 'center';
    headerLeft.style.gap = '8px';
    headerLeft.innerHTML = `<strong>${providerName}</strong> <span style="font-size:11px;color:var(--muted)">(${iocs.length})</span>`;
    
    const expandBtn = document.createElement('span');
    expandBtn.className = 'expand-icon';
    expandBtn.innerHTML = '▼';
    expandBtn.style.cssText = 'font-size:10px;transition:transform 0.2s;';
    
    headerLeft.appendChild(expandBtn);
    header.appendChild(headerLeft);
    
    const link = document.createElement('a');
    link.href = providerLinks[providerName];
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.className = 'provider-dashboard-link';
    link.innerHTML = '🔗';
    link.title = 'Abrir site do provider';
    link.onclick = (e) => e.stopPropagation();
    header.appendChild(link);
    
    dashboardCard.appendChild(header);

    // Stats summary - organized by provider
    const statsContent = document.createElement('div');
    statsContent.className = 'provider-dashboard-stats';
    
    const maliciousCount = iocs.length; // All are malicious now
    let statsHTML = '';
    
    if(providerName === 'AbuseIPDB'){
      const scores = iocs.map(i => i.provider.abuseConfidenceScore).filter(s => s !== undefined);
      const maxScore = scores.length > 0 ? Math.max(...scores) : 0;
      const avgScore = scores.length > 0 ? Math.round(scores.reduce((a,b)=>a+b,0) / scores.length) : 0;
      const totalReports = iocs.map(i => i.provider.totalReports || 0).reduce((a,b)=>a+b,0);
      
      statsHTML = `
        <div class="stat-row">
          <span>Total IOCs:</span>
          <strong>${iocs.length}</strong>
        </div>
        ${scores.length > 0 ? `<div class="stat-row"><span>Score médio:</span><strong>${avgScore}%</strong></div>` : ''}
        ${maxScore > 0 ? `<div class="stat-row"><span>Score máximo:</span><strong style="color:var(--danger)">${maxScore}%</strong></div>` : ''}
        ${totalReports > 0 ? `<div class="stat-row"><span>Total de reportes:</span><strong>${totalReports}</strong></div>` : ''}
      `;
    } else if(providerName === 'VirusTotal'){
      const stats = iocs.map(i => i.provider.data?.attributes?.last_analysis_stats).filter(s => s);
      const totalPositives = stats.map(s => s.malicious || 0).reduce((a,b)=>a+b,0);
      const totalSuspicious = stats.map(s => s.suspicious || 0).reduce((a,b)=>a+b,0);
      const avgReputation = iocs.map(i => i.provider.data?.attributes?.reputation).filter(r => r !== undefined);
      const avgRep = avgReputation.length > 0 ? Math.round(avgReputation.reduce((a,b)=>a+b,0) / avgReputation.length) : null;
      
      statsHTML = `
        <div class="stat-row">
          <span>Total IOCs:</span>
          <strong>${iocs.length}</strong>
        </div>
        ${totalPositives > 0 ? `<div class="stat-row"><span>Detecções maliciosas:</span><strong style="color:var(--danger)">${totalPositives}</strong></div>` : ''}
        ${totalSuspicious > 0 ? `<div class="stat-row"><span>Detecções suspeitas:</span><strong style="color:#f2c94c">${totalSuspicious}</strong></div>` : ''}
        ${avgRep !== null ? `<div class="stat-row"><span>Reputação média:</span><strong>${avgRep}</strong></div>` : ''}
      `;
    } else if(providerName === 'Talos'){
      const risks = iocs.map(i => i.provider.reputation?.risk_score).filter(r => r !== undefined);
      const avgRisk = risks.length > 0 ? Math.round(risks.reduce((a,b)=>a+b,0) / risks.length) : 0;
      const maxRisk = risks.length > 0 ? Math.max(...risks) : 0;
      
      statsHTML = `
        <div class="stat-row">
          <span>Total IOCs:</span>
          <strong>${iocs.length}</strong>
        </div>
        ${avgRisk > 0 ? `<div class="stat-row"><span>Risk médio:</span><strong>${avgRisk}</strong></div>` : ''}
        ${maxRisk > 0 ? `<div class="stat-row"><span>Risk máximo:</span><strong style="color:var(--danger)">${maxRisk}</strong></div>` : ''}
      `;
    } else if(providerName === 'URLScan'){
      const totalHits = iocs.map(i => i.provider.total || 0).reduce((a,b)=>a+b,0);
      
      statsHTML = `
        <div class="stat-row">
          <span>Total IOCs:</span>
          <strong>${iocs.length}</strong>
        </div>
        ${totalHits > 0 ? `<div class="stat-row"><span>Total de hits:</span><strong>${totalHits}</strong></div>` : ''}
      `;
    } else if(providerName === 'Have I Been Pwned'){
      const totalBreaches = iocs.map(i => Array.isArray(i.provider) ? i.provider.length : 0).reduce((a,b)=>a+b,0);
      
      statsHTML = `
        <div class="stat-row">
          <span>Total IOCs:</span>
          <strong>${iocs.length}</strong>
        </div>
        ${totalBreaches > 0 ? `<div class="stat-row"><span>Total de vazamentos:</span><strong style="color:var(--danger)">${totalBreaches}</strong></div>` : ''}
      `;
    } else {
      statsHTML = `
        <div class="stat-row">
          <span>Total IOCs:</span>
          <strong>${iocs.length}</strong>
        </div>
      `;
    }
    
    statsContent.innerHTML = statsHTML;
    dashboardCard.appendChild(statsContent);

    // Expandable IOC list
    const iocList = document.createElement('div');
    iocList.className = 'provider-ioc-list';
    iocList.style.display = 'none';
    iocList.style.maxHeight = '300px';
    iocList.style.overflowY = 'auto';
    iocList.style.marginTop = '8px';
    iocList.style.paddingTop = '8px';
    iocList.style.borderTop = '1px solid rgba(255,255,255,0.1)';
    
    // Sort IOCs by relevance (higher scores first)
    const sortedIocs = [...iocs].sort((a, b) => {
      if(providerName === 'AbuseIPDB'){
        const scoreA = a.provider.abuseConfidenceScore || 0;
        const scoreB = b.provider.abuseConfidenceScore || 0;
        return scoreB - scoreA;
      }
      if(providerName === 'VirusTotal'){
        const malA = a.provider.data?.attributes?.last_analysis_stats?.malicious || 0;
        const malB = b.provider.data?.attributes?.last_analysis_stats?.malicious || 0;
        return malB - malA;
      }
      if(providerName === 'Talos'){
        const riskA = a.provider.reputation?.risk_score || 0;
        const riskB = b.provider.reputation?.risk_score || 0;
        return riskB - riskA;
      }
      return 0;
    });
    
    sortedIocs.forEach(iocData => {
      const iocItem = document.createElement('div');
      iocItem.className = 'provider-ioc-item';
      
      const iocLeft = document.createElement('div');
      iocLeft.style.display = 'flex';
      iocLeft.style.alignItems = 'center';
      iocLeft.style.gap = '8px';
      iocLeft.style.flex = '1';
      
      const iocBadge = document.createElement('span');
      iocBadge.style.cssText = 'padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold;background:var(--danger);color:#fff;';
      iocBadge.textContent = 'MAL';
      
      const iocText = document.createElement('span');
      iocText.style.cssText = 'font-size:11px;color:#e6eef6;font-weight:500;';
      iocText.textContent = iocData.ioc;
      
      const iocType = document.createElement('span');
      iocType.style.cssText = 'font-size:10px;color:var(--muted);';
      iocType.textContent = `(${iocData.type})`;
      
      // Add provider-specific info
      let providerInfo = '';
      if(providerName === 'AbuseIPDB' && iocData.provider.abuseConfidenceScore !== undefined){
        providerInfo = `Score: ${iocData.provider.abuseConfidenceScore}%`;
      } else if(providerName === 'VirusTotal' && iocData.provider.data?.attributes?.last_analysis_stats){
        const stats = iocData.provider.data.attributes.last_analysis_stats;
        providerInfo = `Mal: ${stats.malicious || 0} | Sus: ${stats.suspicious || 0}`;
      } else if(providerName === 'Talos' && iocData.provider.reputation?.risk_score !== undefined){
        providerInfo = `Risk: ${iocData.provider.reputation.risk_score}`;
      }
      
      const iocInfo = document.createElement('span');
      iocInfo.style.cssText = 'font-size:10px;color:var(--accent);margin-left:auto;';
      iocInfo.textContent = providerInfo;
      
      iocLeft.appendChild(iocBadge);
      iocLeft.appendChild(iocText);
      iocLeft.appendChild(iocType);
      if(providerInfo) iocLeft.appendChild(iocInfo);
      
      const iocLink = document.createElement('a');
      iocLink.href = iocData.link;
      iocLink.target = '_blank';
      iocLink.rel = 'noopener noreferrer';
      iocLink.innerHTML = '🔗';
      iocLink.style.cssText = 'font-size:12px;color:var(--accent);text-decoration:none;padding:4px;';
      iocLink.title = 'Ver no site do provider';
      
      iocItem.appendChild(iocLeft);
      iocItem.appendChild(iocLink);
      iocList.appendChild(iocItem);
    });
    
    dashboardCard.appendChild(iocList);
    
    // Toggle expand/collapse
    let isExpanded = false;
    header.addEventListener('click', (e) => {
      // Don't toggle if clicking the link
      if(e.target.tagName === 'A') return;
      
      isExpanded = !isExpanded;
      iocList.style.display = isExpanded ? 'block' : 'none';
      expandBtn.style.transform = isExpanded ? 'rotate(180deg)' : 'rotate(0deg)';
      expandBtn.textContent = isExpanded ? '▲' : '▼';
    });
    
    statsEl.appendChild(dashboardCard);
  });

  if(statsEl.children.length === 0){
    const empty = document.createElement('div');
    empty.className = 'providers-empty';
    empty.style.cssText = 'text-align:center;padding:32px;color:var(--muted);';
    if(results.length === 0){
      empty.innerHTML = 'Nenhum IOC analisado ainda.<br/><small style="font-size:12px;margin-top:8px;display:block;">Ative a análise clicando no botão "🔍 IOC" na página.</small>';
    } else {
      empty.innerHTML = 'Nenhum IOC malicioso encontrado.<br/><small style="font-size:12px;margin-top:8px;display:block;">Apenas IOCs classificados como MALICIOUS são exibidos.</small>';
    }
    statsEl.appendChild(empty);
  }
}

async function render(){
  // Check extension status - try multiple methods
  let active = false;
  
  // First try to get from content script
  const tabs = await chrome.tabs.query({active:true,currentWindow:true});
  if(tabs[0]) {
    try {
      const statusResponse = await chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_STATUS' });
      if(statusResponse && statusResponse.active !== undefined) {
        active = statusResponse.active;
      }
    } catch(e) {
      // Content script might not be loaded, try storage
      try {
        const storageResult = await chrome.storage.local.get('ioc_quick_active_state');
        if(storageResult.ioc_quick_active_state !== undefined) {
          active = storageResult.ioc_quick_active_state;
        }
      } catch(e2) {
        // Fallback to checkExtensionStatus
        active = await checkExtensionStatus();
      }
    }
  }
  
  isExtensionActive = active;
  updateToggleButton(active);
  
  const state = await getState();
  
  // Count malicious IOCs from results
  const mal = (state.results || []).filter(r=>r.malicious).length;
  
  document.getElementById('malicious').innerText = mal;
  document.getElementById('scantime').innerText = friendly(state.lastScan);
  
  // Render history
  await renderHistory();

  if(!state.results || state.results.length===0){
    renderProviderDashboards([]);
    return;
  }
  
  // Filter results to show only MALICIOUS IOCs with relevant data
  let filteredResults = (state.results || []).filter(r => {
    // Only show MALICIOUS IOCs
    if(!r.malicious) return false;
    
    // Show if has relevant data from any provider
    if(r.hasRelevantData) return true;
    // Or if has any providers with data
    if(r.providers && Object.keys(r.providers).length > 0) {
      return Object.keys(r.providers).some(providerName => {
        const provider = r.providers[providerName];
        return hasRelevantProviderData(provider, providerName);
      });
    }
    return false;
  });
  
  // Apply user filters
  filteredResults = applyFilters(filteredResults);
  
  // Render provider dashboards (only malicious)
  renderProviderDashboards(filteredResults);
}

// Check if provider has relevant data (same logic as background)
function hasRelevantProviderData(provider, providerName){
  if(!provider || !providerName) return false;
  try{
    if(providerName === 'AbuseIPDB'){
      // Exclude 0% scores
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
      return provider.reputation && (
        provider.reputation.risk_score !== undefined ||
        provider.reputation.category ||
        provider.reputation.description
      );
    }
    if(providerName === 'URLScan'){
      return provider.total !== undefined && provider.total > 0;
    }
    if(providerName === 'HIBP'){
      return Array.isArray(provider);
    }
  }catch(e){
    return false;
  }
  return false;
}

// Helper function to check if content script is loaded
async function checkContentScript(tabId){
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: 'PING' });
    return response && response.status === 'pong';
  } catch(e) {
    // If error, content script might not be loaded
    return false;
  }
}

// Toggle Active/Inactive button
const toggleBtn = document.getElementById('toggle-active');
if(toggleBtn) {
  toggleBtn.addEventListener('click', async function(e){
    e.stopPropagation();
    e.preventDefault();
    
    const tabs = await chrome.tabs.query({active:true,currentWindow:true});
    if(!tabs[0]) {
      alert('Nenhuma aba ativa encontrada.');
      return false;
    }
    
    this.disabled = true;
    
    try {
      let response;
      try {
        response = await chrome.tabs.sendMessage(tabs[0].id, { type: 'TOGGLE_ACTIVE' });
      } catch(e) {
        // Content script might not be loaded, try to inject it
        await chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          files: ['content.js']
        });
        await new Promise(resolve => setTimeout(resolve, 800));
        response = await chrome.tabs.sendMessage(tabs[0].id, { type: 'TOGGLE_ACTIVE' });
      }
      
      if(response && response.status === 'ok'){
        isExtensionActive = response.active;
        updateToggleButton(response.active);
        
        // Verify status after a moment
        setTimeout(async () => {
          try {
            const statusCheck = await chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_STATUS' });
            if(statusCheck && statusCheck.active !== undefined) {
              isExtensionActive = statusCheck.active;
              updateToggleButton(statusCheck.active);
            }
          } catch(e) {
            // Ignore errors in verification
          }
        }, 300);
      } else {
        alert('Erro ao alterar status da extensão.');
      }
    } catch(e) {
      console.error('Toggle error:', e);
      alert('Não foi possível ativar a extensão nesta página. Tente recarregar a página.');
    } finally {
      this.disabled = false;
    }
    
    return false;
  });
}

// Scan button - executes scan manually
let isScanning = false;
const scanBtn = document.getElementById('scan');
if(scanBtn) {
  scanBtn.addEventListener('click', async function(e){
    e.stopPropagation();
    e.preventDefault();
    
    // Prevent multiple simultaneous scans
    if(isScanning) {
      console.log('Scan already in progress');
      return false;
    }
    
    const tabs = await chrome.tabs.query({active:true,currentWindow:true});
    if(!tabs[0]) {
      showNotification('Nenhuma aba ativa encontrada.', 'error');
      return false;
    }
    
    // Check actual status from content script or storage
    let actualStatus = false;
    try {
      const statusResponse = await chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_STATUS' });
      actualStatus = statusResponse && statusResponse.active === true;
    } catch(e) {
      // Content script might not be loaded, try storage
      try {
        const storageResult = await chrome.storage.local.get('ioc_quick_active_state');
        actualStatus = storageResult.ioc_quick_active_state === true;
        
        // If not loaded, try to inject
        if(!actualStatus) {
          await chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            files: ['content.js']
          });
          await new Promise(resolve => setTimeout(resolve, 800));
          const statusResponse = await chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_STATUS' });
          actualStatus = statusResponse && statusResponse.active === true;
        }
      } catch(e2) {
        showNotification('Não foi possível verificar o status da extensão. Tente recarregar a página.', 'error');
        return false;
      }
    }
    
    if(!actualStatus){
      showNotification('A extensão precisa estar ativada primeiro. Clique em "Ativar".', 'warning');
      return false;
    }
    
    isScanning = true;
    const originalText = this.textContent;
    this.disabled = true;
    this.innerHTML = '⏳ Escaneando...';
    
    // Show loading indicator in summary
    showLoadingState(true);
    
    try {
      const response = await chrome.tabs.sendMessage(tabs[0].id, { type: 'MANUAL_SCAN' });
      
      if(!response) {
        throw new Error('Nenhuma resposta recebida do content script.');
      }
      
      if(response.status === 'error'){
        showNotification(response.message || 'Erro ao executar scan.', 'error');
        isScanning = false;
        this.disabled = false;
        this.textContent = originalText;
        showLoadingState(false);
        return false;
      }
      
      if(response.status === 'ok'){
        // Wait for processing to complete, then re-render
        // Poll for state update with faster checks
        let attempts = 0;
        const maxAttempts = 30; // 30 * 400ms = 12 seconds max
        
        const checkState = async () => {
          attempts++;
          const state = await getState();
          const hasNewData = state.lastScan > 0;
          const hasResults = state.results && state.results.length > 0;
          
          if(hasNewData && hasResults) {
            showLoadingState(false);
            showNotification(`Scan concluído! ${state.results.length} IOCs analisados.`, 'success');
            render();
            isScanning = false;
            this.disabled = false;
            this.textContent = originalText;
          } else if(attempts >= maxAttempts) {
            showLoadingState(false);
            showNotification('Scan concluído (pode estar processando ainda).', 'info');
            render();
            isScanning = false;
            this.disabled = false;
            this.textContent = originalText;
          } else {
            // Update progress
            const progress = Math.min(Math.round((attempts / maxAttempts) * 100), 95);
            this.innerHTML = `⏳ Escaneando... ${progress}%`;
            setTimeout(checkState, 400);
          }
        };
        
        // Start checking after short delay
        setTimeout(checkState, 800);
      }
    } catch(e) {
      console.error('Scan error:', e);
      showNotification('Erro ao executar scan: ' + (e.message || 'Erro desconhecido'), 'error');
      isScanning = false;
      this.disabled = false;
      this.textContent = originalText;
      showLoadingState(false);
    }
    
    return false;
  });
}

// Notification system
function showNotification(message, type = 'info') {
  // Remove existing notification if any
  const existing = document.getElementById('notification');
  if(existing) existing.remove();
  
  const notification = document.createElement('div');
  notification.id = 'notification';
  notification.style.cssText = `
    position: fixed;
    top: 12px;
    left: 50%;
    transform: translateX(-50%);
    padding: 12px 20px;
    border-radius: 8px;
    background: ${type === 'error' ? '#dc2626' : type === 'success' ? '#2e7d32' : type === 'warning' ? '#f59e0b' : '#6b7280'};
    color: white;
    font-size: 13px;
    font-weight: 600;
    z-index: 10000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    animation: slideDown 0.3s ease-out;
  `;
  notification.textContent = message;
  
  // Add animation style if not exists
  if(!document.getElementById('notification-style')) {
    const style = document.createElement('style');
    style.id = 'notification-style';
    style.textContent = `
      @keyframes slideDown {
        from { transform: translateX(-50%) translateY(-20px); opacity: 0; }
        to { transform: translateX(-50%) translateY(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);
  }
  
  document.body.appendChild(notification);
  
  // Auto remove after 3 seconds
  setTimeout(() => {
    if(notification.parentNode) {
      notification.style.animation = 'slideDown 0.3s ease-out reverse';
      setTimeout(() => notification.remove(), 300);
    }
  }, 3000);
}

// Loading state
function showLoadingState(show) {
  const summaryItems = document.querySelectorAll('.summary-item');
  summaryItems.forEach(item => {
    if(show) {
      item.style.opacity = '0.6';
      item.style.position = 'relative';
      if(!item.querySelector('.loading-spinner')) {
        const spinner = document.createElement('div');
        spinner.className = 'loading-spinner';
        spinner.style.cssText = `
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          width: 20px;
          height: 20px;
          border: 2px solid rgba(255,255,255,0.3);
          border-top-color: var(--accent);
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        `;
        item.appendChild(spinner);
        
        // Add spinner animation if not exists
        if(!document.getElementById('spinner-style')) {
          const style = document.createElement('style');
          style.id = 'spinner-style';
          style.textContent = '@keyframes spin { to { transform: translate(-50%, -50%) rotate(360deg); } }';
          document.head.appendChild(style);
        }
      }
    } else {
      item.style.opacity = '1';
      const spinner = item.querySelector('.loading-spinner');
      if(spinner) spinner.remove();
    }
  });
}

// History rendering
let historyExpanded = false;
async function renderHistory() {
  const historySection = document.getElementById('history-section');
  const historyContent = document.getElementById('history-content');
  const toggleBtn = document.getElementById('toggle-history');
  
  if(!historySection || !historyContent || !toggleBtn) return;
  
  // Remove existing listener if any
  const newToggleBtn = toggleBtn.cloneNode(true);
  toggleBtn.parentNode.replaceChild(newToggleBtn, toggleBtn);
  
  const history = await getHistory();
  
  if(history.length === 0) {
    historySection.style.display = 'none';
    return;
  }
  
  historySection.style.display = 'block';
  
  newToggleBtn.addEventListener('click', () => {
    historyExpanded = !historyExpanded;
    historyContent.style.display = historyExpanded ? 'block' : 'none';
    newToggleBtn.textContent = historyExpanded ? 'Ocultar' : 'Mostrar';
  });
  
  historyContent.innerHTML = history.slice(0, 5).map(entry => {
    const date = new Date(entry.timestamp);
    const urlShort = entry.url.length > 40 ? entry.url.substring(0, 40) + '...' : entry.url;
    return `
      <div style="padding:6px;margin:4px 0;background:rgba(0,0,0,0.2);border-radius:4px;font-size:11px">
        <div style="color:var(--accent);font-weight:600">${date.toLocaleString('pt-BR')}</div>
        <div style="color:var(--muted);font-size:10px;margin-top:2px">${urlShort}</div>
        <div style="margin-top:4px;display:flex;gap:8px;font-size:10px">
          <span>Total: ${entry.summary.totalIOCs}</span>
          <span style="color:var(--danger)">Maliciosos: ${entry.summary.maliciousCount}</span>
          <span style="color:var(--ok)">Limpos: ${entry.summary.cleanCount}</span>
        </div>
      </div>
    `;
  }).join('');
}

// Clear button - clears all stored data
const clearBtn = document.getElementById('clear');
if(clearBtn) {
  clearBtn.addEventListener('click', async function(e){
    e.stopPropagation();
    e.preventDefault();
    e.cancelBubble = true;
    
    // Prevent any other action
    if(this.disabled) {
      return false;
    }
    
    this.disabled = true;
    const originalText = this.textContent;
    this.textContent = 'Limpando...';
    
    try {
      // Clear state from background
      await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ type: 'CLEAR_STATE' }, (resp) => {
          if(chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(resp);
          }
        });
      });
      
      // Clear active state from storage
      await chrome.storage.local.remove('ioc_quick_active_state');
      
      // Clear badge
      chrome.action.setBadgeText({ text: '' });
      
      // Clear UI immediately
      document.getElementById('total').innerText = '0';
      document.getElementById('malicious').innerText = '0';
      document.getElementById('scantime').innerText = '-';
      
      const statsEl = document.getElementById('provider-stats');
      if(statsEl) {
        statsEl.innerHTML = '<div class="providers-empty" style="text-align:center;padding:32px;color:var(--muted);">Nenhum dado disponível</div>';
      }
      
      // Update toggle button to inactive
      isExtensionActive = false;
      updateToggleButton(false);
      
      // Re-render to ensure everything is cleared
      setTimeout(() => {
        render();
        this.disabled = false;
        this.textContent = originalText;
      }, 100);
    } catch(e) {
      console.error('Clear error:', e);
      this.disabled = false;
      this.textContent = originalText;
    }
    
    return false;
  }, { capture: true });
}

// Export functions
function exportToJSON(state) {
  const exportData = {
    exportDate: new Date().toISOString(),
    scanDate: state.lastScan ? new Date(state.lastScan).toISOString() : null,
    summary: {
      totalIOCs: Object.values(state.pageIOCs || {}).reduce((acc, arr) => (acc + (arr ? arr.length : 0)), 0),
      maliciousCount: (state.results || []).filter(r => r.malicious).length,
      cleanCount: (state.results || []).filter(r => !r.malicious).length
    },
    pageIOCs: state.pageIOCs || {},
    results: (state.results || []).map(r => ({
      ioc: r.ioc,
      type: r.type,
      malicious: r.malicious,
      reasons: r.reasons || [],
      providers: r.providers || {},
      errors: r.errors || []
    }))
  };
  
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ioc-quick-check-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportToCSV(state) {
  const results = state.results || [];
  if(results.length === 0) {
    alert('Nenhum resultado para exportar.');
    return;
  }
  
  const headers = ['IOC', 'Tipo', 'Malicioso', 'Razões', 'Providers', 'Erros'];
  const rows = results.map(r => [
    r.ioc,
    r.type,
    r.malicious ? 'Sim' : 'Não',
    (r.reasons || []).join('; '),
    Object.keys(r.providers || {}).join(', '),
    (r.errors || []).map(e => `${e.provider}: ${e.error}`).join('; ')
  ]);
  
  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
  ].join('\n');
  
  const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' }); // BOM for Excel
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ioc-quick-check-${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Filter functions
let currentFilters = { search: '', type: '' };

function applyFilters(results) {
  return results.filter(r => {
    // Search filter
    if(currentFilters.search) {
      const searchLower = currentFilters.search.toLowerCase();
      const matchesSearch = 
        r.ioc.toLowerCase().includes(searchLower) ||
        r.type.toLowerCase().includes(searchLower) ||
        (r.reasons || []).some(reason => reason.toLowerCase().includes(searchLower)) ||
        Object.keys(r.providers || {}).some(p => p.toLowerCase().includes(searchLower));
      if(!matchesSearch) return false;
    }
    
    // Type filter
    if(currentFilters.type && r.type !== currentFilters.type) {
      return false;
    }
    
    return true;
  });
}

// Event listeners for filters
const filterSearch = document.getElementById('filter-search');
const filterType = document.getElementById('filter-type');

if(filterSearch) {
  filterSearch.addEventListener('input', (e) => {
    currentFilters.search = e.target.value;
    render();
  });
}

if(filterType) {
  filterType.addEventListener('change', (e) => {
    currentFilters.type = e.target.value;
    render();
  });
}

// Export buttons
const exportJsonBtn = document.getElementById('export-json');
const exportCsvBtn = document.getElementById('export-csv');

if(exportJsonBtn) {
  exportJsonBtn.addEventListener('click', async () => {
    const state = await getState();
    if(!state.results || state.results.length === 0) {
      alert('Nenhum resultado para exportar. Execute um scan primeiro.');
      return;
    }
    exportToJSON(state);
  });
}

if(exportCsvBtn) {
  exportCsvBtn.addEventListener('click', async () => {
    const state = await getState();
    if(!state.results || state.results.length === 0) {
      alert('Nenhum resultado para exportar. Execute um scan primeiro.');
      return;
    }
    exportToCSV(state);
  });
}

// Manual IOC analysis
const manualIocInput = document.getElementById('manual-ioc-input');
const analyzeManualBtn = document.getElementById('analyze-manual');

// Detect IOC type from input
function detectIOCType(value) {
  if(!value || !value.trim()) return null;
  
  const trimmed = value.trim();
  
  // Check IP
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;
  if(ipRegex.test(trimmed)) return 'ip';
  
  // Check URL
  try {
    new URL(trimmed);
    if(/^https?:\/\//i.test(trimmed)) return 'url';
  } catch(e) {}
  
  // Check hash (MD5, SHA1, SHA256)
  const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
  if(hashRegex.test(trimmed)) return 'hash';
  
  // Check email
  const emailRegex = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$/;
  if(emailRegex.test(trimmed)) return 'email';
  
  // Check domain
  const domainRegex = /^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$/;
  if(domainRegex.test(trimmed) && !ipRegex.test(trimmed)) return 'domain';
  
  return null;
}

if(manualIocInput && analyzeManualBtn) {
  // Visual feedback for valid IOC types
  manualIocInput.addEventListener('input', (e) => {
    const value = e.target.value.trim();
    if(value) {
      const iocType = detectIOCType(value);
      if(iocType) {
        e.target.style.borderColor = 'var(--ok)';
        e.target.title = `Tipo detectado: ${iocType.toUpperCase()}`;
      } else {
        e.target.style.borderColor = 'rgba(255,255,255,0.1)';
        e.target.title = '';
      }
    } else {
      e.target.style.borderColor = 'rgba(255,255,255,0.1)';
      e.target.title = '';
    }
  });
  
  // Allow Enter key to trigger analysis
  manualIocInput.addEventListener('keypress', (e) => {
    if(e.key === 'Enter' && !analyzeManualBtn.disabled) {
      analyzeManualBtn.click();
    }
  });
  
  analyzeManualBtn.addEventListener('click', async function(e) {
    e.stopPropagation();
    e.preventDefault();
    
    const iocValue = manualIocInput.value.trim();
    
    if(!iocValue) {
      showNotification('Por favor, insira um IP, URL, Hash ou Email para analisar.', 'warning');
      manualIocInput.focus();
      return;
    }
    
    // Detect IOC type
    const iocType = detectIOCType(iocValue);
    
    if(!iocType) {
      showNotification('Formato não reconhecido. Por favor, insira um IP, URL, Hash (MD5/SHA1/SHA256), Email ou Domínio válido.', 'error');
      manualIocInput.focus();
      return;
    }
    
    // Disable button and show loading
    this.disabled = true;
    const originalText = this.textContent;
    this.innerHTML = '⏳ Analisando...';
    manualIocInput.disabled = true;
    
    showLoadingState(true);
    
    try {
      // Prepare IOC object based on type
      const iocs = {
        ips: iocType === 'ip' ? [iocValue] : [],
        urls: iocType === 'url' ? [iocValue] : [],
        emails: iocType === 'email' ? [iocValue] : [],
        hashes: iocType === 'hash' ? [iocValue] : [],
        domains: iocType === 'domain' ? [iocValue] : []
      };
      
      // Send to background for processing
      try {
        const response = await new Promise((resolve) => {
          chrome.runtime.sendMessage({ 
            type: 'ANALYZE_MANUAL_IOC', 
            data: { iocs, manual: true, iocValue, iocType }
          }, (resp) => {
            if(chrome.runtime.lastError) {
              resolve({ status: 'error', message: chrome.runtime.lastError.message });
            } else {
              resolve(resp || { status: 'error', message: 'No response' });
            }
          });
        });
        
        if(response && response.status === 'ok') {
          // Wait for processing to complete by polling state
          let attempts = 0;
          const maxAttempts = 40; // Increased timeout for manual analysis
          const startTime = Date.now();
          
          const checkState = async () => {
            attempts++;
            const state = await getState();
            const hasNewData = state.lastScan > startTime; // Check if scan happened after we started
            const hasResults = state.results && state.results.length > 0;
            
            // Check if our specific IOC is in the results
            const ourIocFound = state.results && state.results.some(r => r.ioc === iocValue);
            
            if(hasNewData && (hasResults || ourIocFound)) {
              showLoadingState(false);
              showNotification(`Análise concluída! IOC "${iocValue}" processado.`, 'success');
              render();
              this.disabled = false;
              this.textContent = originalText;
              manualIocInput.disabled = false;
              manualIocInput.value = ''; // Clear input after successful analysis
            } else if(attempts >= maxAttempts) {
              showLoadingState(false);
              showNotification('Análise concluída (pode estar processando ainda).', 'info');
              render();
              this.disabled = false;
              this.textContent = originalText;
              manualIocInput.disabled = false;
            } else {
              this.innerHTML = `⏳ Analisando... ${Math.min(Math.round((attempts / maxAttempts) * 100), 95)}%`;
              setTimeout(checkState, 500); // Slightly longer delay
            }
          };
          
          // Start checking after short delay
          setTimeout(checkState, 1000);
        } else {
          showLoadingState(false);
          showNotification(response?.message || 'Erro ao iniciar análise.', 'error');
          this.disabled = false;
          this.textContent = originalText;
          manualIocInput.disabled = false;
        }
      } catch(err) {
        // Handle sendMessage errors
        showLoadingState(false);
        showNotification('Erro ao comunicar com o background: ' + (err.message || 'Erro desconhecido'), 'error');
        this.disabled = false;
        this.textContent = originalText;
        manualIocInput.disabled = false;
      }
    } catch(e) {
      console.error('Manual analysis error:', e);
      showLoadingState(false);
      showNotification('Erro ao analisar IOC: ' + (e.message || 'Erro desconhecido'), 'error');
      this.disabled = false;
      this.textContent = originalText;
      manualIocInput.disabled = false;
    }
  });
}

document.getElementById('open-options').addEventListener('click', ()=> chrome.runtime.openOptionsPage());
document.getElementById('opts').addEventListener('click', ()=> chrome.runtime.openOptionsPage());

render();
