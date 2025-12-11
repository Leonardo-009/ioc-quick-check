// options.js - save / load API keys and active APIs
const STORE = 'ioc_qc_keys_v3';
const APIS_STORE = 'ioc_qc_apis_v3';

async function load(){
  const s = await chrome.storage.local.get([STORE, APIS_STORE]);
  const keys = s[STORE]||{};
  const apis = s[APIS_STORE] || {
    abuseipdb: true,
    virustotal: true,
    talos: true,
    urlscan: true,
    hibp: true
  };
  
  document.getElementById('abuseipdb').value = keys.abuseipdb||'';
  document.getElementById('virustotal').value = keys.virustotal||'';
  document.getElementById('urlscan').value = keys.urlscan||'';
  document.getElementById('hibp').value = keys.hibp||'';
  
  document.getElementById('api_abuseipdb').checked = apis.abuseipdb !== false;
  document.getElementById('api_virustotal').checked = apis.virustotal !== false;
  document.getElementById('api_talos').checked = apis.talos !== false;
  document.getElementById('api_urlscan').checked = apis.urlscan !== false;
  document.getElementById('api_hibp').checked = apis.hibp !== false;
}

async function save(){
  const keys = {
    abuseipdb: document.getElementById('abuseipdb').value.trim(),
    virustotal: document.getElementById('virustotal').value.trim(),
    urlscan: document.getElementById('urlscan').value.trim(),
    hibp: document.getElementById('hibp').value.trim()
  };
  const apis = {
    abuseipdb: document.getElementById('api_abuseipdb').checked,
    virustotal: document.getElementById('api_virustotal').checked,
    talos: document.getElementById('api_talos').checked,
    urlscan: document.getElementById('api_urlscan').checked,
    hibp: document.getElementById('api_hibp').checked
  };
  await chrome.storage.local.set({ [STORE]: keys, [APIS_STORE]: apis });
  alert('Configurações salvas localmente.');
}

async function clearKeys(){
  await chrome.storage.local.set({ [STORE]: {}, [APIS_STORE]: {
    abuseipdb: true,
    virustotal: true,
    talos: true,
    urlscan: true,
    hibp: true
  }});
  load();
  alert('Chaves limpas. APIs reativadas.');
}

document.getElementById('save').addEventListener('click', save);
document.getElementById('clear').addEventListener('click', clearKeys);
document.addEventListener('DOMContentLoaded', load);
