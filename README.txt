IOC Quick-Check - Versão 3.1 (unpacked)

Uma extensão do Chrome para detecção e análise automática de IOCs (Indicators of Compromise)
em páginas web, integrando múltiplas APIs de Threat Intelligence.

INSTALAÇÃO:
1) Extraia a pasta "ioc-quick-check" em seu PC.
2) Abra Chrome -> chrome://extensions/ e ative Developer mode.
3) Clique em "Load unpacked" e selecione a pasta extraída.
4) Abra a extensão e vá em Configurações para inserir suas API keys:
   - AbuseIPDB (opcional, mas recomendado)
   - VirusTotal (opcional, mas recomendado)
   - URLScan (opcional)
   - Have I Been Pwned (opcional)
   - Talos não exige chave
5) Ative a extensão clicando no botão "Ativar" no popup.
6) Clique em "Scan" para analisar a página atual.
7) Veja os resultados no dashboard organizados por provider.

FUNCIONALIDADES:

✨ MELHORIAS NA VERSÃO 3.1:
- ✅ Tratamento de erros robusto com mensagens descritivas
- ✅ Validação de IOCs antes de enviar para APIs
- ✅ Exportação de resultados em JSON e CSV
- ✅ Filtros de busca e por tipo de IOC
- ✅ Histórico de scans recentes (últimos 50)
- ✅ Loading states e feedback visual melhorado
- ✅ Notificações visuais para ações do usuário
- ✅ Regex melhoradas para detecção mais precisa de IOCs
- ✅ Detecção de IPs, URLs, emails, hashes (MD5, SHA1, SHA256) e domínios

TIPOS DE IOC SUPORTADOS:
- IPs (IPv4)
- URLs (HTTP/HTTPS)
- Emails
- Hashes (MD5, SHA1, SHA256)
- Domínios

APIS DE THREAT INTELLIGENCE:
- AbuseIPDB: Verificação de reputação de IPs
- VirusTotal: Análise de IOCs múltiplos (IPs, URLs, domínios, hashes)
- Talos Intelligence: Reputação de IPs (sem API key necessária)
- URLScan.io: Busca de URLs maliciosas
- Have I Been Pwned: Verificação de vazamentos de emails

NOTAS IMPORTANTES:
⚠️ CUIDADO com rate-limits das APIs (especialmente VirusTotal). 
   A extensão usa cache local por 1 hora para reduzir chamadas.

🔐 NUNCA compartilhe suas chaves de API. Elas são armazenadas 
   localmente no navegador (chrome.storage.local).

🔒 Para ambientes de produção, considere mover as consultas para 
   um servidor proxy para proteger suas chaves de API.

📊 EXPORTAÇÃO:
- JSON: Exporta todos os dados completos em formato JSON
- CSV: Exporta resultados em formato CSV compatível com Excel

🔍 FILTROS:
- Busca por texto: Filtra IOCs por conteúdo
- Filtro por tipo: Filtra por tipo de IOC (IP, URL, email, hash, domínio)

📈 HISTÓRICO:
A extensão mantém histórico dos últimos 50 scans com:
- Data e hora do scan
- URL da página analisada
- Estatísticas resumidas (total, maliciosos, limpos)

SUPORTE:
Para questões ou melhorias, consulte o código-fonte ou entre em contato
com o mantenedor do projeto.

