(() => {
  'use strict';
  // Read the current page before any page-specific handlers use it.
  const page = document.body.dataset.page;

  // Keep page navigation immediate to avoid a fade-out/reload flicker.
  window.addEventListener('pageshow', () => {
    document.querySelector('.wrap')?.classList.remove('page-leaving');
  });

  // Donut slices remain clickable; chart hover tooltips are intentionally disabled.
  document.addEventListener('click', (event) => {
    const target = event.target.closest('.donut-slice[data-href]');
    if (target) window.location.href = target.getAttribute('data-href');
  });
  document.addEventListener('keydown', (event) => {
    const target = event.target.closest('.donut-slice[data-href]');
    if (target && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      window.location.href = target.getAttribute('data-href');
    }
  });

  // Resolve alerts in the background so failures are visible and the page does
  // not navigate away. Works for both server-rendered and refreshed table rows.
  document.addEventListener('submit', async (event) => {
    const form = event.target.closest('form[data-close-alert], form[action*="/alerts/"][action$="/close"]');
    if (!form) return;
    event.preventDefault();
    const button = form.querySelector('button[type="submit"], button:not([type])');
    const row = form.closest('tr');
    const original = button?.textContent || '✓ Resolve';
    if (button) { button.disabled = true; button.textContent = 'Resolving…'; }
    try {
      const response = await fetch(form.action, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
        body: new URLSearchParams(new FormData(form)).toString()
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.ok) throw new Error(result.error || `Could not resolve alert (${response.status})`);
      const stateCell = row?.children?.[1];
      if (stateCell) stateCell.replaceChildren(make('span', 'badge CLOSED', 'CLOSED'));
      if (row) row.style.opacity = '.58';
      form.replaceWith(make('span', 'muted', 'Resolved'));
      announce(`Alert ${result.id || ''} resolved successfully.`);
    } catch (error) {
      if (button) { button.disabled = false; button.textContent = original; }
      announce(error.message || 'Unable to resolve this alert. Please try again.', true);
    }
  });

  let appNotice;
  function announce(message, isError = false) {
    if (!appNotice) {
      appNotice = document.createElement('div');
      appNotice.className = 'app-notice';
      appNotice.setAttribute('role', 'status');
      appNotice.setAttribute('aria-live', 'polite');
      document.body.appendChild(appNotice);
    }
    appNotice.textContent = message;
    appNotice.classList.toggle('is-error', isError);
    appNotice.classList.add('is-visible');
    window.clearTimeout(appNotice.hideTimer);
    appNotice.hideTimer = window.setTimeout(() => appNotice.classList.remove('is-visible'), 4500);
  }

  // API-driven background updates: request structured data and patch only
  // changing elements. Never fetch/replace the HTML document or the whole page.
  const refreshSeconds = Number(document.body.dataset.refresh || 0);
  const refreshable = new Set(['overview', 'live', 'geomap', 'alerts', 'explorer', 'sessions']);
  if (!refreshable.has(page) || !Number.isFinite(refreshSeconds) || refreshSeconds < 1) return;
  let refreshing = false;
  const text = (selector, value) => {
    const el = document.querySelector(selector);
    if (el && value !== undefined && value !== null) el.textContent = String(value);
  };
  const fmtTime = (stamp) => {
    if (!stamp) return '-';
    const d = new Date(stamp);
    return Number.isNaN(d.getTime()) ? String(stamp) : d.toISOString().slice(11, 19);
  };
  const make = (tag, className, value) => {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (value !== undefined && value !== null) el.textContent = String(value);
    return el;
  };
  async function getJSON(url) {
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store',
      headers: { 'Accept': 'application/json' } });
    if (!response.ok) throw new Error(`Refresh failed (${response.status})`);
    return response.json();
  }
  async function updateOverview() {
    const data = await getJSON('/api/overview/refresh');
    text('#metric-total-events', Number(data.metrics.totalEvents).toLocaleString());
    text('#metric-active-sessions', data.metrics.activeSessions);
    text('#metric-unique-actors', data.metrics.uniqueActors);
    text('#metric-open-alerts', data.metrics.openAlerts);
    // Replace chart SVGs only; surrounding panels, scroll, and page state persist.
    const timeline = document.querySelector('#overview-timeline');
    const donut = document.querySelector('#overview-donut');
    if (timeline && typeof data.timeline_svg === 'string') timeline.innerHTML = data.timeline_svg;
    if (donut && typeof data.donut_svg === 'string') {
      // Animate the breakdown when the page first opens, but don't replay the
      // entrance animation on every quiet 10-second background data refresh.
      const parsedDonut = document.createElement('template');
      parsedDonut.innerHTML = data.donut_svg;
      parsedDonut.content.querySelectorAll('.donut-slice[data-animated="true"]').forEach((slice) => {
        slice.removeAttribute('data-animated');
      });
      donut.replaceChildren(parsedDonut.content.cloneNode(true));
    }
  }
  async function updateLive() {
    const events = await getJSON('/api/events?limit=100');
    const body = document.querySelector('#live-events-body');
    if (!body || !Array.isArray(events)) return;
    const fragment = document.createDocumentFragment();
    const sources = new Set();
    events.forEach((e) => {
      if (e.src_ip) sources.add(e.src_ip);
      const tr = make('tr', 'mono');
      tr.append(make('td', '', fmtTime(e.timestamp)));
      const categoryCell = make('td');
      categoryCell.append(make('span', `badge ${e.category || 'INFO'}`, e.category || 'INFO'));
      tr.append(categoryCell, make('td', 'eventid', e.eventid || '-'));
      const ipCell = make('td');
      if (e.src_ip) {
        const ip = make('a', '', e.src_ip);
        ip.href = `/explorer?q=${encodeURIComponent(e.src_ip)}`;
        ipCell.append(ip);
      } else ipCell.textContent = '-';
      tr.append(ipCell);
      const sessionCell = make('td');
      if (e.session) {
        const link = make('a', '', e.session.length > 12 ? `${e.session.slice(0, 12)}…` : e.session);
        link.href = `/sessions/${encodeURIComponent(e.session)}`;
        sessionCell.append(link);
      } else sessionCell.textContent = '-';
      tr.append(sessionCell);
      const activityCell = make('td');
      activityCell.append(make('div', 'trunc', e.input || e.username || e.version || e.message || '-'));
      tr.append(activityCell);
      fragment.append(tr);
    });
    if (!events.length) {
      const tr = make('tr');
      const td = make('td', 'empty', 'Waiting for telemetry. New Cowrie events will appear here once they are ingested.');
      td.colSpan = 6; tr.append(td); fragment.append(tr);
    }
    body.replaceChildren(fragment);
    text('#live-event-count', events.length);
    text('#live-source-count', sources.size);
  }
  const geoMapState = { selectedIp: null, customView: false, dragging: false, dragStart: null };
  const geoEsc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  function geoSvg() { return document.querySelector('#geo-map-container .interactive-worldmap'); }
  function geoViewBox(svg) {
    const raw = (svg?.getAttribute('viewBox') || '0 10 1000 410').trim().split(/[ ,]+/).map(Number);
    return raw.length === 4 && raw.every(Number.isFinite) ? raw : [0, 10, 1000, 410];
  }
  function setGeoViewBox(svg, box) {
    if (!svg) return;
    svg.setAttribute('viewBox', box.map((n) => Number(n.toFixed(2))).join(' '));
    geoMapState.customView = !(box[0] === 0 && box[1] === 10 && box[2] === 1000 && box[3] === 410);
  }
  function geoZoom(factor, cx, cy) {
    const svg = geoSvg(); if (!svg) return;
    const [x, y, w, h] = geoViewBox(svg);
    const nw = Math.max(35, Math.min(1000, w * factor));
    const nh = nw * h / w;
    const px = Number.isFinite(cx) ? cx : x + w / 2;
    const py = Number.isFinite(cy) ? cy : y + h / 2;
    const rx = (px - x) / w, ry = (py - y) / h;
    setGeoViewBox(svg, [px - rx * nw, py - ry * nh, nw, nh]);
  }
  function geoFitVisible() {
    const svg = geoSvg(); if (!svg) return;
    const points = [...svg.querySelectorAll('.geo-node')].filter((n) => n.style.display !== 'none')
      .map((n) => [Number(n.dataset.x), Number(n.dataset.y)]).filter(([x,y]) => Number.isFinite(x) && Number.isFinite(y));
    if (!points.length) { setGeoViewBox(svg, [0, 10, 1000, 410]); return; }
    const xs = points.map(p=>p[0]), ys = points.map(p=>p[1]);
    const minX=Math.min(...xs), maxX=Math.max(...xs), minY=Math.min(...ys), maxY=Math.max(...ys);
    const aspect = 1000 / 410;
    let w = Math.max(100, (maxX-minX) * 1.25 + 80, (maxY-minY) * aspect * 1.25 + 80);
    w = Math.min(1000, w); const h = w / aspect;
    setGeoViewBox(svg, [(minX+maxX)/2-w/2, (minY+maxY)/2-h/2, w, h]);
  }
  function geoNodeMatches(node) {
    const q = (document.querySelector('#geo-search')?.value || '').trim().toLowerCase();
    const risk = document.querySelector('#geo-risk-filter')?.value || 'ALL';
    const haystack = [node.dataset.ip,node.dataset.city,node.dataset.region,node.dataset.country,node.dataset.org].join(' ').toLowerCase();
    return (!q || haystack.includes(q)) && (risk === 'ALL' || node.dataset.risk === risk);
  }
  function applyGeoFilters() {
    const svg = geoSvg(); if (!svg) return;
    const visibleIps = new Set();
    svg.querySelectorAll('.geo-node').forEach((node) => {
      const show = geoNodeMatches(node); node.style.display = show ? '' : 'none';
      if (show) visibleIps.add(node.dataset.ip);
    });
    const showRoutes = document.querySelector('#geo-show-routes')?.checked !== false;
    svg.querySelectorAll('.arc').forEach((arc) => { arc.style.display = visibleIps.has(arc.dataset.ip) && showRoutes ? '' : 'none'; });
    document.querySelectorAll('[data-geo-row="true"]').forEach((row) => {
      const q = (document.querySelector('#geo-search')?.value || '').trim().toLowerCase();
      const risk = document.querySelector('#geo-risk-filter')?.value || 'ALL';
      const hay = [row.dataset.ip,row.dataset.city,row.dataset.country,row.dataset.org].join(' ').toLowerCase();
      row.style.display = (!q || hay.includes(q)) && (risk === 'ALL' || row.dataset.risk === risk) ? '' : 'none';
    });
    const visible = visibleIps.size;
    text('#geo-source-count', `${visible} of ${svg.querySelectorAll('.geo-node').length} sources`);
    text('#geo-map-status', `${visible} source IP(s) visible. Select a marker or source row to inspect details.`);
  }
  function selectGeoNode(node) {
    if (!node) return;
    geoMapState.selectedIp = node.dataset.ip || null;
    const ip = node.dataset.ip || 'Unknown IP';
    const lat = Number(node.dataset.lat), lng = Number(node.dataset.lng);
    const score = Math.max(0, Math.min(100, Number(node.dataset.score || 0)));
    const risk = node.dataset.risk || 'LOW';
    text('#geo-detail-ip', ip);
    text('#geo-detail-location', `${node.dataset.city || 'Unknown city'}${node.dataset.region ? ', ' + node.dataset.region : ''}, ${node.dataset.country || 'Unknown country'}`);
    const riskEl = document.querySelector('#geo-detail-risk');
    if (riskEl) { riskEl.textContent = risk; riskEl.className = `badge ${risk}`; }
    text('#geo-detail-score', `${score}/100`);
    const scoreBar = document.querySelector('#geo-detail-score-bar');
    if (scoreBar) { scoreBar.style.width = `${score}%`; scoreBar.dataset.risk = risk; }
    text('#geo-detail-lat', Number.isFinite(lat) ? lat.toFixed(6) : 'Unavailable');
    text('#geo-detail-lng', Number.isFinite(lng) ? lng.toFixed(6) : 'Unavailable');
    text('#geo-detail-sessions', node.dataset.sessions || '1');
    text('#geo-detail-events', node.dataset.events || '0');
    text('#geo-detail-org', node.dataset.org || 'Unknown network');
    const source = node.dataset.source || 'unknown';
    text('#geo-detail-source', source);
    const radius = Number(node.dataset.radiusKm);
    text('#geo-detail-accuracy', Number.isFinite(radius) && radius > 0 ? `Approx. ${radius} km radius` : 'Approximate; radius unavailable');
    const flags = [];
    if (node.dataset.vpn === 'true') flags.push('VPN');
    if (node.dataset.proxy === 'true') flags.push('Proxy');
    if (node.dataset.tor === 'true') flags.push('Tor');
    text('#geo-detail-indicators', flags.length ? flags.join(' · ') : 'No positive flags reported');
    const copy = document.querySelector('#geo-copy-coords'); if (copy) copy.disabled = !Number.isFinite(lat) || !Number.isFinite(lng);
    const osm = document.querySelector('#geo-open-map');
    if (osm && Number.isFinite(lat) && Number.isFinite(lng)) {
      osm.href = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lng}#map=10/${lat}/${lng}`;
      osm.classList.remove('disabled'); osm.setAttribute('aria-disabled','false');
    }
    const investigate = document.querySelector('#geo-investigate');
    if (investigate) { investigate.href = `/explorer?q=${encodeURIComponent(ip)}`; investigate.classList.remove('disabled'); investigate.setAttribute('aria-disabled','false'); }
    const note = 'IP geolocation estimates a network region. It is not GPS and cannot reliably identify a person, device, or street address.';
    text('#geo-detail-note', note);
    const sessionList = document.querySelector('#geo-detail-session-list');
    if (sessionList) {
      sessionList.replaceChildren();
      const ids = (node.dataset.sessionIds || '').split(',').filter(Boolean).slice(0,8);
      if (!ids.length) sessionList.textContent = 'No session IDs available.';
      else ids.forEach((id) => { const a=make('a','geo-session-link',id.length>22 ? `${id.slice(0,22)}…` : id); a.href=`/sessions/${encodeURIComponent(id)}`; a.title=id; sessionList.append(a); });
    }
    document.querySelectorAll('.geo-node.is-selected').forEach((n) => n.classList.remove('is-selected'));
    node.classList.add('is-selected');
    document.querySelectorAll('[data-geo-row="true"].is-selected').forEach((r) => r.classList.remove('is-selected'));
    const row = [...document.querySelectorAll('[data-geo-row="true"]')].find((r) => r.dataset.ip === ip);
    row?.classList.add('is-selected');
  }
  function focusGeoIp(ip, zoom=true) {
    const svg = geoSvg(); if (!svg) return;
    const node = [...svg.querySelectorAll('.geo-node')].find((n) => n.dataset.ip === ip);
    if (!node) return;
    selectGeoNode(node);
    if (zoom) {
      const x=Number(node.dataset.x), y=Number(node.dataset.y);
      const [vx,vy,w,h]=geoViewBox(svg);
      if (w > 500 || x < vx || x > vx+w || y < vy || y > vy+h) {
        const nw=180, nh=nw*410/1000; setGeoViewBox(svg,[x-nw/2,y-nh/2,nw,nh]);
      }
    }
  }
  function attachGeoSvgInteractions() {
    const svg = geoSvg(); if (!svg || svg.dataset.interactionsReady === 'true') return;
    svg.dataset.interactionsReady = 'true';
    svg.addEventListener('click', (event) => {
      const node = event.target.closest('.geo-node'); if (node) { event.stopPropagation(); selectGeoNode(node); }
    });
    svg.addEventListener('keydown', (event) => {
      const node = event.target.closest('.geo-node');
      if (node && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); selectGeoNode(node); }
    });
    svg.addEventListener('wheel', (event) => {
      event.preventDefault();
      const [x,y,w,h]=geoViewBox(svg); const rect=svg.getBoundingClientRect();
      const px=x+(event.clientX-rect.left)/rect.width*w; const py=y+(event.clientY-rect.top)/rect.height*h;
      geoZoom(event.deltaY < 0 ? 0.82 : 1.22, px, py);
    }, {passive:false});
    svg.addEventListener('pointerdown', (event) => {
      if (event.target.closest('.geo-node') || event.target.closest('.honeypot')) return;
      geoMapState.dragging=true; geoMapState.dragStart={x:event.clientX,y:event.clientY,box:geoViewBox(svg)};
      svg.setPointerCapture?.(event.pointerId); svg.classList.add('is-panning');
    });
    svg.addEventListener('pointermove', (event) => {
      if (!geoMapState.dragging || !geoMapState.dragStart) return;
      const rect=svg.getBoundingClientRect(); const b=geoMapState.dragStart.box;
      const dx=(event.clientX-geoMapState.dragStart.x)*b[2]/rect.width;
      const dy=(event.clientY-geoMapState.dragStart.y)*b[3]/rect.height;
      setGeoViewBox(svg,[b[0]-dx,b[1]-dy,b[2],b[3]]);
    });
    const endPan=()=>{geoMapState.dragging=false;geoMapState.dragStart=null;svg.classList.remove('is-panning');};
    svg.addEventListener('pointerup',endPan); svg.addEventListener('pointercancel',endPan); svg.addEventListener('lostpointercapture',endPan);
  }
  function initGeoControls() {
    document.querySelector('#geo-search')?.addEventListener('input', applyGeoFilters);
    document.querySelector('#geo-risk-filter')?.addEventListener('change', applyGeoFilters);
    document.querySelector('#geo-fit')?.addEventListener('click', geoFitVisible);
    document.querySelector('#geo-zoom-in')?.addEventListener('click', () => geoZoom(0.78));
    document.querySelector('#geo-zoom-out')?.addEventListener('click', () => geoZoom(1.28));
    document.querySelector('#geo-reset')?.addEventListener('click', () => { const svg=geoSvg(); if(svg) setGeoViewBox(svg,[0,10,1000,410]); geoMapState.customView=false; });
    document.querySelector('#geo-show-routes')?.addEventListener('change', (event) => {
      const arcs=document.querySelector('#geo-map-container .map-arcs'); if(arcs) arcs.style.display=event.target.checked?'':'none';
    });
    document.querySelector('#geo-copy-coords')?.addEventListener('click', async () => {
      const node=[...document.querySelectorAll('.geo-node')].find((n)=>n.dataset.ip===geoMapState.selectedIp); if(!node) return;
      const coords=`${node.dataset.lat}, ${node.dataset.lng}`;
      try { await navigator.clipboard.writeText(coords); text('#geo-map-status',`Copied coordinates: ${coords}`); }
      catch (_) { text('#geo-map-status',`Coordinates: ${coords} (copy manually)`); }
    });
    document.querySelector('#geo-sources-body')?.addEventListener('click',(event)=>{
      const row=event.target.closest('[data-geo-row="true"]'); if(row && !event.target.closest('a')) focusGeoIp(row.dataset.ip,true);
    });
    document.querySelector('#geo-sources-body')?.addEventListener('keydown',(event)=>{
      const row=event.target.closest('[data-geo-row="true"]'); if(row && (event.key==='Enter'||event.key===' ')){event.preventDefault();focusGeoIp(row.dataset.ip,true);}
    });
    attachGeoSvgInteractions(); applyGeoFilters();
    const first=document.querySelector('#geo-map-container .geo-node'); if(first) selectGeoNode(first);
  }
  function renderGeoSourceTable(nodes) {
    const body=document.querySelector('#geo-sources-body'); if(!body || !Array.isArray(nodes)) return;
    const frag=document.createDocumentFragment();
    nodes.forEach((n)=>{
      const tr=make('tr'); tr.dataset.geoRow='true'; tr.dataset.ip=n.ip||''; tr.dataset.city=n.city||''; tr.dataset.country=n.countryName||''; tr.dataset.org=n.org||''; tr.dataset.risk=n.riskLevel||'LOW'; tr.tabIndex=0;
      cell(tr,n.ip||'-','mono'); cell(tr,`${n.flag||''} ${n.city||'Unknown'}, ${n.countryName||'Unknown'}`);
      cell(tr,Number(n.lat).toFixed(6),'mono'); cell(tr,Number(n.lng).toFixed(6),'mono');
      const risk=make('td'); risk.append(make('span',`badge ${n.riskLevel||'LOW'}`,n.riskLevel||'LOW')); tr.append(risk);
      cell(tr,n.threatScore??0); cell(tr,n.sessionCount??1); cell(tr,n.eventCount??0);
      const action=make('td'); addLink(action,`/explorer?q=${encodeURIComponent(n.ip||'')}`,'Inspect events →'); tr.append(action); frag.append(tr);
    });
    if(!nodes.length){const tr=make('tr');const td=make('td','empty','No source IPs have coordinates available yet.');td.colSpan=9;tr.append(td);frag.append(tr);}
    body.replaceChildren(frag);
  }
  function renderGeoCountryTable(countries) {
    const body=document.querySelector('#geo-countries-body'); if(!body || !Array.isArray(countries)) return;
    const frag=document.createDocumentFragment();
    countries.forEach((c)=>{const tr=make('tr');cell(tr,`${c.flag||''} ${c.name||'Unknown'}`);cell(tr,c.sessionCount);cell(tr,c.eventCount);cell(tr,`${c.percentage}%`);cell(tr,c.CRITICAL);cell(tr,c.HIGH);cell(tr,c.MEDIUM);cell(tr,c.LOW);frag.append(tr);});
    if(!countries.length){const tr=make('tr');const td=make('td','empty','No geographic activity to display yet.');td.colSpan=8;tr.append(td);frag.append(tr);}
    body.replaceChildren(frag);
  }
  async function updateGeo() {
    const data = await getJSON('/api/geo/visual');
    text('#geo-countries', data.stats.totalCountries);
    text('#geo-nodes', data.stats.mappedNodes);
    text('#geo-events', data.stats.totalEvents);
    text('#geo-top-country', data.stats.topCountry);
    const map = document.querySelector('#geo-map-container');
    const oldSvg=geoSvg(); const oldView=oldSvg?.getAttribute('viewBox');
    if (map && typeof data.map_svg === 'string') {
      map.innerHTML = data.map_svg;
      const newSvg=geoSvg(); if(newSvg && oldView) newSvg.setAttribute('viewBox',oldView);
    }
    renderGeoSourceTable(data.nodes || []); renderGeoCountryTable(data.countries || []);
    attachGeoSvgInteractions(); applyGeoFilters();
    if(geoMapState.selectedIp) focusGeoIp(geoMapState.selectedIp,false);
  }
  const cell = (tr, value, className = '') => tr.append(make('td', className, value));
  const addLink = (parent, href, label, className = '') => {
    const link = make('a', className, label); link.href = href; parent.append(link); return link;
  };
  async function updateAlerts() {
    const severity = new URLSearchParams(location.search).get('severity') || 'ALL';
    const alerts = await getJSON(`/api/alerts?severity=${encodeURIComponent(severity)}`);
    const body = document.querySelector('#alerts-body');
    if (!body || !Array.isArray(alerts)) return;
    const fragment = document.createDocumentFragment();
    alerts.forEach((a) => {
      const tr = make('tr'); if (a.status === 'CLOSED') tr.style.opacity = '.5';
      const sev = make('td'); sev.append(make('span', `badge ${a.severity || 'LOW'}`, a.severity || 'LOW')); tr.append(sev);
      const state = make('td'); state.append(make('span', `badge ${a.status || 'OPEN'}`, a.status || 'OPEN')); tr.append(state);
      const detection = make('td'); detection.style.cssText = 'color:#e5e7eb;font-weight:500';
      detection.append(document.createTextNode(a.title || 'Alert'));
      detection.append(make('div', 'muted', a.reason || '')); tr.append(detection);
      const ip = make('td', 'mono'); addLink(ip, `/explorer?q=${encodeURIComponent(a.src_ip || '')}`, a.src_ip || '-'); tr.append(ip);
      const session = make('td', 'mono'); if (a.session_id) addLink(session, `/sessions/${encodeURIComponent(a.session_id)}`, a.session_id.slice(0,12)); else session.textContent='-'; tr.append(session);
      const mitre = make('td'); if (a.mitre) mitre.append(make('span', 'tag', a.mitre)); tr.append(mitre);
      cell(tr, a.timestamp ? new Date(a.timestamp).toISOString().replace('T',' ').slice(0,19) : '-', 'mono');
      const action = make('td');
      if (a.status !== 'CLOSED') {
        const form = make('form'); form.method='post'; form.action=`/alerts/${encodeURIComponent(a.id)}/close`; form.dataset.closeAlert='true';
        const next = make('input'); next.type='hidden'; next.name='next'; next.value=`/alerts?severity=${encodeURIComponent(severity)}`; form.append(next);
        const button = make('button', 'btn ok', '✓ Resolve'); button.type='submit'; button.title='Mark this alert as resolved'; form.append(button); action.append(form);
      }
      tr.append(action); fragment.append(tr);
    });
    if (!alerts.length) { const tr=make('tr'); const td=make('td','empty','No alerts in this view.'); td.colSpan=8; tr.append(td); fragment.append(tr); }
    body.replaceChildren(fragment);
  }
  async function updateExplorer() {
    const form = document.querySelector('form.searchbar');
    const q = form?.querySelector('[name="q"]')?.value || '';
    const category = form?.querySelector('[name="category"]')?.value || 'ALL';
    const events = await getJSON(`/api/events?limit=500&q=${encodeURIComponent(q)}&category=${encodeURIComponent(category)}`);
    const body = document.querySelector('#explorer-events-body');
    if (!body || !Array.isArray(events)) return;
    const fragment = document.createDocumentFragment();
    events.forEach((e) => {
      const tr=make('tr','mono'); cell(tr,fmtTime(e.timestamp));
      const cat=make('td'); cat.append(make('span',`badge ${e.category || 'INFO'}`,e.category || 'INFO')); tr.append(cat);
      cell(tr,e.eventid || '-', 'eventid');
      const ip=make('td'); ip.style.color='#fda4af'; ip.textContent=e.src_ip || '-'; tr.append(ip);
      const session=make('td'); if(e.session) addLink(session,`/sessions/${encodeURIComponent(e.session)}`,e.session); else session.textContent='-'; tr.append(session);
      const activity=make('td'); activity.append(make('div','trunc',e.input || e.username || e.version || '-'));
      if(e.mitre_context) e.mitre_context.split(' | ').forEach(tag=>activity.append(make('span','tag',tag.split(' ')[0])));
      tr.append(activity); fragment.append(tr);
    });
    if(!events.length){const tr=make('tr');const td=make('td','empty','No matching events.');td.colSpan=6;tr.append(td);fragment.append(tr);}
    body.replaceChildren(fragment); text('#explorer-event-count',events.length);
  }
  async function updateSessions() {
    const sort = new URLSearchParams(location.search).get('sort') || 'LATEST';
    const sessions = await getJSON(`/api/sessions?sort=${encodeURIComponent(sort)}`);
    const body = document.querySelector('#sessions-body'); if(!body || !Array.isArray(sessions)) return;
    const fragment=document.createDocumentFragment();
    sessions.forEach((s)=>{
      const tr=make('tr','mono');
      let td=make('td'); addLink(td,`/sessions/${encodeURIComponent(s.id)}`,s.id.slice(0,12)); tr.append(td);
      td=make('td'); addLink(td,`/explorer?q=${encodeURIComponent(s.src_ip)}`,s.src_ip); tr.append(td);
      cell(tr,`${s.location?.flag || ''} ${s.location?.city || 'Unknown'}, ${s.location?.countryCode || '—'}`);
      const risk=make('td');risk.append(make('span',`badge ${s.riskLevel || 'LOW'}`,s.riskLevel || 'LOW'));tr.append(risk);
      cell(tr,s.threatScore ?? 0); cell(tr,s.start_time ? new Date(s.start_time).toISOString().replace('T',' ').slice(0,19) : '-');
      const count=make('td');count.append(make('span','tag',s.eventCount ?? 0));tr.append(count);
      td=make('td');addLink(td,`/sessions/${encodeURIComponent(s.id)}`,'Open investigation →');tr.append(td);
      fragment.append(tr);
    });
    if(!sessions.length){const tr=make('tr');const td=make('td','empty','No sessions to review yet.');td.colSpan=8;tr.append(td);fragment.append(tr);}
    body.replaceChildren(fragment);
  }
  async function refreshData() {
    if (refreshing || document.hidden || !navigator.onLine) return;
    const active = document.activeElement;
    if (active && (active.matches('textarea, select, button') ||
        (active.matches('input') && !active.matches('#geo-search')) || active.closest('form'))) return;
    refreshing = true;
    try {
      if (page === 'overview') await updateOverview();
      else if (page === 'live') await updateLive();
      else if (page === 'geomap') await updateGeo();
      else if (page === 'alerts') await updateAlerts();
      else if (page === 'explorer') await updateExplorer();
      else if (page === 'sessions') await updateSessions();
    } catch (_) {
      // If the API is temporarily unavailable, preserve the current view silently.
    } finally {
      refreshing = false;
    }
  }
  // The slash key advertised in the top bar opens Event Explorer.
  document.addEventListener('keydown', (event) => {
    if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
    const target = event.target;
    if (target && target.matches('input, textarea, select, [contenteditable="true"]')) return;
    event.preventDefault();
    window.location.href = '/explorer';
  });
  if (page === 'geomap') initGeoControls();
  window.setInterval(refreshData, Math.max(5, refreshSeconds) * 1000);
})();
