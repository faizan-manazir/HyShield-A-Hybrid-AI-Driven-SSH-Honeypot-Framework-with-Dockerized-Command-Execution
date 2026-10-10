const geoip = require('geoip-lite');

// Country code to country name and flag mapping
const COUNTRY_DATA = {
  US: { name: 'United States', flag: '🇺🇸', defaultCity: 'Ashburn', defaultLL: [39.0438, -77.4874] },
  DE: { name: 'Germany', flag: '🇩🇪', defaultCity: 'Frankfurt', defaultLL: [50.1109, 8.6821] },
  RU: { name: 'Russian Federation', flag: '🇷🇺', defaultCity: 'Moscow', defaultLL: [55.7558, 37.6173] },
  CN: { name: 'China', flag: '🇨🇳', defaultCity: 'Beijing', defaultLL: [39.9042, 116.4074] },
  NL: { name: 'Netherlands', flag: '🇳🇱', defaultCity: 'Amsterdam', defaultLL: [52.3676, 4.9041] },
  GB: { name: 'United Kingdom', flag: '🇬🇧', defaultCity: 'London', defaultLL: [51.5074, -0.1278] },
  FR: { name: 'France', flag: '🇫🇷', defaultCity: 'Paris', defaultLL: [48.8566, 2.3522] },
  UA: { name: 'Ukraine', flag: '🇺🇦', defaultCity: 'Kyiv', defaultLL: [50.4501, 30.5234] },
  BR: { name: 'Brazil', flag: '🇧🇷', defaultCity: 'Sao Paulo', defaultLL: [-23.5505, -46.6333] },
  IN: { name: 'India', flag: '🇮🇳', defaultCity: 'Mumbai', defaultLL: [19.0760, 72.8777] },
  JP: { name: 'Japan', flag: '🇯🇵', defaultCity: 'Tokyo', defaultLL: [35.6762, 139.6503] },
  KR: { name: 'South Korea', flag: '🇰🇷', defaultCity: 'Seoul', defaultLL: [37.5665, 126.9780] },
  SG: { name: 'Singapore', flag: '🇸🇬', defaultCity: 'Singapore', defaultLL: [1.3521, 103.8198] },
  CA: { name: 'Canada', flag: '🇨🇦', defaultCity: 'Toronto', defaultLL: [43.6532, -79.3832] },
  AU: { name: 'Australia', flag: '🇦🇺', defaultCity: 'Sydney', defaultLL: [-33.8688, 151.2093] },
  IR: { name: 'Iran', flag: '🇮🇷', defaultCity: 'Tehran', defaultLL: [35.6892, 51.3890] },
  VN: { name: 'Vietnam', flag: '🇻🇳', defaultCity: 'Hanoi', defaultLL: [21.0285, 105.8542] },
  ID: { name: 'Indonesia', flag: '🇮🇩', defaultCity: 'Jakarta', defaultLL: [-6.2088, 106.8456] },
  TR: { name: 'Turkey', flag: '🇹🇷', defaultCity: 'Istanbul', defaultLL: [41.0082, 28.9784] },
  RO: { name: 'Romania', flag: '🇷🇴', defaultCity: 'Bucharest', defaultLL: [44.4268, 26.1025] },
  PL: { name: 'Poland', flag: '🇵🇱', defaultCity: 'Warsaw', defaultLL: [52.2297, 21.0122] },
  PK: { name: 'Pakistan', flag: '🇵🇰', defaultCity: 'Islamabad', defaultLL: [33.6844, 73.0479] },
  HK: { name: 'Hong Kong', flag: '🇭🇰', defaultCity: 'Hong Kong', defaultLL: [22.3193, 114.1694] }
};

// Realistic threat simulation profiles for local/loopback test sessions
const SIMULATED_ORIGINS = [
  { country: 'RU', city: 'Saint Petersburg', ll: [59.9343, 30.3351], org: 'Mirai Scanner Botnet / AS12389' },
  { country: 'CN', city: 'Shanghai', ll: [31.2304, 121.4737], org: 'Chinanet Automated SSH Prober' },
  { country: 'NL', city: 'Rotterdam', ll: [51.9244, 4.4777], org: 'Tor Exit Node / Hosting Solutions' },
  { country: 'US', city: 'San Jose', ll: [37.3382, -121.8863], org: 'Compromised Cloud VPS / AWS EC2' },
  { country: 'DE', city: 'Frankfurt', ll: [50.1109, 8.6821], org: 'Hetzner Online GmbH Automated Brute' },
  { country: 'BR', city: 'Rio de Janeiro', ll: [-22.9068, -43.1729], org: 'Brute-force Script / Telecom ISP' }
];

function isPrivateOrLoopback(ip) {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  return false;
}

// Deterministic index from string (e.g. session id or IP)
function getHashIndex(str, max) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash) % max;
}

const geoCache = {};

function fetchLiveGeo(ip) {
  if (geoCache[ip] || isPrivateOrLoopback(ip)) return;
  
  // Mark as pending to avoid duplicate requests
  geoCache[ip] = { pending: true };
  
  fetch(`http://ip-api.com/json/${ip}`)
    .then(res => res.json())
    .then(data => {
      if (data.status === 'success') {
        const code = data.countryCode;
        const meta = COUNTRY_DATA[code] || { name: code, flag: '🌐' };
        
        geoCache[ip] = {
          ip,
          isPrivate: false,
          countryCode: code,
          countryName: data.country || meta.name,
          flag: meta.flag || '🌐',
          city: data.city || 'Unknown City',
          region: data.regionName || '',
          timezone: data.timezone || '',
          lat: data.lat,
          lng: data.lon,
          ll: [data.lat, data.lon],
          org: data.isp || data.org || 'Public Autonomous System'
        };
      } else {
        // API rate limited or failed lookup
        geoCache[ip] = { pending: false, failed: true, retryAfter: Date.now() + 60000 };
      }
    })
    .catch(err => {
      // Network error
      geoCache[ip] = { pending: false, failed: true, retryAfter: Date.now() + 60000 };
    });
}

function resolveGeo(ip, seedContext = '') {
  if (ip === '192.168.100.11') {
    return {
      ip,
      isPrivate: true,
      countryCode: 'PK',
      countryName: 'Pakistan (Analyst LAN)',
      flag: '🇵🇰',
      city: 'Local Workstation (LAN)',
      region: 'Intranet 192.168.100.x',
      timezone: 'Asia/Karachi',
      lat: 33.6844,
      lng: 73.0479,
      ll: [33.6844, 73.0479],
      org: 'Local Analyst Node (192.168.100.11)'
    };
  }

  // If real public IP, check live cache first
  if (!isPrivateOrLoopback(ip)) {
    if (geoCache[ip]) {
      if (geoCache[ip].failed && Date.now() > geoCache[ip].retryAfter) {
         delete geoCache[ip]; // Allow retry
      } else if (!geoCache[ip].pending && !geoCache[ip].failed) {
         return geoCache[ip];
      }
    }
    
    // Kick off live fetch in background if not pending or recently failed
    if (!geoCache[ip]) {
       fetchLiveGeo(ip);
    }

    // Fallback to geoip-lite temporarily
    const geo = geoip.lookup(ip);
    if (geo && geo.country) {
      const code = geo.country.toUpperCase();
      const meta = COUNTRY_DATA[code] || { name: code, flag: '🌐', defaultCity: 'Unknown City', defaultLL: geo.ll || [0, 0] };
      const resolvedCity = (geo.city && geo.city.trim()) ? geo.city : (meta.defaultCity || 'Unknown City');
      return {
        ip,
        isPrivate: false,
        countryCode: code,
        countryName: meta.name || code,
        flag: meta.flag || '🌐',
        city: resolvedCity,
        region: geo.region || '',
        timezone: geo.timezone || '',
        lat: geo.ll ? geo.ll[0] : meta.defaultLL[0],
        lng: geo.ll ? geo.ll[1] : meta.defaultLL[1],
        ll: geo.ll || meta.defaultLL,
        org: 'Resolving Live ISP...'
      };
    }
  }

  // Handle Loopback/Private IP
  if (process.env.DEMO_MODE === 'true') {
    // If seedContext (e.g. session id or IP hash) is provided, give a deterministic simulated external origin for demo
    const profileIndex = getHashIndex(seedContext || ip || 'default', SIMULATED_ORIGINS.length);
    const sim = SIMULATED_ORIGINS[profileIndex];
    const meta = COUNTRY_DATA[sim.country];

    return {
      ip,
      isPrivate: true,
      countryCode: sim.country,
      countryName: meta.name,
      flag: meta.flag,
      city: sim.city,
      region: 'Demo Telemetry',
      timezone: 'UTC',
      lat: sim.ll[0],
      lng: sim.ll[1],
      ll: sim.ll,
      org: sim.org
    };
  } else {
    // Real-data mode: Do not invent geographic locations for private IP addresses
    return {
      ip,
      isPrivate: true,
      countryCode: 'LAN',
      countryName: 'Private Network',
      flag: '🏠',
      city: 'Local Area Network',
      region: 'Internal',
      timezone: 'UTC',
      lat: 0,
      lng: 0,
      ll: [0, 0],
      org: 'Private Address Space'
    };
  }
}

module.exports = {
  resolveGeo,
  isPrivateOrLoopback,
  COUNTRY_DATA,
  SIMULATED_ORIGINS
};
