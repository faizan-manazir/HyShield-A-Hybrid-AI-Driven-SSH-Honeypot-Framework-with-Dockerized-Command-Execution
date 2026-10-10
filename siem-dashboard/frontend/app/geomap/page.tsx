"use client";
import { useEffect, useState } from 'react';
import { Globe, Shield, MapPin, Activity, Navigation, Radio, ArrowUpRight, Filter, Eye, RefreshCw, Zap } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import { ComposableMap, Geographies, Geography, Marker, Line, Graticule, Sphere } from 'react-simple-maps';

const geoUrl = "/countries-110m.json";

interface GeoNode {
  id: string;
  ip: string;
  sessionId: string;
  city: string;
  countryName: string;
  countryCode: string;
  flag: string;
  org: string;
  lat: number;
  lng: number;
  eventCount: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  startTime: string;
  isPrivate: boolean;
}

interface CountryStat {
  code: string;
  name: string;
  flag: string;
  eventCount: number;
  sessionCount: number;
  percentage: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  lat: number;
  lng: number;
}

interface GeoPayload {
  honeypot: {
    name: string;
    lat: number;
    lng: number;
    city: string;
    country: string;
    flag: string;
  };
  countries: CountryStat[];
  attackNodes: GeoNode[];
  attackArcs: any[];
  stats: {
    totalCountries: number;
    totalMappedNodes: number;
    totalAttacks: number;
    topCountry: string;
  };
}

export default function GeoMapPage() {
  const [data, setData] = useState<GeoPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GeoNode | null>(null);
  const [showArcs, setShowArcs] = useState(true);
  const [filterRisk, setFilterRisk] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const handleSimulateAttacks = async () => {
    setGenerating(true);
    try {
      await fetch('http://localhost:5000/api/generate-events', { method: 'POST' });
      fetchData();
    } catch (err) {
      console.error("Failed to generate attacks", err);
    } finally {
      setGenerating(false);
    }
  };

  const fetchData = () => {
    setLoading(true);
    fetch('http://localhost:5000/api/geo')
      .then(res => res.json())
      .then((payload: GeoPayload) => {
        setData(payload);
        if (payload.attackNodes.length > 0) {
          setSelectedNode(payload.attackNodes[0]);
        }
        setLoading(false);
      })
      .catch(err => {
        console.error("Failed to load geo telemetry", err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchData(); // Initial load with spinner
    
    const fetchLive = () => {
      fetch('http://localhost:5000/api/geo')
        .then(res => res.json())
        .then((payload: GeoPayload) => setData(payload))
        .catch(console.error);
    };

    const interval = setInterval(fetchLive, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading || !data) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[80vh] text-cyan-400 font-mono">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="w-8 h-8 animate-spin text-cyan-500" />
          <p className="tracking-widest uppercase text-sm animate-pulse">Initializing Global Threat Geolocation Matrix...</p>
        </div>
      </div>
    );
  }

  const filteredNodes = data.attackNodes.filter(node => {
    const matchesRisk = filterRisk === 'ALL' || node.riskLevel === filterRisk;
    const matchesSearch = 
      node.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      node.countryName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      node.city.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesRisk && matchesSearch;
  });

  return (
    <div className="p-8 font-sans max-w-[1700px] mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-white/5 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Globe className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-wide flex items-center gap-2">
                Global Threat Geolocation & Attack Map
              </h1>
              <p className="text-xs text-gray-400 mt-1">
                Real-time IP geolocation telemetry, adversary origins, and attack trajectories for the HyShield SSH Honeypot
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleSimulateAttacks}
            disabled={generating}
            className="flex items-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold px-4 py-2.5 rounded-xl shadow-lg shadow-cyan-500/20 transition-all cursor-pointer disabled:opacity-50"
          >
            <Zap className={`w-4 h-4 text-yellow-300 ${generating ? 'animate-bounce' : ''}`} />
            <span>{generating ? 'Simulating Global Attacks...' : 'Simulate Global Attacks'}</span>
          </button>

          {/* Live Honeypot Node Status */}
          <div className="flex items-center gap-3 bg-[#111116] border border-white/5 rounded-xl px-4 py-2.5 shadow-lg">
            <div className="relative flex items-center justify-center">
              <span className="w-3 h-3 bg-cyan-500 rounded-full animate-ping absolute opacity-75"></span>
              <span className="w-2.5 h-2.5 bg-cyan-400 rounded-full relative"></span>
            </div>
            <div>
              <p className="text-[10px] text-gray-400 font-semibold uppercase tracking-wider">Honeypot Sensor Destination</p>
              <p className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                <span>{data.honeypot.flag}</span>
                <span>{data.honeypot.city}</span>
                <span className="text-[10px] text-cyan-400 font-normal">[{data.honeypot.lat.toFixed(2)}, {data.honeypot.lng.toFixed(2)}]</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Top Threat Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111116] border border-white/5 rounded-xl p-4 flex items-center justify-between shadow-lg">
          <div>
            <p className="text-[11px] font-bold text-gray-400 uppercase tracking-wider">Active Attack Origins</p>
            <p className="text-2xl font-bold text-white mt-1 font-mono">{data.stats.totalCountries} Countries</p>
            <p className="text-[10px] text-cyan-400 mt-1 flex items-center gap-1 font-mono">
              <Radio className="w-3 h-3" /> Live global distribution
            </p>
          </div>
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-cyan-400">
            <Globe className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#111116] border border-white/5 rounded-xl p-4 flex items-center justify-between shadow-lg">
          <div>
            <p className="text-[11px] font-bold text-gray-400 uppercase tracking-wider">Unique Attack Nodes</p>
            <p className="text-2xl font-bold text-white mt-1 font-mono">{data.stats.totalMappedNodes} Nodes</p>
            <p className="text-[10px] text-emerald-400 mt-1 flex items-center gap-1 font-mono">
              <MapPin className="w-3 h-3" /> 100% Geo-resolved
            </p>
          </div>
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400">
            <Navigation className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#111116] border border-white/5 rounded-xl p-4 flex items-center justify-between shadow-lg">
          <div>
            <p className="text-[11px] font-bold text-gray-400 uppercase tracking-wider">Primary Threat Vector</p>
            <p className="text-lg font-bold text-amber-400 mt-1 truncate">{data.stats.topCountry}</p>
            <p className="text-[10px] text-gray-400 mt-1 font-mono">Dominant attack volume</p>
          </div>
          <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-400">
            <Activity className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#111116] border border-white/5 rounded-xl p-4 flex items-center justify-between shadow-lg">
          <div>
            <p className="text-[11px] font-bold text-gray-400 uppercase tracking-wider">Intercepted Inbound Attacks</p>
            <p className="text-2xl font-bold text-rose-400 mt-1 font-mono">{data.stats.totalAttacks} Events</p>
            <p className="text-[10px] text-rose-400/80 mt-1 font-mono">Port 22 SSH Probes</p>
          </div>
          <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400">
            <Shield className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Main Interactive Map Section */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* World Map Container (Span 3) */}
        <div className="xl:col-span-3 bg-[#111116] border border-white/5 rounded-2xl overflow-hidden shadow-2xl flex flex-col relative">
          {/* Map Toolbar Controls */}
          <div className="p-4 bg-[#14161f] border-b border-white/5 flex flex-wrap items-center justify-between gap-4 z-10">
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                <Filter className="w-3.5 h-3.5 text-cyan-400" /> Filter:
              </span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(level => (
                <button
                  key={level}
                  onClick={() => setFilterRisk(level)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold tracking-wider uppercase transition-all ${
                    filterRisk === level
                      ? level === 'CRITICAL' ? 'bg-rose-500 text-white shadow-lg shadow-rose-500/30'
                      : level === 'HIGH' ? 'bg-orange-500 text-white shadow-lg shadow-orange-500/30'
                      : level === 'MEDIUM' ? 'bg-amber-500 text-white shadow-lg shadow-amber-500/30'
                      : 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/30'
                      : 'bg-white/5 text-gray-400 hover:text-white hover:bg-white/10'
                  }`}
                >
                  {level}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-4">
              <label className="flex items-center gap-2 text-xs text-gray-300 font-medium cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={showArcs}
                  onChange={e => setShowArcs(e.target.checked)}
                  className="rounded border-white/10 bg-[#0a0a0f] text-cyan-500 focus:ring-0 focus:ring-offset-0"
                />
                <span>Show Attack Trajectories</span>
              </label>

              <button
                onClick={fetchData}
                title="Refresh Map"
                className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* SVG Map Canvas */}
          <div className="relative bg-[#080a10] min-h-[480px] w-full flex items-center justify-center p-2">
            <ComposableMap
              projectionConfig={{
                rotate: [-10, 0, 0],
                scale: 145
              }}
              style={{ width: "100%", height: "auto", maxHeight: "560px" }}
            >
              <Sphere stroke="rgba(255,255,255,0.04)" strokeWidth={0.5} id="sphere" fill="#080a10" />
              <Graticule stroke="rgba(6,182,212,0.06)" strokeWidth={0.5} />
              
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="#141926"
                      stroke="#222b3d"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "#1f273b", outline: "none" },
                        pressed: { outline: "none" },
                      }}
                    />
                  ))
                }
              </Geographies>

              {/* Trajectory Attack Arcs */}
              {showArcs &&
                filteredNodes.map(node => (
                  <Line
                    key={`line-${node.id}`}
                    from={[node.lng, node.lat]}
                    to={[data.honeypot.lng, data.honeypot.lat]}
                    stroke={
                      node.riskLevel === 'CRITICAL' ? 'rgba(244, 63, 94, 0.45)' :
                      node.riskLevel === 'HIGH' ? 'rgba(249, 115, 22, 0.45)' :
                      'rgba(234, 179, 8, 0.45)'
                    }
                    strokeWidth={1.5}
                    strokeDasharray="4 4"
                  />
                ))}

              {/* Honeypot Sensor Destination Marker */}
              <Marker coordinates={[data.honeypot.lng, data.honeypot.lat]}>
                <g>
                  <circle r={10} fill="rgba(6, 182, 212, 0.25)" className="animate-ping" />
                  <circle r={5} fill="#06b6d4" stroke="#ffffff" strokeWidth={1.5} />
                  <text
                    textAnchor="middle"
                    y={-12}
                    style={{ fontFamily: "monospace", fontSize: 9, fill: "#38bdf8", fontWeight: "bold" }}
                  >
                    HONEYPOT SENSOR
                  </text>
                </g>
              </Marker>

              {/* Attacking Nodes Markers */}
              {filteredNodes.map(node => {
                const isSelected = selectedNode?.id === node.id;
                const markerColor = 
                  node.riskLevel === 'CRITICAL' ? '#f43f5e' :
                  node.riskLevel === 'HIGH' ? '#f97316' : '#eab308';

                return (
                  <Marker
                    key={`marker-${node.id}`}
                    coordinates={[node.lng, node.lat]}
                    onClick={() => setSelectedNode(node)}
                    style={{ cursor: "pointer" }}
                  >
                    <g className="transition-transform duration-200 hover:scale-125">
                      <circle
                        r={isSelected ? 10 : 7}
                        fill={markerColor}
                        fillOpacity={0.3}
                        className="animate-pulse"
                      />
                      <circle
                        r={isSelected ? 5 : 3.5}
                        fill={markerColor}
                        stroke="#ffffff"
                        strokeWidth={1}
                      />
                    </g>
                  </Marker>
                );
              })}
            </ComposableMap>

            {/* Selected Node Floating Card in Map Corner */}
            <AnimatePresence>
              {selectedNode && (
                <motion.div
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 15 }}
                  className="absolute bottom-4 left-4 max-w-sm w-full bg-[#111116]/95 backdrop-blur-md border border-cyan-500/30 rounded-xl p-4 shadow-2xl z-20"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xl">{selectedNode.flag}</span>
                      <div>
                        <Link href={`/explorer?q=${selectedNode.ip}`}>
                          <h4 className="text-sm font-mono font-bold text-white flex items-center gap-2 cursor-pointer hover:text-cyan-400 hover:underline transition-colors">
                            {selectedNode.ip}
                          </h4>
                        </Link>
                        <p className="text-[11px] text-gray-400">
                          {selectedNode.city}, {selectedNode.countryName}
                        </p>
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${
                      selectedNode.riskLevel === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' :
                      selectedNode.riskLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                      'bg-amber-500/20 text-amber-400 border-amber-500/30'
                    }`}>
                      {selectedNode.riskLevel}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-gray-400 my-3 bg-[#080a10] p-2.5 rounded-lg border border-white/5">
                    <div>
                      <p className="text-gray-500 text-[10px] uppercase">Coordinates</p>
                      <p className="text-gray-200 mt-0.5">[{selectedNode.lat.toFixed(2)}, {selectedNode.lng.toFixed(2)}]</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-[10px] uppercase">Attack Count</p>
                      <p className="text-cyan-400 font-bold mt-0.5">{selectedNode.eventCount} logged events</p>
                    </div>
                    <div className="col-span-2 border-t border-white/5 pt-1.5 mt-0.5">
                      <p className="text-gray-500 text-[10px] uppercase">Identified AS / Network</p>
                      <p className="text-gray-300 truncate mt-0.5">{selectedNode.org}</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <span className="text-[10px] text-gray-500 font-mono">
                      SESS: {selectedNode.sessionId.substring(0, 8)}...
                    </span>
                    <Link
                      href={`/sessions/${selectedNode.sessionId}`}
                      className="text-xs font-bold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
                    >
                      Investigate Session <ArrowUpRight className="w-3.5 h-3.5" />
                    </Link>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Right Panel: Top Attacking Countries (Span 1) */}
        <div className="bg-[#111116] border border-white/5 rounded-2xl p-5 shadow-2xl flex flex-col h-full">
          <div className="flex items-center justify-between pb-4 border-b border-white/5">
            <h3 className="text-sm font-bold text-white flex items-center gap-2 uppercase tracking-wider">
              <Globe className="w-4 h-4 text-cyan-400" /> Origin Distribution
            </h3>
            <span className="text-[10px] font-mono text-gray-400 bg-white/5 px-2 py-0.5 rounded">
              {data.countries.length} Nations
            </span>
          </div>

          <div className="divide-y divide-white/5 overflow-y-auto flex-1 max-h-[500px] mt-2 pr-1">
            {data.countries.map((c, idx) => (
              <div key={c.code} className="py-3 hover:bg-white/[0.02] transition-colors rounded-lg px-2 group">
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{c.flag}</span>
                    <div>
                      <p className="text-xs font-bold text-gray-200 group-hover:text-cyan-400 transition-colors">
                        {c.name}
                      </p>
                      <p className="text-[10px] font-mono text-gray-500">
                        {c.sessionCount} sessions • {c.eventCount} probes
                      </p>
                    </div>
                  </div>
                  <span className="text-xs font-mono font-bold text-cyan-400">
                    {c.percentage}%
                  </span>
                </div>

                {/* Percentage Bar */}
                <div className="w-full h-1.5 bg-[#0a0a0f] rounded-full overflow-hidden border border-white/5 mt-1">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500"
                    style={{ width: `${Math.max(c.percentage, 5)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Quick Info Box */}
          <div className="mt-4 pt-4 border-t border-white/5 bg-[#0a0a0f] rounded-xl p-3 border border-white/5">
            <p className="text-[11px] text-gray-400 flex items-center gap-1.5 font-semibold">
              <Shield className="w-3.5 h-3.5 text-cyan-400" /> Geo-Defense Insight
            </p>
            <p className="text-[10px] text-gray-500 mt-1 leading-relaxed">
              GeoIP resolution links honeypot SSH connection events to Autonomous System Numbers (ASN) and geographic coordinates for spatial adversary attribution.
            </p>
          </div>
        </div>
      </div>

      {/* Bottom Table: Geographical Threat Nodes Explorer */}
      <div className="bg-[#111116] border border-white/5 rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-5 border-b border-white/5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Navigation className="w-4 h-4 text-cyan-400" /> Resolved Geographical Threat Actors
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Comprehensive registry of unique source IP locations, attack counts, and session references
            </p>
          </div>

          <div className="w-full md:w-72">
            <input
              type="text"
              placeholder="Search by IP, Country, or City..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-[#0a0a0f] border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500/50 font-mono transition-colors"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono text-gray-400">
            <thead className="bg-[#161822] text-[10px] uppercase font-semibold text-gray-300 border-b border-white/5">
              <tr>
                <th className="px-6 py-3.5">Source IP</th>
                <th className="px-6 py-3.5">Country & Location</th>
                <th className="px-6 py-3.5">Coordinates [Lat, Lng]</th>
                <th className="px-6 py-3.5">Identified Network / Org</th>
                <th className="px-6 py-3.5">Event Count</th>
                <th className="px-6 py-3.5">Severity</th>
                <th className="px-6 py-3.5 text-right">Session Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredNodes.map(node => (
                <tr
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className={`hover:bg-white/[0.03] transition-colors cursor-pointer ${
                    selectedNode?.id === node.id ? 'bg-cyan-500/5' : ''
                  }`}
                >
                  <td className="px-6 py-4 font-bold text-cyan-400">{node.ip}</td>
                  <td className="px-6 py-4">
                    <span className="text-sm mr-2">{node.flag}</span>
                    <span className="text-gray-200 font-semibold">{node.city}</span>,{' '}
                    <span className="text-gray-400">{node.countryName}</span>
                  </td>
                  <td className="px-6 py-4 text-gray-400">
                    [{node.lat.toFixed(4)}, {node.lng.toFixed(4)}]
                  </td>
                  <td className="px-6 py-4 text-gray-300 max-w-xs truncate">{node.org}</td>
                  <td className="px-6 py-4">
                    <span className="bg-white/5 px-2 py-0.5 rounded text-gray-200 border border-white/10">
                      {node.eventCount}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      node.riskLevel === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' :
                      node.riskLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                      'bg-amber-500/20 text-amber-400 border-amber-500/30'
                    }`}>
                      {node.riskLevel}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <Link
                      href={`/sessions/${node.sessionId}`}
                      className="inline-flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 font-sans text-xs font-bold transition-colors"
                    >
                      <Eye className="w-3.5 h-3.5" /> Inspect
                    </Link>
                  </td>
                </tr>
              ))}
              {filteredNodes.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-gray-500 font-sans">
                    No geographical nodes matched the filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
