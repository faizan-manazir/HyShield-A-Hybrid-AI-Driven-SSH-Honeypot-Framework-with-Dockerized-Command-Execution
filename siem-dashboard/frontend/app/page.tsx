"use client";
import { useEffect, useState } from 'react';
import { Activity, ShieldAlert, Users, Zap, Shield, PieChart as PieChartIcon } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import Link from 'next/link';

const COLORS = ['#8b5cf6', '#f97316', '#3b82f6', '#6b7280']; // AUTH, CMD, SESS, INFO

export default function SecurityOverview() {
  const [data, setData] = useState<any>(null);
  const [topActors, setTopActors] = useState<any[]>([]);

  useEffect(() => {
    const fetchData = () => {
      fetch('http://localhost:5000/api/overview/metrics')
        .then(res => res.json())
        .then(setData)
        .catch(console.error);
        
      fetch('http://localhost:5000/api/actors')
        .then(res => res.json())
        .then(data => setTopActors(data.slice(0, 5)))
        .catch(console.error);
    };

    fetchData(); // initial fetch
    const interval = setInterval(fetchData, 5000); // live polling every 5s
    return () => clearInterval(interval);
  }, []);

  if (!data) return <div className="p-8 text-gray-400 animate-pulse flex items-center gap-3"><Zap className="w-5 h-5 text-cyan-500"/> Initializing Live SIEM Telemetry...</div>;

  const metrics = [
    { label: 'TOTAL EVENTS', value: data.metrics.totalEvents.toLocaleString(), icon: Activity, color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/20' },
    { label: 'ACTIVE SESSIONS', value: data.metrics.activeSessions, icon: Zap, color: 'text-emerald-400', bg: 'bg-emerald-400/10', border: 'border-emerald-400/20' },
    { label: 'UNIQUE SOURCES', value: data.metrics.uniqueActors, icon: Users, color: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/20' },
    { label: 'OPEN ALERTS', value: data.metrics.openAlerts, icon: ShieldAlert, color: 'text-rose-400', bg: 'bg-rose-400/10', border: 'border-rose-400/20' },
  ];

  return (
    <div className="p-8">
      <header className="mb-8 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Global Security Overview</h1>
          <p className="text-gray-400 text-sm mt-1">Real-time threat monitoring and activity summary</p>
        </div>
        <div className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-full shadow-[0_0_15px_rgba(16,185,129,0.15)]">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]"></div>
          <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-widest">Live Telemetry</span>
        </div>
      </header>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        {metrics.map((metric) => {
          const Icon = metric.icon;
          return (
            <div key={metric.label} className="bg-[#111116] border border-white/5 rounded-xl p-6 relative overflow-hidden group hover:border-white/10 transition-colors shadow-lg">
              <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-transparent to-current opacity-5 -mr-8 -mt-8 rounded-full ${metric.color} transition-transform group-hover:scale-110`}></div>
              <div className="flex justify-between items-start mb-4">
                <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">{metric.label}</h3>
                <div className={`p-2 rounded-lg ${metric.bg} ${metric.border} border`}>
                  <Icon className={`w-4 h-4 ${metric.color}`} />
                </div>
              </div>
              <p className="text-4xl font-light text-white">{metric.value}</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mb-6">
        {/* Timeline Chart */}
        <div className="xl:col-span-2 bg-[#111116] border border-white/5 rounded-xl p-6 shadow-lg flex flex-col">
          <div className="flex justify-between items-center mb-6">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2"><Activity className="w-4 h-4 text-cyan-500" /> Security Activity Timeline</h3>
            <span className="text-xs text-gray-500 border border-white/5 rounded px-2 py-1 bg-white/[0.02]">Last 100 Events</span>
          </div>
          <div className="flex-1 min-h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.timeline}>
                <defs>
                  <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#444" fontSize={10} tickMargin={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#444" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0a0a0f', border: '1px solid #333', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="events" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorEvents)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Pie Chart */}
        <div className="bg-[#111116] border border-white/5 rounded-xl p-6 shadow-lg flex flex-col">
          <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2"><PieChartIcon className="w-4 h-4 text-cyan-500" /> Event Distribution</h3>
          <div className="flex-1 min-h-[250px] w-full flex items-center justify-center -ml-4">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.categoryData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {data.categoryData?.map((entry: any, index: number) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#0a0a0f', border: '1px solid #333', borderRadius: '8px' }} itemStyle={{ color: '#fff' }} />
                <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: '12px', color: '#9ca3af' }}/>
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Alerts List */}
        <div className="xl:col-span-2 bg-[#111116] border border-white/5 rounded-xl p-0 overflow-hidden flex flex-col shadow-lg">
          <div className="p-6 border-b border-white/5 flex justify-between items-center">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2"><ShieldAlert className="w-4 h-4 text-rose-500" /> Recent Alerts</h3>
            <Link href="/alerts" className="text-xs text-cyan-500 hover:text-cyan-400">View All →</Link>
          </div>
          <div className="flex-1 overflow-y-auto max-h-[350px]">
            {data.recentAlerts.map((alert: any) => (
              <div key={alert.id} className="p-4 border-b border-white/5 hover:bg-white/[0.02] transition-colors cursor-pointer group">
                <div className="flex items-start gap-3">
                  <div className={`mt-1 flex-shrink-0 w-2 h-2 rounded-full ${
                    alert.severity === 'CRITICAL' ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]' :
                    alert.severity === 'HIGH' ? 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]' :
                    alert.severity === 'MEDIUM' ? 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.8)]' : 'bg-blue-500'
                  }`} />
                  <div className="flex-1">
                    <h4 className="text-sm font-medium text-gray-200 group-hover:text-cyan-400 transition-colors">{alert.title}</h4>
                    <p className="text-xs text-gray-500 mt-1">{alert.reason}</p>
                    <div className="flex items-center justify-between mt-3">
                      <div className="flex items-center gap-2">
                        <Link href={`/explorer?q=${alert.src_ip}`} className="text-[10px] font-mono text-gray-400 bg-white/5 hover:bg-white/10 transition-colors px-2 py-1 rounded border border-white/5 cursor-pointer">
                          {alert.src_ip}
                        </Link>
                        <Link href={`/sessions/${alert.session_id}`} className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 hover:bg-cyan-500/20 transition-colors px-2 py-1 rounded border border-cyan-500/20 cursor-pointer flex items-center gap-1">
                          SESS:{alert.session_id.substring(0,8)} <span className="text-[8px]">↗</span>
                        </Link>
                      </div>
                      <span className="text-[10px] text-gray-600 font-mono">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
            {data.recentAlerts.length === 0 && (
              <div className="p-8 text-center text-gray-500 text-sm h-full flex flex-col items-center justify-center">
                <Shield className="w-8 h-8 mx-auto mb-3 opacity-20" />
                No recent alerts detected
              </div>
            )}
          </div>
        </div>

        {/* Top Threat Actors Widget */}
        <div className="bg-[#111116] border border-white/5 rounded-xl p-0 overflow-hidden flex flex-col shadow-lg">
          <div className="p-6 border-b border-white/5 flex justify-between items-center">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2"><Users className="w-4 h-4 text-amber-500" /> Active Threat Sources</h3>
            <div className="flex items-center gap-3">
              <Link href="/geomap" className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold">Threat Map 🌐</Link>
              <Link href="/actors" className="text-xs text-gray-400 hover:text-gray-200">View All →</Link>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto max-h-[350px]">
            {topActors.length === 0 ? (
              <div className="p-8 text-center text-gray-500 text-sm h-full flex items-center justify-center">No active sources</div>
            ) : (
              <div className="divide-y divide-white/5">
                {topActors.map(actor => (
                  <div key={actor.ip} className="p-4 hover:bg-white/[0.02] transition-colors flex justify-between items-center">
                    <div>
                      <h4 className="text-sm font-mono font-bold text-gray-200 flex items-center gap-1.5">
                        {actor.location?.flag && <span className="text-base">{actor.location.flag}</span>}
                        <Link href={`/explorer?q=${actor.ip}`} className="hover:text-cyan-400 hover:underline transition-colors">{actor.ip}</Link>
                      </h4>
                      <p className="text-xs text-gray-500 mt-1">
                        {actor.location?.city ? `${actor.location.city}, ${actor.location.countryCode} • ` : ''}{actor.eventCount} logged events
                      </p>
                    </div>
                    <span className={`px-2 py-1 rounded text-[10px] font-bold tracking-widest border ${
                      actor.riskLevel === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/20' :
                      actor.riskLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/20' :
                      'bg-emerald-500/20 text-emerald-400 border-emerald-500/20'
                    }`}>
                      {actor.riskLevel}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
