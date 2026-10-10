"use client";
import { useEffect, useState } from 'react';
import { use } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';

export default function SessionInvestigation({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [session, setSession] = useState<any>(null);

  useEffect(() => {
    fetch(`http://localhost:5000/api/sessions/${id}`)
      .then(r => r.json())
      .then(setSession)
      .catch(console.error);
  }, [id]);

  if (!session) return <div className="p-8 text-gray-400 animate-pulse">Loading forensics...</div>;

  // Calculate duration
  let duration = '0s';
  if (session.events.length > 1) {
    const start = new Date(session.events[0].timestamp).getTime();
    const end = new Date(session.events[session.events.length - 1].timestamp).getTime();
    duration = Math.max(1, Math.floor((end - start) / 1000)) + 's';
  }

  // TTY Log reconstruction directly from JSON
  const ttyEvents = session.events.filter((e: any) => e.input || (e.eventid && e.eventid.includes('command')));
  const ttyLog = ttyEvents.map((e: any) => e.input || e.message || '').filter(Boolean).join('\n');

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="p-8 min-h-screen font-sans">
      <header className="mb-10">
        <h1 className="text-2xl font-bold text-white mb-2">Session Investigation</h1>
        <p className="text-gray-400 mb-6 font-mono text-xs uppercase tracking-wider">SESSION: {id}</p>
        
        <div className="flex gap-3 mt-4">
          <span className={`px-3 py-1.5 rounded text-[11px] font-bold tracking-widest ${
             session.riskLevel === 'CRITICAL' || session.riskLevel === 'HIGH' 
             ? 'bg-red-950/50 text-red-500 border border-red-900/50' 
             : 'bg-[#1a1f2e] text-gray-300 border border-white/5'
          }`}>Risk: {session.riskLevel || 'LOW'}</span>
          <span className="bg-[#1a1f2e] border border-white/5 text-gray-300 px-3 py-1.5 rounded text-[11px] font-bold tracking-widest">Threat Score: {session.threatScore || 0}/100</span>
          <Link href={`/explorer?q=${session.src_ip}`} className="bg-[#1a1f2e] border border-white/5 text-gray-300 hover:text-cyan-400 hover:border-cyan-500/50 transition-colors px-3 py-1.5 rounded text-[11px] font-bold tracking-widest cursor-pointer">
            Source IP: {session.src_ip}
          </Link>
          {session.location && (
            <Link href="/geomap" className="bg-[#1a1f2e] border border-cyan-500/20 text-cyan-300 hover:bg-cyan-900/30 hover:border-cyan-400/50 transition-colors px-3 py-1.5 rounded text-[11px] font-bold tracking-widest flex items-center gap-1.5 cursor-pointer">
              <span>{session.location.flag}</span>
              <span>{session.location.city}, {session.location.countryName}</span>
              <span className="text-gray-500 font-mono font-normal">[{session.location.lat?.toFixed(2)}, {session.location.lng?.toFixed(2)}]</span>
            </Link>
          )}
          <span className="bg-[#1a1f2e] border border-white/5 text-gray-300 px-3 py-1.5 rounded text-[11px] font-bold tracking-widest">Duration: {duration}</span>
        </div>
      </header>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        <div className="xl:col-span-5">
          <div className="bg-[#11141d] rounded-lg p-6 h-full border border-white/5 shadow-2xl">
            <h3 className="text-sm font-semibold text-white mb-8 uppercase tracking-wide">ATTACK STORY</h3>
            <div className="ml-2">
              <AnimatePresence>
              {session.events.map((e: any, i: number) => {
                let stage = 'ACTIVITY';
                let isActive = false;
                if (e.eventid === 'cowrie.session.connect') stage = 'CONNECTION';
                if (e.eventid === 'cowrie.client.version') stage = 'FINGERPRINT';
                if (e.eventid === 'cowrie.login.failed') stage = 'AUTHENTICATION';
                if (e.eventid === 'cowrie.login.success') {
                    stage = 'ACCESS';
                    isActive = true;
                }
                if (e.eventid === 'cowrie.session.closed') stage = 'FORENSICS';
                
                let desc = e.message || e.input || e.eventid;
                
                return (
                  <motion.div 
                    key={i} 
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="flex gap-6 relative mb-8 last:mb-0 group"
                  >
                    {i !== session.events.length - 1 && (
                      <div className="absolute left-[5px] top-4 bottom-[-32px] w-[2px] bg-white/5 group-hover:bg-white/10 transition-colors" />
                    )}
                    <div className="relative mt-1 z-10">
                      <div className={`w-3 h-3 rounded-full shadow-md ${isActive ? 'bg-red-500 shadow-red-500/20' : 'bg-[#3a4155]'}`}></div>
                    </div>
                    <div className="flex-1 -mt-1">
                      <div className="flex justify-between items-baseline mb-1">
                        <h4 className="text-[11px] font-bold tracking-wider text-white uppercase">{stage}</h4>
                        <span className="text-[10px] text-gray-500 font-mono">{new Date(e.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-xs text-gray-400 mt-1">{desc}</p>
                    </div>
                  </motion.div>
                );
              })}
              </AnimatePresence>
            </div>
          </div>
        </div>
        
        <div className="xl:col-span-7 space-y-6">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-[#11141d] rounded-lg p-6 border border-white/5 shadow-2xl">
            <h3 className="text-sm font-semibold text-white mb-4">Forensic Evidence (TTY Log)</h3>
            <div className="bg-[#0f111a] border border-[#2a2e38] rounded-lg overflow-hidden shadow-2xl">
              <div className="bg-[#1a1d27] border-b border-[#2a2e38] px-4 py-2 flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-rose-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                </div>
                <div className="flex-1 text-center text-[10px] text-gray-500 font-mono tracking-wider font-bold">
                  root@{session.src_ip} — ssh — 80x24
                </div>
              </div>
              <div className="p-4 font-mono text-[13px] text-green-400 min-h-[200px] whitespace-pre-wrap leading-relaxed overflow-x-auto selection:bg-green-500/30">
                {ttyLog ? ttyLog : <span className="text-gray-600 italic">No interactive shell commands recorded in this session.</span>}
                <span className="animate-pulse inline-block w-2 h-4 bg-green-400 ml-1 align-middle"></span>
              </div>
            </div>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-[#11141d] rounded-lg p-6 border border-white/5 shadow-2xl">
            <h3 className="text-sm font-semibold text-white mb-6">Threat Score Explanation</h3>
            
            {session.dimensions && (
              <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="bg-[#0a0c14] border border-white/5 p-3 rounded text-center">
                  <div className="text-[10px] text-gray-500 uppercase font-bold tracking-widest mb-1">Access</div>
                  <div className="text-lg font-mono text-white">{session.dimensions.access}/25</div>
                </div>
                <div className="bg-[#0a0c14] border border-white/5 p-3 rounded text-center">
                  <div className="text-[10px] text-gray-500 uppercase font-bold tracking-widest mb-1">Activity</div>
                  <div className="text-lg font-mono text-white">{session.dimensions.activity}/25</div>
                </div>
                <div className="bg-[#0a0c14] border border-white/5 p-3 rounded text-center">
                  <div className="text-[10px] text-gray-500 uppercase font-bold tracking-widest mb-1">Weaponize</div>
                  <div className="text-lg font-mono text-white">{session.dimensions.weaponization}/25</div>
                </div>
                <div className="bg-[#0a0c14] border border-white/5 p-3 rounded text-center">
                  <div className="text-[10px] text-gray-500 uppercase font-bold tracking-widest mb-1">Intent</div>
                  <div className="text-lg font-mono text-white">{session.dimensions.intent}/25</div>
                </div>
              </div>
            )}

            <ul className="space-y-4 text-xs">
              {session.explanations?.length > 0 ? session.explanations.map((ex: any, i: number) => (
                <li key={i} className="flex justify-between items-start text-gray-300">
                  <div className="flex-1 pr-4">
                    <span className="bg-white/5 text-gray-400 px-2 py-0.5 rounded text-[9px] font-bold tracking-wider mr-2 uppercase">{ex.dimension}</span>
                    {ex.reason}
                    {ex.mitre && (
                      <Link href="/mitre" className="inline-block ml-2 text-[10px] bg-blue-900/30 hover:bg-blue-800/50 text-blue-400 border border-blue-800/50 hover:border-blue-400/50 px-1.5 py-0.5 rounded font-mono transition-colors cursor-pointer">
                        {ex.mitre}
                      </Link>
                    )}
                  </div>
                  <span className="font-mono text-gray-400 shrink-0 mt-0.5">+{ex.score}</span> 
                </li>
              )) : <li className="text-gray-500 italic">No suspicious activity detected.</li>}
              <li className="flex justify-between items-center text-white font-bold pt-4 mt-2 border-t border-white/10">
                 <span className="text-sm font-bold">Composite Threat Score</span> 
                 <span className="text-sm">{session.threatScore || 0} / 100</span>
              </li>
            </ul>
          </motion.div>
        </div>
      </div>
    </motion.div>
  );
}
