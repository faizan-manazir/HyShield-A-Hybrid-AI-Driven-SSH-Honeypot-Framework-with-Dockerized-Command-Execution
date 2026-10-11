"use client";
import { useState, useEffect } from 'react';
import { Target, Activity } from 'lucide-react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { API_BASE_URL } from '@/lib/api';

export default function MitrePage() {
  const [tactics, setTactics] = useState<any[]>([]);

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/mitre`)
      .then(r => r.json())
      .then(setTactics)
      .catch(console.error);
  }, []);
  return (
    <div className="p-8 font-sans max-w-[1600px] mx-auto overflow-x-auto">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Target className="text-cyan-500 w-6 h-6" /> MITRE ATT&CK Matrix
          </h1>
          <p className="text-sm text-gray-400 mt-2 ml-9">Mapping honeypot alerts to adversary tactics and techniques.</p>
        </div>
      </div>

      <div className="flex gap-4 min-w-max pb-8">
        {tactics.map((tactic, i) => (
          <motion.div 
            key={tactic.name} 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="w-64 flex-shrink-0"
          >
            <div className="bg-[#1a1a24] border border-white/5 rounded-t-lg p-3 text-center border-b-2 border-b-cyan-500">
              <h3 className="text-xs font-bold text-gray-200 uppercase tracking-widest">{tactic.name}</h3>
            </div>
            <div className="bg-[#111116] border border-white/5 border-t-0 rounded-b-lg p-2 space-y-2 min-h-[400px]">
              {tactic.techniques.map((tech, j) => (
                <Link key={j} href={`/explorer?q=${encodeURIComponent(tech.name)}`} className="block">
                  <div 
                    className={`p-3 rounded border flex flex-col justify-between hover:bg-white/10 transition-colors cursor-pointer ${
                      tech.count > 0 && tech.severity === 'CRITICAL' ? 'bg-rose-500/10 border-rose-500/30' :
                      tech.count > 0 && tech.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30' :
                      tech.count > 0 ? 'bg-amber-500/10 border-amber-500/30' : 'bg-[#0a0a0f] border-white/5 opacity-50'
                    }`}
                  >
                    <p className={`text-xs font-bold ${tech.count > 0 ? 'text-gray-200' : 'text-gray-500'}`}>{tech.name}</p>
                    <div className="flex justify-between items-end mt-4">
                      <span className="text-[10px] uppercase font-bold tracking-widest text-gray-500">T{1000 + i*10 + j}</span>
                      {tech.count > 0 && (
                        <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                          tech.severity === 'CRITICAL' ? 'bg-rose-500 text-white' :
                          tech.severity === 'HIGH' ? 'bg-orange-500 text-white' : 'bg-amber-500 text-white'
                        }`}>
                          {tech.count}
                        </span>
                      )}
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
