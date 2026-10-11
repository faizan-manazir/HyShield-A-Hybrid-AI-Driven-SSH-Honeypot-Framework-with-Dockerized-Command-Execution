"use client";
import { useState, useEffect } from 'react';
import { Bug, AlertTriangle, ShieldCheck, Server } from 'lucide-react';
import { motion } from 'framer-motion';
import { API_BASE_URL } from '@/lib/api';

export default function VulnerabilitiesPage() {
  const [mockVulns, setMockVulns] = useState<any[]>([]);

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/vulnerabilities`)
      .then(r => r.json())
      .then(setMockVulns)
      .catch(console.error);
  }, []);
  return (
    <div className="p-8 font-sans max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Bug className="text-cyan-500 w-6 h-6" /> Simulated Vulnerabilities
          </h1>
          <p className="text-sm text-gray-400 mt-2 ml-9">Hardcoded example CVEs. NOT an actual vulnerability scanner.</p>
        </div>
        <div className="bg-amber-500/10 border border-amber-500/30 text-amber-500 px-4 py-2 rounded text-xs font-bold flex items-center gap-2">
          SIMULATED DATA (NOT A REAL SCANNER)
        </div>
        <div className="flex gap-4">
          <div className="bg-[#111116] border border-white/5 rounded-lg px-4 py-2 text-center">
            <p className="text-xs text-gray-500 font-bold uppercase tracking-widest">Critical</p>
            <p className="text-lg font-bold text-rose-500">2</p>
          </div>
          <div className="bg-[#111116] border border-white/5 rounded-lg px-4 py-2 text-center">
            <p className="text-xs text-gray-500 font-bold uppercase tracking-widest">High</p>
            <p className="text-lg font-bold text-orange-500">1</p>
          </div>
        </div>
      </div>

      <div className="bg-[#111116] border border-white/5 rounded-xl overflow-hidden shadow-lg">
        <table className="w-full text-left text-sm text-gray-400">
          <thead className="bg-[#1a1a24] text-xs uppercase font-semibold text-gray-300 border-b border-white/5">
            <tr>
              <th className="px-6 py-4">CVE ID</th>
              <th className="px-6 py-4">Package</th>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">CVSS Score</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Published</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {mockVulns.map((vuln, i) => (
              <motion.tr 
                key={vuln.id} 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
                className="hover:bg-white/[0.02] font-mono text-xs"
              >
                <td className="px-6 py-4 font-bold text-cyan-400">{vuln.id}</td>
                <td className="px-6 py-4 text-gray-300">{vuln.package} <span className="text-gray-600">v{vuln.version}</span></td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-[10px] uppercase font-bold tracking-widest ${
                    vuln.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/20' :
                    vuln.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/20' : 
                    'bg-yellow-500/20 text-yellow-400 border border-yellow-500/20'
                  }`}>{vuln.severity}</span>
                </td>
                <td className="px-6 py-4 text-gray-200 font-bold">{vuln.cvss.toFixed(1)}</td>
                <td className="px-6 py-4">
                  <span className={`flex items-center gap-2 ${vuln.status === 'Vulnerable' ? 'text-rose-400' : vuln.status === 'Patched' ? 'text-emerald-400' : 'text-gray-500'}`}>
                    {vuln.status === 'Vulnerable' ? <AlertTriangle className="w-4 h-4" /> : vuln.status === 'Patched' ? <ShieldCheck className="w-4 h-4" /> : <Server className="w-4 h-4" />}
                    {vuln.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-gray-500">{vuln.published}</td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
