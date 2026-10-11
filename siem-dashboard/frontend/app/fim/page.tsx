"use client";
import { useState, useEffect } from 'react';
import { FileSearch, FileCode2, FileWarning, Trash2 } from 'lucide-react';
import { motion } from 'framer-motion';
import { API_BASE_URL } from '@/lib/api';

export default function FIMPage() {
  const [mockFim, setMockFim] = useState<any[]>([]);

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/fim`)
      .then(r => r.json())
      .then(setMockFim)
      .catch(console.error);
  }, []);
  return (
    <div className="p-8 font-sans max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <FileSearch className="text-cyan-500 w-6 h-6" /> Inferred File Activity (Pseudo-FIM)
          </h1>
          <p className="text-sm text-gray-400 mt-2 ml-9">Tracking potential changes to files inferred from TTY command logs. Not backed by a verified FIM agent.</p>
        </div>
        <div className="bg-amber-500/10 border border-amber-500/30 text-amber-500 px-4 py-2 rounded text-xs font-bold flex items-center gap-2">
          <FileWarning className="w-4 h-4" /> SIMULATED / INFERRED DATA
        </div>
      </div>

      <div className="bg-[#111116] border border-white/5 rounded-xl overflow-hidden shadow-lg">
        <table className="w-full text-left text-sm text-gray-400">
          <thead className="bg-[#1a1a24] text-xs uppercase font-semibold text-gray-300 border-b border-white/5">
            <tr>
              <th className="px-6 py-4">File Path</th>
              <th className="px-6 py-4">Action</th>
              <th className="px-6 py-4">User</th>
              <th className="px-6 py-4">Timestamp</th>
              <th className="px-6 py-4">SHA-256 Hash</th>
              <th className="px-6 py-4">Risk</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {mockFim.map((file, i) => (
              <motion.tr 
                key={file.id} 
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.1 }}
                className="hover:bg-white/[0.02] font-mono text-xs"
              >
                <td className="px-6 py-4 font-bold text-gray-200">{file.path}</td>
                <td className="px-6 py-4">
                  <span className={`flex items-center gap-2 uppercase tracking-widest font-bold text-[10px] ${
                    file.action === 'modified' ? 'text-amber-500' : 
                    file.action === 'added' ? 'text-emerald-500' : 'text-rose-500'
                  }`}>
                    {file.action === 'modified' ? <FileCode2 className="w-4 h-4" /> : 
                     file.action === 'added' ? <FileWarning className="w-4 h-4" /> : <Trash2 className="w-4 h-4" />}
                    {file.action}
                  </span>
                </td>
                <td className="px-6 py-4 text-cyan-400">{file.user}</td>
                <td className="px-6 py-4 text-gray-500">{file.time}</td>
                <td className="px-6 py-4 text-gray-500">{file.hash}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-[10px] uppercase font-bold tracking-widest ${
                    file.risk === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/20' : 'bg-orange-500/20 text-orange-400 border border-orange-500/20'
                  }`}>{file.risk}</span>
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
