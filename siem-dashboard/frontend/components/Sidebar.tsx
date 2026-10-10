"use client";
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Activity, Search, AlertTriangle, Users, Terminal, Settings, Target, Bug, FileSearch, Globe } from 'lucide-react';

export default function Sidebar() {
  const pathname = usePathname();

  const links = [
    { section: 'Dashboards', items: [
      { name: 'Security Overview', href: '/', icon: Shield },
      { name: 'Threat Map (Geo)', href: '/geomap', icon: Globe },
      { name: 'MITRE ATT&CK', href: '/mitre', icon: Target },
    ]},
    { section: 'Threat Hunting', items: [
      { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
      { name: 'Event Explorer', href: '/explorer', icon: Search },
      { name: 'Actors', href: '/actors', icon: Users },
      { name: 'Sessions', href: '/sessions', icon: Terminal },
    ]}
  ];

  return (
    <aside className="w-64 bg-[#0a0a0f] border-r border-white/5 text-gray-400 h-screen flex flex-col font-sans">
      <div className="p-6 flex items-center gap-3">
        <div className="w-8 h-8 rounded bg-cyan-500/10 flex items-center justify-center border border-cyan-500/30">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-white tracking-widest leading-none">HYSHIELD</h1>
          <p className="text-[10px] text-cyan-500 uppercase tracking-widest mt-1 font-semibold">SIEM DASHBOARD</p>
        </div>
      </div>
      
      <nav className="flex-1 px-4 py-4 space-y-8 overflow-y-auto">
        {links.map(group => (
          <div key={group.section}>
            <h2 className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-3 px-3">{group.section}</h2>
            <ul className="space-y-1">
              {group.items.map(item => {
                const Icon = item.icon;
                const isActive = pathname === item.href;
                return (
                  <li key={item.name}>
                    <Link 
                      href={item.href} 
                      className={`flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-200 ${
                        isActive 
                        ? 'bg-cyan-900/20 text-cyan-400 border border-cyan-500/10 shadow-[0_0_15px_rgba(6,182,212,0.15)]' 
                        : 'hover:bg-white/5 hover:text-gray-200 border border-transparent'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                      <span className="text-sm font-medium">{item.name}</span>
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>
      
      <div className="p-4 border-t border-white/5">
        <Link href="/settings" className="flex items-center gap-3 px-3 py-2 w-full rounded-lg hover:bg-white/5 transition-colors text-gray-500 hover:text-gray-300">
          <Settings className="w-4 h-4" />
          <span className="text-sm font-medium">System Settings</span>
        </Link>
      </div>
    </aside>
  );
}
