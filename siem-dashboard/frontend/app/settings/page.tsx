"use client";
import { useState, useEffect } from 'react';
import { Settings, Save, Shield, Database, Lock, Server, CheckCircle2, Globe, FileCode2, Terminal, AlertTriangle, Cpu } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { API_BASE_URL } from '@/lib/api';

export default function SettingsPage() {
  const [saved, setSaved] = useState(false);
  const [activeTab, setActiveTab] = useState('global');
  const [config, setConfig] = useState({
    alertLevel: 7, logRetention: 90, arEnabled: true, arCommand: 'firewall-drop', arTimeout: 600, vtEnabled: true, vtKey: '************************', otxEnabled: false
  });

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/settings`)
      .then(r => r.json())
      .then(setConfig)
      .catch(console.error);
  }, []);

  const handleSave = () => {
    fetch(`${API_BASE_URL}/api/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    }).then(() => {
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    });
  };

  const tabs = [
    { id: 'global', name: 'Global Settings', icon: Globe },
    { id: 'response', name: 'Active Response', icon: Shield },
    { id: 'intel', name: 'Threat Intelligence', icon: Database },
    { id: 'raw', name: 'Raw Configuration', icon: FileCode2 }
  ];

  const generateRawConfig = () => `<!-- HyShield / SIEM Configuration -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>yes</logall_json>
    <email_notification>yes</email_notification>
    <memory_size>2048</memory_size>
  </global>

  <alerts>
    <log_alert_level>${config.alertLevel}</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <active-response>
    <disabled>${config.arEnabled ? 'no' : 'yes'}</disabled>
    <command>${config.arCommand}</command>
    <location>local</location>
    <level>8</level>
    <timeout>${config.arTimeout}</timeout>
  </active-response>

  <integration>
    <name>virustotal</name>
    <api_key>${config.vtEnabled ? config.vtKey : ''}</api_key>
    <rule_id>100202,100203</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>`;

  const renderTabContent = () => {
    switch (activeTab) {
      case 'global':
        return (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
            <div className="bg-[#111116] border border-white/5 rounded-xl p-6 shadow-lg">
              <h3 className="text-sm font-bold text-white mb-6 uppercase tracking-widest flex items-center gap-2"><Globe className="w-4 h-4 text-blue-400"/> Global Configuration</h3>
              <div className="space-y-6">
                <div className="flex flex-col gap-2">
                  <label className="text-xs font-semibold text-gray-400 uppercase">Minimum Alert Level Threshold</label>
                  <p className="text-[11px] text-gray-500 mb-2">Events below this level are logged but do not trigger visible SIEM alerts (Standard: 7).</p>
                  <input type="number" value={config.alertLevel} onChange={e => setConfig({...config, alertLevel: Number(e.target.value)})} className="w-full bg-[#0a0a0f] border border-white/10 rounded-lg px-4 py-2 text-white font-mono text-sm focus:border-cyan-500/50 focus:outline-none transition-colors" />
                </div>
                <div className="flex flex-col gap-2">
                  <label className="text-xs font-semibold text-gray-400 uppercase">Log Retention Period (Days)</label>
                  <p className="text-[11px] text-gray-500 mb-2">Duration to keep raw JSON event logs before automatic archival rotation.</p>
                  <input type="number" value={config.logRetention} onChange={e => setConfig({...config, logRetention: Number(e.target.value)})} className="w-full bg-[#0a0a0f] border border-white/10 rounded-lg px-4 py-2 text-white font-mono text-sm focus:border-cyan-500/50 focus:outline-none transition-colors" />
                </div>
              </div>
            </div>
            
            <div className="bg-[#1a1616] border border-rose-500/20 rounded-xl p-6 shadow-lg">
              <h3 className="text-sm font-bold text-rose-500 mb-2 uppercase tracking-widest flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> Danger Zone</h3>
              <p className="text-xs text-gray-400 mb-4">Wipe all stored events, metrics, and honeypot records from the in-memory SIEM database.</p>
              <button className="py-2 px-6 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 border border-rose-500/30 rounded text-xs font-bold uppercase tracking-widest transition-colors">
                Purge Database
              </button>
            </div>
          </motion.div>
        );
      case 'response':
        return (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
            <div className="bg-[#111116] border border-white/5 rounded-xl p-6 shadow-lg">
              <h3 className="text-sm font-bold text-white mb-6 uppercase tracking-widest flex items-center gap-2"><Shield className="w-4 h-4 text-rose-400"/> Active Response Engine</h3>
              <div className="space-y-6">
                <div className="flex items-center justify-between border-b border-white/5 pb-6">
                  <div>
                    <h4 className="text-sm font-semibold text-gray-200">Enable Active Response</h4>
                    <p className="text-xs text-gray-500 mt-1">Automatically execute blocking scripts against malicious sources upon detection.</p>
                  </div>
                  <div onClick={() => setConfig({...config, arEnabled: !config.arEnabled})} className={`w-12 h-6 rounded-full relative cursor-pointer transition-colors ${config.arEnabled ? 'bg-cyan-600 shadow-[0_0_10px_rgba(6,182,212,0.5)]' : 'bg-[#0a0a0f] border border-white/10'}`}>
                    <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-all ${config.arEnabled ? 'right-1' : 'left-1 bg-gray-500'}`}></div>
                  </div>
                </div>
                <div className={`space-y-6 ${!config.arEnabled ? 'opacity-50 pointer-events-none grayscale' : ''}`}>
                  <div className="flex flex-col gap-2">
                    <label className="text-xs font-semibold text-gray-400 uppercase">Response Command Script</label>
                    <select value={config.arCommand} onChange={e => setConfig({...config, arCommand: e.target.value})} className="w-full appearance-none bg-[#0a0a0f] border border-white/10 rounded-lg px-4 py-3 text-gray-300 font-mono text-sm focus:border-cyan-500/50 focus:outline-none">
                      <option value="firewall-drop">firewall-drop (iptables / Windows Firewall)</option>
                      <option value="host-deny">host-deny (tcp wrappers / hosts.deny)</option>
                      <option value="route-null">route-null (null routing)</option>
                    </select>
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-xs font-semibold text-gray-400 uppercase">Block Timeout (Seconds)</label>
                    <p className="text-[11px] text-gray-500 mb-2">How long the attacker should be blocked before the rule expires (Default: 600s / 10m).</p>
                    <input type="number" value={config.arTimeout} onChange={e => setConfig({...config, arTimeout: Number(e.target.value)})} className="w-full bg-[#0a0a0f] border border-white/10 rounded-lg px-4 py-2 text-white font-mono text-sm focus:border-cyan-500/50 focus:outline-none transition-colors" />
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        );
      case 'intel':
        return (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
            <div className="bg-[#111116] border border-white/5 rounded-xl p-6 shadow-lg">
              <h3 className="text-sm font-bold text-white mb-6 uppercase tracking-widest flex items-center gap-2"><Database className="w-4 h-4 text-emerald-400"/> API Integrations</h3>
              <div className="space-y-6">
                
                <div className="border border-white/5 rounded-lg p-5 bg-[#0a0a0f]">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Cpu className="w-5 h-5 text-cyan-400" />
                      <h4 className="text-sm font-semibold text-gray-200">VirusTotal Threat Feed</h4>
                    </div>
                    <div onClick={() => setConfig({...config, vtEnabled: !config.vtEnabled})} className={`w-10 h-5 rounded-full relative cursor-pointer transition-colors ${config.vtEnabled ? 'bg-cyan-600 shadow-[0_0_10px_rgba(6,182,212,0.5)]' : 'bg-[#111116] border border-white/10'}`}>
                      <div className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all ${config.vtEnabled ? 'right-1' : 'left-1 bg-gray-500'}`}></div>
                    </div>
                  </div>
                  <input 
                    type="password" 
                    disabled={!config.vtEnabled}
                    value={config.vtKey} 
                    onChange={e => setConfig({...config, vtKey: e.target.value})} 
                    className={`w-full bg-[#111116] border border-white/10 rounded px-4 py-2 text-gray-300 font-mono text-sm focus:border-cyan-500/50 focus:outline-none ${!config.vtEnabled ? 'opacity-50' : ''}`}
                    placeholder="Enter VirusTotal API Key" 
                  />
                </div>

                <div className="border border-white/5 rounded-lg p-5 bg-[#0a0a0f]">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Globe className="w-5 h-5 text-amber-400" />
                      <div>
                        <h4 className="text-sm font-semibold text-gray-200">AlienVault OTX</h4>
                        <p className="text-[11px] text-gray-500 mt-1">Open Threat Exchange Indicator matching.</p>
                      </div>
                    </div>
                    <div onClick={() => setConfig({...config, otxEnabled: !config.otxEnabled})} className={`w-10 h-5 rounded-full relative cursor-pointer transition-colors ${config.otxEnabled ? 'bg-cyan-600 shadow-[0_0_10px_rgba(6,182,212,0.5)]' : 'bg-[#111116] border border-white/10'}`}>
                      <div className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all ${config.otxEnabled ? 'right-1' : 'left-1 bg-gray-500'}`}></div>
                    </div>
                  </div>
                </div>

              </div>
            </div>
          </motion.div>
        );
      case 'raw':
        return (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
            <div className="bg-[#111116] border border-white/5 rounded-xl p-6 shadow-lg h-[500px] flex flex-col">
              <h3 className="text-sm font-bold text-white mb-4 uppercase tracking-widest flex items-center gap-2"><Terminal className="w-4 h-4 text-cyan-400"/> ossec.conf / Generated Configuration</h3>
              <div className="flex-1 bg-[#050508] border border-white/5 rounded-lg p-4 overflow-auto">
                <pre className="text-[12px] text-gray-300 font-mono leading-relaxed">
                  <code>
{generateRawConfig()}
                  </code>
                </pre>
              </div>
            </div>
          </motion.div>
        );
    }
  };

  return (
    <div className="p-8 font-sans max-w-6xl mx-auto">
      <div className="flex justify-between items-center mb-8 pb-6 border-b border-white/5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Settings className="text-cyan-500 w-6 h-6" /> Platform Configuration
          </h1>
          <p className="text-sm text-gray-400 mt-2 ml-9">Manage SIEM rules, Active Response, and Threat Intelligence parameters.</p>
        </div>
        <button 
          onClick={handleSave}
          className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white px-6 py-2.5 rounded-lg font-bold text-sm tracking-wide transition-colors shadow-[0_0_15px_rgba(6,182,212,0.3)]"
        >
          {saved ? <CheckCircle2 className="w-4 h-4" /> : <Save className="w-4 h-4" />}
          {saved ? 'APPLIED GLOBALLY' : 'APPLY CONFIGURATION'}
        </button>
      </div>

      <div className="flex gap-8">
        {/* Settings Sidebar Menu */}
        <div className="w-64 flex-shrink-0 space-y-1">
          {tabs.map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold tracking-wide transition-all ${
                  isActive 
                  ? 'bg-cyan-900/20 text-cyan-400 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.1)]' 
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-gray-500'}`} />
                {tab.name}
              </button>
            )
          })}
        </div>

        {/* Content Pane */}
        <div className="flex-1 min-w-0">
          <AnimatePresence mode="wait">
            <div key={activeTab}>
              {renderTabContent()}
            </div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
