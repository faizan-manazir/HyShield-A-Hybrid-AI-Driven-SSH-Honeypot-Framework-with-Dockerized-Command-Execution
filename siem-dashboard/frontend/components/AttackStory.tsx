import React from 'react';

type AttackStageProps = {
  stage: string;
  description: string;
  time: string;
  isActive?: boolean;
};

const AttackStage = ({ stage, description, time, isActive = false }: AttackStageProps) => (
  <div className="flex gap-4 relative">
    {/* Line */}
    <div className="absolute left-[11px] top-8 bottom-[-24px] w-[2px] bg-gray-800" />
    
    {/* Node */}
    <div className="relative mt-1">
      <div className={`w-6 h-6 rounded-full border-4 border-gray-900 flex items-center justify-center ${isActive ? 'bg-red-500' : 'bg-gray-700'}`}>
      </div>
    </div>
    
    {/* Content */}
    <div className="flex-1 pb-8">
      <div className="flex justify-between items-baseline mb-1">
        <h4 className="text-sm font-bold text-gray-200">{stage}</h4>
        <span className="text-xs text-gray-500 font-mono">{time}</span>
      </div>
      <p className="text-sm text-gray-400">{description}</p>
    </div>
  </div>
);

export default function AttackStory() {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 max-w-2xl">
      <h3 className="text-lg font-medium text-white mb-6 uppercase tracking-wider border-b border-gray-800 pb-4">Attack Story</h3>
      <div className="ml-2">
        <AttackStage stage="CONNECTION" description="SSH connection established from 192.168.1.100" time="10:42:01" />
        <AttackStage stage="FINGERPRINT" description="SSH client identified (OpenSSH_8.2p1)" time="10:42:02" />
        <AttackStage stage="AUTHENTICATION" description="3 Failed Login Attempts detected" time="10:42:05" />
        <AttackStage stage="ACCESS" description="Successful login as 'root'" time="10:42:07" isActive={true} />
        <AttackStage stage="ACTIVITY" description="Executed: whoami, id, uname -a" time="10:42:15" />
        <AttackStage stage="FORENSICS" description="TTY recording created, session closed" time="10:43:00" />
      </div>
    </div>
  );
}
