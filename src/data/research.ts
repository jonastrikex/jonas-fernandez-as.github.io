export type Severity = 'medium' | 'high' | 'critical';

export interface ResearchEntry {
  id: string;
  ref: string;
  cwe: string;
  severity: Severity;
  score: string;
  title: string;
  body: string;
  links: { label: string; url: string }[];
  notes: string[];
}

export const research: ResearchEntry[] = [
  {
    id: 'CVE-2026-14856',
    ref: 'CWE-79',
    cwe: 'CWE-79',
    severity: 'medium',
    score: 'Medium · 6.5',
    title: 'Stored Cross-Site Scripting in Media Manager of TastyIgniter',
    body: 'Vulnerability in the Media Manager of TastyIgniter allowing Stored XSS. Coordinated and published via official INCIBE advisory, with a dedicated public PoC repository.',
    links: [
      { label: 'Advisory ↗', url: 'https://www.incibe.es/incibe-cert/alerta-temprana/avisos/cross-site-scripting-xss-almacenado-en-media-manager-de-tastyigniter' },
      { label: 'PoC ↗', url: 'https://github.com/jonastrikex/CVE-2026-14856-TastyIgniter' },
    ],
    notes: ['Published via INCIBE'],
  },
  {
    id: 'CVE-2026-112174',
    ref: 'CWE-250',
    cwe: 'CWE-250',
    severity: 'critical',
    score: 'Critical · 9.3',
    title: 'Local Privilege Escalation in Enter Iperius Backup',
    body: 'Local privilege escalation in Enter Iperius Backup 8.8.3 for Windows. Insufficient separation between the elevated GUI and low-privileged local users allows an attacker to abuse native Windows dialogs exposed by the application to execute programs that inherit its elevated context, escalating to SYSTEM or Administrator. Coordinated disclosure with the vendor via INCIBE, patched in version 8.8.9.',
    links: [
      { label: 'INCIBE advisory ↗', url: 'https://www.incibe.es/en/incibe-cert/notices/aviso/privilege-escalation-enters-iperius-backup' },
    ],
    notes: ['CVE-2026-112174', 'Fixed in 8.8.9'],
  },
  {
    id: 'INC-2026-0168',
    ref: 'CWE-434 · CWE-94',
    cwe: 'CWE-434 · CWE-94',
    severity: 'high',
    score: 'High · 8.6',
    title: 'Remote Code Execution via File Upload in School Management Software',
    body: 'Remote Code Execution vulnerability in the add-on upload functionality of a school management platform. Vendor and product name withheld while disclosure is coordinated directly.',
    links: [],
    notes: ['Under embargo · INCIBE'],
  },
  {
    id: 'INC-2026-0175',
    ref: 'CWE-538',
    cwe: 'CWE-538',
    severity: 'high',
    score: 'High · 8.7',
    title: 'Unauthenticated Disclosure of Sensitive Configuration (.env)',
    body: 'An information disclosure vulnerability in a gym management platform: a misconfigured access-control file, written in syntax unsupported by the deployed web server, allowed unauthenticated remote access to a sensitive environment configuration file — exposing database and SMTP credentials.',
    links: [],
    notes: ['Reported to vendor · PoC'],
  },
];
