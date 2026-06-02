/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { ShieldCheck, AlertTriangle, Key, Database, ShieldAlert, Lock, Code2, Cpu } from 'lucide-react';

interface OwaspItem {
  id: string;
  rank: string;
  title: string;
  icon: React.ElementType;
  description: string;
  relevance: string;
  mitigation: string;
}

export default function OwaspTop10Reference() {
  const owaspList: OwaspItem[] = [
    {
      id: 'A01',
      rank: 'A01:2021',
      title: 'Broken Access Control',
      icon: ShieldAlert,
      description: 'Users can act outside of their intended permissions. For example, a regular user modifying headers or URLs to read administrator secrets.',
      relevance: 'Our "Classified Secrets" endpoint strictly verifies that the authenticated JWT contains the role="admin", rejecting regular or unauthenticated tokens with 403 Forbidden.',
      mitigation: 'Implement server-side role validation for all restricted logic. Never rely purely on client-side state hiding.'
    },
    {
      id: 'A02',
      rank: 'A02:2021',
      title: 'Cryptographic Failures',
      icon: Lock,
      description: 'Storing passwords in plain-text, using weak SHA-1 hashes, or shipping static security keys.',
      relevance: 'Our system derives individual user salts upon signup and applies PBKDF2-SHA512 key stretching over 10,000 recursive iterations. It signs JWT tokens with a unique cryptographic HMAC-SHA256 signature.',
      mitigation: 'Use modern salted key-derivation algorithms with stretching rounds and implement cryptographic timing-safe comparisons.'
    },
    {
      id: 'A03',
      rank: 'A03:2021',
      title: 'Injection',
      icon: Database,
      description: 'Relational query query-strings are directly concatenated with user text inputs, letting attackers inject logical clauses (like OR 1=1) to query unmapped datasets.',
      relevance: 'Our security lab demonstrates this live! The Search database accepts search literals and runs side-by-side SQL simulation of vulnerable raw string templates vs secured bound parameters.',
      mitigation: 'Utilize parameterized SQL queries or ORM mappers where data parameters are bound as typed literal payloads which are not interpreted as parser keywords.'
    },
    {
      id: 'A05',
      rank: 'A05:2021',
      title: 'Security Misconfiguration',
      icon: ShieldCheck,
      description: 'Missing HTTP security headers, verbose framework error tracebacks leaked publicly, or active default credentials.',
      relevance: 'Our Node server injects rigid default security headers like X-Content-Type-Options: nosniff, anti-clickjacking X-Frame-Options, and a customized Content-Security-Policy (CSP) header.',
      mitigation: 'Harden configuration profiles, turn off granular debug pages in live environments, and return generic error summaries to public queries.'
    },
    {
      id: 'A07',
      rank: 'A07:2021',
      title: 'Identification and Authentication Failures',
      icon: Key,
      description: 'Permitting trivial passwords, allowing credential stuffing, or returning verbose authentication prompts (e.g., "Username not found" vs "Password incorrect") which leak registrations.',
      relevance: 'Our authentication APIs reject short passwords (<6 characters) and return structured, unified error responses ("Invalid username or password") to mask account registration metrics.',
      mitigation: 'Impose minimum user passport criteria, implement rate-limiting, and mask validation details on failures.'
    }
  ];

  return (
    <div id="owasp-reference" className="space-y-6">
      <div className="border-b border-gray-100 pb-4">
        <h2 className="text-xl font-semibold tracking-tight text-gray-900">OWASP Top 10 Security Reference</h2>
        <p className="text-sm text-gray-500 mt-1">
          Explore how this web application explicitly models defenses corresponding to the Open Worldwide Application Security Project standard.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {owaspList.map((item) => {
          const Icon = item.icon;
          return (
            <div key={item.id} id={`owasp-card-${item.id}`} className="bg-white border border-gray-100 rounded-xl p-5 hover:shadow-sm transition-all duration-200">
              <div className="flex items-start gap-4">
                <div className="p-2.5 bg-gray-50 rounded-lg text-gray-600 border border-gray-100 shrink-0">
                  <Icon className="w-5 h-5" />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-medium px-2 py-0.5 bg-gray-100 text-gray-600 rounded">
                      {item.rank}
                    </span>
                    <h3 className="font-semibold text-gray-950 text-sm">{item.title}</h3>
                  </div>
                  <p className="text-xs text-gray-600 leading-relaxed font-sans">{item.description}</p>
                  
                  <div className="pt-2 border-t border-gray-50 space-y-1.5 text-[11px]">
                    <div>
                      <span className="font-mono text-emerald-600 font-semibold block uppercase tracking-wider text-[9px]">How we address this:</span>
                      <p className="text-gray-700 leading-normal">{item.relevance}</p>
                    </div>
                    <div>
                      <span className="font-mono text-gray-500 font-semibold block uppercase tracking-wider text-[9px]">Best Practice Mitigation:</span>
                      <p className="text-gray-500 leading-normal italic">{item.mitigation}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      
      <div className="bg-amber-50 border border-amber-100 rounded-xl p-4 flex gap-3 text-xs text-amber-900 leading-relaxed">
        <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
        <div>
          <h4 className="font-semibold mb-0.5">Secure Coding Checklist</h4>
          <p>
            Always run stateful validation blocks on the server. Because external request payloads can easily be manipulated using custom tools (curl, headers tampering), client-side JavaScript is treated as <strong>vulnerable user input</strong> that must undergo validation and cryptographic signature verification.
          </p>
        </div>
      </div>
    </div>
  );
}
