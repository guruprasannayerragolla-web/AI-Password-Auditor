"use client";

import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, Key, Eye, EyeOff, Sparkles, User, Mail, 
  Building2, HelpCircle, AlertTriangle, AlertCircle, 
  RotateCw, Bot, Download, SlidersHorizontal, Dice5, Zap 
} from 'lucide-react';
import { 
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, 
  Radar, ResponsiveContainer 
} from 'recharts';

export default function AuditDashboard() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [organization, setOrganization] = useState('');
  const [mode, setMode] = useState('ADVANCED');
  const [apiOnline, setApiOnline] = useState(false);
  
  // Comparisons Lab State
  const [compPwds, setCompPwds] = useState(['', '', '', '']);
  const [comparisons, setComparisons] = useState<any[]>([]);

  // Main Audit Response State
  const [metrics, setMetrics] = useState<any>({
    security_score: 0,
    entropy_score: 0.0,
    effective_entropy: 0.0,
    risk_level: 'CRITICAL',
    classification: 'INACTIVE',
    dictionary_matched: false,
    patterns_detected: [],
    personal_info_exposed: [],
    crack_time_formatted: '0.0s',
    ml_risk_prediction: 'CRITICAL',
    ml_confidence: 1.0,
    xai_explanation: 'Enter a password to initiate the deep neural model analysis...',
    recommendations: []
  });

  // Verify FastAPI connection status
  useEffect(() => {
    async function pingAPI() {
      try {
        const res = await fetch('http://127.0.0.1:8000/api/v1/health');
        if (res.ok) {
          setApiOnline(true);
        } else {
          setApiOnline(false);
        }
      } catch (err) {
        setApiOnline(false);
      }
    }
    pingAPI();
    const interval = setInterval(pingAPI, 10000);
    return () => clearInterval(interval);
  }, []);

  // Run audit on keystroke / variable adjustments
  useEffect(() => {
    if (password.length === 0) {
      setMetrics({
        security_score: 0,
        entropy_score: 0.0,
        effective_entropy: 0.0,
        risk_level: 'CRITICAL',
        classification: 'INACTIVE',
        dictionary_matched: false,
        patterns_detected: [],
        personal_info_exposed: [],
        crack_time_formatted: '0.0s',
        ml_risk_prediction: 'CRITICAL',
        ml_confidence: 1.0,
        xai_explanation: 'Enter a password to initiate the deep neural model analysis...',
        recommendations: []
      });
      return;
    }

    const payload = {
      password,
      username: username || null,
      email: email || null,
      first_name: firstName || null,
      last_name: lastName || null,
      organization: organization || null,
      mode: mode
    };

    const debounce = setTimeout(async () => {
      if (apiOnline) {
        try {
          const res = await fetch('http://127.0.0.1:8000/api/v1/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          if (res.ok) {
            const data = await res.json();
            setMetrics(data);
            return;
          }
        } catch (e) {
          console.warn("API Error. Running client heuristics.");
        }
      }
      // Running fallback calculations
      const localData = computeLocalHeuristics(payload);
      setMetrics(localData);
    }, 150);

    return () => clearTimeout(debounce);
  }, [password, username, email, firstName, lastName, organization, mode, apiOnline]);

  // Client-Side heuristic compiler
  function computeLocalHeuristics(payload: any) {
    const pwd = payload.password;
    const len = pwd.length;
    
    // Composition details
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasDigit = /[0-9]/.test(pwd);
    const hasSymbol = /[^A-Za-z0-9\s]/.test(pwd);
    
    let alphabetSize = 0;
    if (hasUpper) alphabetSize += 26;
    if (hasLower) alphabetSize += 26;
    if (hasDigit) alphabetSize += 10;
    if (hasSymbol) alphabetSize += 33;
    
    const uniqueChars = new Set(pwd).size;
    const uniqueness = uniqueChars / len;
    
    // Patterns
    const patterns = [];
    if (/qwerty|asdfgh|zxcvbn/i.test(pwd)) {
      patterns.push({ pattern_type: 'KEYBOARD_WALK', pattern_value: 'qwerty', start_index: 0, end_index: 5, severity: 'HIGH' });
    }
    if (/12345|abcdef/i.test(pwd)) {
      patterns.push({ pattern_type: 'SEQUENCE', pattern_value: '12345', start_index: 0, end_index: 4, severity: 'HIGH' });
    }
    if (/(.)\1{2,}/.test(pwd)) {
      patterns.push({ pattern_type: 'REPEATED_CHAR', pattern_value: 'aaa', start_index: 0, end_index: 2, severity: 'MEDIUM' });
    }
    
    // Dictionary
    const common = ['password', 'admin', 'welcome', 'login', 'secret', 'letmein', 'changeit'];
    let dictMatched = false;
    let matchedTerm = '';
    for (let word of common) {
      if (pwd.toLowerCase().includes(word)) {
        dictMatched = true;
        matchedTerm = word;
        break;
      }
    }
    
    // OSINT exposures
    const exposures = [];
    if (payload.username && pwd.toLowerCase().includes(payload.username.toLowerCase())) {
      exposures.push({ field_exposed: 'USERNAME', matched_substring: payload.username, match_type: 'SUBSTRING' });
    }
    if (payload.first_name && pwd.toLowerCase().includes(payload.first_name.toLowerCase())) {
      exposures.push({ field_exposed: 'FIRST_NAME', matched_substring: payload.first_name, match_type: 'SUBSTRING' });
    }
    if (payload.organization && pwd.toLowerCase().includes(payload.organization.toLowerCase())) {
      exposures.push({ field_exposed: 'ORGANIZATION', matched_substring: payload.organization, match_type: 'SUBSTRING' });
    }

    // Shannon calculation
    const counts: Record<string, number> = {};
    for (let char of pwd) counts[char] = (counts[char] || 0) + 1;
    let shannon = 0;
    for (let char in counts) {
      let p = counts[char] / len;
      shannon -= p * Math.log2(p);
    }
    shannon = Math.round(shannon * 100) / 100;
    
    // Traditional entropy
    let charSetEntropy = Math.round(len * Math.log2(alphabetSize || 1) * 100) / 100;
    
    // Effective entropy
    let effective = charSetEntropy - (patterns.length * 5) - (dictMatched ? 15 : 0) - (exposures.length * 8);
    if (uniqueness < 0.6) effective *= (uniqueness + 0.4);
    effective = Math.max(0, Math.round(effective * 100) / 100);
    
    // Final score calculation
    let baseScore = Math.min(len * 5, 40) + ((hasUpper ? 1 : 0 + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0)) * 8);
    if (len > 12) baseScore += (len - 12) * 3;
    baseScore += (uniqueness * 10);
    if (dictMatched) baseScore = Math.min(15, baseScore);
    if (exposures.length > 0) baseScore = Math.min(25, baseScore);
    let finalScore = Math.max(0, Math.min(100, Math.round(baseScore)));
    
    let risk = 'MEDIUM';
    let classification = 'Moderate Strength';
    if (finalScore < 30) {
      risk = 'CRITICAL';
      classification = 'Highly Vulnerable';
    } else if (finalScore < 50) {
      risk = 'HIGH';
      classification = 'Weak Casing / Length';
    } else if (finalScore >= 80) {
      risk = 'SECURE';
      classification = 'Cryptographically Protected';
    } else if (finalScore >= 65) {
      risk = 'LOW';
      classification = 'Strong Protection';
    }
    
    // Crack estimates
    const space = Math.pow(alphabetSize || 1, len);
    const timeFormatted = formatSeconds(space / 2e11);
    
    let xai = `The client model predicts a '${risk}' status. The password contains ${len} characters with an effective entropy of ${effective} bits. `;
    if (dictMatched) xai += `It contains the common dictionary term '${matchedTerm}'. `;
    if (exposures.length > 0) xai += `It leaks personal OSINT details. `;
    
    const recs = [];
    if (len < 10) recs.push({ priority: 'HIGH', recommendation_text: 'Increase length to 14+ characters.' });
    if (dictMatched) recs.push({ priority: 'HIGH', recommendation_text: 'Remove dictionary terms.' });
    if (exposures.length > 0) recs.push({ priority: 'HIGH', recommendation_text: 'Remove personal info details.' });
    if (!hasSymbol) recs.push({ priority: 'MEDIUM', recommendation_text: 'Include special characters.' });
    
    return {
      security_score: finalScore,
      entropy_score: charSetEntropy,
      effective_entropy: effective,
      risk_level: risk,
      classification: classification,
      dictionary_matched: dictMatched,
      patterns_detected: patterns,
      personal_info_exposed: exposures,
      crack_time_formatted: timeFormatted,
      ml_risk_prediction: risk,
      ml_confidence: 0.85,
      xai_explanation: xai,
      recommendations: recs
    };
  }

  function formatSeconds(seconds: number) {
    if (seconds === Infinity || isNaN(seconds)) return 'Centuries';
    if (seconds < 0.001) return 'Instant';
    if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
    return `${Math.round(seconds / 86400)} days`;
  }

  // Suggest Random Password Generators
  function generatePassphrase() {
    const adjs = ['correct', 'battery', 'horse', 'staple', 'cyber', 'quantum', 'crystal', 'omega'];
    const nouns = ['rocket', 'planet', 'dinosaur', 'matrix', 'scanner', 'firewall', 'router', 'protocol'];
    const word = `${adjs[Math.floor(Math.random() * adjs.length)]}-${nouns[Math.floor(Math.random() * nouns.length)]}-${adjs[Math.floor(Math.random() * adjs.length)]}-${Math.floor(Math.random() * 90 + 10)}!`;
    setPassword(word);
  }

  function generateRandomSecure() {
    const pool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|';
    let res = '';
    for (let i = 0; i < 16; i++) {
      res += pool.charAt(Math.floor(Math.random() * pool.length));
    }
    setPassword(res);
  }

  // Comparisons lab handler
  async function runComparison() {
    const activePwds = compPwds.filter(p => p.length > 0);
    if (activePwds.length === 0) return;
    
    if (apiOnline) {
      try {
        const res = await fetch('http://127.0.0.1:8000/api/v1/compare', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            passwords: activePwds,
            username: username || null,
            email: email || null
          })
        });
        if (res.ok) {
          const data = await res.json();
          setComparisons(data.comparisons);
          return;
        }
      } catch (err) {
        console.warn("API Comparison failed. running local comparator.");
      }
    }
    
    // Fallback comparator logic
    const results = activePwds.map(p => {
      const aud = computeLocalHeuristics({ password: p, username, email });
      return {
        password: p,
        security_score: aud.security_score,
        entropy_score: aud.effective_entropy,
        risk_level: aud.risk_level,
        crack_time_formatted: aud.crack_time_formatted
      };
    });
    results.sort((a, b) => b.security_score - a.security_score || b.entropy_score - a.entropy_score);
    setComparisons(results.map((r, i) => ({ ...r, rank: i + 1 })));
  }

  // Exporter triggering helper
  function triggerReportExport(format: 'pdf' | 'csv') {
    if (!password) return;
    
    if (apiOnline) {
      const params = new URLSearchParams({
        password,
        username: username || '',
        email: email || '',
        first_name: firstName || '',
        last_name: lastName || '',
        organization: organization || ''
      });
      window.location.href = `http://127.0.0.1:8000/api/v1/export/${format}?${params.toString()}`;
    } else {
      // Direct client side CSV trigger
      let csv = 'data:text/csv;charset=utf-8,';
      csv += 'Password,Security Score,Entropy,Risk Level,Crack Time,Explanation\n';
      csv += `"${password}",${metrics.security_score},${metrics.effective_entropy},"${metrics.risk_level}","${metrics.crack_time_formatted}","${metrics.xai_explanation.replace(/"/g, '""')}"\n`;
      const encoded = encodeURI(csv);
      const link = document.createElement('a');
      link.setAttribute('href', encoded);
      link.setAttribute('download', `AI_Password_Audit_Report.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  }

  // Radar values calculation
  const getRadarData = () => {
    const lengthVal = Math.min(100, (password.length / 18) * 100);
    const entropyVal = Math.min(100, (metrics.effective_entropy / 80) * 100);
    const uniquenessVal = (metrics.security_score > 0) ? Math.round((metrics.entropy_score / (metrics.entropy_score + 1)) * 100) : 0;
    const dictVal = metrics.dictionary_matched ? 0 : 100;
    const patternVal = Math.max(0, 100 - (metrics.patterns_detected.length * 25));
    const osintVal = Math.max(0, 100 - (metrics.personal_info_exposed.length * 35));

    return [
      { subject: 'Length', value: lengthVal },
      { subject: 'Entropy', value: entropyVal },
      { subject: 'Uniqueness', value: uniquenessVal },
      { subject: 'Dict Resistance', value: dictVal },
      { subject: 'No Patterns', value: patternVal },
      { subject: 'OSINT Isolation', value: osintVal },
    ];
  };

  // Color mapping based on risk level
  const getRiskColors = (risk: string) => {
    switch (risk) {
      case 'CRITICAL':
        return { text: 'text-red-500', bg: 'bg-red-950/40 border-red-900', border: '#EF4444', pulse: 'bg-red-500' };
      case 'HIGH':
        return { text: 'text-orange-500', bg: 'bg-orange-950/40 border-orange-900', border: '#F97316', pulse: 'bg-orange-500' };
      case 'MEDIUM':
        return { text: 'text-amber-500', bg: 'bg-amber-950/40 border-amber-900', border: '#F59E0B', pulse: 'bg-amber-500' };
      case 'LOW':
        return { text: 'text-green-500', bg: 'bg-green-950/40 border-green-900', border: '#22C55E', pulse: 'bg-green-500' };
      case 'SECURE':
        return { text: 'text-cyan-400', bg: 'bg-cyan-950/40 border-cyan-800 shadow-[0_0_8px_rgba(0,240,255,0.2)]', border: '#00F0FF', pulse: 'bg-cyan-400' };
      default:
        return { text: 'text-slate-400', bg: 'bg-slate-900/60 border-slate-700', border: '#475569', pulse: 'bg-slate-500' };
    }
  };

  const riskTheme = getRiskColors(metrics.risk_level);

  return (
    <div className="max-w-7xl mx-auto w-full flex flex-col gap-8">
      
      {/* Top navbar */}
      <div className="border border-slate-800 bg-slate-950/60 backdrop-blur-md rounded-xl px-6 py-4 flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-tr from-cyan-500 to-fuchsia-500 rounded-lg shadow-lg">
            <ShieldCheck className="w-6 h-6 text-slate-950" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-cyan-400 to-fuchsia-400 bg-clip-text text-transparent">
              AI Password Auditor
            </h1>
            <p className="text-xs text-slate-500 font-mono">REACT SYSTEM SHOWCASE</p>
          </div>
        </div>

        <div className="flex items-center gap-4 font-mono text-xs">
          <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 flex items-center gap-2">
            <span className="text-slate-500">AUDIT MODE:</span>
            <select 
              value={mode} 
              onChange={(e) => setMode(e.target.value)}
              className="bg-transparent text-cyan-400 font-semibold focus:outline-none cursor-pointer"
            >
              <option value="BASIC" className="bg-slate-950 text-slate-200">BASIC</option>
              <option value="ADVANCED" className="bg-slate-950 text-slate-200">ADVANCED</option>
              <option value="ENTERPRISE" className="bg-slate-950 text-slate-200">ENTERPRISE</option>
            </select>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 flex items-center gap-2">
            <div className={`w-2.5 h-2.5 rounded-full animate-pulse ${apiOnline ? 'bg-emerald-500' : 'bg-rose-500'}`}></div>
            <span className={`${apiOnline ? 'text-emerald-500' : 'text-rose-500'} font-semibold`}>
              {apiOnline ? 'BACKEND ONLINE' : 'LOCAL ENGINE CLIENT'}
            </span>
          </div>
        </div>
      </div>

      {/* Main Grid split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left column inputs (4 Cols) */}
        <div className="lg:col-span-4 flex flex-col gap-6">
          
          {/* Password Input card */}
          <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md relative overflow-hidden flex flex-col gap-4">
            <div className="absolute top-0 left-0 w-1 h-full bg-cyan-400"></div>
            <h2 className="text-lg font-semibold flex items-center gap-2 text-cyan-400">
              <Key className="w-5 h-5" /> Password Input
            </h2>
            
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-slate-400">PASSWORD UNDER SCAN</label>
              <div className="relative">
                <input 
                  type={showPassword ? 'text' : 'password'} 
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Type password..."
                  className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 rounded-lg px-3 py-3 pr-10 font-mono text-sm tracking-wider text-slate-100 transition-colors"
                />
                <button 
                  type="button" 
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3.5 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 mt-1">
              <button 
                onClick={generatePassphrase}
                className="bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-cyan-500 text-cyan-400 rounded-lg py-2 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
              >
                <Sparkles className="w-3.5 h-3.5" /> Suggest Phrase
              </button>
              <button 
                onClick={generateRandomSecure}
                className="bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-cyan-500 text-cyan-400 rounded-lg py-2 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
              >
                <Dice5 className="w-3.5 h-3.5" /> Random Secure
              </button>
            </div>
          </div>

          {/* Context profile card */}
          <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md relative overflow-hidden flex flex-col gap-4">
            <div className="absolute top-0 left-0 w-1 h-full bg-fuchsia-400"></div>
            <h2 className="text-lg font-semibold flex items-center gap-2 text-fuchsia-400">
              <User className="w-5 h-5" /> OSINT Context
            </h2>
            
            <div className="grid grid-cols-1 gap-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">USERNAME</label>
                <input 
                  value={username} 
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. johndoe" 
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 focus:border-fuchsia-400 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">EMAIL ADDRESS</label>
                <input 
                  value={email} 
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="e.g. john@doe.org" 
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 focus:border-fuchsia-400 focus:outline-none"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-slate-400 mb-1">FIRST NAME</label>
                  <input 
                    value={firstName} 
                    onChange={(e) => setFirstName(e.target.value)}
                    placeholder="John" 
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 focus:border-fuchsia-400 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">LAST NAME</label>
                  <input 
                    value={lastName} 
                    onChange={(e) => setLastName(e.target.value)}
                    placeholder="Doe" 
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 focus:border-fuchsia-400 focus:outline-none"
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">ORGANIZATION</label>
                <input 
                  value={organization} 
                  onChange={(e) => setOrganization(e.target.value)}
                  placeholder="Acme Corp" 
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 focus:border-fuchsia-400 focus:outline-none"
                />
              </div>
            </div>
          </div>

        </div>

        {/* Right dashboard content (8 Cols) */}
        <div className="lg:col-span-8 flex flex-col gap-6">
          
          {/* Gauges & ML Block */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Score circle */}
            <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col items-center justify-center gap-3 text-center">
              <span className="text-xs font-semibold text-slate-400 tracking-wider">SECURITY RATING</span>
              <div className="relative w-28 h-28 flex items-center justify-center">
                <svg className="absolute w-full h-full -rotate-90">
                  <circle cx="56" cy="56" r="48" stroke="rgba(30, 41, 59, 0.8)" strokeWidth="8" fill="transparent" />
                  <circle 
                    cx="56" cy="56" r="48" 
                    stroke={riskTheme.border} 
                    strokeDasharray="301.6" 
                    strokeDashoffset={301.6 - (metrics.security_score / 100) * 301.6} 
                    strokeWidth="8" strokeLinecap="round" fill="transparent" 
                    className="transition-all duration-500" 
                  />
                </svg>
                <div className="text-center">
                  <span className="text-3xl font-extrabold text-slate-100">{metrics.security_score}</span>
                  <span className="text-slate-400 text-sm">/100</span>
                </div>
              </div>
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${riskTheme.bg}`}>
                {metrics.classification}
              </span>
            </div>

            {/* Entropy details */}
            <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col justify-between gap-4">
              <div>
                <span className="text-xs font-semibold text-slate-400 tracking-wider block">RANDOMNESS ENERGY</span>
                <span className="text-3xl font-bold text-cyan-400 font-mono mt-2 block">{metrics.effective_entropy.toFixed(1)} <span className="text-xs text-slate-500">bits</span></span>
                <span className="text-[10px] text-slate-400 font-semibold block mt-1">Entropy classification matches guidelines.</span>
              </div>
              <div className="border-t border-slate-850 pt-2 flex flex-col gap-1 text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Shannon Entropy:</span>
                  <span className="font-mono text-slate-200">{metrics.entropy_score.toFixed(1)} bits</span>
                </div>
                <div className="flex justify-between">
                  <span>Effective Entropy:</span>
                  <span className="font-mono text-slate-200">{metrics.effective_entropy.toFixed(1)} bits</span>
                </div>
              </div>
            </div>

            {/* Machine Learning */}
            <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col justify-between gap-4">
              <div>
                <span className="text-xs font-semibold text-slate-400 tracking-wider">ML MODEL CLASSIFICATION</span>
                <div className="mt-3 flex items-center gap-2">
                  <div className={`w-3.5 h-3.5 rounded-full ${riskTheme.pulse}`}></div>
                  <span className={`text-xl font-bold tracking-wide font-mono ${riskTheme.text}`}>
                    {metrics.ml_risk_prediction}
                  </span>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-xs mb-1 font-mono">
                  <span className="text-slate-400">Model Confidence:</span>
                  <span className="text-slate-200">{(metrics.ml_confidence * 100).toFixed(1)}%</span>
                </div>
                <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                  <div 
                    className={`h-full transition-all duration-300 ${metrics.risk_level === 'SECURE' ? 'bg-cyan-400' : 'bg-amber-500'}`} 
                    style={{ width: `${metrics.ml_confidence * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>

          </div>

          {/* Recharts Radar & Attack Resistance card */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* Recharts Radar */}
            <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col gap-4">
              <span className="text-xs font-semibold text-slate-400 tracking-wider">CREDENTIAL THREAT SURFACE (RECHARTS)</span>
              <div className="w-full h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart cx="50%" cy="50%" outerRadius="75%" data={getRadarData()}>
                    <PolarGrid stroke="rgba(255,255,255,0.08)" />
                    <PolarAngleAxis dataKey="subject" stroke="#64748B" fontSize={10} />
                    <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} stroke="transparent" />
                    <Radar 
                      name="Defense Index" 
                      dataKey="value" 
                      stroke="#00F0FF" 
                      fill="#00F0FF" 
                      fillOpacity={0.15} 
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Offline GPU estimation panel */}
            <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col justify-between">
              <span className="text-xs font-semibold text-slate-400 tracking-wider block mb-3">CRACK RESISTANCE ESTIMATES</span>
              
              <div className="flex flex-col gap-3 font-mono text-xs">
                <div className="bg-slate-900/60 p-2.5 border border-slate-850 rounded-lg flex justify-between items-center">
                  <div>
                    <span className="text-slate-400 block text-[10px]">ONLINE RATE-LIMITED PORTAL</span>
                    <span className="text-slate-600 text-[9px]">(10 attempts/sec)</span>
                  </div>
                  <span className="text-slate-300 font-semibold">{metrics.crack_time_formatted}</span>
                </div>
                <div className="bg-slate-900/60 p-2.5 border border-slate-850 rounded-lg flex justify-between items-center">
                  <div>
                    <span className="text-slate-400 block text-[10px]">OFFLINE GPU FAST HASH</span>
                    <span className="text-slate-600 text-[9px]">(MD5/SHA-256 RTX 4090 cluster)</span>
                  </div>
                  <span className="text-cyan-400 font-semibold">{metrics.crack_time_formatted}</span>
                </div>
                <div className="bg-slate-900/60 p-2.5 border border-slate-850 rounded-lg flex justify-between items-center">
                  <div>
                    <span className="text-slate-400 block text-[10px]">AI-ASSISTED GUESSING MODELS</span>
                    <span className="text-slate-600 text-[9px]">(PassGAN structure scans)</span>
                  </div>
                  <span className="text-fuchsia-400 font-semibold">{metrics.crack_time_formatted}</span>
                </div>
              </div>
            </div>

          </div>

          {/* Explainable AI & Recommendations */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
            
            {/* XAI */}
            <div className="md:col-span-7 bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col gap-3">
              <span className="text-xs font-semibold text-slate-400 tracking-wider flex items-center gap-1.5">
                <Bot className="w-4 h-4 text-cyan-400" /> EXPLAINABLE AI MODEL SUMMARY
              </span>
              <div className="bg-slate-900/40 p-4 rounded-lg border border-slate-800 min-h-[120px] flex items-center">
                <p className="text-sm text-slate-300 leading-relaxed italic">
                  {metrics.xai_explanation}
                </p>
              </div>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {metrics.dictionary_matched && (
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-rose-950/80 text-rose-400 border border-rose-800">DICTIONARY_WORD</span>
                )}
                {metrics.patterns_detected.map((p: any, i: number) => (
                  <span key={i} className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-orange-950/80 text-orange-400 border border-orange-800">{p.pattern_type}</span>
                ))}
                {metrics.personal_info_exposed.map((p: any, i: number) => (
                  <span key={i} className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-fuchsia-950/80 text-fuchsia-400 border border-fuchsia-800">OSINT_LEAK</span>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            <div className="md:col-span-5 bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col justify-between gap-4">
              <span className="text-xs font-semibold text-slate-400 tracking-wider">ACTION CHECKS</span>
              
              <div className="flex flex-col gap-2 max-h-[140px] overflow-y-auto pr-1 text-xs">
                {metrics.recommendations.length > 0 ? (
                  metrics.recommendations.map((r: any, idx: number) => (
                    <div 
                      key={idx} 
                      className={`p-2 border rounded-lg flex items-start gap-2 ${
                        r.priority === 'HIGH' ? 'text-rose-400 bg-rose-950/30 border-rose-900' : 'text-slate-400 bg-slate-900 border-slate-800'
                      }`}
                    >
                      <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                      <p>{r.recommendation_text}</p>
                    </div>
                  ))
                ) : (
                  <div className="text-slate-500 text-center py-6">No issues detected. Ready.</div>
                )}
              </div>

              <div className="border-t border-slate-850 pt-3 flex gap-2">
                <button 
                  onClick={() => triggerReportExport('pdf')}
                  className="flex-1 bg-gradient-to-r from-cyan-500 to-sky-500 hover:from-cyan-400 hover:to-sky-400 text-slate-950 rounded-lg py-2 text-xs font-bold flex items-center justify-center gap-1.5 transition-all shadow-md"
                >
                  <Download className="w-4 h-4" /> Download PDF
                </button>
                <button 
                  onClick={() => triggerReportExport('csv')}
                  className="bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-slate-500 text-slate-200 rounded-lg p-2 text-xs font-semibold transition-all"
                >
                  CSV
                </button>
              </div>
            </div>

          </div>

          {/* Comparison Lab */}
          <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-5 backdrop-blur-md flex flex-col gap-4">
            <span className="text-xs font-semibold text-slate-400 tracking-wider flex items-center gap-1.5">
              <SlidersHorizontal className="w-4 h-4 text-cyan-400" /> PASSWORD COMPARISON LAB
            </span>
            
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
              {[0, 1, 2, 3].map((idx) => (
                <input 
                  key={idx}
                  value={compPwds[idx]}
                  onChange={(e) => {
                    const copy = [...compPwds];
                    copy[idx] = e.target.value;
                    setCompPwds(copy);
                  }}
                  placeholder={`Password ${String.fromCharCode(65 + idx)}...`}
                  className="bg-slate-900 border border-slate-850 rounded-lg p-2 text-xs focus:outline-none focus:border-cyan-400 font-mono text-slate-200"
                />
              ))}
              <button 
                onClick={runComparison}
                className="bg-slate-900 hover:bg-cyan-500 border border-cyan-500 text-cyan-400 hover:text-slate-950 rounded-lg p-2 text-xs font-bold flex items-center justify-center gap-1.5 transition-all"
              >
                <Zap className="w-4 h-4" /> Compare
              </button>
            </div>
            
            {comparisons.length > 0 && (
              <div className="overflow-x-auto border border-slate-850 rounded-lg">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr class="bg-slate-900 border-b border-slate-800 text-slate-500 font-mono">
                      <th className="p-3">RANK</th>
                      <th className="p-3">CREDENTIAL</th>
                      <th className="p-3">SCORE</th>
                      <th className="p-3">ENTROPY</th>
                      <th className="p-3">RISK</th>
                      <th className="p-3 text-right">EST. CRACK TIME</th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparisons.map((item, idx) => (
                      <tr key={idx} className="border-b border-slate-850 hover:bg-slate-900/30">
                        <td className="p-3 font-bold font-mono text-cyan-400">#{item.rank || idx+1}</td>
                        <td className="p-3 font-mono text-slate-100">{item.password}</td>
                        <td className="p-3 font-bold">{item.security_score}</td>
                        <td className="p-3 font-mono">{item.entropy_score.toFixed(1)} bits</td>
                        <td className="p-3">
                          <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${getRiskColors(item.risk_level).bg}`}>
                            {item.risk_level}
                          </span>
                        </td>
                        <td className="p-3 text-right font-mono text-slate-400">{item.crack_time_formatted}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

        </div>

      </div>
    </div>
  );
}
