import React, { useState, useRef } from 'react';
import { 
  Shield, 
  Upload, 
  Activity, 
  Database, 
  Zap, 
  RefreshCw, 
  AlertTriangle, 
  ChevronRight, 
  Search, 
  Bell,
  Terminal,
  Clock,
  ShieldAlert,
  CheckCircle,
  Info,
  FileText,
  Download // Added Download Icon
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';

const API_BASE = "http://localhost:8000";

const App = () => {
  // UI State
  const [activeTab, setActiveTab] = useState('overview');
  const [file, setFile] = useState(null);
  const [filterIp, setFilterIp] = useState("");
  
  // Analysis State
  const [isProcessing, setIsProcessing] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [progress, setProgress] = useState(0);
  const [safetyScore, setSafetyScore] = useState(100);
  
  // Data State
  const [liveStreamData, setLiveStreamData] = useState([]);
  const [fullDataset, setFullDataset] = useState([]); // NEW: Stores all data for export
  const [anomaliesCount, setAnomaliesCount] = useState(0);
  const [totalFlowsCount, setTotalFlowsCount] = useState(0);
  const [notifications, setNotifications] = useState([]);

  const streamRef = useRef(null);

  // --- Handlers ---

  const addNotification = (message, type = 'info') => {
    const id = Date.now();
    setNotifications(prev => [{ id, message, type }, ...prev]);
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  };

  const handleFileChange = (e) => {
    if (e.target.files.length > 0) {
      setFile(e.target.files[0]);
      addNotification(`Loaded ${e.target.files[0].name}`, 'info');
    }
  };

  const executeAnalysis = async () => {
    if (!file) {
      addNotification("Please select a PCAP or CSV file first", "warning");
      return;
    }

    setIsProcessing(true);
    setLiveStreamData([]);
    setFullDataset([]); // Reset full dataset
    setAnomaliesCount(0);
    setTotalFlowsCount(0);
    setProgress(0);
    setSafetyScore(100);

    const formData = new FormData();
    formData.append("file", file);
    if (filterIp) formData.append("filter_ip", filterIp);

    try {
      // Step 1: Send to Python Engine
      const response = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.detail || "Analysis failed");
      }

      // Step 2: Store Full Data for Export
      setFullDataset(result.data);

      // Step 3: Begin Output Layer
      setIsProcessing(false);
      startStreaming(result.data, result.summary.avg_safety);

    } catch (error) {
      addNotification(error.message, "danger");
      setIsProcessing(false);
    }
  };

  const startStreaming = (data, finalSafety) => {
    setIsStreaming(true);
    let index = 0;
    const streamBatchSize = 1;

    streamRef.current = setInterval(() => {
      if (index >= data.length) {
        clearInterval(streamRef.current);
        setIsStreaming(false);
        setSafetyScore(finalSafety);
        addNotification("Analysis Complete: Final report generated", "success");
        return;
      }

      const nextBatch = data.slice(index, index + streamBatchSize);
      setLiveStreamData(prev => [...prev.slice(-49), ...nextBatch]); // Keep window of 50
      
      const batchAnomalies = nextBatch.filter(f => f.label === 'Anomaly').length;
      setAnomaliesCount(prev => prev + batchAnomalies);
      setTotalFlowsCount(prev => prev + streamBatchSize);
      
      index += streamBatchSize;
      const currentProgress = Math.round((index / data.length) * 100);
      setProgress(currentProgress);

      // Dynamic Safety Calculation
      if (batchAnomalies > 0) {
        setSafetyScore(prev => Math.max(0, prev - 5));
        addNotification(`Anomaly detected in flow #0x${index.toString(16)}`, 'danger');
      } else {
        setSafetyScore(prev => Math.min(100, prev + 0.5));
      }

    }, 80); 
  };

  // --- Export Handlers ---

  const downloadFile = (content, filename, contentType) => {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    addNotification(`${filename} downloaded successfully`, 'success');
  };

  const handleExportJSON = () => {
    if (fullDataset.length === 0) {
      addNotification("No data available to export", "warning");
      return;
    }
    const jsonString = JSON.stringify(fullDataset, null, 2);
    downloadFile(jsonString, `security_report_${Date.now()}.json`, 'application/json');
  };

  const handleExportCSV = () => {
    if (fullDataset.length === 0) {
      addNotification("No data available to export", "warning");
      return;
    }

    // Flatten the object structure for CSV
    // We assume all rows have the same feature keys as the first row
    const featureKeys = Object.keys(fullDataset[0].features);
    const headers = ['ID', 'Label', 'Anomaly Score', ...featureKeys];

    const csvRows = [
      headers.join(','), // Header row
      ...fullDataset.map(row => {
        const featureValues = featureKeys.map(key => row.features[key]);
        return [
          row.id,
          row.label,
          row.raw_score.toFixed(6),
          ...featureValues
        ].join(',');
      })
    ];

    const csvString = csvRows.join('\n');
    downloadFile(csvString, `dataset_matrix_${Date.now()}.csv`, 'text/csv');
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 50) return 'text-amber-400';
    return 'text-rose-500';
  };

  return (
    <div className="flex min-h-screen bg-[#050505] text-slate-300 font-sans selection:bg-indigo-500/30">
      
      {/* Sidebar Navigation */}
      <aside className="fixed left-0 top-0 h-full w-64 bg-[#0a0a0a] border-r border-white/5 flex flex-col p-6 z-50 shadow-2xl">
        <div className="flex items-center gap-3 mb-10 px-2">
          <div className="p-2 bg-indigo-600 rounded-lg shadow-lg shadow-indigo-600/20">
            <Shield className="text-white" size={20} />
          </div>
          <span className="text-lg font-black tracking-tighter text-white italic uppercase tracking-wider">DDOS SCANNER</span>
        </div>

        <nav className="space-y-1">
          <button 
            onClick={() => setActiveTab('overview')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${activeTab === 'overview' ? 'bg-white/5 text-white border border-white/10' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'}`}
          >
            <Activity size={18} />
            <span className="text-sm font-medium">System Overview</span>
          </button>
          <button 
            onClick={() => setActiveTab('matrix')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${activeTab === 'matrix' ? 'bg-white/5 text-white border border-white/10' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'}`}
          >
            <Database size={18} />
            <span className="text-sm font-medium">Flow Matrix</span>
          </button>
        </nav>

        <div className="mt-auto p-4 bg-indigo-600/5 border border-indigo-500/10 rounded-2xl">
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert size={14} className="text-indigo-400" />
            <span className="text-[10px] font-bold uppercase text-indigo-400 tracking-wider font-mono">Engine Status</span>
          </div>
          <div className="flex items-center gap-2">
            <div className={`w-1.5 h-1.5 rounded-full bg-emerald-500 ${isStreaming ? 'animate-ping' : 'animate-pulse'}`} />
            <p className="text-[11px] text-slate-400 italic">Isolation Forest Online</p>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="pl-64 flex-1 min-h-screen">
        
        {/* Header Bar */}
        <header className="h-16 border-b border-white/5 bg-[#050505]/80 backdrop-blur sticky top-0 z-40 px-8 flex items-center justify-between">
          <div className="flex items-center gap-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
            <Terminal size={12}/> <span>NIDS Engine</span>
            <ChevronRight size={10} />
            <span className="text-white">{activeTab}</span>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="relative group">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 group-focus-within:text-indigo-500 transition-colors" size={14} />
              <input 
                type="text" 
                placeholder="Filter Traffic IP..." 
                className="bg-white/5 border border-white/10 rounded-full pl-9 pr-4 py-1.5 text-xs focus:outline-none focus:border-indigo-500/50 w-64 transition-all"
                value={filterIp}
                onChange={(e) => setFilterIp(e.target.value)}
              />
            </div>
            <div className="p-2 text-slate-500 hover:text-white cursor-pointer relative">
               <Bell size={18} />
               {notifications.length > 0 && <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-rose-500 rounded-full" />}
            </div>
          </div>
        </header>

        <div className="p-8 max-w-7xl mx-auto">
          {activeTab === 'overview' && (
            <div className="space-y-8 animate-in fade-in duration-700">
              
              {/* Hero / Upload Section */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 bg-[#0a0a0a] border border-white/5 rounded-3xl p-8 relative overflow-hidden group">
                   <div className="absolute top-0 right-0 p-8 opacity-5 text-indigo-500">
                      <Zap size={150} />
                   </div>

                  <div className="relative z-10">
                    <h2 className="text-2xl font-bold text-white mb-2 tracking-tight italic">Traffic Ingestion Layer</h2>
                    <p className="text-slate-500 mb-8 max-w-md text-sm leading-relaxed">
                      Initialize raw dataset by uploading it below and run for Real time analysis
                    </p>
                    
                    <div 
                      className="border-2 border-dashed border-white/10 rounded-2xl p-12 flex flex-col items-center justify-center hover:border-indigo-500/30 hover:bg-indigo-500/[0.02] transition-all cursor-pointer group-hover:border-indigo-500/20"
                      onClick={() => document.getElementById('fu').click()}
                    >
                      <input id="fu" type="file" className="hidden" onChange={handleFileChange} accept=".pcap,.csv,.pcapng" />
                      <div className="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center mb-4 transition-transform group-hover:scale-110 shadow-inner">
                        <Upload className={file ? "text-indigo-400" : "text-slate-600"} size={28} />
                      </div>
                      <span className="text-sm font-semibold text-slate-300 font-mono tracking-tight">
                        {file ? file.name : "Select PCAP or Flow CSV Source"}
                      </span>
                      <p className="text-[10px] text-slate-600 mt-2 uppercase font-bold tracking-widest">Supports Wireshark & FlowMeter formats</p>
                    </div>

                    <button 
                      onClick={executeAnalysis}
                      disabled={!file || isProcessing || isStreaming}
                      className="mt-6 w-full py-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:bg-slate-800 text-white font-black rounded-2xl transition-all shadow-lg shadow-indigo-600/20 flex items-center justify-center gap-2 uppercase text-xs tracking-widest"
                    >
                      {isProcessing ? <RefreshCw className="animate-spin" size={16} /> : <Zap size={16} />}
                      {isProcessing ? "Ingesting Layers..." : isStreaming ? `Scanning Traffic ${progress}%` : "Run Real-Time Analysis"}
                    </button>
                  </div>
                </div>

                {/* Safety Index Gauge */}
                <div className="bg-[#0a0a0a] border border-white/5 rounded-3xl p-8 flex flex-col items-center justify-center text-center relative overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-b from-indigo-500/5 to-transparent opacity-50" />
                  <div className={`text-7xl font-black mb-4 tracking-tighter tabular-nums transition-all duration-500 ${getScoreColor(safetyScore)}`}>
                    {Math.round(safetyScore)}
                  </div>
                  <h3 className="text-white font-bold text-lg tracking-tight italic">Safety Index</h3>
                  <p className="text-slate-500 text-[10px] mt-2 px-4 leading-relaxed uppercase font-bold tracking-widest opacity-60">
                    Real-time Threat Neutrality
                  </p>
                  
                  <div className="mt-8 w-full space-y-4 relative z-10">
                    <div className="flex justify-between text-[10px] font-black text-slate-500 uppercase tracking-widest">
                      <span>Scan Progress</span>
                      <span className="text-indigo-400">{progress}%</span>
                    </div>
                    <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-indigo-500 transition-all duration-500 shadow-[0_0_8px_rgba(99,102,241,0.5)]" 
                        style={{ width: `${progress}%` }} 
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Live Telemetry Chart */}
              <div className="bg-[#0a0a0a] border border-white/5 p-8 rounded-3xl shadow-inner relative overflow-hidden">
                <div className="flex justify-between items-center mb-8 relative z-10">
                   <div>
                      <h3 className="font-bold text-white text-lg flex items-center gap-2 italic">
                        <Activity size={18} className="text-indigo-400" />
                        Live Anomaly Telemetry
                      </h3>
                      <p className="text-xs text-slate-500 font-medium">Isolation Forest Score Variance Feed</p>
                   </div>
                   <div className="flex gap-4 text-[10px] font-black uppercase tracking-widest">
                      <div className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full bg-indigo-500 shadow-[0_0_5px_rgba(99,102,241,0.8)]" />
                        <span className="text-slate-400">Baseline</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_5px_rgba(244,63,94,0.8)]" />
                        <span className="text-rose-500">Anomaly</span>
                      </div>
                   </div>
                </div>
                
                <div className="h-64 w-full relative z-10">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={liveStreamData}>
                      <defs>
                        <linearGradient id="colorAnom" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1a1a1a" vertical={false} />
                      <XAxis dataKey="id" hide />
                      <YAxis stroke="#333" fontSize={10} domain={[-0.3, 0.3]} tickFormatter={(v) => v.toFixed(1)} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#000', border: '1px solid #222', borderRadius: '12px', fontSize: '10px' }}
                        itemStyle={{ color: '#fff' }}
                        cursor={{ stroke: '#444' }}
                      />
                      <Area 
                        type="monotone" 
                        dataKey="raw_score" 
                        stroke="#6366f1" 
                        strokeWidth={2}
                        fillOpacity={1} 
                        fill="url(#colorAnom)" 
                        isAnimationActive={false}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Status Stats */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {[
                  { label: 'Total Flows', value: totalFlowsCount, icon: FileText, color: 'text-indigo-400' },
                  { label: 'Flagged Threats', value: anomaliesCount, icon: AlertTriangle, color: 'text-rose-500' },
                  { label: 'System Health', value: safetyScore > 80 ? 'Optimal' : 'Compromised', icon: CheckCircle, color: safetyScore > 80 ? 'text-emerald-400' : 'text-rose-500' },
                  { label: 'Engine Latency', value: '24ms', icon: Clock, color: 'text-slate-500' }
                ].map((stat, i) => (
                  <div key={i} className="bg-[#0a0a0a] border border-white/5 p-6 rounded-2xl hover:border-indigo-500/20 transition-colors">
                    <div className="flex justify-between items-start mb-2">
                        <p className="text-[10px] font-black text-slate-600 uppercase tracking-widest">{stat.label}</p>
                        <stat.icon size={14} className={stat.color} />
                    </div>
                    <p className="text-2xl font-bold text-white tabular-nums">{stat.value}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'matrix' && (
            <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
              <div className="flex justify-between items-end mb-2">
                 <div>
                    <h2 className="text-2xl font-bold text-white italic tracking-tight">Flow Feature Matrix</h2>
                    <p className="text-xs text-slate-500 font-medium">Deep-packet inspection results and unsupervised anomaly weights.</p>
                 </div>
                 <div className="flex gap-2">
                    {/* BUTTONS ENABLED HERE */}
                    <button 
                      onClick={handleExportJSON}
                      disabled={fullDataset.length === 0}
                      className="px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-white/10 transition-all disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-2"
                    >
                      <Download size={12} /> Export JSON
                    </button>
                    <button 
                      onClick={handleExportCSV}
                      disabled={fullDataset.length === 0}
                      className="px-4 py-2 bg-indigo-600 rounded-xl text-[10px] font-black uppercase tracking-widest text-white shadow-lg shadow-indigo-600/20 hover:bg-indigo-500 transition-all disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-2"
                    >
                      <FileText size={12} /> Full Dataset Report
                    </button>
                 </div>
              </div>
              
              <div className="bg-[#0a0a0a] border border-white/5 rounded-3xl overflow-hidden shadow-2xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[11px] border-collapse">
                    <thead>
                      <tr className="bg-white/[0.02] border-b border-white/5 text-slate-500 font-black uppercase tracking-widest">
                        <th className="px-6 py-5">Flow Identification</th>
                        <th className="px-6 py-5">Duration (μs)</th>
                        <th className="px-6 py-5">Fwd Max Packet</th>
                        <th className="px-6 py-5">Isolation Score</th>
                        <th className="px-6 py-5 text-right">Detection Label</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono">
                      {liveStreamData.slice().reverse().map((row, idx) => (
                        <tr key={idx} className="hover:bg-white/[0.01] transition-colors group">
                          <td className="px-6 py-4 text-slate-500 group-hover:text-indigo-400">0x{row.id.toString(16).padStart(4, '0')}</td>
                          <td className="px-6 py-4 text-slate-300 font-medium">{(row.features['Flow Duration'] || 0).toFixed(4)}</td>
                          <td className="px-6 py-4 text-slate-400">{row.features['Fwd Packet Length Max']}</td>
                          <td className={`px-6 py-4 font-bold ${row.raw_score < 0 ? 'text-rose-500' : 'text-slate-500'}`}>
                            {row.raw_score.toFixed(6)}
                          </td>
                          <td className="px-6 py-4 text-right">
                            <span className={`px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-tighter border ${
                              row.label === 'Anomaly' ? 'bg-rose-500/10 text-rose-500 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                            }`}>
                              {row.label}
                            </span>
                          </td>
                        </tr>
                      ))}
                      {!isStreaming && liveStreamData.length === 0 && (
                        <tr>
                           <td colSpan="5" className="px-6 py-32 text-center">
                              <div className="flex flex-col items-center gap-4 opacity-20">
                                 <Database size={64} />
                                 <p className="text-xs font-black uppercase tracking-[0.2em]">Awaiting Data Stream</p>
                              </div>
                           </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Floating Alerts (Notifications) */}
      <div className="fixed bottom-8 right-8 space-y-3 z-[100]">
        {notifications.map(n => (
          <div 
            key={n.id} 
            className={`px-6 py-4 rounded-2xl border flex items-center gap-4 shadow-2xl animate-in slide-in-from-right-10 duration-300 ${
              n.type === 'danger' ? 'bg-rose-950/20 border-rose-500/50 text-rose-500' : 
              n.type === 'success' ? 'bg-emerald-950/20 border-emerald-500/50 text-emerald-500' :
              'bg-[#0a0a0a] border-white/10 text-slate-200'
            }`}
          >
            {n.type === 'danger' ? <AlertTriangle size={18} className="animate-pulse" /> : 
             n.type === 'success' ? <CheckCircle size={18} /> : 
             <Info size={18} className="text-indigo-400" />}
            <span className="text-xs font-black uppercase tracking-wider">{n.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default App;