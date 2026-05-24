import React, { useState } from 'react';
import { Shield, Terminal, Lock, Unlock, CheckCircle, XCircle } from 'lucide-react';
import axios from 'axios';

export default function App() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  const [testForm, setTestForm] = useState({
    device_type: 'camera',
    source_ip: '192.168.1.100',
    user_id: 'alice@company.com',
    auth_token: 'valid-token-123',
    device_id: 'camera-office-01'
  });

  const handleSubmitTest = async () => {
    try {
      setLoading(true);

      const alertPayload = {
        id: `test-${Date.now()}`,
        timestamp: new Date().toISOString(),
        agent_id: "001",
        rule: {
          level: 5,
          description: "Test: IoT Device Access Request"
        },
        device_type: testForm.device_type,
        device_id: testForm.device_id,
        source_ip: testForm.source_ip,
        user_id: testForm.user_id,
        auth_token: testForm.auth_token
      };

      const response = await axios.post('/api/access-control', alertPayload);

      // Add to history
      const result = {
        timestamp: new Date().toLocaleTimeString(),
        input: testForm,
        decision: response.data.decision_action,
        confidence: response.data.decision_confidence,
        reason: response.data.decision_reason,
        rule_matched: response.data.deterministic_decision ? 'Rule-Based' : 'LLM Analysis'
      };

      setHistory(prev => [result, ...prev]);

    } catch (err) {
      alert('Error: ' + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-gray-100 p-8">

      {/* Header */}
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-blue-500" />
          <h1 className="text-3xl font-bold text-white">IoT Access Sentinel</h1>
        </div>
      </div>

      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Left: Test Form */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-blue-500" />
            Test Alert
          </h2>

          <div className="space-y-3">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Device Type</label>
              <input
                type="text"
                value={testForm.device_type}
                onChange={(e) => setTestForm({ ...testForm, device_type: e.target.value })}
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm text-white focus:border-blue-500 outline-none"
              />
            </div>

            <div>
              <label className="block text-xs text-gray-400 mb-1">Source IP</label>
              <input
                type="text"
                value={testForm.source_ip}
                onChange={(e) => setTestForm({ ...testForm, source_ip: e.target.value })}
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm text-white focus:border-blue-500 outline-none"
              />
            </div>

            <div>
              <label className="block text-xs text-gray-400 mb-1">User ID</label>
              <input
                type="text"
                value={testForm.user_id}
                onChange={(e) => setTestForm({ ...testForm, user_id: e.target.value })}
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm text-white focus:border-blue-500 outline-none"
              />
            </div>

            <div>
              <label className="block text-xs text-gray-400 mb-1">Auth Token</label>
              <input
                type="text"
                value={testForm.auth_token}
                onChange={(e) => setTestForm({ ...testForm, auth_token: e.target.value })}
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm text-white focus:border-blue-500 outline-none"
              />
            </div>

            <div>
              <label className="block text-xs text-gray-400 mb-1">Device ID</label>
              <input
                type="text"
                value={testForm.device_id}
                onChange={(e) => setTestForm({ ...testForm, device_id: e.target.value })}
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm text-white focus:border-blue-500 outline-none"
              />
            </div>
          </div>

          <button
            onClick={handleSubmitTest}
            disabled={loading}
            className="mt-6 w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 text-white font-semibold rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Processing...
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                Test Access Request
              </>
            )}
          </button>
        </div>

        {/* Right: History */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 overflow-hidden flex flex-col max-h-[600px]">
          <h2 className="text-lg font-bold text-white mb-4">Decision History</h2>

          <div className="flex-1 overflow-y-auto space-y-3 pr-2">
            {history.length === 0 ? (
              <div className="text-center text-gray-500 py-12">
                No tests yet. Submit a request to see results.
              </div>
            ) : (
              history.map((item, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded-lg border-l-4 ${item.decision === 'ALLOW'
                    ? 'bg-green-500/10 border-l-green-500'
                    : 'bg-red-500/10 border-l-red-500'
                    }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-gray-400">{item.timestamp}</span>
                    <div className="flex items-center gap-2">
                      {item.decision === 'ALLOW' ? (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-500" />
                      )}
                      <span className={`font-bold text-sm ${item.decision === 'ALLOW' ? 'text-green-400' : 'text-red-400'
                        }`}>
                        {item.decision}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-1 mb-3">
                    <p className="text-xs text-gray-400">
                      <span className="font-mono text-white">{item.input.user_id}</span> →
                      <span className="font-mono text-white ml-1">{item.input.device_id}</span>
                    </p>
                    <p className="text-xs text-gray-400">
                      from <span className="font-mono text-white">{item.input.source_ip}</span>
                    </p>
                  </div>

                  <div className="bg-slate-900/50 rounded p-2 mb-2">
                    <p className="text-xs text-gray-300 leading-relaxed italic">
                      "{item.reason}"
                    </p>
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <span className={`px-2 py-1 rounded ${item.rule_matched === 'Rule-Based'
                      ? 'bg-purple-500/20 text-purple-400'
                      : 'bg-blue-500/20 text-blue-400'
                      }`}>
                      {item.rule_matched}
                    </span>
                    <span className="text-gray-500">
                      {(item.confidence * 100).toFixed(0)}% confident
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
