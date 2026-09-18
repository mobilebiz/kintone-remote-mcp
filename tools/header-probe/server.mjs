// Streamable HTTP の最小 MCP サーバー。受信ヘッダーを JSON-RPC メソッドごとに記録するだけ。
import http from 'node:http';
import fs from 'node:fs';

const PORT = Number(process.env.PORT || 39111);
const LOG = process.env.PROBE_LOG || '/tmp/hdrprobe.jsonl';
const WATCH = ['x-kintone-base-url','x-kintone-api-token','x-kintone-username','x-kintone-password','authorization','mcp-protocol-version','mcp-session-id','user-agent','accept','origin','host'];

const record = (entry) => {
  fs.appendFileSync(LOG, JSON.stringify(entry) + '\n');
  console.log(`[${entry.client}] ${entry.method.padEnd(24)} kintone-headers=${entry.kintoneHeaders.join(',') || 'NONE'}`);
};

const TOOLS = [{
  name: 'probe',
  title: 'Header Probe',
  description: 'Returns which X-Kintone-* headers arrived with this tools/call request.',
  inputSchema: { type: 'object', properties: { ping: { type: 'string' } }, required: [], additionalProperties: false },
}];

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url.startsWith('/health')) {
    res.writeHead(200, {'content-type':'application/json'}); res.end('{"status":"ok"}'); return;
  }
  // GET(SSE) / DELETE は提供しない → 405 (設計 §2.2 の方針どおり)
  if (req.method !== 'POST') {
    res.writeHead(405, {'content-type':'application/json'});
    res.end(JSON.stringify({jsonrpc:'2.0',error:{code:-32000,message:'Method Not Allowed'},id:null}));
    console.log(`[-] ${req.method} ${req.url} -> 405`);
    return;
  }
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    let msg; try { msg = JSON.parse(body); } catch { msg = {}; }
    const msgs = Array.isArray(msg) ? msg : [msg];
    const present = WATCH.filter((h) => req.headers[h] !== undefined);
    const kintoneHeaders = present.filter((h) => h.startsWith('x-kintone-'));
    const client = (req.headers['user-agent'] || 'unknown').slice(0, 60);

    for (const m of msgs) {
      record({
        at: new Date().toISOString(),
        client,
        method: m.method || '(response)',
        kintoneHeaders,
        allWatched: Object.fromEntries(present.map((h) => [h, h.includes('token') || h.includes('password') || h === 'authorization' ? '<present>' : req.headers[h]])),
      });
    }

    const reqs = msgs.filter((m) => m.id !== undefined && m.method);
    if (reqs.length === 0) { res.writeHead(202); res.end(); return; } // 通知のみ

    const results = reqs.map((m) => {
      if (m.method === 'initialize') {
        return { jsonrpc:'2.0', id:m.id, result:{
          protocolVersion: m.params?.protocolVersion || '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: { name:'header-probe', version:'0.0.1' },
        }};
      }
      if (m.method === 'tools/list') return { jsonrpc:'2.0', id:m.id, result:{ tools: TOOLS } };
      if (m.method === 'tools/call') {
        return { jsonrpc:'2.0', id:m.id, result:{ content:[{ type:'text',
          text:`tools/call で届いた X-Kintone-* ヘッダー: ${kintoneHeaders.join(', ') || '(なし)'}` }] }};
      }
      if (m.method === 'ping') return { jsonrpc:'2.0', id:m.id, result:{} };
      return { jsonrpc:'2.0', id:m.id, error:{ code:-32601, message:`Method not found: ${m.method}` } };
    });

    res.writeHead(200, {'content-type':'application/json'});
    res.end(JSON.stringify(Array.isArray(msg) ? results : results[0]));
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`header-probe listening on 127.0.0.1:${PORT} (log: ${LOG})`));
