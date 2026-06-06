// HTML status-page renderer.  Live updates are driven by the JavaScript
// shipped in LIVE_JS, which polls the JSON endpoint every 3 seconds.

use super::{
    AuthDesc, ListenerSummary, ServerSummary, UpstreamRow, VHostSummary,
};
use crate::cert::state::CertState;
use crate::error::{HttpResponse, bytes_body};
use crate::metrics::{Snapshot, SparklineData, TimePeriod};
use bytes::Bytes;
use hyper::{Response, StatusCode};
use std::time::{SystemTime, UNIX_EPOCH};

// PNG logo embedded at compile time and served from a sub-path so the
// browser caches it after the first load rather than bloating the HTML.
pub(super) const LOGO_PNG: &[u8] =
    include_bytes!("../../../docs/hypershunt-logo.png");
pub(super) const LOGO_FILE: &str = "hypershunt-logo.png";

/// Serve the PNG logo with a 24-hour cache and ETag support.
/// Returns 304 Not Modified when the client's ETag matches.
pub(super) fn serve_logo(
    headers: &hyper::HeaderMap,
) -> HttpResponse {
    let etag = format!("\"{}\"", LOGO_PNG.len());
    let already_cached = headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == etag)
        .unwrap_or(false);
    if already_cached {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .body(bytes_body(Bytes::new()))
            .expect("known-valid response");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/png")
        .header("Cache-Control", "public, max-age=86400")
        .header("Content-Length", LOGO_PNG.len().to_string())
        .header("ETag", &etag)
        .body(bytes_body(Bytes::from_static(LOGO_PNG)))
        .expect("known-valid response")
}

// All CSS for the status page, kept as a const so format! doesn't
// need to escape the braces inside it.
const CSS: &str = r#"
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#f5f7fa;--surface:#fff;--border:#dde3eb;
  --text:#1a2332;--muted:#5e6e82;--accent:#1e3a5f;
  --accent-bg:#edf2f8;
  --green:#16a34a;--green-bg:#dcfce7;
  --amber:#b45309;--amber-bg:#fef3c7;
  --red:#b91c1c;--red-bg:#fee2e2;
  --spark-stroke:#1e3a5f;--spark-fill:rgba(0,0,0,.07);
  --spark-grid:#dde3eb;
  --cpu-color:#7c3aed;--auth-color:#dc2626;--jwt-color:#ea580c;
  --mem-color:#0891b2;--active-color:#059669;
  --jwt-issued-color:#16a34a;
  --live-dot:#22c55e;
}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",
  system-ui,sans-serif;font-size:15px;line-height:1.65;color:var(--text);
  background:var(--bg);display:flex;min-height:100vh}
a{color:var(--accent)}

/* --- Sidebar --- */
.sidebar{width:240px;flex-shrink:0;background:var(--surface);
  border-right:1px solid var(--border);position:sticky;top:0;
  height:100vh;overflow-y:auto;display:flex;flex-direction:column}
.sidebar-brand{padding:.9rem 1rem .75rem;border-bottom:1px solid var(--border)}
.sidebar-brand img{width:140px;display:block}
.sidebar-live{display:flex;align-items:center;gap:.4rem;
  padding:.45rem 1rem;font-size:.78rem;color:var(--muted);
  border-bottom:1px solid var(--border)}
.sidebar details>summary{display:none}
.sidebar-nav{display:block;padding:.6rem 0 1rem;flex:1}
.nav-group-label{font-size:.68rem;font-weight:700;
  text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
  padding:.6rem 1.25rem .2rem}
.nav-link{display:block;padding:.28rem 1.25rem;font-size:.875rem;
  color:var(--text);text-decoration:none;
  border-left:3px solid transparent;transition:.12s}
.nav-link:hover,.nav-link.active{border-left-color:var(--accent);
  background:var(--accent-bg);color:var(--accent)}
.sidebar-footer{padding:.75rem 1rem;font-size:.72rem;color:var(--muted);
  border-top:1px solid var(--border)}

/* --- Main content --- */
.main{flex:1;min-width:0;padding:2rem 2.5rem 4rem}
.main-inner{max-width:860px}

/* --- Sections --- */
.section{margin-bottom:1.5rem;scroll-margin-top:1.5rem}
h2{font-size:.82rem;font-weight:700;color:var(--muted);
  text-transform:uppercase;letter-spacing:.06em;margin:0 0 .65rem}
.card{background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:1.25rem 1.5rem}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem}

/* --- Stats --- */
.stat-val{font-size:2rem;font-weight:800;color:var(--accent);
  letter-spacing:-.03em;margin:.15rem 0 0;line-height:1.1}
.stat-label{font-size:.82rem;color:var(--muted)}
.big-val{font-size:1.4rem;font-weight:700;color:var(--accent)}

/* --- Tables --- */
.info-table{width:100%;border-collapse:collapse;font-size:.875rem}
.info-table th{text-align:left;color:var(--muted);font-weight:600;
  font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;
  padding:.4rem .6rem .4rem 0;border-bottom:1px solid var(--border)}
.info-table td{padding:.4rem .6rem .4rem 0;
  border-bottom:1px solid var(--border);word-break:break-word}
.info-table tr:last-child td{border-bottom:none}
.info-table tbody tr:hover td{background:var(--accent-bg)}

/* --- Rate table --- */
.rate-table{width:100%;border-collapse:collapse;font-size:.875rem;
  margin-bottom:.75rem}
.rate-table th{color:var(--muted);font-weight:600;
  font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;
  padding:.3rem .4rem .5rem 0;text-align:left}
.rate-table th:last-child{text-align:right}
.rate-table td{padding:.3rem .4rem;border-top:1px solid var(--border)}
.rate-table td:last-child{text-align:right;font-weight:600;
  color:var(--accent);font-variant-numeric:tabular-nums}

/* --- Status codes --- */
.sc-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:.6rem}
.sc{border-radius:8px;padding:.9rem;text-align:center}
.sc-val{font-size:1.4rem;font-weight:800;letter-spacing:-.02em}
.sc-label{font-size:.72rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.05em;margin-top:.1rem;opacity:.85}
.sc-2xx{background:var(--green-bg);color:var(--green)}
.sc-3xx{background:var(--accent-bg);color:var(--accent)}
.sc-4xx{background:var(--amber-bg);color:var(--amber)}
.sc-5xx{background:var(--red-bg);color:var(--red)}

/* --- Security event cards --- */
.sec-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:.75rem}
/* Surface card with coloured left stripe; text stays neutral */
.sec-card{background:var(--surface);border:1px solid var(--border);
  border-radius:8px;padding:1rem 1.25rem}
.sec-card-auth{border-left:4px solid var(--red)}
.sec-card-jwt-fail{border-left:4px solid var(--amber)}
.sec-card-jwt-exp{border-left:4px solid var(--amber)}
.sec-card-jwt-issued{border-left:4px solid var(--green)}
.sec-card-title{font-size:.72rem;font-weight:700;color:var(--muted);
  text-transform:uppercase;letter-spacing:.05em}
.sec-card-val{font-size:1.4rem;font-weight:800;letter-spacing:-.02em;
  color:var(--accent)}
.sec-card-sub{font-size:.75rem;margin-top:.2rem;color:var(--muted)}

/* --- Latency bars --- */
.bar-row{display:flex;align-items:center;gap:.6rem;
  margin:.25rem 0;font-size:.82rem}
.bar-label{width:5.5rem;color:var(--muted);flex-shrink:0;
  text-align:right;white-space:nowrap}
.bar-track{flex:1;background:var(--accent-bg);border-radius:4px;
  height:.85rem;overflow:hidden}
.bar-fill{height:100%;background:var(--accent);border-radius:4px;
  min-width:2px}
.bar-count{width:4.5rem;color:var(--text);
  font-variant-numeric:tabular-nums;text-align:right}

/* --- Sparklines --- */
.sparkline{display:block;width:100%;height:56px;margin-top:.75rem}

/* --- Badges --- */
.badge{display:inline-block;font-size:.75rem;font-weight:600;
  background:var(--accent-bg);color:var(--accent);
  border-radius:4px;padding:.1rem .45rem}

/* --- Certs --- */
.cert-ok{color:var(--green)}
.cert-warn{color:var(--amber)}
.cert-crit{color:var(--red);font-weight:700}

/* --- Live dot --- */
.live-dot{display:inline-block;width:8px;height:8px;
  background:var(--live-dot);border-radius:50%;flex-shrink:0;
  animation:pulse 2s infinite}
.live-dot.offline{background:var(--red);animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* --- Mono --- */
.mono{font-family:ui-monospace,"SF Mono",Consolas,monospace;font-size:.82rem}

/* --- Sidebar controls (period + refresh, always visible) --- */
.sidebar-controls{display:flex;flex-direction:column;gap:.5rem;
  padding:.6rem 1.25rem .75rem;
  border-top:1px solid var(--border)}
.sidebar-controls label{font-size:.78rem;font-weight:600;
  color:var(--muted);display:block;margin-bottom:.15rem}
.sidebar-controls select{background:var(--surface);
  border:1px solid var(--border);border-radius:6px;
  padding:.28rem .5rem;font-size:.82rem;color:var(--text);
  cursor:pointer;width:100%;outline:none}
.sidebar-controls select:hover{border-color:var(--accent)}
.sidebar-controls select:focus{border-color:var(--accent);
  box-shadow:0 0 0 2px rgba(30,58,95,.15)}

/* --- Mobile --- */
@media(max-width:768px){
  body{display:block}
  .sidebar{width:100%;height:auto;position:static;border-right:none;
    border-bottom:1px solid var(--border)}
  .sidebar-nav{display:none}
  .sidebar details{cursor:pointer}
  .sidebar details[open] .sidebar-nav{display:block}
  .sidebar summary{padding:.6rem 1rem;font-size:.875rem;
    font-weight:600;color:var(--accent);list-style:none;
    display:flex;align-items:center;gap:.4rem}
  .sidebar summary::-webkit-details-marker{display:none}
  .main{padding:1.25rem 1rem 3rem}
  .grid-3,.sc-grid{grid-template-columns:1fr 1fr}
  .sec-grid{grid-template-columns:1fr 1fr}
}
@media(max-width:480px){
  .grid-3,.grid-2,.sc-grid,.sec-grid{grid-template-columns:1fr}
}
"#;

// Inline JavaScript for live updates.
const LIVE_JS: &str = r#"<script>
(function(){
var POLL_MS=3000;
var cur='15min';
var lastData=null;
var online=true;
var timer;

// Navigate logo to referring page if available.
var ll=document.getElementById('logo-link');
if(ll)ll.href=document.referrer||'/';

document.getElementById('period-sel').addEventListener('change',function(){
  cur=this.value;
  poll();
});
document.getElementById('refresh-sel').addEventListener('change',function(){
  POLL_MS=+this.value;
  clearInterval(timer);
  timer=setInterval(poll,POLL_MS);
});

function setText(id,v){var el=document.getElementById(id);if(el)el.textContent=v;}
function fmt(n){return (+n).toLocaleString();}

function setOnline(on){
  if(on===online)return;
  online=on;
  var dot=document.getElementById('live-dot');
  var lbl=document.getElementById('live-label');
  if(dot){dot.classList.toggle('offline',!on);}
  if(lbl){lbl.textContent=on?'Live':'Offline';lbl.style.color=on?'':'var(--red)';}
}

function drawSparkline(id,data,color,fmtMax,stepSecs){
  var svg=document.getElementById(id);
  if(!svg||!data||data.length<2)return;
  var W=400,H=50,LH=14;
  svg.setAttribute('viewBox','0 0 '+W+' '+(H+LH));
  var vals=data.map(function(v){return v==null?0:+v;});
  var max=Math.max.apply(null,vals)||1;
  var n=vals.length,pad=2;
  var pts=vals.map(function(v,i){
    var x=((i/(n-1))*W).toFixed(1);
    var y=(H-pad-(v/max)*(H-pad*2)).toFixed(1);
    return x+','+y;
  });
  svg.innerHTML='';
  var NS='http://www.w3.org/2000/svg';
  [0.25,0.5,0.75].forEach(function(f){
    var line=document.createElementNS(NS,'line');
    var y=(H*(1-f)).toFixed(1);
    line.setAttribute('x1','0');line.setAttribute('x2',String(W));
    line.setAttribute('y1',y);line.setAttribute('y2',y);
    line.setAttribute('stroke','var(--spark-grid)');
    line.setAttribute('stroke-width','1');
    svg.appendChild(line);
  });
  var area=document.createElementNS(NS,'path');
  var fx=pts[0].split(',')[0],lx=pts[n-1].split(',')[0];
  area.setAttribute('d','M'+fx+','+H+' L'+pts.join(' L')+' L'+lx+','+H+' Z');
  area.setAttribute('fill','var(--spark-fill)');
  svg.appendChild(area);
  var pl=document.createElementNS(NS,'polyline');
  pl.setAttribute('points',pts.join(' '));
  pl.setAttribute('fill','none');
  pl.setAttribute('stroke',color||'var(--spark-stroke)');
  pl.setAttribute('stroke-width','1.5');
  pl.setAttribute('stroke-linejoin','round');
  svg.appendChild(pl);
  if(fmtMax){
    var lbl=document.createElementNS(NS,'text');
    lbl.setAttribute('x',String(W-2));lbl.setAttribute('y','11');
    lbl.setAttribute('text-anchor','end');lbl.setAttribute('font-size','10');
    lbl.setAttribute('fill','var(--muted)');lbl.textContent=fmtMax(max);
    svg.appendChild(lbl);
  }
  if(stepSecs&&n>1){
    var totalSecs=stepSecs*n;
    function tl(s){
      if(s<60)return'-'+s+'s';
      if(s<3600)return'-'+Math.round(s/60)+'m';
      if(s<86400)return'-'+Math.round(s/3600)+'h';
      return'-'+Math.round(s/86400)+'d';
    }
    [{x:2,s:totalSecs,a:'start'},{x:W/2,s:totalSecs/2,a:'middle'},
     {x:W-2,s:0,a:'end'}].forEach(function(t){
      var tx=document.createElementNS(NS,'text');
      tx.setAttribute('x',t.x.toFixed(0));
      tx.setAttribute('y',String(H+LH-1));
      tx.setAttribute('text-anchor',t.a);tx.setAttribute('font-size','9');
      tx.setAttribute('fill','var(--muted)');
      tx.textContent=t.s===0?'now':tl(Math.round(t.s));
      svg.appendChild(tx);
    });
  }
}

function escHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function fmtTs(ts){
  // Format a Unix timestamp as "YYYY-MM-DD HH:MM UTC".
  var d=new Date(ts*1000);
  return d.toISOString().replace('T',' ').slice(0,16)+' UTC';
}

function updateCerts(certs){
  var sec=document.getElementById('certs-section');
  if(!sec)return;
  if(!certs||!certs.length){sec.style.display='none';return;}
  sec.style.display='';
  var tbody=sec.querySelector('tbody');
  if(!tbody)return;
  function cc(ts){
    var days=(ts-Math.floor(Date.now()/1000))/86400;
    if(days<7)return'cert-crit';
    if(days<30)return'cert-warn';
    return'cert-ok';
  }
  tbody.innerHTML=certs.map(function(c){
    var cls=cc(c.expiry_ts);
    var status=cls==='cert-ok'?'OK':cls==='cert-warn'?'Expiring soon':'Critical';
    return'<tr><td class="mono">'+escHtml(c.domains.join(', '))+'</td>'+
      '<td class="'+cls+' mono">'+escHtml(fmtTs(c.expiry_ts))+'</td>'+
      '<td class="mono">'+escHtml(fmtTs(c.next_renewal_ts))+'</td>'+
      '<td><span class="badge '+cls+'">'+status+'</span></td></tr>';
  }).join('');
}

function updatePaths(d){
  var rows=(d&&d.top_paths)?d.top_paths:[];
  var tbody=document.getElementById('paths-tbody');
  if(!tbody)return;
  if(!rows.length){
    tbody.innerHTML='<tr><td colspan="2" style="color:var(--muted);font-style:italic">No data yet</td></tr>';
    return;
  }
  var maxH=rows[0][1]||1;
  tbody.innerHTML=rows.map(function(r){
    var pct=(r[1]/maxH*100).toFixed(1);
    return'<tr><td class="mono" style="word-break:break-all">'+escHtml(r[0])+'</td>'+
      '<td style="text-align:right;white-space:nowrap;padding-left:.6rem">'+
      '<span style="display:inline-block;height:.6rem;width:'+pct+'px;max-width:60px;'+
      'background:var(--accent);border-radius:2px;vertical-align:middle;margin-right:.3rem"></span>'+
      fmt(r[1])+'</td></tr>';
  }).join('');
}

function fmtBytes(n){
  n=+n||0;
  if(n>=(1<<30))return (n/(1<<30)).toFixed(1)+' GiB';
  if(n>=(1<<20))return (n/(1<<20)).toFixed(1)+' MiB';
  if(n>=(1<<10))return (n/(1<<10)).toFixed(1)+' KiB';
  return n+' B';
}

// Refresh the newly-surfaced metric sections.  Every id is optional:
// setText no-ops when a section was server-side hidden, so a feature
// that only becomes active after page load simply waits for a reload.
function updateExtra(d){
  if(d.stream){var s=d.stream;
    setText('val-stream-active',s.conns_active);
    setText('val-stream-total',fmt(s.conns_total));
    setText('val-stream-in',fmtBytes(s.bytes_in));
    setText('val-stream-out',fmtBytes(s.bytes_out));}
  if(d.datagram){var g=d.datagram;
    setText('val-dgram-flows',fmt(g.flows_active));
    setText('val-dgram-pkts',fmt(g.datagrams_in)+' / '+fmt(g.datagrams_out));
    setText('val-dgram-bytes',fmtBytes(g.bytes_in)+' / '+fmtBytes(g.bytes_out));
    setText('val-dgram-create',fmt(g.flow_create));
    setText('val-dgram-evict',fmt(g.flow_evict));}
  if(d.proxy_lb){var l=d.proxy_lb;
    setText('val-lb-picks',fmt(l.picks));
    setText('val-lb-noup',fmt(l.no_upstream));
    setText('val-lb-retries',fmt(l.retries));
    setText('val-lb-eject',fmt(l.ejections));
    setText('val-lb-hc',fmt(l.health_checks));
    setText('val-lb-hfr',fmt(l.health_failures)+' / '+fmt(l.health_recoveries));}
  if(d.proxy_upstream){var u=d.proxy_upstream;
    setText('val-up-bytes',fmtBytes(u.bytes_in)+' / '+fmtBytes(u.bytes_out));
    setText('val-up-cerr',fmt(u.connect_errors));}
  if(d.http_conns){
    setText('val-http-conns-active',d.http_conns.active);
    setText('val-http-conns-total',fmt(d.http_conns.total));}
  if(d.tls){
    setText('val-tls-hs',fmt(d.tls.handshakes));
    setText('val-tls-hs-fail',fmt(d.tls.failures));
    setText('val-tls-hs-to',fmt(d.tls.timeouts));}
  if(d.acme){
    setText('val-acme-iss',fmt(d.acme.issuances));
    setText('val-acme-iss-fail',fmt(d.acme.issuance_failures));
    setText('val-acme-ren',fmt(d.acme.renewals));
    setText('val-acme-ren-fail',fmt(d.acme.renewal_failures));}
  if(d.ocsp){
    setText('val-ocsp',fmt(d.ocsp.refreshes));
    setText('val-ocsp-fail',fmt(d.ocsp.refresh_failures));}
  if(d.oidc){var o=d.oidc;
    setText('val-oidc-disc',fmt(o.discoveries));
    setText('val-oidc-disc-fail',fmt(o.discovery_failures));
    setText('val-oidc-ref',fmt(o.refreshes));
    setText('val-oidc-ref-fail',fmt(o.refresh_failures));
    setText('val-oidc-logout',fmt(o.logouts));
    setText('val-oidc-bearer',fmt(o.bearer_validations));
    setText('val-oidc-bearer-fail',fmt(o.bearer_failures));
    setText('val-oidc-iss',fmt(o.callback_iss_mismatches));}
  if(d.rate_limit){
    setText('val-rl-triggers',fmt(d.rate_limit.triggers));
    setText('val-rl-keys',fmt(d.rate_limit.active_keys));}
  if(d.geoip){
    setText('val-geoip',fmt(d.geoip.lookups));
    setText('val-geoip-miss',fmt(d.geoip.misses));}
  if(d.compression){var c=d.compression;
    setText('val-cmp-resp',fmt(c.responses));
    setText('val-cmp-skip',fmt(c.skipped));
    setText('val-cmp-split',fmt(c.gzip)+' / '+fmt(c.brotli)+' / '+fmt(c.zstd));
    setText('val-cmp-bytes',fmtBytes(c.bytes_in)+' → '+fmtBytes(c.bytes_out));
    var saved=c.bytes_in>0?
      (Math.max(0,(1-c.bytes_out/c.bytes_in))*100).toFixed(1)+'%':'—';
    setText('val-cmp-saved',saved);}
  if(d.backends){var b=d.backends;
    ['fcgi','scgi'].forEach(function(k){
      if(b[k]){setText('val-'+k+'-req',fmt(b[k].requests));
        setText('val-'+k+'-err',fmt(b[k].errors));
        setText('val-'+k+'-inf',b[k].in_flight);}});
    if(b.cgi){setText('val-cgi-req',fmt(b.cgi.requests));
      setText('val-cgi-err',fmt(b.cgi.errors));
      setText('val-cgi-inf',b.cgi.in_flight);
      setText('val-cgi-spawn',fmt(b.cgi.spawn_failures));
      setText('val-cgi-to',fmt(b.cgi.timeouts));}
    if(b.static){setText('val-static-bytes',fmtBytes(b.static.bytes_served));
      setText('val-static-304',fmt(b.static.not_modified));
      setText('val-static-206',fmt(b.static.range));}}
}

function updateUpstreams(ups){
  var card=document.getElementById('upstreams-card');
  if(!card)return;
  if(!ups||!ups.length){card.style.display='none';return;}
  card.style.display='';
  var tbody=document.getElementById('upstreams-tbody');
  if(!tbody)return;
  tbody.innerHTML=ups.map(function(u){
    var cls=u.ejected?'cert-crit':(u.healthy?'cert-ok':'cert-warn');
    var st=u.ejected?'Ejected':(u.healthy?'Healthy':'Unhealthy');
    return'<tr><td>'+escHtml(u.label)+'</td><td class="mono">'+escHtml(u.url)+
      '</td><td>'+u.weight+'</td><td>'+u.in_flight+
      '</td><td><span class="badge '+cls+'">'+st+'</span></td></tr>';
  }).join('');
}

function poll(){
  fetch(location.pathname+'?format=json&period='+cur,{
    headers:{'Accept':'application/json'},cache:'no-store'
  })
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
  .then(function(d){
    setOnline(true);lastData=d;
    setText('val-uptime',d.uptime_human);
    setText('val-active',d.requests_active);
    setText('val-total',fmt(d.requests_total));
    setText('val-rps',d.rates.current_per_sec.toFixed(2));
    setText('val-rate-cur',d.rates.current_per_sec.toFixed(2));
    setText('val-rate-1m',d.rates.avg_1min.toFixed(2));
    setText('val-rate-5m',d.rates.avg_5min.toFixed(2));
    setText('val-rate-15m',d.rates.avg_15min.toFixed(2));
    setText('val-2xx',fmt(d.status['2xx']));
    setText('val-3xx',fmt(d.status['3xx']));
    setText('val-4xx',fmt(d.status['4xx']));
    setText('val-5xx',fmt(d.status['5xx']));
    setText('val-auth-total',fmt(d.auth_failures_total));
    setText('val-jwt-fail-total',fmt(d.jwt_failures_total));
    setText('val-jwt-exp-total',fmt(d.jwt_expiries_total));
    setText('val-jwt-issued-total',fmt(d.jwt_issued_total));
    setText('val-auth-1h',fmt(d.auth_fail_1h));
    setText('val-jwt-fail-1h',fmt(d.jwt_fail_1h));
    setText('val-jwt-exp-1h',fmt(d.jwt_expiry_1h));
    setText('val-jwt-issued-1h',fmt(d.jwt_issued_1h));
    if(d.memory_kb!=null)setText('val-mem',Math.round(d.memory_kb/1024)+' MiB');
    if(d.cpu_percent!=null)setText('val-cpu',d.cpu_percent.toFixed(1)+'%');
    var lk=['lt_1','lt_10','lt_50','lt_200','lt_1000','ge_1000'];
    var tot=lk.reduce(function(s,k){return s+(d.latency_ms[k]||0);},0);
    lk.forEach(function(k){
      var c=d.latency_ms[k]||0;
      var pct=tot>0?(c/tot*100).toFixed(1):'0.0';
      var fill=document.querySelector('.bar-fill[data-lat="'+k+'"]');
      var cnt=document.querySelector('.bar-count[data-lat="'+k+'"]');
      if(fill)fill.style.width=pct+'%';
      if(cnt)cnt.textContent=fmt(c);
    });
    if(d.sparkline){
      var sp=d.sparkline,step=sp.step_secs;
      if(sp.req_rate&&sp.req_rate.length)
        drawSparkline('spark-rate',sp.req_rate,'var(--spark-stroke)',
          function(v){return v.toFixed(1)+' req/s';},step);
      if(sp.mem_kb&&sp.mem_kb.length)
        drawSparkline('spark-mem',sp.mem_kb,'var(--mem-color)',
          function(v){return Math.round(v/1024)+' MiB';},step);
      if(sp.cpu_pct&&sp.cpu_pct.length)
        drawSparkline('spark-cpu',sp.cpu_pct,'var(--cpu-color)',
          function(v){return v.toFixed(1)+'%';},step);
      if(sp.auth_fail)
        drawSparkline('spark-auth',sp.auth_fail,'var(--auth-color)',
          function(v){return v.toFixed(0)+' failures';},step);
      if(sp.jwt_fail)
        drawSparkline('spark-jwt-fail',sp.jwt_fail,'var(--jwt-color)',
          function(v){return v.toFixed(0)+' bad sig';},step);
      if(sp.jwt_expiry)
        drawSparkline('spark-jwt-expiry',sp.jwt_expiry,'var(--jwt-color)',
          function(v){return v.toFixed(0)+' expired';},step);
      if(sp.jwt_issued)
        drawSparkline('spark-jwt-issued',sp.jwt_issued,
          'var(--jwt-issued-color)',
          function(v){return v.toFixed(0)+' issued';},step);
      if(sp.err4xx)
        drawSparkline('spark-4xx',sp.err4xx,'var(--amber)',
          function(v){return v.toFixed(0)+' 4xx';},step);
      if(sp.err5xx)
        drawSparkline('spark-5xx',sp.err5xx,'var(--red)',
          function(v){return v.toFixed(0)+' 5xx';},step);
      if(sp.active){
        setText('val-active-hist',fmt(d.requests_active));
        drawSparkline('spark-active',sp.active,'var(--active-color)',
          function(v){return v.toFixed(0)+' req';},step);
      }
    }
    updateCerts(d.certs);
    updatePaths(d);
    updateExtra(d);
    updateUpstreams(d.upstreams);
  })
  .catch(function(){setOnline(false);});
}

poll();
timer=setInterval(poll,POLL_MS);
})();
</script>"#;

pub(super) fn render_html(
    s: &Snapshot,
    _sp: &SparklineData,
    _top_paths: &[(String, u64)],
    _period: TimePeriod,
    sum: &ServerSummary,
    certs: &[CertState],
    upstreams: &[UpstreamRow],
    matched_prefix: &str,
) -> HttpResponse {
    let total_lat: u64 = s.latency.iter().sum();
    // Logo served from a sub-path relative to wherever the status
    // location is mounted (/, /status, /.hypershunt/status, …).
    let logo_src = format!(
        "{}/{}",
        matched_prefix.trim_end_matches('/'),
        LOGO_FILE
    );
    let resource_sec = resource_section(s.memory_kb, s.cpu_percent);
    let certs_sec = certs_section(certs);
    let listeners_sec = listeners_section(&sum.listeners);
    let vhosts_sec = vhosts_section(&sum.vhosts);
    let auth_sec = auth_section(sum.auth.as_ref());
    // Newly-surfaced metric sections.  Each is an empty string when
    // its subsystem is idle, so the matching nav link is suppressed too.
    let proxying_sec = proxying_section(s, sum, upstreams);
    let network_sec = network_section(s);
    let security_extra_sec = security_extra_section(s);
    let compression_sec = compression_section(s);
    let backends_sec = backends_section(s);
    let breakdown_sec = breakdown_section(s);

    // Sidebar links rendered only when their section is present.
    let nav = |present: bool, href: &str, label: &str| -> String {
        if present {
            format!(r##"<a class="nav-link" href="{href}">{label}</a>"##)
        } else {
            String::new()
        }
    };
    let auth_nav = nav(sum.auth.is_some(), "#sec-security", "Security");
    let mem_nav = nav(
        s.memory_kb.is_some() || s.cpu_percent.is_some(),
        "#sec-system",
        "System",
    );
    let proxying_nav =
        nav(!proxying_sec.is_empty(), "#sec-proxying", "Proxying");
    let network_nav =
        nav(!network_sec.is_empty(), "#sec-network", "Network & TLS");
    let security_extra_nav = nav(
        !security_extra_sec.is_empty(),
        "#sec-security-extra",
        "Access & Identity",
    );
    let compression_nav = nav(
        !compression_sec.is_empty(),
        "#sec-compression",
        "Compression",
    );
    let backends_nav =
        nav(!backends_sec.is_empty(), "#sec-backends", "Backends");
    let breakdown_nav =
        nav(!breakdown_sec.is_empty(), "#sec-breakdown", "Traffic Breakdown");

    // Sidebar group labels print only above a populated group.
    let group = |present: bool, label: &str| -> String {
        if present {
            format!(r#"<div class="nav-group-label">{label}</div>"#)
        } else {
            String::new()
        }
    };
    let proxying_nav_group = group(!proxying_sec.is_empty(), "Proxying");
    let network_nav_group =
        group(!network_sec.is_empty(), "Network &amp; TLS");
    let security_group = group(
        sum.auth.is_some() || !security_extra_sec.is_empty(),
        "Security",
    );
    let backends_nav_group = group(!backends_sec.is_empty(), "Backends");
    let mem_nav_group = group(
        s.memory_kb.is_some() || s.cpu_percent.is_some(),
        "System",
    );

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>hypershunt — Status</title>
<style>{css}</style>
</head>
<body>

<aside class="sidebar">
  <div class="sidebar-brand">
    <a id="logo-link" href="/" style="display:block"><img class="brand-logo" src="{logo_src}" alt="hypershunt" width="140"></a>
  </div>
  <div class="sidebar-live">
    <span class="live-dot" id="live-dot"></span>
    <span id="live-label">Live</span>
  </div>
  <details>
    <summary>Navigation</summary>
    <nav class="sidebar-nav">
      <div class="nav-group-label">Traffic</div>
      <a class="nav-link" href="#sec-overview">Overview</a>
      <a class="nav-link" href="#sec-rates">Request Rate</a>
      <a class="nav-link" href="#sec-status">Status Codes</a>
      <a class="nav-link" href="#sec-latency">Latency</a>
      <a class="nav-link" href="#sec-paths">Top Paths</a>
      {compression_nav}
      {breakdown_nav}
      {proxying_nav_group}{proxying_nav}
      {network_nav_group}{network_nav}
      {security_group}{auth_nav}{security_extra_nav}
      {backends_nav_group}{backends_nav}
      {mem_nav_group}{mem_nav}
      <div class="nav-group-label">Configuration</div>
      <a class="nav-link" href="#sec-certs">Certificates</a>
      <a class="nav-link" href="#sec-config">Listeners</a>
      <a class="nav-link" href="#sec-vhosts">Virtual Hosts</a>
      <a class="nav-link" href="#sec-server">Server</a>
    </nav>
  </details>
  <div class="sidebar-controls">
    <div>
      <label for="period-sel">Period</label>
      <select id="period-sel">
        <option value="5min">5 min</option>
        <option value="15min" selected>15 min</option>
        <option value="1h">1 hour</option>
        <option value="3h">3 hours</option>
        <option value="6h">6 hours</option>
        <option value="12h">12 hours</option>
        <option value="1d">1 day</option>
        <option value="7d">7 days</option>
        <option value="30d">30 days</option>
        <option value="1mo">1 month</option>
        <option value="3mo">3 months</option>
        <option value="6mo">6 months</option>
        <option value="1y">1 year</option>
      </select>
    </div>
    <div>
      <label for="refresh-sel">Refresh</label>
      <select id="refresh-sel">
        <option value="3000" selected>3 s</option>
        <option value="5000">5 s</option>
        <option value="15000">15 s</option>
        <option value="30000">30 s</option>
        <option value="60000">60 s</option>
      </select>
    </div>
  </div>
  <div class="sidebar-footer">hypershunt v{version}</div>
</aside>

<main class="main">
<div class="main-inner">

<h1 style="font-size:1.25rem;font-weight:700;color:var(--accent);
  margin:0 0 1.5rem;letter-spacing:-.02em">Server Status</h1>

<section class="section" id="sec-overview">
  <div class="grid-3">
    <div class="card">
      <div class="stat-label">Uptime</div>
      <div class="stat-val" id="val-uptime">{uptime}</div>
    </div>
    <div class="card">
      <div class="stat-label">Active Requests</div>
      <div class="stat-val" id="val-active">{active}</div>
    </div>
    <div class="card">
      <div class="stat-label">Total Requests</div>
      <div class="stat-val" id="val-total">{total}</div>
    </div>
  </div>
</section>

<section class="section" id="sec-rates">
  <h2>Request Rate</h2>
  <div class="grid-2">
    <div class="card">
      <table class="rate-table">
        <thead><tr><th>Window</th><th>req&thinsp;/&thinsp;s</th></tr></thead>
        <tbody>
          <tr><td>Last 5 s</td>
              <td id="val-rate-cur">{rate_cur:.2}</td></tr>
          <tr><td>1 min avg</td>
              <td id="val-rate-1m">{rate_1m:.2}</td></tr>
          <tr><td>5 min avg</td>
              <td id="val-rate-5m">{rate_5m:.2}</td></tr>
          <tr><td>15 min avg</td>
              <td id="val-rate-15m">{rate_15m:.2}</td></tr>
        </tbody>
      </table>
      <svg id="spark-rate" class="sparkline" aria-hidden="true"></svg>
    </div>
    <div class="card" id="sec-status">
      <h2>Status Codes</h2>
      <div class="sc-grid">
        <div class="sc sc-2xx">
          <div class="sc-val" id="val-2xx">{s2xx}</div>
          <div class="sc-label">2xx</div>
        </div>
        <div class="sc sc-3xx">
          <div class="sc-val" id="val-3xx">{s3xx}</div>
          <div class="sc-label">3xx</div>
        </div>
        <div class="sc sc-4xx">
          <div class="sc-val" id="val-4xx">{s4xx}</div>
          <div class="sc-label">4xx</div>
        </div>
        <div class="sc sc-5xx">
          <div class="sc-val" id="val-5xx">{s5xx}</div>
          <div class="sc-label">5xx</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="stat-label">4xx Error Rate</div>
      <svg id="spark-4xx" class="sparkline" aria-hidden="true"></svg>
    </div>
    <div class="card">
      <div class="stat-label">5xx Error Rate</div>
      <svg id="spark-5xx" class="sparkline" aria-hidden="true"></svg>
    </div>
  </div>
</section>

<section class="section" id="sec-latency">
  <h2>Latency Distribution</h2>
  <div class="card">{latency_bars}</div>
</section>

{resource_sec}

{auth_sec}

<section class="section" id="sec-paths">
  <h2>Top Paths</h2>
  <div class="card">
    <table class="info-table">
      <thead>
        <tr><th>Path</th><th style="text-align:right">Hits</th></tr>
      </thead>
      <tbody id="paths-tbody">
        <tr><td colspan="2"
          style="color:var(--muted);font-style:italic"
          >Loading&hellip;</td></tr>
      </tbody>
    </table>
  </div>
</section>

{compression_sec}

{breakdown_sec}

{proxying_sec}

{network_sec}

{security_extra_sec}

{backends_sec}

{certs_sec}

{listeners_sec}

{vhosts_sec}

<section class="section" id="sec-server">
  <h2>Server</h2>
  <div class="card">
    <table class="info-table">
      <tbody>
        <tr><td style="width:8rem;color:var(--muted)">Version</td>
            <td><span class="badge">v{version}</span></td></tr>
        <tr><td style="color:var(--muted)">PID</td>
            <td>{pid}</td></tr>
      </tbody>
    </table>
  </div>
</section>

</div><!-- main-inner -->
</main>
{js}
</body>
</html>"##,
        css = CSS,
        logo_src = logo_src,
        version = sum.version,
        mem_nav = mem_nav,
        auth_nav = auth_nav,
        compression_nav = compression_nav,
        breakdown_nav = breakdown_nav,
        proxying_nav = proxying_nav,
        proxying_nav_group = proxying_nav_group,
        network_nav = network_nav,
        network_nav_group = network_nav_group,
        security_group = security_group,
        security_extra_nav = security_extra_nav,
        backends_nav = backends_nav,
        backends_nav_group = backends_nav_group,
        mem_nav_group = mem_nav_group,
        compression_sec = compression_sec,
        breakdown_sec = breakdown_sec,
        proxying_sec = proxying_sec,
        network_sec = network_sec,
        security_extra_sec = security_extra_sec,
        backends_sec = backends_sec,
        uptime = s.uptime_human(),
        active = s.requests_active,
        total = fmt_num(s.requests_total),
        rate_cur = s.rate_current,
        rate_1m = s.rate_1min,
        rate_5m = s.rate_5min,
        rate_15m = s.rate_15min,
        s2xx = fmt_num(s.status_2xx),
        s3xx = fmt_num(s.status_3xx),
        s4xx = fmt_num(s.status_4xx),
        s5xx = fmt_num(s.status_5xx),
        latency_bars = latency_bars_html(&s.latency, total_lat),
        resource_sec = resource_sec,
        auth_sec = auth_sec,
        certs_sec = certs_sec,
        listeners_sec = listeners_sec,
        vhosts_sec = vhosts_sec,
        pid = std::process::id(),
        js = LIVE_JS,
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(Bytes::from(html)))
        .expect("known-valid response")
}

fn latency_bars_html(counts: &[u64; 6], total: u64) -> String {
    const LABELS: &[&str] = &[
        "&lt;&nbsp;1&nbsp;ms",
        "&lt;&nbsp;10&nbsp;ms",
        "&lt;&nbsp;50&nbsp;ms",
        "&lt;&nbsp;200&nbsp;ms",
        "&lt;&nbsp;1&nbsp;s",
        "&#8805;&nbsp;1&nbsp;s",
    ];
    const KEYS: &[&str] =
        &["lt_1", "lt_10", "lt_50", "lt_200", "lt_1000", "ge_1000"];
    let mut out = String::new();
    for ((count, label), key) in
        counts.iter().zip(LABELS.iter()).zip(KEYS.iter())
    {
        let pct = if total > 0 {
            (*count as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            r#"<div class="bar-row"><span class="bar-label">{label}</span><div class="bar-track"><div class="bar-fill" data-lat="{key}" style="width:{pct:.1}%"></div></div><span class="bar-count" data-lat="{key}">{count}</span></div>"#,
        ));
    }
    out
}

fn resource_section(
    memory_kb: Option<u64>,
    cpu_percent: Option<f64>,
) -> String {
    let mem = match memory_kb {
        None => String::new(),
        Some(kb) => format!(
            r#"<div class="card"><h2>Memory</h2><div class="big-val" id="val-mem">{} MiB</div><div class="stat-label">Resident set size</div><svg id="spark-mem" class="sparkline" aria-hidden="true"></svg></div>"#,
            kb / 1024
        ),
    };
    let cpu = match cpu_percent {
        None => String::new(),
        Some(pct) => format!(
            r#"<div class="card"><h2>CPU</h2><div class="big-val" id="val-cpu">{pct:.1}%</div><div class="stat-label">Process CPU usage</div><svg id="spark-cpu" class="sparkline" aria-hidden="true"></svg></div>"#,
        ),
    };
    // Active-connections sparkline is always shown when a system section
    // exists; it uses the same section for colocation with mem/cpu.
    let active = r#"<div class="card"><h2>Active Requests</h2><div class="big-val" id="val-active-hist">0</div><div class="stat-label">In-flight now</div><svg id="spark-active" class="sparkline" aria-hidden="true"></svg></div>"#;
    if mem.is_empty() && cpu.is_empty() {
        return String::new();
    }
    format!(
        r#"<section class="section" id="sec-system"><h2>System</h2><div class="grid-2">{mem}{cpu}{active}</div></section>"#
    )
}

fn auth_section(auth: Option<&AuthDesc>) -> String {
    let Some(a) = auth else {
        return String::new();
    };
    let jwt_row = if a.has_jwt_session {
        let secs = a.jwt_validity_secs.unwrap_or(0);
        format!(
            r#"<tr><td style="color:var(--muted)">Session</td><td>JWT (ES256, {})</td></tr>"#,
            fmt_duration_secs(secs)
        )
    } else if let Some(v) = a.jwt_validity_secs {
        format!(
            r#"<tr><td style="color:var(--muted)">Token validity</td><td>{}</td></tr>"#,
            fmt_duration_secs(v)
        )
    } else {
        String::new()
    };
    format!(
        r#"<section class="section" id="sec-security">
  <h2>Security</h2>
  <div class="grid-2" style="margin-bottom:.75rem">
    <div class="sec-card sec-card-auth">
      <div class="sec-card-title">Auth Failures</div>
      <div class="sec-card-val" id="val-auth-total">0</div>
      <div class="sec-card-sub">lifetime &bull;
        <span id="val-auth-1h">0</span> last hour</div>
      <svg id="spark-auth" class="sparkline" aria-hidden="true"></svg>
    </div>
    <div class="sec-card sec-card-jwt-fail">
      <div class="sec-card-title">JWT &mdash; Bad Signature</div>
      <div class="sec-card-val" id="val-jwt-fail-total">0</div>
      <div class="sec-card-sub">lifetime &bull;
        <span id="val-jwt-fail-1h">0</span> last hour</div>
      <svg id="spark-jwt-fail" class="sparkline" aria-hidden="true"></svg>
    </div>
    <div class="sec-card sec-card-jwt-exp">
      <div class="sec-card-title">JWT &mdash; Expired</div>
      <div class="sec-card-val" id="val-jwt-exp-total">0</div>
      <div class="sec-card-sub">lifetime &bull;
        <span id="val-jwt-exp-1h">0</span> last hour</div>
      <svg id="spark-jwt-expiry" class="sparkline" aria-hidden="true"></svg>
    </div>
    <div class="sec-card sec-card-jwt-issued">
      <div class="sec-card-title">JWT &mdash; Issued</div>
      <div class="sec-card-val" id="val-jwt-issued-total">0</div>
      <div class="sec-card-sub">lifetime &bull;
        <span id="val-jwt-issued-1h">0</span> last hour</div>
      <svg id="spark-jwt-issued" class="sparkline" aria-hidden="true"></svg>
    </div>
  </div>
  <div class="card">
    <h2>Auth Backend</h2>
    <table class="info-table">
      <tbody>
        <tr><td style="width:8rem;color:var(--muted)">Method</td>
            <td>{kind}</td></tr>
        <tr><td style="color:var(--muted)">Detail</td>
            <td class="mono">{detail}</td></tr>
        {jwt_row}
      </tbody>
    </table>
  </div>
</section>"#,
        kind = a.kind,
        detail = html_escape(&a.detail),
        jwt_row = jwt_row,
    )
}

fn fmt_duration_secs(secs: u64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn certs_section(certs: &[CertState]) -> String {
    let display =
        if certs.is_empty() { " style=\"display:none\"" } else { "" };
    let rows = certs
        .iter()
        .map(|c| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let expiry_secs = c.expiry_ts - now;
            let cls = if expiry_secs < 7 * 86400 {
                "cert-crit"
            } else if expiry_secs < 30 * 86400 {
                "cert-warn"
            } else {
                "cert-ok"
            };
            let status = match cls {
                "cert-ok" => "OK",
                "cert-warn" => "Expiring soon",
                _ => "Critical",
            };
            format!(
                r#"<tr><td class="mono">{domains}</td><td class="{cls} mono">{expiry}</td><td class="mono">{renewal}</td><td><span class="badge {cls}">{status}</span></td></tr>"#,
                domains = html_escape(&c.domains.join(", ")),
                expiry = html_escape(&fmt_unix_ts(c.expiry_ts)),
                renewal = html_escape(&fmt_unix_ts(c.next_renewal_ts)),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<section id="certs-section" class="section"{display}>
  <h2>TLS Certificates</h2>
  <div class="card">
    <table class="info-table">
      <thead>
        <tr>
          <th>Domain(s)</th>
          <th>Expires</th>
          <th>Renewal</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>"#
    )
}

fn listeners_section(ls: &[ListenerSummary]) -> String {
    if ls.is_empty() {
        return String::new();
    }
    let rows = ls
        .iter()
        .map(|l| {
            let domains = if l.acme_domains.is_empty() {
                "&mdash;".into()
            } else {
                html_escape(&l.acme_domains.join(", "))
            };
            let max_conn = l
                .max_connections
                .map_or("&mdash;".into(), |n| fmt_num(n as u64));
            let timeout = l
                .handler_timeout_secs
                .map_or("&mdash;".into(), |s| format!("{s} s"));
            format!(
                r#"<tr><td class="mono">{addr}</td><td>{proto}</td><td>{domains}</td><td>{max_conn}</td><td>{timeout}</td></tr>"#,
                addr = html_escape(&l.address),
                proto = html_escape(&l.protocol),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<section class="section" id="sec-config">
  <h2>Listeners</h2>
  <div class="card">
    <table class="info-table">
      <thead>
        <tr>
          <th>Bind Address</th>
          <th>Protocol</th>
          <th>ACME Domains</th>
          <th>Max Conn</th>
          <th>Handler Timeout</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>"#
    )
}

fn vhosts_section(vs: &[VHostSummary]) -> String {
    if vs.is_empty() {
        return String::new();
    }
    let rows = vs
        .iter()
        .map(|v| {
            let aliases = if v.aliases.is_empty() {
                "&mdash;".into()
            } else {
                html_escape(&v.aliases.join(", "))
            };
            let locs = v
                .locations
                .iter()
                .map(|l| {
                    format!(
                        "<span class=\"mono\">{}</span> ({})",
                        html_escape(&l.path),
                        html_escape(&l.handler)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                r#"<tr><td class="mono">{name}</td><td>{aliases}</td><td>{locs}</td></tr>"#,
                name = html_escape(&v.name),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<section class="section" id="sec-vhosts">
  <h2>Virtual Hosts</h2>
  <div class="card">
    <table class="info-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Aliases</th>
          <th>Locations</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>"#
    )
}

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM UTC" using integer
/// arithmetic only — no external date crate required.
pub(super) fn fmt_unix_ts(ts: i64) -> String {
    if ts <= 0 {
        return "expired".into();
    }
    // Days and time-of-day.
    let secs_of_day = (ts % 86400) as u32;
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;

    // Gregorian calendar computation from Unix epoch (1970-01-01).
    // Algorithm: civil_from_days (Howard Hinnant, public domain).
    let z = (ts / 86400) + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

/// Format an integer with thousands-separator commas.
pub(super) fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

/// Minimal HTML escaping for user-controlled strings.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// -- Newly-surfaced metric sections -------------------------------
//
// These render point-in-time totals/gauges as label→value tables.
// Each value cell carries a DOM id so the poll() loop can refresh it
// live.  A section returns an empty string when its subsystem shows no
// activity (and, for proxying, no relevant listener), so unused
// features don't clutter the page.

/// One `label → value` row whose value cell has a live-update id.
fn mrow(label: &str, id: &str, val: &str) -> String {
    format!(
        r#"<tr><td style="width:11rem;color:var(--muted)">{label}</td><td id="{id}">{val}</td></tr>"#
    )
}

/// A `.card` wrapping a titled `info-table` of rows.
fn mcard(title: &str, rows: &str) -> String {
    format!(
        r#"<div class="card"><h2>{title}</h2><table class="info-table"><tbody>{rows}</tbody></table></div>"#
    )
}

/// Render bytes as a human-readable size (KiB/MiB/GiB).
fn fmt_bytes(n: u64) -> String {
    const U: &[(&str, u64)] = &[
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (label, div) in U {
        if n >= *div {
            return format!("{:.1} {label}", n as f64 / *div as f64);
        }
    }
    format!("{n} B")
}

/// True when any byte-stream or datagram proxy listener is configured.
fn has_proxy_listener(sum: &ServerSummary) -> bool {
    sum.listeners.iter().any(|l| {
        l.protocol == "stream"
            || l.protocol.starts_with("TLS-stream")
            || l.protocol == "dgram-proxy"
    })
}

/// Proxying section: TCP stream, UDP/datagram, and reverse-proxy
/// load-balancer cards.  Shown when any proxy listener exists or any
/// proxy counter is non-zero.
fn proxying_section(
    s: &Snapshot,
    sum: &ServerSummary,
    upstreams: &[UpstreamRow],
) -> String {
    let active = has_proxy_listener(sum)
        || !upstreams.is_empty()
        || s.stream.conns_total > 0
        || s.datagram.flow_create > 0
        || s.lb.picks > 0
        || s.upstream.bytes_in > 0
        || s.upstream.bytes_out > 0;
    if !active {
        return String::new();
    }
    let stream = mcard(
        "TCP Stream Proxy",
        &format!(
            "{}{}{}{}",
            mrow("Active connections", "val-stream-active",
                &s.stream.conns_active.to_string()),
            mrow("Total connections", "val-stream-total",
                &fmt_num(s.stream.conns_total)),
            mrow("Bytes client&rarr;upstream", "val-stream-in",
                &fmt_bytes(s.stream.bytes_in)),
            mrow("Bytes upstream&rarr;client", "val-stream-out",
                &fmt_bytes(s.stream.bytes_out)),
        ),
    );
    let dgram = mcard(
        "UDP / Datagram Proxy",
        &format!(
            "{}{}{}{}{}",
            mrow("Active flows", "val-dgram-flows",
                &fmt_num(s.datagram.flows_active)),
            mrow("Datagrams in / out", "val-dgram-pkts",
                &format!("{} / {}",
                    fmt_num(s.datagram.datagrams_in),
                    fmt_num(s.datagram.datagrams_out))),
            mrow("Bytes in / out", "val-dgram-bytes",
                &format!("{} / {}",
                    fmt_bytes(s.datagram.bytes_in),
                    fmt_bytes(s.datagram.bytes_out))),
            mrow("Flows created", "val-dgram-create",
                &fmt_num(s.datagram.flow_create)),
            mrow("Flows evicted", "val-dgram-evict",
                &fmt_num(s.datagram.flow_evict)),
        ),
    );
    let lb = mcard(
        "Reverse-Proxy Load Balancer",
        &format!(
            "{}{}{}{}{}{}{}{}",
            mrow("Upstream picks", "val-lb-picks",
                &fmt_num(s.lb.picks)),
            mrow("No upstream available", "val-lb-noup",
                &fmt_num(s.lb.no_upstream)),
            mrow("Retries", "val-lb-retries", &fmt_num(s.lb.retries)),
            mrow("Passive ejections", "val-lb-eject",
                &fmt_num(s.lb.ejections)),
            mrow("Health: checks", "val-lb-hc",
                &fmt_num(s.lb.health_checks)),
            mrow("Health: failures / recoveries", "val-lb-hfr",
                &format!("{} / {}",
                    fmt_num(s.lb.health_failures),
                    fmt_num(s.lb.health_recoveries))),
            mrow("Upstream bytes in / out", "val-up-bytes",
                &format!("{} / {}",
                    fmt_bytes(s.upstream.bytes_in),
                    fmt_bytes(s.upstream.bytes_out))),
            mrow("Upstream connect errors", "val-up-cerr",
                &fmt_num(s.upstream.connect_errors)),
        ),
    );
    let table = upstream_health_table(upstreams);
    format!(
        r#"<section class="section" id="sec-proxying"><h2>Proxying</h2><div class="grid-2">{stream}{dgram}{lb}</div>{table}</section>"#
    )
}

/// Live per-upstream health table for every reverse-proxy pool.  The
/// `id="upstreams-tbody"` body is re-rendered by `updateUpstreams` on
/// each poll; an empty registry hides the card.
fn upstream_health_table(upstreams: &[UpstreamRow]) -> String {
    let hidden = if upstreams.is_empty() {
        " style=\"display:none\""
    } else {
        ""
    };
    let rows: String = upstreams.iter().map(upstream_row_html).collect();
    format!(
        r#"<div class="card" id="upstreams-card"{hidden} style="margin-top:1rem">
  <h2>Upstream Health</h2>
  <table class="info-table">
    <thead><tr><th>Location</th><th>Upstream</th><th>Weight</th><th>In flight</th><th>State</th></tr></thead>
    <tbody id="upstreams-tbody">{rows}</tbody>
  </table>
</div>"#
    )
}

fn upstream_row_html(u: &UpstreamRow) -> String {
    // Ejected takes visual priority over a stale healthy flag.
    let (cls, state) = if u.ejected {
        ("cert-crit", "Ejected")
    } else if u.healthy {
        ("cert-ok", "Healthy")
    } else {
        ("cert-warn", "Unhealthy")
    };
    format!(
        r#"<tr><td>{label}</td><td class="mono">{url}</td><td>{weight}</td><td>{inflight}</td><td><span class="badge {cls}">{state}</span></td></tr>"#,
        label = html_escape(&u.label),
        url = html_escape(&u.url),
        weight = u.weight,
        inflight = u.in_flight,
    )
}

/// TCP TLS handshakes, HTTP connection gauge, OCSP and ACME events.
/// Shown when any related counter is non-zero.
fn network_section(s: &Snapshot) -> String {
    let active = s.tls.handshakes > 0
        || s.http_conns.total > 0
        || s.ocsp.refreshes > 0
        || s.ocsp.refresh_failures > 0
        || s.acme.issuances > 0
        || s.acme.renewals > 0
        || s.acme.issuance_failures > 0
        || s.acme.renewal_failures > 0;
    if !active {
        return String::new();
    }
    let conns = mcard(
        "Connections",
        &format!(
            "{}{}{}{}{}",
            mrow("HTTP connections active", "val-http-conns-active",
                &s.http_conns.active.to_string()),
            mrow("HTTP connections total", "val-http-conns-total",
                &fmt_num(s.http_conns.total)),
            mrow("TLS handshakes", "val-tls-hs",
                &fmt_num(s.tls.handshakes)),
            mrow("TLS handshake failures", "val-tls-hs-fail",
                &fmt_num(s.tls.failures)),
            mrow("TLS handshake timeouts", "val-tls-hs-to",
                &fmt_num(s.tls.timeouts)),
        ),
    );
    let certs = mcard(
        "Certificate Lifecycle",
        &format!(
            "{}{}{}{}{}{}",
            mrow("ACME issuances", "val-acme-iss",
                &fmt_num(s.acme.issuances)),
            mrow("ACME issuance failures", "val-acme-iss-fail",
                &fmt_num(s.acme.issuance_failures)),
            mrow("ACME renewals", "val-acme-ren",
                &fmt_num(s.acme.renewals)),
            mrow("ACME renewal failures", "val-acme-ren-fail",
                &fmt_num(s.acme.renewal_failures)),
            mrow("OCSP refreshes", "val-ocsp",
                &fmt_num(s.ocsp.refreshes)),
            mrow("OCSP refresh failures", "val-ocsp-fail",
                &fmt_num(s.ocsp.refresh_failures)),
        ),
    );
    format!(
        r#"<section class="section" id="sec-network"><h2>Network &amp; TLS</h2><div class="grid-2">{conns}{certs}</div></section>"#
    )
}

/// OIDC, rate-limit, and GeoIP cards.  Each appears only when its own
/// counters show activity, so a deployment that uses one but not the
/// others sees just the relevant card.
fn security_extra_section(s: &Snapshot) -> String {
    let oidc_active = s.oidc.discoveries > 0
        || s.oidc.refreshes > 0
        || s.oidc.logouts > 0
        || s.oidc.bearer_validations > 0
        || s.oidc.discovery_failures > 0
        || s.oidc.bearer_failures > 0;
    let rl_active = s.rate_limit.triggers > 0 || s.rate_limit.active_keys > 0;
    let geo_active = s.geoip.lookups > 0;
    if !oidc_active && !rl_active && !geo_active {
        return String::new();
    }
    let mut cards = String::new();
    if oidc_active {
        cards.push_str(&mcard(
            "OIDC / OAuth",
            &format!(
                "{}{}{}{}{}{}{}{}",
                mrow("Discoveries", "val-oidc-disc",
                    &fmt_num(s.oidc.discoveries)),
                mrow("Discovery failures", "val-oidc-disc-fail",
                    &fmt_num(s.oidc.discovery_failures)),
                mrow("Token refreshes", "val-oidc-ref",
                    &fmt_num(s.oidc.refreshes)),
                mrow("Refresh failures", "val-oidc-ref-fail",
                    &fmt_num(s.oidc.refresh_failures)),
                mrow("Logouts", "val-oidc-logout",
                    &fmt_num(s.oidc.logouts)),
                mrow("Bearer validations", "val-oidc-bearer",
                    &fmt_num(s.oidc.bearer_validations)),
                mrow("Bearer failures", "val-oidc-bearer-fail",
                    &fmt_num(s.oidc.bearer_failures)),
                mrow("Issuer mismatches", "val-oidc-iss",
                    &fmt_num(s.oidc.callback_iss_mismatches)),
            ),
        ));
    }
    if rl_active {
        cards.push_str(&mcard(
            "Rate Limiting",
            &format!(
                "{}{}",
                mrow("Requests denied (429)", "val-rl-triggers",
                    &fmt_num(s.rate_limit.triggers)),
                mrow("Active bucket keys", "val-rl-keys",
                    &fmt_num(s.rate_limit.active_keys)),
            ),
        ));
    }
    if geo_active {
        cards.push_str(&mcard(
            "GeoIP",
            &format!(
                "{}{}",
                mrow("Lookups", "val-geoip", &fmt_num(s.geoip.lookups)),
                mrow("No-country misses", "val-geoip-miss",
                    &fmt_num(s.geoip.misses)),
            ),
        ));
    }
    format!(
        r#"<section class="section" id="sec-security-extra"><h2>Access &amp; Identity</h2><div class="grid-2">{cards}</div></section>"#
    )
}

/// Compression card.  Shown once any response has been negotiated for
/// compression (encoded or deliberately skipped).
fn compression_section(s: &Snapshot) -> String {
    if s.compression.responses == 0 && s.compression.skipped == 0 {
        return String::new();
    }
    // Saved ratio guards against divide-by-zero before any bytes flow.
    let saved = if s.compression.bytes_in > 0 {
        let r = 1.0
            - (s.compression.bytes_out as f64
                / s.compression.bytes_in as f64);
        format!("{:.1}%", (r * 100.0).max(0.0))
    } else {
        "—".into()
    };
    let card = mcard(
        "Response Compression",
        &format!(
            "{}{}{}{}{}",
            mrow("Responses encoded", "val-cmp-resp",
                &fmt_num(s.compression.responses)),
            mrow("Negotiated but skipped", "val-cmp-skip",
                &fmt_num(s.compression.skipped)),
            mrow("gzip / brotli / zstd", "val-cmp-split",
                &format!("{} / {} / {}",
                    fmt_num(s.compression.gzip),
                    fmt_num(s.compression.brotli),
                    fmt_num(s.compression.zstd))),
            mrow("Bytes in &rarr; out", "val-cmp-bytes",
                &format!("{} &rarr; {}",
                    fmt_bytes(s.compression.bytes_in),
                    fmt_bytes(s.compression.bytes_out))),
            mrow("Bandwidth saved", "val-cmp-saved", &saved),
        ),
    );
    format!(
        r#"<section class="section" id="sec-compression"><h2>Compression</h2><div class="grid-2">{card}</div></section>"#
    )
}

/// FastCGI / SCGI / CGI / static-file handler counters.  Shown when any
/// backend handler has served a request or streamed bytes.
fn backends_section(s: &Snapshot) -> String {
    let active = s.fcgi.requests > 0
        || s.scgi.requests > 0
        || s.cgi.requests > 0
        || s.static_files.bytes_served > 0
        || s.static_files.not_modified > 0;
    if !active {
        return String::new();
    }
    let be = |title: &str, id: &str, b: &crate::metrics::BackendSnap| {
        mcard(
            title,
            &format!(
                "{}{}{}",
                mrow("Requests", &format!("val-{id}-req"),
                    &fmt_num(b.requests)),
                mrow("Errors", &format!("val-{id}-err"),
                    &fmt_num(b.errors)),
                mrow("In flight", &format!("val-{id}-inf"),
                    &b.in_flight.to_string()),
            ),
        )
    };
    let cgi = mcard(
        "CGI",
        &format!(
            "{}{}{}{}{}",
            mrow("Requests", "val-cgi-req", &fmt_num(s.cgi.requests)),
            mrow("Errors", "val-cgi-err", &fmt_num(s.cgi.errors)),
            mrow("In flight", "val-cgi-inf", &s.cgi.in_flight.to_string()),
            mrow("Spawn failures", "val-cgi-spawn",
                &fmt_num(s.cgi.spawn_failures)),
            mrow("Timeouts", "val-cgi-to", &fmt_num(s.cgi.timeouts)),
        ),
    );
    let stat = mcard(
        "Static Files",
        &format!(
            "{}{}{}",
            mrow("Bytes served", "val-static-bytes",
                &fmt_bytes(s.static_files.bytes_served)),
            mrow("304 Not Modified", "val-static-304",
                &fmt_num(s.static_files.not_modified)),
            mrow("206 Range responses", "val-static-206",
                &fmt_num(s.static_files.range)),
        ),
    );
    format!(
        r#"<section class="section" id="sec-backends"><h2>Backends</h2><div class="grid-2">{}{}{}{}</div></section>"#,
        be("FastCGI", "fcgi", &s.fcgi),
        be("SCGI", "scgi", &s.scgi),
        cgi,
        stat,
    )
}

/// Per-vhost and per-handler request breakdown tables.  Rendered once
/// at least one routed request has been attributed.
fn breakdown_section(s: &Snapshot) -> String {
    let handler_rows: String = s
        .by_handler
        .iter()
        .filter(|(_, c)| c.total > 0)
        .map(|(name, c)| class_row(name, c))
        .collect();
    let vhost_rows: String = s
        .by_vhost
        .iter()
        .map(|(name, c)| class_row(name, c))
        .collect();
    if handler_rows.is_empty() && vhost_rows.is_empty() {
        return String::new();
    }
    let table = |title: &str, head: &str, rows: &str| {
        format!(
            r#"<div class="card"><h2>{title}</h2><table class="info-table"><thead><tr><th>{head}</th><th>Total</th><th>2xx</th><th>3xx</th><th>4xx</th><th>5xx</th></tr></thead><tbody>{rows}</tbody></table></div>"#
        )
    };
    format!(
        r#"<section class="section" id="sec-breakdown"><h2>Traffic Breakdown</h2><div class="grid-2">{}{}</div></section>"#,
        table("By Handler", "Handler", &handler_rows),
        table("By Vhost", "Vhost", &vhost_rows),
    )
}

fn class_row(name: &str, c: &crate::metrics::ClassSnapshot) -> String {
    format!(
        r#"<tr><td class="mono">{name}</td><td>{total}</td><td>{s2}</td><td>{s3}</td><td>{s4}</td><td>{s5}</td></tr>"#,
        name = html_escape(name),
        total = fmt_num(c.total),
        s2 = fmt_num(c.s2xx),
        s3 = fmt_num(c.s3xx),
        s4 = fmt_num(c.s4xx),
        s5 = fmt_num(c.s5xx),
    )
}
