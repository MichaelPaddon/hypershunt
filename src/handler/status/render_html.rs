// HTML status-page renderer.  Live updates are driven by the JavaScript
// shipped in LIVE_JS, which polls the JSON endpoint every 3 seconds.

use super::{AuthDesc, ListenerSummary, ServerSummary, VHostSummary};
use crate::cert::state::CertState;
use crate::error::{HttpResponse, bytes_body};
use crate::metrics::{Snapshot, SparklineData, TimePeriod};
use bytes::Bytes;
use hyper::{Response, StatusCode};
use std::time::{SystemTime, UNIX_EPOCH};

// Hypershunt logo SVG, inlined for the sidebar brand.
const LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="40 55 600 250" role="img" aria-label="Hypershunt"><line x1="60" y1="180" x2="225" y2="180" stroke="#1e3a5f" stroke-width="2.5" stroke-linecap="round"/><line x1="455" y1="180" x2="620" y2="180" stroke="#1e3a5f" stroke-width="2.5" stroke-linecap="round"/><circle cx="340" cy="180" r="110" fill="#1e3a5f"/><line x1="230" y1="180" x2="238" y2="180" stroke="#FAECE7" stroke-width="2.5" stroke-linecap="round"/><line x1="442" y1="180" x2="450" y2="180" stroke="#FAECE7" stroke-width="2.5" stroke-linecap="round"/><text x="340" y="202" text-anchor="middle" font-family="Futura,'Century Gothic','Avenir Next',sans-serif" font-size="72" font-weight="700" fill="#FAECE7">hypershunt</text></svg>"##;

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
.sidebar-brand svg{width:140px;display:block}
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
) -> HttpResponse {
    let total_lat: u64 = s.latency.iter().sum();
    let resource_sec = resource_section(s.memory_kb, s.cpu_percent);
    let certs_sec = certs_section(certs);
    let listeners_sec = listeners_section(&sum.listeners);
    let vhosts_sec = vhosts_section(&sum.vhosts);
    let auth_sec = auth_section(sum.auth.as_ref());

    // Sidebar auth link only when auth is configured.
    let auth_nav = if sum.auth.is_some() {
        r##"<a class="nav-link" href="#sec-security">Security</a>"##
    } else {
        ""
    };
    let mem_nav = if s.memory_kb.is_some() || s.cpu_percent.is_some() {
        r##"<a class="nav-link" href="#sec-system">System</a>"##
    } else {
        ""
    };

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjIzMCA3MCAyMjAgMjIwIj48Y2lyY2xlIGN4PSIzNDAiIGN5PSIxODAiIHI9IjExMCIgZmlsbD0iIzFlM2E1ZiIvPjx0ZXh0IHg9IjM0MCIgeT0iMTcyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LWZhbWlseT0iRnV0dXJhLCdDZW50dXJ5IEdvdGhpYycsJ0F2ZW5pciBOZXh0JyxzYW5zLXNlcmlmIiBmb250LXNpemU9IjEyMCIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI0ZBRUNFNyIgZG9taW5hbnQtYmFzZWxpbmU9ImNlbnRyYWwiPmE8L3RleHQ+PC9zdmc+">
<title>hypershunt — Status</title>
<style>{css}</style>
</head>
<body>

<aside class="sidebar">
  <div class="sidebar-brand">
    <a id="logo-link" href="/" style="display:block">{logo}</a>
  </div>
  <div class="sidebar-live">
    <span class="live-dot" id="live-dot"></span>
    <span id="live-label">Live</span>
  </div>
  <details>
    <summary>Navigation</summary>
    <nav class="sidebar-nav">
      <div class="nav-group-label">Overview</div>
      <a class="nav-link" href="#sec-overview">Overview</a>
      <a class="nav-link" href="#sec-rates">Request Rate</a>
      <a class="nav-link" href="#sec-status">Status Codes</a>
      <a class="nav-link" href="#sec-latency">Latency</a>
      {mem_nav}
      {auth_nav}
      <div class="nav-group-label">Traffic</div>
      <a class="nav-link" href="#sec-paths">Top Paths</a>
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
        logo = LOGO_SVG,
        version = sum.version,
        mem_nav = mem_nav,
        auth_nav = auth_nav,
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
