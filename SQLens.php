<?php
session_start();
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf'];

function csrf(): void {
    $t = $_POST['_t'] ?? $_GET['_t'] ?? '';
    if (!hash_equals($_SESSION['csrf'], $t)) { http_response_code(403); die('Bad token'); }
}

function qid(string $n): string { return '"'.str_replace('"','""',$n).'"'; }

function jout(array $d): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PARTIAL_OUTPUT_ON_ERROR);
    exit;
}

function db(): ?PDO {
    $p = $_SESSION['db_path'] ?? null;
    if (!$p) return null;
    $r = realpath($p);
    $t = realpath(sys_get_temp_dir());
    if (!$r || !$t || strncmp($r, $t.DIRECTORY_SEPARATOR, strlen($t)+1) !== 0) return null;
    if (!file_exists($r)) return null;
    try {
        $pdo = new PDO('sqlite:'.$r, null, null, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
        $pdo->exec('PRAGMA query_only=ON');
        return $pdo;
    } catch (Throwable) { return null; }
}

function tables(PDO $db): array {
    return $db->query("SELECT name FROM sqlite_master WHERE type IN('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
}

function assertTbl(PDO $db, string $n): void {
    if (!in_array($n, tables($db), true)) jout(['ok'=>false,'error'=>'Unknown table']);
}

function assertCol(PDO $db, string $tbl, string $col): void {
    $cols = array_column($db->query("PRAGMA table_info(".qid($tbl).")")->fetchAll(), 'name');
    if (!in_array($col, $cols, true)) jout(['ok'=>false,'error'=>'Unknown column']);
}

function safeVal(mixed $v): mixed {
    if ($v === null) return null;
    if (is_int($v) || is_float($v)) return $v;
    $s = (string)$v;
    if ($s === '') return '';
    if (strpos($s, "\0") !== false) return blobDesc($s);
    if (mb_check_encoding($s, 'UTF-8')) return $s;
    foreach (['Windows-1252','ISO-8859-1','ISO-8859-15'] as $enc) {
        $c = @iconv($enc, 'UTF-8//TRANSLIT//IGNORE', $s);
        if ($c !== false && mb_check_encoding($c, 'UTF-8')) return ['_enc'=>$enc,'v'=>$c];
    }
    $det = @mb_detect_encoding($s, ['UTF-16LE','UTF-16BE','Shift-JIS','EUC-JP','GB18030'], true);
    if ($det) { $c = @mb_convert_encoding($s, 'UTF-8', $det); if ($c !== false && mb_check_encoding($c,'UTF-8')) return ['_enc'=>$det,'v'=>$c]; }
    return blobDesc($s);
}

function blobDesc(string $s): array {
    $mime = 'application/octet-stream';
    if (function_exists('finfo_buffer')) { $fi = new finfo(FILEINFO_MIME_TYPE); $mime = $fi->buffer($s) ?: $mime; }
    return ['_blob'=>true,'size'=>strlen($s),'hex'=>strtoupper(bin2hex(substr($s,0,12))),'mime'=>$mime];
}

function safeRow(array $row, array $cols): array {
    $out = ['_rid'=>$row['_rid']??null];
    foreach ($cols as $c) $out[$c] = safeVal($row[$c]??null);
    return $out;
}

function csvVal(mixed $v): string {
    if ($v === null) return 'NULL';
    if (is_array($v) && isset($v['_blob'])) return '[BLOB '.$v['size'].'B]';
    if (is_array($v) && isset($v['_enc'])) return $v['v'];
    return (string)$v;
}

// ── Blob download ─────────────────────────────────────────────
if (isset($_GET['dl'])) {
    csrf();
    $pdo = db(); if (!$pdo) { http_response_code(400); die('No DB'); }
    $tbl = $_GET['t']??''; $col = $_GET['c']??''; $rid = (int)($_GET['r']??0);
    assertTbl($pdo,$tbl); assertCol($pdo,$tbl,$col);
    if ($rid<=0) { http_response_code(400); die('Bad rowid'); }
    $stmt = $pdo->prepare('SELECT '.qid($col).' FROM '.qid($tbl).' WHERE rowid=?');
    $stmt->execute([$rid]); $blob = $stmt->fetchColumn();
    if ($blob === false) { http_response_code(404); die('Not found'); }
    $blob = (string)$blob;
    $mime = 'application/octet-stream';
    if (function_exists('finfo_buffer')) { $fi=new finfo(FILEINFO_MIME_TYPE); $mime=$fi->buffer($blob)?:$mime; }
    $extMap=['image/png'=>'png','image/jpeg'=>'jpg','image/gif'=>'gif','image/webp'=>'webp','application/pdf'=>'pdf','application/zip'=>'zip','text/plain'=>'txt'];
    $ext = $extMap[$mime]??'bin';
    header('Content-Type: '.$mime);
    header('Content-Disposition: attachment; filename="blob_'.preg_replace('/[^a-z0-9_]/i','_',$tbl.'_'.$col.'_'.$rid).'.'.$ext.'"');
    header('Content-Length: '.strlen($blob));
    header('Cache-Control: no-store');
    echo $blob; exit;
}

// ── CSV export ────────────────────────────────────────────────
if (isset($_GET['export'])) {
    csrf();
    $pdo = db(); if (!$pdo) { http_response_code(400); die('No DB'); }
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="sqlens_'.date('Ymd_His').'.csv"');
    header('Cache-Control: no-store');
    echo "\xEF\xBB\xBF";
    $out = fopen('php://output','w');
    $tbl = $_GET['table']??''; $flt = trim($_GET['filter']??''); $q = trim($_GET['q']??'');
    if ($tbl !== '') {
        assertTbl($pdo,$tbl);
        $cols = array_column($pdo->query("PRAGMA table_info(".qid($tbl).")")->fetchAll(),'name');
        fputcsv($out,$cols);
        $w=''; $p=[];
        if ($flt!=='') { $conds=array_map(fn($c)=>'CAST('.qid($c).' AS TEXT) LIKE ?',$cols); $w='WHERE '.implode(' OR ',$conds); $p=array_fill(0,count($cols),'%'.$flt.'%'); }
        $st=$pdo->prepare('SELECT '.implode(',',array_map('qid',$cols)).' FROM '.qid($tbl).' '.$w);
        $st->execute($p);
        while ($row=$st->fetch(PDO::FETCH_NUM)) fputcsv($out,array_map('csvVal',$row));
    } elseif ($q!=='') {
        foreach (tables($pdo) as $t) {
            $cols=array_column($pdo->query("PRAGMA table_info(".qid($t).")")->fetchAll(),'name'); if(!$cols) continue;
            $conds=array_map(fn($c)=>'CAST('.qid($c).' AS TEXT) LIKE ?',$cols);
            $st=$pdo->prepare('SELECT '.implode(',',array_map('qid',$cols)).' FROM '.qid($t).' WHERE '.implode(' OR ',$conds).' LIMIT 500');
            $st->execute(array_fill(0,count($cols),'%'.$q.'%'));
            $rows=$st->fetchAll(PDO::FETCH_NUM); if(!$rows) continue;
            fputcsv($out,['=== '.$t.' ===']); fputcsv($out,$cols);
            foreach ($rows as $row) fputcsv($out,array_map('csvVal',$row));
            fputcsv($out,[]);
        }
    }
    fclose($out); exit;
}

// ── File upload ───────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_FILES['db_file'])) {
    csrf();
    header('Content-Type: application/json; charset=utf-8');
    $f = $_FILES['db_file'];
    $errc=[1=>'File too large',2=>'File too large',3=>'Partial upload',4=>'No file',6=>'No tmp dir',7=>'Write fail'];
    if ($f['error']!==UPLOAD_ERR_OK) { echo json_encode(['ok'=>false,'error'=>$errc[$f['error']]??'Error '.$f['error']]); exit; }
    $ext = strtolower(pathinfo($f['name'],PATHINFO_EXTENSION));
    if (!in_array($ext,['db','sqlite','sqlite3','s3db'],true)) { echo json_encode(['ok'=>false,'error'=>'Must be .db/.sqlite/.sqlite3/.s3db']); exit; }
    if (!empty($_SESSION['db_path'])&&file_exists($_SESSION['db_path'])) @unlink($_SESSION['db_path']);
    $tmp = tempnam(sys_get_temp_dir(),'sqlens_');
    if (!$tmp||!move_uploaded_file($f['tmp_name'],$tmp)) { echo json_encode(['ok'=>false,'error'=>'Save failed']); exit; }
    $fh=fopen($tmp,'rb'); $magic=fread($fh,16); fclose($fh);
    if (strncmp($magic,'SQLite format 3',15)!==0) { @unlink($tmp); echo json_encode(['ok'=>false,'error'=>'Not a valid SQLite file']); exit; }
    try { $test=new PDO('sqlite:'.$tmp); $test->query('SELECT name FROM sqlite_master LIMIT 1'); $test=null; }
    catch (Throwable $e) { @unlink($tmp); echo json_encode(['ok'=>false,'error'=>'Corrupt or encrypted: '.$e->getMessage()]); exit; }
    $_SESSION['db_path']=$tmp; $_SESSION['db_name']=htmlspecialchars(basename($f['name']),ENT_QUOTES,'UTF-8'); $_SESSION['db_size']=$f['size'];
    echo json_encode(['ok'=>true,'name'=>$_SESSION['db_name'],'size'=>$f['size']]); exit;
}

// ── AJAX ──────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD']==='POST' && !empty($_POST['action'])) {
    csrf();
    $action = $_POST['action'];
    if ($action==='close') {
        if (!empty($_SESSION['db_path'])&&file_exists($_SESSION['db_path'])) @unlink($_SESSION['db_path']);
        session_destroy(); jout(['ok'=>true]);
    }
    $pdo = db(); if (!$pdo) jout(['ok'=>false,'error'=>'No database loaded']);

    switch ($action) {
        case 'tables':
            $tbls=$pdo->query("SELECT name,type FROM sqlite_master WHERE type IN('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type DESC,name")->fetchAll();
            $out=[];
            foreach ($tbls as $r) {
                try { $cnt=(int)$pdo->query("SELECT COUNT(*) FROM ".qid($r['name']))->fetchColumn(); } catch (Throwable) { $cnt=0; }
                $out[]=['name'=>$r['name'],'type'=>$r['type'],'rows'=>$cnt];
            }
            jout(['ok'=>true,'tables'=>$out,'dbName'=>$_SESSION['db_name']??'unknown.db']);

        case 'table_data':
            $tbl=$_POST['table']??''; assertTbl($pdo,$tbl);
            $page=max(1,(int)($_POST['page']??1)); $limit=max(10,min(500,(int)($_POST['limit']??50)));
            $dir=strtoupper($_POST['dir']??'ASC')==='DESC'?'DESC':'ASC'; $flt=trim($_POST['filter']??'');
            $colInfo=$pdo->query("PRAGMA table_info(".qid($tbl).")")->fetchAll();
            if (!$colInfo) jout(['ok'=>false,'error'=>'No columns']);
            $colNames=array_column($colInfo,'name');
            $sort=$_POST['sort']??''; if (!in_array($sort,$colNames,true)) $sort='';
            $w=''; $p=[];
            if ($flt!=='') { $conds=array_map(fn($c)=>'CAST('.qid($c).' AS TEXT) LIKE ?',$colNames); $w='WHERE '.implode(' OR ',$conds); $p=array_fill(0,count($colNames),'%'.$flt.'%'); }
            $ord=$sort?'ORDER BY '.qid($sort).' '.$dir:'';
            $ts=$pdo->prepare('SELECT COUNT(*) FROM '.qid($tbl).' '.$w); $ts->execute($p); $total=(int)$ts->fetchColumn();
            $sel='rowid AS _rid,'.implode(',',array_map('qid',$colNames));
            $st=$pdo->prepare('SELECT '.$sel.' FROM '.qid($tbl).' '.$w.' '.$ord.' LIMIT '.$limit.' OFFSET '.(($page-1)*$limit));
            $st->execute($p); $raw=$st->fetchAll();
            $rows=array_map(fn($r)=>safeRow($r,$colNames),$raw);
            jout(['ok'=>true,'columns'=>$colInfo,'rows'=>$rows,'total'=>$total,'page'=>$page,'limit'=>$limit,'pages'=>max(1,(int)ceil($total/$limit))]);

        case 'search':
            $q=trim($_POST['query']??''); if ($q==='') jout(['ok'=>true,'results'=>[]]);
            $results=[];
            foreach (tables($pdo) as $t) {
                $cols=array_column($pdo->query("PRAGMA table_info(".qid($t).")")->fetchAll(),'name'); if(!$cols) continue;
                $conds=array_map(fn($c)=>'CAST('.qid($c).' AS TEXT) LIKE ?',$cols);
                $sel='rowid AS _rid,'.implode(',',array_map('qid',$cols));
                $st=$pdo->prepare('SELECT '.$sel.' FROM '.qid($t).' WHERE '.implode(' OR ',$conds).' LIMIT 200');
                $st->execute(array_fill(0,count($cols),'%'.$q.'%'));
                $raw=$st->fetchAll(); if(!$raw) continue;
                $results[]=['table'=>$t,'columns'=>$cols,'rows'=>array_map(fn($r)=>safeRow($r,$cols),$raw),'count'=>count($raw)];
            }
            jout(['ok'=>true,'results'=>$results,'query'=>$q]);

        case 'stats':
            $s=[];
            $s['sqlite_version']=$pdo->query('SELECT sqlite_version()')->fetchColumn();
            $s['page_size']=(int)$pdo->query('PRAGMA page_size')->fetchColumn();
            $s['page_count']=(int)$pdo->query('PRAGMA page_count')->fetchColumn();
            $s['freelist']=(int)$pdo->query('PRAGMA freelist_count')->fetchColumn();
            $s['encoding']=$pdo->query('PRAGMA encoding')->fetchColumn();
            $s['journal']=strtoupper($pdo->query('PRAGMA journal_mode')->fetchColumn());
            $s['auto_vacuum']=(int)$pdo->query('PRAGMA auto_vacuum')->fetchColumn();
            $s['db_bytes']=$s['page_size']*$s['page_count'];
            foreach (['table','view','index','trigger'] as $type)
                $s[$type.'_count']=(int)$pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE type='$type' AND name NOT LIKE 'sqlite_%'")->fetchColumn();
            $s['file_name']=$_SESSION['db_name']??''; $s['file_size']=(int)($_SESSION['db_size']??0);
            $td=[]; $total=0;
            foreach (tables($pdo) as $t) {
                $ti=$pdo->query("SELECT type FROM sqlite_master WHERE name=".$pdo->quote($t))->fetchColumn();
                if ($ti!=='table') continue;
                try {
                    $rc=(int)$pdo->query('SELECT COUNT(*) FROM '.qid($t))->fetchColumn();
                    $ci=$pdo->query('PRAGMA table_info('.qid($t).')')->fetchAll();
                    $blobs=count(array_filter($ci,fn($r)=>strtoupper($r['type'])==='BLOB'));
                    $total+=$rc; $td[]=['name'=>$t,'rows'=>$rc,'cols'=>count($ci),'blobs'=>$blobs];
                } catch (Throwable) {}
            }
            $s['total_rows']=$total; $s['tables']=$td;
            jout(['ok'=>true,'stats'=>$s]);

        case 'schema':
            $tbl=$_POST['table']??''; assertTbl($pdo,$tbl);
            $sql=$pdo->query("SELECT sql FROM sqlite_master WHERE name=".$pdo->quote($tbl))->fetchColumn();
            $idx=$pdo->query("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=".$pdo->quote($tbl)." AND sql IS NOT NULL")->fetchAll(PDO::FETCH_COLUMN);
            jout(['ok'=>true,'sql'=>$sql,'indexes'=>$idx]);

        default: jout(['ok'=>false,'error'=>'Unknown action']);
    }
}

$hasDb = !empty($_SESSION['db_path']) && file_exists($_SESSION['db_path']);
$dbName = htmlspecialchars($_SESSION['db_name']??'',ENT_QUOTES,'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SQLens</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07090e;--bg2:#0d1117;--bg3:#131923;--bg4:#1a2232;
  --bd:#1e2d42;--bd2:#253348;
  --tx:#c9d7e8;--tx2:#7a93b4;--tx3:#4a6080;
  --am:#f0a520;--am2:#c87d10;--amd:#f0a52018;
  --bl:#3b82f6;--bld:#3b82f612;
  --gn:#34d399;--gnd:#34d39912;
  --rd:#f87171;--rdd:#f8717112;
  --or:#fb923c;--ord:#fb923c12;
  --pu:#a78bfa;--pud:#a78bfa12;
  --mono:'JetBrains Mono',monospace;--ui:'Outfit',sans-serif;
  --r:8px;--r2:12px;--sh:0 8px 40px #00000070;
}
html,body{height:100%;background:var(--bg);color:var(--tx);font-family:var(--ui);font-size:14px;overflow:hidden}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:9px}
::selection{background:var(--amd);color:var(--am)}
#app{display:flex;height:100vh}
#sb{width:256px;min-width:256px;background:var(--bg2);border-right:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden;transition:width .25s,min-width .25s}
#sb.off{width:0;min-width:0}
.sbh{padding:15px 17px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:9px;background:linear-gradient(160deg,#101722,var(--bg2));flex-shrink:0}
.logo{width:29px;height:29px;border-radius:7px;background:linear-gradient(135deg,var(--am),var(--am2));display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;box-shadow:0 0 16px var(--amd)}
.lname{font-size:15px;font-weight:700;white-space:nowrap}.lver{font-size:10px;color:var(--tx3);font-family:var(--mono);margin-left:auto;white-space:nowrap}
.sbl{padding:11px 15px 5px;font-size:10px;font-weight:600;letter-spacing:1.4px;color:var(--tx3);text-transform:uppercase;white-space:nowrap}
#tlist{flex:1;overflow-y:auto;padding:3px 7px 10px}
.ti{display:flex;align-items:center;gap:7px;padding:8px 10px;border-radius:var(--r);cursor:pointer;transition:all .12s;margin-bottom:2px;border:1px solid transparent}
.ti:hover{background:var(--bg3);border-color:var(--bd)}.ti.on{background:var(--amd);border-color:#f0a52030;color:var(--am)}
.tin{flex:1;font-size:12.5px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tib{font-family:var(--mono);font-size:10px;color:var(--tx3);background:var(--bg4);padding:1px 6px;border-radius:99px;flex-shrink:0}
.ti.on .tib{background:#f0a52020;color:var(--am)}.vtag{font-size:9px;padding:1px 4px;background:var(--bld);color:var(--bl);border-radius:3px;font-family:var(--mono);flex-shrink:0}
.sbf{border-top:1px solid var(--bd);padding:9px 10px;flex-shrink:0;display:flex;flex-direction:column;gap:5px}
.sbb{width:100%;padding:8px 10px;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);color:var(--tx2);cursor:pointer;font-family:var(--ui);font-size:12px;display:flex;align-items:center;gap:7px;transition:all .12s;text-align:left}
.sbb:hover{background:var(--bg4);border-color:var(--bd2);color:var(--tx)}
#mn{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
#top{height:53px;min-height:53px;background:var(--bg2);border-bottom:1px solid var(--bd);display:flex;align-items:center;padding:0 15px;gap:9px}
.ib{width:30px;height:30px;background:transparent;border:1px solid var(--bd);border-radius:var(--r);color:var(--tx2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:13px;transition:all .12s;flex-shrink:0}
.ib:hover{background:var(--bg3);border-color:var(--bd2);color:var(--tx)}
#dbl{font-family:var(--mono);font-size:11px;color:var(--tx3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px}
#dbl span{color:var(--am);font-weight:500}
#sw{flex:1;position:relative;max-width:460px}
#gs{width:100%;padding:7px 32px 7px 31px;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);color:var(--tx);font-family:var(--ui);font-size:13px;outline:none;transition:all .18s}
#gs:focus{border-color:#f0a52050;box-shadow:0 0 0 3px var(--amd)}#gs::placeholder{color:var(--tx3)}
.sic{position:absolute;left:10px;top:50%;transform:translateY(-50%);font-size:13px;color:var(--tx3);pointer-events:none}
#sc{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--tx3);cursor:pointer;font-size:15px;display:none;padding:2px;line-height:1}
.acts{display:flex;align-items:center;gap:7px;margin-left:auto;flex-shrink:0}
.btn{padding:6px 12px;border-radius:var(--r);border:1px solid var(--bd);background:var(--bg3);color:var(--tx2);cursor:pointer;font-family:var(--ui);font-size:12px;font-weight:500;display:flex;align-items:center;gap:5px;transition:all .12s;white-space:nowrap}
.btn:hover{background:var(--bg4);border-color:var(--bd2);color:var(--tx)}.btn.am{background:var(--am);border-color:var(--am);color:#080c10;font-weight:700}.btn.am:hover{background:var(--am2)}
#ct{flex:1;overflow:hidden;position:relative}
#ups{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px}
#dz{width:100%;max-width:520px;padding:52px 36px;border:2px dashed var(--bd2);border-radius:14px;text-align:center;cursor:pointer;transition:all .22s;background:var(--bg2);position:relative;overflow:hidden}
#dz::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 50% 65%,var(--amd),transparent 68%);opacity:0;transition:opacity .3s;pointer-events:none}
#dz:hover::before,#dz.ov::before{opacity:1}#dz:hover,#dz.ov{border-color:#f0a52060;background:var(--bg3)}
.dzi{font-size:42px;margin-bottom:16px;display:block;opacity:.4}.dzh{font-size:18px;font-weight:600;margin-bottom:6px}.dzp{color:var(--tx2);font-size:13px;margin-bottom:18px}
.dzf{font-family:var(--mono);font-size:11px;color:var(--tx3);background:var(--bg);padding:4px 13px;border-radius:99px;border:1px solid var(--bd);display:inline-block;margin-bottom:20px}
#fi{display:none}
.ub{padding:10px 28px;background:var(--am);border:none;border-radius:var(--r);color:#080c10;font-family:var(--ui);font-size:13px;font-weight:700;cursor:pointer;transition:all .18s}
.ub:hover{background:var(--am2);transform:translateY(-1px);box-shadow:0 4px 16px var(--amd)}
#up{width:100%;max-width:520px;margin-top:16px;display:none}
.pt{height:3px;background:var(--bg4);border-radius:99px;overflow:hidden;margin-bottom:6px}
.pf{height:100%;width:0%;background:linear-gradient(90deg,var(--am2),var(--am));border-radius:99px;position:relative;overflow:hidden;transition:width .08s}
.pf::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,#fff3,transparent);animation:sh 1s infinite}
@keyframes sh{0%{transform:translateX(-100%)}100%{transform:translateX(200%)}}
.pi{display:flex;justify-content:space-between;font-size:11px;color:var(--tx2);font-family:var(--mono)}
#ue{margin-top:8px;color:var(--rd);font-size:12px;background:var(--rdd);padding:7px 12px;border-radius:var(--r);display:none;border-left:3px solid var(--rd)}
#ds{position:absolute;inset:0;display:flex;flex-direction:column;overflow:hidden}#ds.h{display:none}
#tb{padding:9px 15px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--bg2);flex-shrink:0}
#ttn{font-size:14px;font-weight:600;display:flex;align-items:center;gap:6px}.ttic{font-size:12px;color:var(--am)}
#rct{font-family:var(--mono);font-size:10px;color:var(--tx3);background:var(--bg4);padding:2px 8px;border-radius:99px}
.tg{flex:1}
#cf{padding:6px 10px;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);color:var(--tx);font-family:var(--ui);font-size:12px;outline:none;width:180px;transition:border-color .18s}
#cf:focus{border-color:#f0a52050}#cf::placeholder{color:var(--tx3)}
.ls{padding:5px 8px;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);color:var(--tx2);font-family:var(--mono);font-size:11px;outline:none;cursor:pointer}
#tw{flex:1;overflow:auto}
#dt{width:100%;border-collapse:collapse;font-size:13px}
#dt thead th{position:sticky;top:0;z-index:5;background:var(--bg3);padding:9px 12px;text-align:left;font-weight:600;font-size:11px;letter-spacing:.4px;color:var(--tx2);border-bottom:1px solid var(--bd);white-space:nowrap;cursor:pointer;user-select:none}
#dt thead th:hover{color:var(--tx);background:var(--bg4)}#dt thead th.sa::after{content:' ↑';color:var(--am)}#dt thead th.sd::after{content:' ↓';color:var(--am)}
#dt tbody tr{border-bottom:1px solid var(--bd);transition:background .08s}#dt tbody tr:hover{background:var(--bg3)}
#dt tbody td{padding:7px 12px;font-family:var(--mono);font-size:11.5px;max-width:270px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle}
.nv{color:var(--tx3)!important;font-style:italic}.nmv{color:#93c5fd}.bv{color:var(--gn)}
.enc{color:var(--pu)}.etag{font-size:9px;padding:1px 4px;background:var(--pud);color:var(--pu);border-radius:3px;font-family:var(--mono);margin-left:4px;vertical-align:middle}
.bbc{display:flex;align-items:center;gap:5px}.btag{font-size:9px;padding:2px 5px;background:var(--ord);color:var(--or);border-radius:3px;font-family:var(--mono);font-weight:600;flex-shrink:0}
.bhx{font-size:10px;color:var(--tx3);font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;max-width:100px}
.bdl{padding:2px 7px;background:var(--bg4);border:1px solid var(--bd);border-radius:4px;color:var(--tx2);font-size:10px;text-decoration:none;flex-shrink:0;transition:all .12s;white-space:nowrap}
.bdl:hover{background:var(--amd);border-color:#f0a52040;color:var(--am)}
.cp{cursor:pointer}.cp:hover{color:var(--am);text-decoration:underline}
#pg{padding:9px 15px;border-top:1px solid var(--bd);display:flex;align-items:center;gap:7px;flex-shrink:0;background:var(--bg2)}
.pgi{font-family:var(--mono);font-size:11px;color:var(--tx3)}.pgp{flex:1}
.pb{width:27px;height:27px;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);color:var(--tx2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:12px;transition:all .12s;font-family:var(--mono)}
.pb:hover:not(:disabled){background:var(--bg4);border-color:var(--bd2);color:var(--tx)}.pb:disabled{opacity:.25;cursor:not-allowed}.pb.cur{background:var(--am);border-color:var(--am);color:#080c10;font-weight:700}
#pgi{width:50px;padding:4px 6px;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);color:var(--tx);font-family:var(--mono);font-size:11px;text-align:center;outline:none}
#pgi:focus{border-color:#f0a52050}
#ss{position:absolute;inset:0;display:none;flex-direction:column;overflow:hidden}#ss.on{display:flex}
#sh{padding:11px 15px;border-bottom:1px solid var(--bd);background:var(--bg2);flex-shrink:0;display:flex;align-items:center;gap:9px;flex-wrap:wrap}
#sm{color:var(--tx2);font-size:13px}#sm strong{color:var(--am)}
.srx{display:flex;gap:6px;margin-left:auto}
#sr{flex:1;overflow-y:auto;padding:13px 15px;display:flex;flex-direction:column;gap:13px}
.srb{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r2);overflow:hidden}
.srbh{padding:10px 13px;background:var(--bg3);border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px}
.srtn{font-size:13px;font-weight:600}.srmc{font-family:var(--mono);font-size:10px;color:var(--am);background:var(--amd);padding:1px 7px;border-radius:99px}
.srw{overflow-x:auto}
.srt{width:100%;border-collapse:collapse;font-size:11.5px}
.srt th{padding:6px 10px;background:var(--bg3);text-align:left;font-size:10px;letter-spacing:.4px;font-weight:600;color:var(--tx3);border-bottom:1px solid var(--bd);white-space:nowrap}
.srt td{padding:6px 10px;border-bottom:1px solid var(--bd);font-family:var(--mono);font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.srt td.hl{color:var(--am);background:var(--amd)}.srt tr:last-child td{border-bottom:none}.srt tr:hover td{background:var(--bg3)}
#nr{text-align:center;padding:52px 16px;color:var(--tx3);display:none}.nri{font-size:34px;margin-bottom:9px}
.spn{display:none;text-align:center;padding:38px;color:var(--tx3)}
#stp{position:fixed;inset:0;background:#000000a0;z-index:100;display:none;align-items:center;justify-content:center;backdrop-filter:blur(5px)}
#stp.on{display:flex}
#stb{background:var(--bg2);border:1px solid var(--bd2);border-radius:var(--r2);width:min(720px,95vw);max-height:88vh;overflow-y:auto;box-shadow:var(--sh);padding:24px}
.stc{float:right;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);padding:5px 10px;color:var(--tx2);cursor:pointer;font-family:var(--ui);font-size:12px}
.stc:hover{background:var(--bg4);color:var(--tx)}.stt{font-size:16px;font-weight:700;display:flex;align-items:center;gap:8px;margin-bottom:3px}.sts{font-size:11px;color:var(--tx3);font-family:var(--mono);margin-bottom:18px}
.sgd{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:9px;margin-bottom:18px}
.sc{background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r2);padding:13px;position:relative;overflow:hidden}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--am),var(--am2));opacity:0;transition:opacity .18s}
.sc:hover::before{opacity:1}.scl{font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:var(--tx3);font-weight:600;margin-bottom:6px}
.scv{font-family:var(--mono);font-size:19px;font-weight:600;line-height:1}.scv.sm{font-size:13px}.scs{font-size:10px;color:var(--tx3);margin-top:3px;font-family:var(--mono)}
.sps{font-size:10px;font-weight:600;letter-spacing:1.4px;text-transform:uppercase;color:var(--tx3);margin:16px 0 7px}
.stlr{display:flex;align-items:center;gap:8px;padding:7px 11px;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);margin-bottom:4px}
.stln{flex:1;font-size:12.5px;font-weight:500}.stlbw{width:88px;height:3px;background:var(--bg4);border-radius:99px;overflow:hidden}
.stlb{height:100%;background:linear-gradient(90deg,var(--am2),var(--am));border-radius:99px}
.stlc{font-family:var(--mono);font-size:10px;color:var(--tx3)}.stlr2{font-family:var(--mono);font-size:11px;color:var(--tx2)}.obic{font-size:9px;color:var(--or);margin-left:4px}
#schm{position:fixed;inset:0;background:#000000a0;z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(5px)}
#schm.on{display:flex}#schb{background:var(--bg2);border:1px solid var(--bd2);border-radius:var(--r2);width:min(680px,95vw);max-height:80vh;box-shadow:var(--sh);overflow:hidden;display:flex;flex-direction:column}
.mh{padding:12px 16px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:7px}
.mt{font-size:13px;font-weight:600}.mx{margin-left:auto;background:none;border:none;color:var(--tx3);cursor:pointer;font-size:16px;line-height:1}
pre.sql{padding:18px;font-family:var(--mono);font-size:12px;line-height:1.8;color:var(--tx);background:var(--bg);overflow-x:auto;flex:1}
#clm{position:fixed;inset:0;background:#000000a0;z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(5px)}
#clm.on{display:flex}#clb{background:var(--bg2);border:1px solid var(--bd2);border-radius:var(--r2);width:min(580px,95vw);max-height:66vh;box-shadow:var(--sh);overflow:hidden;display:flex;flex-direction:column}
.cmh{padding:11px 15px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:6px}
.cmc{font-size:12px;font-weight:600;color:var(--am);font-family:var(--mono)}.cmx{margin-left:auto;background:none;border:none;color:var(--tx3);cursor:pointer;font-size:16px;line-height:1}
.cmb{padding:15px;overflow-y:auto;font-family:var(--mono);font-size:12.5px;white-space:pre-wrap;word-break:break-all;line-height:1.7}
#toast{position:fixed;bottom:20px;right:20px;z-index:999;background:var(--bg3);border:1px solid var(--bd2);border-radius:var(--r2);padding:10px 15px;font-size:13px;box-shadow:var(--sh);display:flex;align-items:center;gap:8px;transform:translateY(60px);opacity:0;transition:all .25s cubic-bezier(.4,0,.2,1);max-width:300px}
#toast.on{transform:none;opacity:1}#toast.ok{border-left:3px solid var(--gn)}#toast.er{border-left:3px solid var(--rd)}#toast.in{border-left:3px solid var(--bl)}
.spin{width:17px;height:17px;border-radius:50%;border:2px solid var(--bd);border-top-color:var(--am);animation:sp .6s linear infinite;display:inline-block}
@keyframes sp{to{transform:rotate(360deg)}}
.es{text-align:center;padding:52px 16px;color:var(--tx3)}.esi{font-size:30px;margin-bottom:9px;opacity:.4}.es p{font-size:13px}
#ndm{position:absolute;inset:0;background:var(--bg2);display:flex;align-items:center;justify-content:center;flex-direction:column;gap:9px;color:var(--tx3)}
#ndm .ni{font-size:40px;opacity:.22}
@keyframes fi{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}.fi{animation:fi .2s ease both}
</style>
</head>
<body>
<div id="app">
<nav id="sb">
  <div class="sbh"><div class="logo">🔍</div><span class="lname">SQLens</span><span class="lver">v2.0</span></div>
  <div class="sbl">Tables &amp; Views</div>
  <div id="tlist"><div class="es"><div class="esi">🗃️</div><p>No database loaded</p></div></div>
  <div class="sbf">
    <button class="sbb" onclick="openStats()">📊 &nbsp;Statistics</button>
    <button class="sbb" id="schbtn" style="display:none" onclick="showSchema()">📋 &nbsp;Schema</button>
  </div>
</nav>
<div id="mn">
  <div id="top">
    <button class="ib" onclick="document.getElementById('sb').classList.toggle('off')">☰</button>
    <div id="dbl">No database loaded</div>
    <div id="sw"><span class="sic">🔍</span><input id="gs" type="text" placeholder="Search all tables…" autocomplete="off" disabled><button id="sc" onclick="clearSrch()">✕</button></div>
    <div class="acts">
      <button class="btn am" onclick="document.getElementById('fi').click()">⬆ Upload DB</button>
      <button class="btn" id="clsbtn" onclick="closeDb()" style="display:none">✕ Close</button>
    </div>
  </div>
  <div id="ct">
    <div id="ups">
      <div id="dz" ondragover="e=>{e.preventDefault();this.classList.add('ov')}" ondragleave="document.getElementById('dz').classList.remove('ov')" ondrop="doDrop(event)">
        <span class="dzi">🗄️</span>
        <h2 class="dzh">Drop your SQLite database here</h2>
        <p class="dzp">Drag &amp; drop or click to browse</p>
        <div class="dzf">.db &nbsp;·&nbsp; .sqlite &nbsp;·&nbsp; .sqlite3 &nbsp;·&nbsp; .s3db</div><br>
        <label class="ub" for="fi">Choose File</label>
        <input type="file" id="fi" accept=".db,.sqlite,.sqlite3,.s3db" onchange="doUpload(this.files[0])">
      </div>
      <div id="up">
        <div class="pt"><div class="pf" id="pf"></div></div>
        <div class="pi"><span id="pl">Uploading…</span><span id="pp">0%</span></div>
        <div id="ue"></div>
      </div>
    </div>
    <div id="ds" class="h">
      <div id="tb">
        <div id="ttn"><span class="ttic">📋</span><span id="ttnm">—</span></div>
        <div id="rct"></div>
        <div class="tg"></div>
        <input id="cf" type="text" placeholder="Filter rows…" oninput="fltChange()" autocomplete="off">
        <select class="ls" id="lsel" onchange="limChange()">
          <option value="25">25/page</option><option value="50" selected>50/page</option><option value="100">100/page</option><option value="250">250/page</option><option value="500">500/page</option>
        </select>
        <button class="btn" onclick="expCSV('tbl')">📥 CSV</button>
        <button class="btn" onclick="expPDF()">📄 PDF</button>
      </div>
      <div id="tw">
        <div id="ndm"><span class="ni">👈</span><p>Select a table</p></div>
        <table id="dt" style="display:none"><thead id="dth"></thead><tbody id="dtb"></tbody></table>
      </div>
      <div id="pg" style="display:none">
        <span class="pgi" id="pginf"></span><div class="pgp"></div>
        <button class="pb" id="pgf" onclick="goP(1)">«</button>
        <button class="pb" id="pgpv" onclick="goP(S.page-1)">‹</button>
        <div id="pgps" style="display:flex;gap:3px"></div>
        <button class="pb" id="pgnx" onclick="goP(S.page+1)">›</button>
        <button class="pb" id="pgl" onclick="goP(S.totalPages)">»</button>
        <input type="number" id="pgi" min="1" placeholder="Go…" onkeydown="if(event.key==='Enter')goP(+this.value)">
      </div>
    </div>
    <div id="ss">
      <div id="sh"><div id="sm">Searching…</div><div class="srx" id="srx" style="display:none"><button class="btn" onclick="expCSV('srch')">📥 CSV</button><button class="btn" onclick="expSrchPDF()">📄 PDF</button></div></div>
      <div id="sr"><div class="spn" id="spn"><div class="spin"></div></div><div id="nr"><div class="nri">🔍</div><p>No results</p></div></div>
    </div>
  </div>
</div>
</div>

<div id="stp" onclick="if(event.target===this)this.classList.remove('on')">
  <div id="stb">
    <button class="stc" onclick="document.getElementById('stp').classList.remove('on')">✕ Close</button>
    <div class="stt">📊 Statistics</div><div class="sts" id="stfs">—</div>
    <div class="sgd" id="sgd"></div>
    <div class="sps">Table Breakdown</div><div id="stl"></div>
  </div>
</div>

<div id="schm" onclick="if(event.target===this)this.classList.remove('on')">
  <div id="schb">
    <div class="mh"><span class="mt">📋 Schema — <span id="schn"></span></span><button class="mx" onclick="document.getElementById('schm').classList.remove('on')">✕</button></div>
    <pre class="sql" id="schsql"></pre>
  </div>
</div>

<div id="clm" onclick="if(event.target===this)this.classList.remove('on')">
  <div id="clb">
    <div class="cmh"><span class="cmc" id="cmc"></span><button class="cmx" onclick="document.getElementById('clm').classList.remove('on')">✕</button></div>
    <div class="cmb" id="cmb"></div>
  </div>
</div>

<div id="toast"></div>

<script>
const CSRF='<?=addslashes($CSRF)?>';
const S={hasDb:<?=$hasDb?'true':'false'?>,dbName:'<?=addslashes($dbName)?>',table:null,page:1,totalPages:1,totalRows:0,sortCol:'',sortDir:'ASC',filter:'',limit:50,srchQ:'',cols:[],rows:[],_lt:null,_st:null};

document.addEventListener('DOMContentLoaded',()=>{
  if(S.hasDb){activateDb();loadTables();}
  document.getElementById('gs').addEventListener('input',onSrch);
});

function activateDb(){
  document.getElementById('ups').style.display='none';
  document.getElementById('ds').classList.remove('h');
  const gs=document.getElementById('gs'); gs.disabled=false;
  document.getElementById('clsbtn').style.display='';
  document.getElementById('dbl').innerHTML='Loaded: <span>'+esc(S.dbName)+'</span>';
}
function deactivateDb(){
  document.getElementById('ups').style.display='';
  document.getElementById('ds').classList.add('h');
  document.getElementById('ss').classList.remove('on');
  const gs=document.getElementById('gs'); gs.disabled=true; gs.value='';
  document.getElementById('sc').style.display='none';
  document.getElementById('clsbtn').style.display='none';
  document.getElementById('schbtn').style.display='none';
  document.getElementById('dbl').innerHTML='No database loaded';
  document.getElementById('tlist').innerHTML='<div class="es"><div class="esi">🗃️</div><p>No database loaded</p></div>';
  S.table=null;
}

async function loadTables(){
  const r=await api({action:'tables'}); if(!r.ok){toast(r.error,'er');return;}
  S.dbName=r.dbName;
  document.getElementById('dbl').innerHTML='Loaded: <span>'+esc(r.dbName)+'</span>';
  const el=document.getElementById('tlist');
  if(!r.tables.length){el.innerHTML='<div class="es"><div class="esi">🗄️</div><p>No tables</p></div>';return;}
  el.innerHTML=r.tables.map(t=>`<div class="ti fi" id="ti-${attr(t.name)}" onclick="selTable('${attr(t.name)}')">
    <span style="font-size:12px;opacity:.5">${t.type==='view'?'👁️':'📋'}</span>
    <span class="tin" title="${attr(t.name)}">${esc(t.name)}</span>
    ${t.type==='view'?'<span class="vtag">VIEW</span>':''}
    <span class="tib">${fmtN(t.rows)}</span></div>`).join('');
}

function selTable(n){
  document.getElementById('gs').value=''; document.getElementById('sc').style.display='none';
  document.getElementById('ss').classList.remove('on'); document.getElementById('ds').classList.remove('h');
  document.querySelectorAll('.ti').forEach(e=>e.classList.remove('on'));
  const el=document.getElementById('ti-'+n); if(el) el.classList.add('on');
  S.table=n; S.page=1; S.sortCol=''; S.sortDir='ASC'; S.filter='';
  document.getElementById('cf').value=''; document.getElementById('ttnm').textContent=n;
  document.getElementById('schbtn').style.display=''; loadTableData();
}

async function loadTableData(){
  if(!S.table) return;
  document.getElementById('dt').style.display=''; document.getElementById('ndm').style.display='none';
  document.getElementById('dtb').innerHTML='<tr><td colspan="99" style="text-align:center;padding:36px"><div class="spin" style="margin:0 auto"></div></td></tr>';
  document.getElementById('pg').style.display='none';
  const r=await api({action:'table_data',table:S.table,page:S.page,limit:S.limit,sort:S.sortCol,dir:S.sortDir,filter:S.filter});
  if(!r.ok){toast(r.error,'er');return;}
  S.cols=r.columns.map(c=>c.name); S.rows=r.rows; S.totalRows=r.total; S.totalPages=r.pages; S.page=r.page;
  document.getElementById('dth').innerHTML='<tr>'+r.columns.map(c=>{
    const ac=S.sortCol===c.name,cls=ac?(S.sortDir==='ASC'?'sa':'sd'):'';
    return `<th class="${cls}" onclick="sortBy('${attr(c.name)}')" title="${attr(c.type||'')}">${esc(c.name)}${c.pk?'<span style="color:var(--am);font-size:9px"> PK</span>':''}</th>`;
  }).join('')+'</tr>';
  document.getElementById('dtb').innerHTML=!r.rows.length
    ?`<tr><td colspan="${r.columns.length}" style="text-align:center;padding:36px;color:var(--tx3)">No rows</td></tr>`
    :r.rows.map(row=>'<tr>'+r.columns.map(c=>renderCell(c.name,row[c.name],row._rid,S.table)).join('')+'</tr>').join('');
  document.getElementById('rct').textContent=fmtN(r.total)+' rows';
  renderPag();
}

function renderCell(col,val,rid,tbl){
  if(val===null||val===undefined) return '<td class="nv">NULL</td>';
  if(typeof val==='object'&&val._blob){
    const dl=`?dl=1&t=${encodeURIComponent(tbl)}&c=${encodeURIComponent(col)}&r=${encodeURIComponent(rid||0)}&_t=${CSRF}`;
    const hx=val.hex?val.hex.match(/.{1,2}/g).join(' '):'';
    return `<td><div class="bbc"><span class="btag">BLOB</span><span class="bhx">${esc(hx)}</span><span style="font-family:var(--mono);font-size:10px;color:var(--tx3)">${fmtB(val.size)}</span><a href="${dl}" class="bdl" download title="${esc(val.mime)}">↓ Download</a></div></td>`;
  }
  if(typeof val==='object'&&val._enc){
    const s=String(val.v),d=s.length>70?s.slice(0,70)+'…':s,nm=s.length>70;
    return `<td class="enc${nm?' cp':''}" ${nm?`onclick="openCell('${attr(col)}','${attr(s)}')"`:''}>${esc(d)}<span class="etag">${esc(val._enc)}</span></td>`;
  }
  const s=String(val),isN=!isNaN(val)&&s.trim()!=='',cls=isN?'nmv':(s==='0'||s==='1'?'bv':''),nm=s.length>80,d=nm?s.slice(0,80)+'…':s;
  return `<td class="${cls}${nm?' cp':''}" ${nm?`onclick="openCell('${attr(col)}','${attr(s)}')"`:''}title="${attr(s)}">${esc(d)}</td>`;
}

function renderSCell(col,val,rid,tbl,q){
  if(val===null||val===undefined) return '<td class="nv">NULL</td>';
  if(typeof val==='object'&&val._blob){
    const dl=`?dl=1&t=${encodeURIComponent(tbl)}&c=${encodeURIComponent(col)}&r=${encodeURIComponent(rid||0)}&_t=${CSRF}`;
    return `<td><span class="btag">BLOB</span> <span style="font-size:10px;color:var(--tx3);font-family:var(--mono)">${fmtB(val.size)}</span> <a href="${dl}" class="bdl" download>↓</a></td>`;
  }
  if(typeof val==='object'&&val._enc){const s=String(val.v),d=s.length>50?s.slice(0,50)+'…':s,hl=s.toLowerCase().includes(q.toLowerCase());return `<td class="${hl?'hl':'enc'}">${esc(d)}<span class="etag">${esc(val._enc)}</span></td>`;}
  const s=String(val),d=s.length>55?s.slice(0,55)+'…':s,hl=s.toLowerCase().includes(q.toLowerCase());
  return `<td class="${hl?'hl':''}">${esc(d)}</td>`;
}

function renderPag(){
  const pg=document.getElementById('pg'); pg.style.display=S.totalRows>0?'':'none';
  const s=(S.page-1)*S.limit+1,e=Math.min(S.page*S.limit,S.totalRows);
  document.getElementById('pginf').textContent=`${fmtN(s)}–${fmtN(e)} of ${fmtN(S.totalRows)}`;
  ['pgf','pgpv'].forEach(id=>document.getElementById(id).disabled=S.page<=1);
  ['pgnx','pgl'].forEach(id=>document.getElementById(id).disabled=S.page>=S.totalPages);
  document.getElementById('pgi').max=S.totalPages;
  const tp=S.totalPages,cp=S.page,pages=[];
  if(tp<=7){for(let i=1;i<=tp;i++)pages.push(i);}
  else{pages.push(1);if(cp>3)pages.push('…');for(let i=Math.max(2,cp-1);i<=Math.min(tp-1,cp+1);i++)pages.push(i);if(cp<tp-2)pages.push('…');pages.push(tp);}
  document.getElementById('pgps').innerHTML=pages.map(p=>p==='…'?'<span style="color:var(--tx3);padding:0 3px">…</span>':`<button class="pb ${p===cp?'cur':''}" onclick="goP(${p})">${p}</button>`).join('');
}
function goP(n){n=Math.max(1,Math.min(S.totalPages,+n));if(n===S.page)return;S.page=n;loadTableData();}
function sortBy(c){S.sortCol===c?S.sortDir=S.sortDir==='ASC'?'DESC':'ASC':(S.sortCol=c,S.sortDir='ASC');S.page=1;loadTableData();}
function fltChange(){clearTimeout(S._lt);S.filter=document.getElementById('cf').value;S.page=1;S._lt=setTimeout(loadTableData,340);}
function limChange(){S.limit=+document.getElementById('lsel').value;S.page=1;loadTableData();}

function doDrop(e){e.preventDefault();document.getElementById('dz').classList.remove('ov');if(e.dataTransfer.files[0])doUpload(e.dataTransfer.files[0]);}
function doUpload(file){
  const pf=document.getElementById('pf'),pl=document.getElementById('pl'),pp=document.getElementById('pp'),pe=document.getElementById('ue'),pw=document.getElementById('up');
  pe.style.display='none';pw.style.display='block';pf.style.width='0%';pl.textContent='Uploading '+file.name+'…';pp.textContent='0%';
  const fd=new FormData(); fd.append('db_file',file); fd.append('_t',CSRF);
  const xhr=new XMLHttpRequest();
  xhr.upload.onprogress=e=>{if(e.lengthComputable){const p=Math.round(e.loaded/e.total*100);pf.style.width=p+'%';pp.textContent=p+'%';if(p===100)pl.textContent='Processing…';}};
  xhr.onload=()=>{try{const r=JSON.parse(xhr.responseText);if(r.ok){pf.style.width='100%';pl.textContent='✓ '+r.name;pp.textContent=fmtB(r.size);S.hasDb=true;S.dbName=r.name;setTimeout(()=>{activateDb();loadTables();pw.style.display='none';},500);}else upErr(r.error||'Upload failed');}catch{upErr('Server error');}};
  xhr.onerror=()=>upErr('Network error');
  xhr.open('POST',location.href); xhr.send(fd);
}
function upErr(m){const pe=document.getElementById('ue');pe.textContent='⚠ '+m;pe.style.display='block';document.getElementById('pf').style.width='0%';toast(m,'er');}

async function closeDb(){if(!confirm('Close database?'))return;await api({action:'close'});S.hasDb=false;deactivateDb();toast('Closed','in');}

function onSrch(e){
  const q=e.target.value.trim();document.getElementById('sc').style.display=q?'':'none';
  clearTimeout(S._st);if(!q){clearSrch();return;}S._st=setTimeout(()=>doSearch(q),360);
}
function clearSrch(){document.getElementById('gs').value='';document.getElementById('sc').style.display='none';document.getElementById('ss').classList.remove('on');if(S.table)document.getElementById('ds').classList.remove('h');S.srchQ='';}
async function doSearch(q){
  S.srchQ=q;document.getElementById('ss').classList.add('on');document.getElementById('ds').classList.add('h');
  document.getElementById('spn').style.display='block';document.getElementById('nr').style.display='none';document.getElementById('srx').style.display='none';
  document.getElementById('sm').innerHTML=`Searching for <strong>${esc(q)}</strong>…`;
  const cont=document.getElementById('sr');
  [...cont.children].forEach(c=>{if(c.id!=='spn'&&c.id!=='nr')c.remove();});
  const r=await api({action:'search',query:q});document.getElementById('spn').style.display='none';
  if(!r.ok){toast(r.error,'er');return;}
  const tot=r.results.reduce((s,rr)=>s+rr.count,0);
  if(!r.results.length){document.getElementById('nr').style.display='block';document.getElementById('sm').innerHTML=`No results for <strong>${esc(q)}</strong>`;return;}
  document.getElementById('sm').innerHTML=`<strong>${fmtN(tot)}</strong> row${tot!==1?'s':''} across <strong>${r.results.length}</strong> table${r.results.length!==1?'s':''} matching <strong>${esc(q)}</strong>`;
  document.getElementById('srx').style.display='';
  r.results.forEach(res=>{
    const blk=document.createElement('div');blk.className='srb fi';
    blk.innerHTML=`<div class="srbh"><span>📋</span><span class="srtn">${esc(res.table)}</span><span class="srmc">${fmtN(res.count)} match${res.count!==1?'es':''}</span><button class="btn" style="margin-left:auto;padding:4px 9px;font-size:11px" onclick="selTable('${attr(res.table)}')">Browse →</button></div>
    <div class="srw"><table class="srt"><thead><tr>${res.columns.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${res.rows.map(row=>'<tr>'+res.columns.map(c=>renderSCell(c,row[c],row._rid,res.table,q)).join('')+'</tr>').join('')}</tbody></table></div>`;
    cont.appendChild(blk);
  });
}

async function openStats(){
  document.getElementById('stp').classList.add('on');
  const r=await api({action:'stats'});if(!r.ok){toast(r.error,'er');return;}
  const s=r.stats;
  document.getElementById('stfs').textContent=s.file_name+' · '+fmtB(s.file_size);
  const cards=[
    {l:'SQLite',v:s.sqlite_version},{l:'Tables',v:fmtN(s.table_count)},{l:'Views',v:fmtN(s.view_count)},
    {l:'Indexes',v:fmtN(s.index_count)},{l:'Triggers',v:fmtN(s.trigger_count)},{l:'Total Rows',v:fmtN(s.total_rows)},
    {l:'DB Size',v:fmtB(s.db_bytes),sub:`${fmtN(s.page_count)} × ${fmtB(s.page_size)}`},
    {l:'Free Pages',v:fmtN(s.freelist)},{l:'Encoding',v:s.encoding,sm:1},
    {l:'Journal',v:s.journal,sm:1},{l:'Auto Vacuum',v:['None','Full','Incremental'][s.auto_vacuum]||s.auto_vacuum,sm:1},{l:'File',v:fmtB(s.file_size),sm:1},
  ];
  document.getElementById('sgd').innerHTML=cards.map(c=>`<div class="sc"><div class="scl">${c.l}</div><div class="scv ${c.sm?'sm':''}">${c.v}</div>${c.sub?`<div class="scs">${c.sub}</div>`:''}</div>`).join('');
  const mx=Math.max(...s.tables.map(t=>t.rows),1);
  document.getElementById('stl').innerHTML=s.tables.slice().sort((a,b)=>b.rows-a.rows).map(t=>`
    <div class="stlr"><span class="stln">${esc(t.name)}${t.blobs>0?`<span class="obic">BLOB×${t.blobs}</span>`:''}</span>
    <div class="stlbw"><div class="stlb" style="width:${Math.max(2,t.rows/mx*100)}%"></div></div>
    <span class="stlc">${t.cols} col${t.cols!==1?'s':''}</span><span class="stlr2">${fmtN(t.rows)} rows</span></div>`).join('')||'<p style="color:var(--tx3);font-size:13px">No tables</p>';
}

async function showSchema(){
  if(!S.table)return;
  const r=await api({action:'schema',table:S.table});if(!r.ok){toast(r.error,'er');return;}
  let txt=r.sql||'-- no schema';
  if(r.indexes&&r.indexes.length)txt+='\n\n-- Indexes\n'+r.indexes.join(';\n')+';';
  document.getElementById('schn').textContent=S.table;
  document.getElementById('schsql').textContent=txt;
  document.getElementById('schm').classList.add('on');
}

function openCell(col,val){document.getElementById('cmc').textContent=col;document.getElementById('cmb').textContent=val;document.getElementById('clm').classList.add('on');}

function flatVal(v){
  if(v===null||v===undefined)return'NULL';
  if(typeof v==='object'&&v._blob)return`[BLOB ${fmtB(v.size)}]`;
  if(typeof v==='object'&&v._enc)return v.v;
  return String(v);
}
function expCSV(mode){
  const u=new URL(location.href); u.searchParams.set('_t',CSRF);
  if(mode==='tbl'&&S.table){u.searchParams.set('export','csv');u.searchParams.set('table',S.table);if(S.filter)u.searchParams.set('filter',S.filter);}
  else if(mode==='srch'&&S.srchQ){u.searchParams.set('export','csv');u.searchParams.set('q',S.srchQ);}
  else return; window.open(u,'_blank');
}
function expPDF(){
  if(!S.table||!S.cols.length)return;
  const {jsPDF}=window.jspdf,doc=new jsPDF({orientation:'landscape',unit:'mm',format:'a4'});
  doc.setFont('helvetica','bold');doc.setFontSize(12);doc.text('SQLens: '+S.table,14,14);
  doc.setFont('helvetica','normal');doc.setFontSize(8);doc.setTextColor(120);
  doc.text('Exported '+new Date().toLocaleString()+(S.filter?'  Filter: '+S.filter:''),14,20);doc.setTextColor(0);
  doc.autoTable({head:[S.cols],body:S.rows.map(r=>S.cols.map(c=>flatVal(r[c]).slice(0,120))),startY:24,
    styles:{font:'helvetica',fontSize:7.5,cellPadding:2},
    headStyles:{fillColor:[13,17,23],textColor:[240,165,32],fontStyle:'bold'},
    alternateRowStyles:{fillColor:[245,247,250]},margin:{left:13,right:13}});
  doc.save('sqlens_'+S.table+'_'+ds()+'.pdf');toast('PDF exported','ok');
}
async function expSrchPDF(){
  if(!S.srchQ)return;
  const r=await api({action:'search',query:S.srchQ});
  if(!r.ok||!r.results.length){toast('No results','er');return;}
  const {jsPDF}=window.jspdf,doc=new jsPDF({orientation:'landscape',unit:'mm',format:'a4'});
  doc.setFont('helvetica','bold');doc.setFontSize(12);doc.text('SQLens Search: "'+S.srchQ+'"',14,13);
  doc.setFont('helvetica','normal');doc.setFontSize(8);doc.setTextColor(120);doc.text(new Date().toLocaleString(),14,19);doc.setTextColor(0);
  r.results.forEach((res,i)=>{
    if(i>0)doc.addPage();
    const sy=i===0?23:13;doc.setFont('helvetica','bold');doc.setFontSize(10);
    doc.text('Table: '+res.table+' ('+res.count+' matches)',14,sy);
    doc.autoTable({head:[res.columns],body:res.rows.map(row=>res.columns.map(c=>flatVal(row[c]).slice(0,80))),startY:sy+4,
      styles:{font:'helvetica',fontSize:7,cellPadding:2},
      headStyles:{fillColor:[13,17,23],textColor:[240,165,32],fontStyle:'bold'},
      alternateRowStyles:{fillColor:[245,247,250]},margin:{left:13,right:13}});
  });
  doc.save('sqlens_search_'+ds()+'.pdf');toast('PDF exported','ok');
}

async function api(body){
  try{const r=await fetch(location.href,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'XMLHttpRequest'},body:new URLSearchParams({...body,_t:CSRF})});return await r.json();}
  catch(e){return{ok:false,error:'Network: '+e.message};}
}
function esc(s){if(s==null)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function attr(s){if(s==null)return'';return String(s).replace(/'/g,'&#39;').replace(/"/g,'&quot;').replace(/[\n\r]/g,' ');}
function fmtN(n){return Number(n).toLocaleString();}
function fmtB(b){b=+b;if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(2)+' MB';return(b/1073741824).toFixed(2)+' GB';}
function ds(){return new Date().toISOString().slice(0,19).replace(/[T:]/g,'-');}
let _tt;function toast(m,t='in'){const el=document.getElementById('toast');el.textContent=(t==='ok'?'✓ ':t==='er'?'⚠ ':'ℹ ')+m;el.className='on '+t;clearTimeout(_tt);_tt=setTimeout(()=>el.className='',3400);}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){document.querySelectorAll('.on[id]').forEach(el=>{if(['stp','schm','clm'].includes(el.id))el.classList.remove('on');});if(S.srchQ)clearSrch();}});
</script>
</body>
</html>
