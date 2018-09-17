<?php
    // get2: sets get2cookie and redirects to get3
    $cookie2="get2cookie" . date('Y-m-d_H-i');
    setcookie("get2cookie", $cookie2 );
    error_log("get2.php: setting get2cookie:$cookie2");
    header("Location: /test/get3.php");
?>
