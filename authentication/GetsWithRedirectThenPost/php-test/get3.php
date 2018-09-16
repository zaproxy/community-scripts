<?php
    // get3: 
    // - check presence and value of get2cookie
    // - sets get3cookie
    // - redirects to get4

    // compute the cookie for the current minute and display an authent error if the cookie presented by the client is not present or older
    $get2ExpectedCookie =  "get2cookie" . date('Y-m-d_H-i');

    if (!isset($_COOKIE['get2cookie'])) {
        error_log("get3.php: get2cookie not set");
    }
    else{
        $get2FoundCookie = $_COOKIE['get2cookie'];
        error_log("get3.php: get2cookie=$get2FoundCookie");

        if ($get2ExpectedCookie !== $get2FoundCookie){
            echo "Authentification error<br>";
            echo "Expected: <br>";
            echo " $get2ExpectedCookie<br>";
            echo "Found: <br>";
            echo " $get2FoundCookie<br>";
        }
        else{
            $cookie3="get3cookie" . date('Y-m-d_H-i');
            setcookie("get3cookie", $cookie3 );
            error_log("get3.php: setting get3cookie:$cookie3");
            header("Location: /test/get4.php");
        }
    }
?>
