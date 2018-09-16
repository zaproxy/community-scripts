<?php
    echo "this is only a test<br>";
    // compute the cookie for the current minute and display an authent error if the cookie presented by the client is older
    $get2ExpectedCookie =  "get2cookie" . date('Y-m-d_H-i');
    $get3ExpectedCookie =  "get3cookie" . date('Y-m-d_H-i');
    $postExpectedCookie = "postcookie" . date('Y-m-d_H-i');
    $get2FoundCookie ="";
    $get3FoundCookie ="";
    $postFoundCookie ="";
    if (isset($_COOKIE['get2cookie'])) {
        $get2FoundCookie = $_COOKIE['get2cookie'];
        error_log("test.php: get2cookie=$get2FoundCookie");
    }
    else{
        error_log("test.php: get2cookie not set");
    }
    if (isset($_COOKIE['get3cookie'])) {
        $get3FoundCookie = $_COOKIE['get3cookie'];
        error_log("test.php: get3FoundCookie=$get3FoundCookie");
    }
    else{
        error_log("test.php: get3cookie not set");
    }
    if (isset($_COOKIE['postcookie'])) {
        $postFoundCookie = $_COOKIE['postcookie'];
        error_log("test.php: postcookie=$postFoundCookie");
    }
    else{
        error_log("test.php: postcookie not set");
    }
    
    if ($get2ExpectedCookie !== $get2FoundCookie || $get3ExpectedCookie !== $get3FoundCookie || $postExpectedCookie !== $postFoundCookie){
        echo "Authentification error<br>";
        echo "Expected: <br>";
        echo " $get2ExpectedCookie $get3ExpectedCookie $postExpectedCookie<br>";
        echo "Found: <br>";
        echo " $get2FoundCookie $get3FoundCookie $postFoundCookie<br>";
    }

?>
