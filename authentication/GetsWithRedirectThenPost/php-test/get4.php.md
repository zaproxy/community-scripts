<?php
    // get4: 
    // - check presence and value of get2cookie and get3cookie
    // - outputs "this is get4"

    // compute the cookie for the current minute and display an authent error if the cookie presented by the client is older
    $get2ExpectedCookie =  "get2cookie" . date('Y-m-d_H-i');
    $get3ExpectedCookie =  "get3cookie" . date('Y-m-d_H-i');

   if (!isset($_COOKIE['get2cookie'])) {
        error_log("get4.php: get2cookie not set");
    }
    else{
        $get2FoundCookie = $_COOKIE['get2cookie'];
        error_log("get4.php: get2cookie=$get2FoundCookie");
        if (!isset($_COOKIE['get3cookie'])) {
            error_log("get4.php: get3cookie not set");
        }
        else {
            $get3FoundCookie = $_COOKIE['get3cookie'];
            error_log("get4.php: get3FoundCookie=$get3FoundCookie");

            if ($get2ExpectedCookie !== $get2FoundCookie || $get3ExpectedCookie !== $get3FoundCookie){
                echo "Authentification error<br>";
                echo "Expected: <br>";
                echo " $get2ExpectedCookie $get3ExpectedCookie<br>";
                echo "Found: <br>";
                echo " $get2FoundCookie $get3FoundCookie<br>";
            }
        }
    }

?>
    <p>this is get4</p>
    <form action="/test/post.php" method="post">
      <input type="hidden" name="scope" value="all">
      <button class="button redB" style="margin: 5px;">Login</button>
    </form>


