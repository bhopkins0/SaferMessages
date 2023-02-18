<?php
session_start();
include('resources/functions.php');
if (isPost() && isset($_POST["pw"]) && isset($_POST["rpw"])) {
    if (preliminarySignUpCheck($_POST["pw"], $_POST["rpw"]) != "Success") {
        $errorMsg = preliminarySignUpCheck($_POST["pw"], $_POST["rpw"]);
    } elseif (createAccount($_POST["pw"])) {
        accountLogin($_SESSION["msg_username"], $_POST["pw"]);
    } else {
        $errorMsg = "Error: Account creation was not successful";
    }
}
?>

<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="/resources/bootstrap.min.css" rel="stylesheet">
    <link href="/resources/signup.css" rel="stylesheet">
</head>
<body>
<main class="form-signup w-100 m-auto">
    <form action="/signup.php" method="post">
        <h1>Sign up</h1>
        <?php
        if (isset($errorMsg)) {
            echo <<<EOL
            <div class="alert alert-danger" role="alert">$errorMsg</div>
            EOL;
        } else {
            echo "<p class='text-muted'>Your username will be generated for you</p>";
        }
        ?>
        <div class="form-floating">
            <input type="password" class="form-control" id="pw" name="pw" placeholder="Password">
            <label for="pw">Password</label>
        </div>
        <div class="form-floating">
            <input type="password" class="form-control" id="rpw" name="rpw" placeholder="Repeat Password">
            <label for="rpw">Repeat Password</label>
        </div>
        <button type="submit" class="w-100 btn btn-lg btn-primary">Sign up</button>
        <p class="text-end text-muted">Or log in to your account <a href="/index.php">here</a>!</p>
    </form>
</main>

</body>
</html>
