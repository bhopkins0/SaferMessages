<?php
session_start();
include('resources/functions.php');
if (isPost() && isset($_POST["pw"]) && isset($_POST["user"])) {
    if (!preliminaryLoginCheck($_POST["user"], $_POST["pw"]) || !isUserUsed($_POST["user"])) {
        $errorMsg = "Error: Incorrect Username or Password";
    } elseif (!accountLogin($_POST["user"], $_POST["pw"])) {
        $errorMsg = "Error: Incorrect Username or Password";
    }
}
?>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="/resources/bootstrap.min.css" rel="stylesheet">
    <link href="/resources/index.css" rel="stylesheet">

</head>
<body>
<main class="form-signin w-100 m-auto">
    <form action="/index.php" method="POST">
        <h1>Login</h1>
        <?php
        if (isset($errorMsg)) {
            echo <<<EOL
            <div class="alert alert-danger" role="alert">$errorMsg</div>
            EOL;
        }
        ?>
        <div class="form-floating">
            <input type="text" class="form-control" id="user" name="user" placeholder="Username will be auto-generated.">
            <label for="user">Username</label>
        </div>
        <div class="form-floating">
            <input type="password" class="form-control" id="pw" name="pw" placeholder="Password">
            <label for="pw">Password</label>
        </div>
        <button type="submit" class="w-100 btn btn-lg btn-primary">Sign in</button>
        <p class="text-end text-muted">Or create an account <a href="signup.php">here</a>!</p>
    </form>
</main>

</body>
</html>
