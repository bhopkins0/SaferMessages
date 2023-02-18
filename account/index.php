<?php
session_start();
include('../resources/functions.php');
if (!isLoggedIn()) {
    header("Location: /index.php");
    die();
}

if (isPost() && isset($_POST["message"])) {
    if (!isset($_POST["toUser"])) {
        $errorMsg = "Error: Invalid recipient username";
    } elseif (!isset($_POST["msgPassword"])) {
        $errorMsg = "Error: You must enter a password";
    } else {
        $messageResult = sendMessage($_POST["message"], $_POST["msgPassword"], $_POST["toUser"]);
        if ($messageResult == "Success")
            $successMsg = "Message sent successfully";
        else
            $errorMsg = $messageResult;
    }
}

if (isPost() && $_POST["action"] == "decrypt_msg") {
    if (!isset($_POST["dlk"])) {
        $msgOpError = "Error: Potential Security Violation";
    } elseif (!isset($_POST["msg_id"])) {
        $msgOpError = "Error: Message does not exist";
    } elseif (!isset($_POST["dmsg_password"])) {
        $msgOpError = "Error: Incorrect password for decrypting message";
    } elseif (decryptionSecurityCheck($_POST["msg_id"],$_POST["dlk"], $_POST["dmsg_password"]) != "Success") {
        $msgOpError = decryptionSecurityCheck($_POST["msg_id"], $_POST["dlk"], $_POST["dmsg_password"]);
    } else {
        $msgInfo = getMessageInfo($_POST["msg_id"], $_POST["dmsg_password"]);
        $msgOpSuccess = decryptMessage($_POST["msg_id"], $msgInfo["message"], $_POST["dmsg_password"], $msgInfo["message_iv"],$msgInfo["message_tag"]);
    }
}

if (isPost() && $_POST["action"] == "delete_msg") {
    if (!isset($_POST["dlk"])) {
        $msgOpError = "Error: Potential Security Violation";
    } elseif (!isset($_POST["msg_id"])) {
        $msgOpError = "Error: Message does not exist";
    }  elseif (deleteMessage($_POST["msg_id"],$_POST["dlk"]) != "Success") {
        $msgOpError = deleteMessage($_POST["msg_id"],$_POST["dlk"]);
    } else {
        $deletedMessage = true;
    }
}


?>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="/resources/bootstrap.min.css" rel="stylesheet">
    <style>
        html,
        body {
            height: 100%;
        }

        body {
            background-color: #f5f5f5;
        }

    </style>
</head>
<body>
<div class="container-fluid p-5 bg-dark text-white">
    <div class="container my-5">
        <h1>SaferMessages <small class="text-muted">Beta</small></h1>
        <p class="lead">Your username is <?php echo $_SESSION["msg_username"]; ?>. </p>
    </div>
</div>

<div class="container">
    <?php
    if (isset($msgOpError))
        echo '<div class="alert alert-danger mt-4 text-center" role="alert"><h2>'.$msgOpError.'</h2></div>';
    if (isset($msgOpSuccess))
        echo '<div class="alert alert-success mt-4 text-center"><h2>Message successfully decrypted.</h2></div><div class="alert alert-dark mt-2 text-break" role="alert"><p class="lead">From:</p><p>'.$msgInfo["user_from"].'</p><hr><p class="lead">Message:</p>'.htmlspecialchars($msgOpSuccess).'</p><form method="post"><input type="hidden" id="msg_id" name="msg_id" value="'.$_POST["msg_id"].'"><input type="hidden" id="dlk" name="dlk" value="'.$_SESSION["msg_dl_key"].'"><input type="hidden" id="action" name="action" value="delete_msg"><input class="btn btn-outline-danger w-100" type="submit" value="Delete Message"></form></div>';
    if ($deletedMessage)
        echo '<div class="alert alert-success mt-4 text-center" role="alert"><h2>Message successfully deleted.</h2></p></div>';
    ?>
    <div class="row align-items-md-stretch my-5 mt-5">
        <div class="col-md-6">
            <div class="h-100 p-5 bg-light border rounded-3 mt-2">
                <h2>Messagebox</h2>

                <hr>
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                        <tr>
                            <th scope="col">#</th>
                            <th scope="col">From</th>
                            <th scope="col"></th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php getTableOfMessages(); ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="h-100 p-5 bg-light border rounded-3 mt-2">
                <h2>Send a Message</h2>
                <?php
                if (isset($errorMsg))
                    echo '<div class="alert alert-danger" role="alert">'.$errorMsg.'</div>';
                if (isset($successMsg))
                    echo '<div class="alert alert-success" role="alert">'.$successMsg.'</div>';


                ?>
                <hr>
                <form method="POST">
                    <div class="mb-3">
                        <label for="toUser" class="form-label">To:</label>
                        <input type="text" class="form-control" id="toUser" name="toUser" placeholder="Username">
                    </div>
                    <div class="mb-3">
                        <label for="msgPassword" class="form-label">Password to encrypt the message:</label>
                        <input type="password" class="form-control" id="msgPassword" name="msgPassword" placeholder="Password">
                    </div>

                    <div class="mb-3">
                        <label for="message" class="form-label">Message:</label>
                        <textarea class="form-control" id="message" name="message" rows="5"></textarea>
                    </div>
                    <div class="d-grid gap-2 mt-3">
                        <button type="submit" class="btn btn-primary">Submit</button>
                    </div>
                </form>
                <p class="text-muted">The user you are sending the message to will need to know the message password to decrypt it.</p>
            </div>
        </div>
    </div>
    <?php
    $key = $_SESSION["msg_dl_key"];
    echo <<<EOL
<div class="p-4 mt-2 d-flex align-items-center justify-content-center">
<form method="post" action="logout.php" class="col-sm-9 col-md-6 col-lg-8">
<input type="hidden" id="lo" name="lo" value="$key">
<div class="d-grid mx-auto pb-3">
<input class="btn btn-outline-danger" type="submit" value="Logout">
</div>
</form>
</div>
EOL;
    ?>

</div>

</body>
</html>
