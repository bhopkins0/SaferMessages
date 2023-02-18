<?php
session_start();

function startMySQL(): bool|mysqli
{
    $mysqlHostname = "";
    $mysqlUser = "";
    $mysqlPass = '';
    $mysqlDB = "";

    return mysqli_connect($mysqlHostname, $mysqlUser, $mysqlPass, $mysqlDB);
}

function isPost()
{
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        return true;
    }
}

function preliminaryLoginCheck($password): bool
{
    if (strlen($password) < 8 || strlen($password) > 64) {
        return false;
    }
    return true;
}

function preliminarySignUpCheck($password, $rpassword): string
{
    if (strlen($password) < 8 || strlen($password) > 64) {
        return "Error: Password must be between 8 characters and 64 characters";
    } elseif ($password != $rpassword) {
        return "Error: Passwords do not match";
    }
    return "Success";
}

function isUserUsed($user)
{
    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "SELECT acc_id FROM users WHERE username=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("s", $user);
    $stmt->execute();
    $userFound = (bool)$stmt->get_result()->fetch_row();
    if ($userFound) {
        return true;
    } else {
        return false;
    }
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);
}

function createAccount($password)
{
    $mysqlConn = startMySQL();
    $username = bin2hex(random_bytes(12));
    if (isUserUsed($username)) {
        header("Location: /signup.php");
        die();
    }
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    if ($stmt = mysqli_prepare($mysqlConn, $sql)) {
        mysqli_stmt_bind_param($stmt, "ss", $username, $hashedPassword);
        mysqli_stmt_execute($stmt);
        $_SESSION["msg_username"] = $username;
        $_SESSION["msg_dl_key"] = random_int(1, 1000000);
        return true;
    } else {
        return false;
    }
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);
}

function accountLogin($username, $password)
{
    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "SELECT acc_id, username, password FROM users WHERE username=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $retrievedAccount = $result->fetch_assoc();
    if (password_verify($password, $retrievedAccount["password"])) {
        $_SESSION["msg_username"] = $username;
        $_SESSION["msg_acc_id"] = $retrievedAccount["acc_id"];
        $_SESSION["msg_dl_key"] = random_int(1, 1000000);
        header("Location: /account/index.php");
        return true;
    } else {
        return false;
    }
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);
}

function isLoggedIn(): bool
{
    if (isset($_SESSION["msg_acc_id"])) {
        return true;
    }
    return false;
}

function encryptMessage($message, $messagePassword) {
        $ivlen = openssl_cipher_iv_length("aes-128-gcm");
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext = openssl_encrypt($message, "aes-128-gcm", $messagePassword, $options=0, $iv ,$tag);
        $iv_encoded = base64_encode($iv);
        $tag_encoded = base64_encode($tag);
        $hashedPassword = password_hash($messagePassword, PASSWORD_BCRYPT);

        return array($ciphertext, $hashedPassword, $iv_encoded, $tag_encoded);
}

function sendMessage($message, $messagePassword, $userTo) {
    $userFrom = $_SESSION["msg_username"];
    if (strlen($messagePassword) < 8 || strlen($messagePassword) > 64)
        return "Error: Password must be between 8 characters and 64 characters";
    if (!isUserUsed($userTo))
        return "Error: User not found";
    if (strlen($message) > 500 || strlen($message) < 1)
        return "Error: Message must be 1 to 500 characters";
    $encryptedMessageInfo = encryptMessage($message, $messagePassword);
    addMessageToDatabase($userFrom, $userTo, $encryptedMessageInfo[1], $encryptedMessageInfo[2], $encryptedMessageInfo[3], $encryptedMessageInfo[0]);
    return "Success";




}
function addMessageToDatabase($userFrom, $userTo, $messagePassword, $initializationVector, $macTag, $message) {

    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "INSERT INTO messages (user_from, user_to, message_password, message_iv, message_tag, message) VALUES (?, ?, ?, ?, ?, ?)";
    if ($stmt = mysqli_prepare($mysqlConn, $sql)) {
        mysqli_stmt_bind_param($stmt, "ssssss", $userFrom, $userTo, $messagePassword, $initializationVector, $macTag, $message);
        mysqli_stmt_execute($stmt);
        return true;
    } else {
        return false;
    }
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);

}

function verifyMessagePassword($message_id, $password)
{
    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }

    $sql = "SELECT message_password FROM messages WHERE message_id=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("i", $message_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $retrievedMessage = $result->fetch_assoc();

    if (password_verify($password, $retrievedMessage["message_password"]))
        return true;
    else
        return false;

    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);
}

function getTableOfMessages(): void
{
    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "SELECT message_id, user_to, user_from FROM messages WHERE user_to=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("s", $_SESSION["msg_username"]);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $incvar = 1;
        while ($row = $result->fetch_assoc()) {
            echo "<tr><td>$incvar</td><td>" . $row["user_from"] . '</td><td><form method="post"><input type="hidden" id="msg_id" name="msg_id" value="'.$row["message_id"].'"><input type="hidden" id="dlk" name="dlk" value="'.$_SESSION["msg_dl_key"].'"><input type="hidden" id="action" name="action" value="decrypt_msg"><div class="row"><div class="col-sm mb-1"><input type="password" class="form-control" name="dmsg_password" id="dmsg_password" placeholder="Password" aria-label="Message Password"></div><div class="col-sm"><input class="btn btn-primary w-100" type="submit" value="Open"></div></div></form></td></tr>'."\n";
            $incvar++;
        }
    }
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);
}



function decryptionSecurityCheck($messageID, $dlk, $messagePassword) {

    // Preliminary password check

    if (strlen($messagePassword) < 8 || strlen($messagePassword) > 64)
        return "Error: Incorrect password for decrypting message";

    // Verify message is intended to be for appropriate user

    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "SELECT user_to FROM messages WHERE message_id=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("i", $messageID);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows == 0) {
        return "Error: Potential Security Violation";
    }
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);

    // Prevent potential cross-site attack

    if ($dlk != $_SESSION["msg_dl_key"])
        return "Error: Potential Security Violation";

    // Check decryption password

    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "SELECT message_password FROM messages WHERE message_id=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("i", $messageID);
    $stmt->execute();
    $result = $stmt->get_result();
    $retrievedMessage = $result->fetch_assoc();
    if (!password_verify($messagePassword, $retrievedMessage["message_password"])) {
        return "Error: Message password is incorrect";
    }
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);

    // Else return success

    return "Success";


}


function deleteMessage($messageID, $dlk) {

    // Verify message is intended to be for appropriate user

    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "SELECT user_to FROM messages WHERE message_id=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("i", $messageID);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows == 0) {
        return "Error: Potential Security Violation";
    }
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);

    // Prevent potential cross-site attack

    if ($dlk != $_SESSION["msg_dl_key"])
        return "Error: Potential Security Violation";

    // Delete message from database

    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "DELETE FROM messages WHERE message_id=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("i", $messageID);
    $stmt->execute();
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);

    // Else return success

    return "Success";


}


function getMessageInfo($messageID, $messagePassword) {
    $mysqlConn = startMySQL();
    if ($mysqlConn === false) {
        die("ERROR");
    }
    $sql = "SELECT user_from, message, message_iv, message_tag FROM messages WHERE message_id=?";
    $stmt = $mysqlConn->prepare($sql);
    $stmt->bind_param("i", $messageID);
    $stmt->execute();
    $result = $stmt->get_result();
    $retrievedMessage = $result->fetch_assoc();
    mysqli_stmt_close($stmt);
    mysqli_close($mysqlConn);
    return $retrievedMessage;
}


function decryptMessage($messageID, $message, $messagePassword, $initializationVector, $tag) {

    // Implement password verification with database
    $iv_decoded = base64_decode($initializationVector);
    $tag_decoded = base64_decode($tag);
    if (!verifyMessagePassword($messageID, $messagePassword))
        return "Error: Incorrect password";
    return openssl_decrypt($message, "aes-128-gcm", $messagePassword, $options=0, $iv_decoded, $tag_decoded);
}

function logoutButton(): void
{
    session_destroy();
    $_SESSION["msg_username"] = "";
    $_SESSION["msg_dl_key"] = "";
    $_SESSION["msg_acc_id"] = "";
    header("Location: /index.php");
    die();
}


