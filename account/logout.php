<?php
session_start();
include('../resources/functions.php');
if (!isLoggedIn()) {
    header("Location: /index.php");
    die();
}
if ($_POST["lo"] == $_SESSION["msg_dl_key"])
    logoutButton();
else
    header("Location: index.php");
