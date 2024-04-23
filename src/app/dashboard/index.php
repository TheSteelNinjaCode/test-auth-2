<?php

use Lib\Auth\Auth;

$auth = new Auth();
$userName = $auth->getPayload()['name'];

?>

<p>welcome <?= $userName ?></p>