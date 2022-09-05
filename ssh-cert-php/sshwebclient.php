<?php
header("content-type: text/plain");
$filename = $_GET['token'];
$attrs = json_decode(file_get_contents($filename), 1);
print_r($attrs);
