<?php
function unpack_zip($file, $dest) {
    $zip = new ZipArchive();
    $zip->open($file);
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = $zip->getNameIndex($i);
        $target = $dest . '/' . $name;
        // ruleid: php.archive-path-traversal
        file_put_contents($target, $zip->getFromIndex($i));
    }
}

function unpack_zip_base($file, $dest) {
    $zip = new ZipArchive();
    $zip->open($file);
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = basename($zip->getNameIndex($i));
        // ok: php.archive-path-traversal
        file_put_contents($dest . '/' . $name, $zip->getFromIndex($i));
    }
}

function greet() {
    $name = $_GET['name'];
    // ruleid: php.request-html-injection
    echo "<h1>Hello " . $name . "</h1>";
    // ok: php.request-html-injection
    echo "<h1>Hello " . htmlspecialchars($name, ENT_QUOTES) . "</h1>";
}
