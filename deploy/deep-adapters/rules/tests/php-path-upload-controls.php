<?php

function installPlugin(\ZipArchive $zip): void
{
    $manifest = json_decode($zip->getFromName('plugin.json'), true);
    // ruleid: php.archive-path-traversal
    $zip->extractTo(PLUGIN_ROOT . '/' . $manifest['name']);
}

function installPluginChecked(\ZipArchive $zip): void
{
    $manifest = json_decode($zip->getFromName('plugin.json'), true);
    // ok: php.archive-path-traversal
    $zip->extractTo(PLUGIN_ROOT . '/' . basename($manifest['name']));
}

function storeUpload($file, string $dir): void
{
    $name = $file->getClientOriginalName();
    // ruleid: php.request-path-traversal
    move_uploaded_file($file->getPathname(), $dir . '/' . $name);
}

function storeUploadSafe($file, string $dir): void
{
    $name = basename($file->getClientOriginalName());
    // ok: php.request-path-traversal
    move_uploaded_file($file->getPathname(), $dir . '/' . $name);
}
