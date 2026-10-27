<?php
// Native static fixtures only. Never execute this file.
function command_controls($obj) {
    // ruleid: php.request-command-injection
    system($_GET['cmd']);
    $cmd = 'tool ' . trim($_POST['arg']);
    // ruleid: php.request-command-injection
    exec($cmd);
    // ruleid: php.request-command-injection
    shell_exec(htmlspecialchars($_REQUEST['cmd']));
    // ok: php.request-command-injection
    system('fixed-command');
    // ok: php.request-command-injection
    $obj->exec($_GET['cmd']);
    $cmd = $_GET['cmd']; $cmd = 'fixed-command';
    // ok: php.request-command-injection
    exec($cmd);
}
function sql_controls($db) {
    // ruleid: php.request-sql-injection
    mysqli_query($db, $_GET['sql']);
    $sql = 'SELECT * FROM t WHERE id=' . trim($_COOKIE['id']);
    // ruleid: php.request-sql-injection
    mysqli_prepare($db, $sql);
    // ok: php.request-sql-injection
    pg_query_params($db, 'SELECT * FROM t WHERE id=$1', [$_POST['id']]);
    // ok: php.request-sql-injection
    $db->query($_GET['sql']);
}
function path_controls($obj) {
    // ruleid: php.request-path-traversal
    file_get_contents($_GET['path']);
    $path = '/data/' . trim($_POST['path']);
    // ruleid: php.request-path-traversal
    fopen($path, 'r');
    // ok: php.request-path-traversal
    file_put_contents('/fixed/path', $_REQUEST['content']);
    // ok: php.request-path-traversal
    $obj->readfile($_GET['path']);
}
function inclusion_controls($obj) {
    // ruleid: php.request-file-inclusion
    include $_GET['template'];
    $path = '/templates/' . trim($_POST['template']);
    // ruleid: php.request-file-inclusion
    require_once $path;
    // ok: php.request-file-inclusion
    require 'fixed.php';
    // Sink names in strings and comments must not match.
    $text = 'include $_GET[template]';
}
function deserialization_controls($obj) {
    // ruleid: php.request-unsafe-deserialization
    unserialize($_COOKIE['state']);
    $state = base64_decode($_POST['state']);
    // ruleid: php.request-unsafe-deserialization
    unserialize($state, ['allowed_classes' => false]);
    // ok: php.request-unsafe-deserialization
    unserialize('a:0:{}');
    // ok: php.request-unsafe-deserialization
    $obj->unserialize($_GET['state']);
}

// Static syntax fixtures; never execute.
function named_controls($db, $obj) {
    // ruleid: php.request-command-injection
    \system(command: $_GET['cmd']);
    // ruleid: php.request-command-injection
    exec(command: $_POST['cmd']);
    // ruleid: php.request-command-injection
    \shell_exec(command: $_REQUEST['cmd']);
    // ruleid: php.request-command-injection
    passthru(result_code: $code, command: $_COOKIE['cmd']);
    // ruleid: php.request-command-injection
    \popen(mode: 'r', command: $_GET['cmd']);
    // ruleid: php.request-sql-injection
    \mysqli_query(mysql: $db, query: $_GET['sql']);
    // ruleid: php.request-sql-injection
    mysqli_multi_query(query: $_POST['sql'], mysql: $db);
    // ruleid: php.request-sql-injection
    \mysqli_prepare($db, query: $_GET['sql']);
    // ruleid: php.request-sql-injection
    pg_query(query: $_GET['sql'], connection: $db);
    // ruleid: php.request-sql-injection
    \pg_query_params($db, query: $_GET['sql'], params: []);
    // ruleid: php.request-path-traversal
    \file_get_contents(filename: $_GET['path']);
    // ruleid: php.request-path-traversal
    fopen(mode: 'r', filename: $_POST['path']);
    // ruleid: php.request-path-traversal
    \readfile(use_include_path: false, filename: $_GET['path']);
    // ruleid: php.request-path-traversal
    file_put_contents(data: 'fixed', filename: $_GET['path']);
    // ruleid: php.request-unsafe-deserialization
    \unserialize(options: ['allowed_classes' => false], data: $_GET['blob']);
    // ok: php.request-sql-injection
    \pg_query_params($db, query: 'SELECT $1', params: [$_GET['id']]);
    // ok: php.request-sql-injection
    \mysqli_query(query: 'SELECT 1', mysql: $_GET['not_sql']);
    // ok: php.request-path-traversal
    \file_put_contents(data: $_POST['content'], filename: '/fixed');
    // ok: php.request-path-traversal
    \fopen(filename: '/fixed', mode: $_POST['mode']);
    // ok: php.request-unsafe-deserialization
    \unserialize(data: 'a:0:{}', options: $_GET['options']);
    // ok: php.request-command-injection
    \popen(command: 'fixed', mode: $_GET['mode']);
    // ok: php.request-command-injection
    $obj->exec(command: $_GET['cmd']);
    // ruleid: php.request-command-injection
    system($_GET['cmd'], result_code: $code);
    // ruleid: php.request-command-injection
    \exec($_GET['cmd'], output: $output);
    // ruleid: php.request-command-injection
    shell_exec(command: $_GET['cmd']);
    // ruleid: php.request-command-injection
    \passthru($_GET['cmd'], result_code: $code);
    // ruleid: php.request-command-injection
    popen($_GET['cmd'], mode: 'r');
    // ruleid: php.request-sql-injection
    mysqli_query($db, $_GET['sql'], result_mode: 0);
    // ruleid: php.request-sql-injection
    \mysqli_multi_query($db, query: $_GET['sql']);
    // ruleid: php.request-sql-injection
    mysqli_prepare(query: $_GET['sql'], mysql: $db);
    // ruleid: php.request-sql-injection
    \pg_query($db, query: $_GET['sql']);
    // ruleid: php.request-sql-injection
    pg_query_params(params: [], connection: $db, query: $_GET['sql']);
    // ruleid: php.request-sql-injection
    \pg_query(connection: $_GET['sql']);
    // ruleid: php.request-sql-injection
    pg_query_params(connection: $_GET['sql'], query: []);
    // ruleid: php.request-sql-injection
    \pg_query_params($_GET['sql'], query: []);
    // ruleid: php.request-path-traversal
    file_get_contents($_GET['path'], use_include_path: false);
    // ruleid: php.request-path-traversal
    \fopen($_GET['path'], mode: 'r');
    // ruleid: php.request-path-traversal
    readfile(filename: $_GET['path']);
    // ruleid: php.request-path-traversal
    \file_put_contents($_GET['path'], data: 'fixed');
    // ruleid: php.request-unsafe-deserialization
    unserialize($_GET['blob'], options: ['allowed_classes' => false]);
    // ok: php.request-sql-injection
    pg_query_params(connection: 'SELECT $1', query: [$_GET['value']]);
    // ok: php.request-sql-injection
    \pg_query_params('SELECT $1', query: [$_GET['value']]);
    // ok: php.request-command-injection
    system(result_code: $code, command: 'fixed');
    // ok: php.request-command-injection
    \exec(output: $output, command: 'fixed');
    // ok: php.request-command-injection
    passthru(command: 'fixed', result_code: $code);
    // ok: php.request-sql-injection
    \mysqli_multi_query(mysql: $_GET['not_sql'], query: 'SELECT 1');
    // ok: php.request-sql-injection
    mysqli_prepare(query: 'SELECT 1', mysql: $_GET['not_sql']);
    // ok: php.request-sql-injection
    \pg_query(query: 'SELECT 1', connection: $_GET['not_sql']);
    // ok: php.request-path-traversal
    file_get_contents(filename: '/fixed', context: $_GET['context']);
    // ok: php.request-path-traversal
    \readfile(filename: '/fixed', context: $_GET['context']);
    // ok: php.request-command-injection
    shell_exec(command: 'fixed');
}
