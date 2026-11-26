<?php
use Symfony\Component\HttpFoundation\Request;

function direct_source() {
    $value = $_GET['item'];
    // ruleid: php.request-sql-injection
    return ' AND item = ' . $value;
}

function framework_source(Request $request, $db) {
    $value = $request->get('item');
    // ruleid: php.request-sql-injection
    $comparison = '(item = ' . $value . ')';
    // ok: php.request-sql-injection
    $bound = '(item = ' . $db->quote($value) . ')';
    // ok: php.request-sql-injection
    $url = '/items?id=' . $value;
    return [$comparison, $bound, $url];
}

function other_accessor($reader) {
    $value = $reader->get('item');
    // ok: php.request-sql-injection
    return ' AND item = ' . $value;
}
