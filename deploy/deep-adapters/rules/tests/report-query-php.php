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

function decodedRecordWithMisspelledOption(string $filename) {
    // ruleid: php.request-unsafe-deserialization
    return unserialize((string) file_get_contents($filename), [
        'allowedClasses' => [RecordFixture::class],
    ]);
}

function decodedRecordWithRecognizedOption(string $filename) {
    // ok: php.request-unsafe-deserialization
    return unserialize((string) file_get_contents($filename), [
        'allowed_classes' => [RecordFixture::class],
    ]);
}

function paginationFromOptions(array $parameters) {
    // ruleid: php.parameter-sql-text
    return 'LIMIT ' . $parameters['limit'];
}

function paginationWithIntegerConversion(array $parameters) {
    // ok: php.parameter-sql-text
    return 'LIMIT ' . (int) $parameters['limit'];
}
