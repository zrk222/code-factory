<?php
function search_logs($keyword) {
    $command = "cat /var/log/app.log";
    $command .= " | grep '$keyword'";
    // ruleid: php.parameter-shell-command
    return shell_exec($command);
}

function search_logs_safe($keyword) {
    $command = "cat /var/log/app.log | grep " . escapeshellarg($keyword);
    // ok: php.parameter-shell-command
    return shell_exec($command);
}

function run_wrapper($cmd) {
    // ok: php.parameter-shell-command
    return shell_exec($cmd);
}

class ListFormatHelper {
    public function rows($connection, array $contentType) {
        $query = sprintf('SELECT id FROM content WHERE content_type = "%s"', $contentType['slug']);
        // ruleid: php.parameter-sql-text
        return $connection->fetchAllAssociative($query);
    }

    public function rowsBound($connection, array $contentType) {
        // ok: php.parameter-sql-text
        return $connection->fetchAllAssociative('SELECT id FROM content WHERE content_type = :t', ['t' => $contentType['slug']]);
    }

    public function rowsCast($connection, $id) {
        // ok: php.parameter-sql-text
        return $connection->query('SELECT id FROM content WHERE id = ' . (int) $id);
    }
}
