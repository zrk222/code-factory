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
        // ruleid: php.parameter-sql-text
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

class ReactionStore {
    public function removeFor($store, string $user) {
        // ruleid: php.parameter-sql-text
        return $store->delete('reactions', 'value LIKE \'%user":"' . $user . '"%\'');
    }

    public function removeForBound($store, string $user) {
        // ok: php.parameter-sql-text
        return $store->delete('reactions', ['user' => $user]);
    }
}

class QuotedIdentifierStore {
    public function byField($db, string $entity, string $field, $id) {
        // ok: php.parameter-sql-text
        return $db->query("SELECT * FROM `$entity` WHERE `{$field}` = ?", [$id]);
    }

    public function byFieldConcat($db, string $field, $id) {
        // ok: php.parameter-sql-text
        $sql = 'SELECT * FROM items WHERE `' . $field . '` = ?';
        // ok: php.parameter-sql-text
        return $db->executeQuery($sql, [$id]);
    }

    public function byValue($db, string $entity, string $name) {
        // ruleid: php.parameter-sql-text
        return $db->query("SELECT * FROM `$entity` WHERE name = '$name'");
    }

    public function byValueConcat($db, string $name) {
        // ruleid: php.parameter-sql-text
        $sql = 'SELECT * FROM items WHERE `name` = \'' . $name . '\'';
        // ruleid: php.parameter-sql-text
        return $db->executeQuery($sql);
    }
}
