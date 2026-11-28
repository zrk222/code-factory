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

    // Backtick quotes cover only the operand between them, not later operands of the chain.
    public function indexes($db, string $table, array $indices) {
        foreach ($indices as $key => $columnList) {
            // ok: php.parameter-sql-text
            $db->executeQuery('ALTER TABLE `' . $table . '` DROP INDEX `' . $key . '`;');
            // ruleid: php.parameter-sql-text
            $db->executeQuery('ALTER TABLE `' . $table . '` ADD INDEX `' . $key . '` (' . $columnList . ');');
            // ruleid: php.parameter-sql-text
            $db->executeQuery('ALTER TABLE `' . $key . '` ADD INDEX (' . $columnList . ') `' . $key . '`');
        }
    }

    public function mappedColumns($db, array $fields, array $ids) {
        $quoted = implode(', ', array_map(fn (string $f) => $db->quoteIdentifier($f), $fields));
        // ok: php.parameter-sql-text
        $db->executeQuery('CREATE INDEX i ON items (' . $quoted . ')');
        $callable = implode(', ', array_map([$db, 'quoteIdentifier'], $fields));
        // ok: php.parameter-sql-text
        $db->executeQuery('CREATE INDEX j ON items (' . $callable . ')');
        $numbers = implode(',', array_map('intval', $ids));
        // ok: php.parameter-sql-text
        $db->executeQuery('CREATE INDEX k ON items (' . $numbers . ')');
        $trimmed = implode(', ', array_map(fn ($f) => trim($f), $fields));
        // ruleid: php.parameter-sql-text
        $db->executeQuery('CREATE INDEX l ON items (' . $trimmed . ')');
    }
}

class ReportAdapter {
    public function columns($db, $configuration) {
        $sql = $this->buildQueryString($configuration);
        if (!preg_match('/(ALTER|CREATE|DROP|DELETE) /i', $sql)) {
            // ruleid: php.parameter-sql-text
            return $db->fetchAssociative($sql . ' LIMIT 0,1');
        }
        return [];
    }

    public function update($db, array $values) {
        // ok: php.parameter-sql-text
        return $db->query('UPDATE items SET ' . $this->buildArray('UPDATE', $values));
    }
}

class AdodbStyleDriver extends ADOConnection {
    public function columns($table) {
        // ruleid: php.parameter-sql-text
        return $this->Execute("PRAGMA table_info('$table')");
    }

    public function rename($table, $column, $value) {
        // ok: php.parameter-sql-text
        $sql = "UPDATE $table SET $column = " . (int) $value . " WHERE $column = " . $this->qstr($value);
        return $this->Execute($sql);
    }

    public function rows($limit) {
        $sql = 'SELECT * FROM items LIMIT ' . $limit;
        // ruleid: php.parameter-sql-text
        return $this->GetAll($sql);
    }

    public function dropTable($table) {
        // ok: php.parameter-sql-text
        return $this->Execute("DROP TABLE $table");
    }

    public function bound($table) {
        // ok: php.parameter-sql-text
        return $this->execute('PRAGMA table_info(?)', [$table]);
    }

    public function statement($stmt, array $values) {
        // ok: php.parameter-sql-text
        return $stmt->execute($values);
    }
}

class VcsCommandRunner {
    public function cloneRepo($process, $url, $path) {
        // ok: php.parameter-sql-text
        $this->process->execute(['git', 'clone', '--', $url, $path]);
        // ok: php.parameter-sql-text
        return $process->execute('git clone -- ' . $url);
    }
}

class RecyclebinListing extends AdminController {
    public function listAction(Request $request) {
        $db = Db::get();
        $filters = json_decode($request->get('filter'), true);
        foreach ($filters as $filter) {
            $value = $filter['value'];
            $operator = '=';
            // ruleid: php.request-sql-injection
            $condition = '`name` ' . $operator . " '" . $value . "' ";
            // ok: php.request-sql-injection
            $quoted = '`name` ' . $operator . ' ' . $db->quote($value);
        }
        $storeId = $request->query->get('storeId');
        // ruleid: php.request-sql-injection
        $store = '(storeId = ' . $storeId . ')';
        // ok: php.request-sql-injection
        $cast = '(storeId = ' . (int) $storeId . ')';
        $ids = $request->request->all('ids');
        // ok: php.request-sql-injection
        $list = 'id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')';
        $title = $request->get('title');
        // ok: php.request-sql-injection
        $markup = "<span class='" . $title . "' id='t'>";
        return [$condition, $quoted, $store, $cast, $list, $markup];
    }
}


function readNumericRecordIds($database, array $userIds) {
    $values = implode(',', array_map('intval', $userIds));
    $query = sprintf('SELECT name FROM records WHERE id IN (%s)', $values);
    // ok: php.parameter-sql-text
    return $database->query($query);
}

function readTrimmedRecordIds($database, array $userIds) {
    $values = implode(',', array_map('trim', $userIds));
    $query = sprintf('SELECT name FROM records WHERE id IN (%s)', $values);
    // ruleid: php.parameter-sql-text
    return $database->query($query);
}

class UnquotedNumericFieldReview {
 public $active;
 public $other;
 function save($role) {
 $this->active = $this->active ? $this->active : 0;
 $sql = "UPDATE ".DATABASE_PREFIX."report SET";
 // ruleid: php.parameter-sql-text
 $sql .= ", active = ".$this->active;
 $value = $this->driver->query($sql);
 }
}

class UnquotedNumericFieldCast {
 public $active;
 public $other;
 function save($role) {
 $this->active = $this->active ? $this->active : 0;
 $sql = "UPDATE ".DATABASE_PREFIX."report SET";
 // ok: php.parameter-sql-text
 $sql .= ", active = ".(int) $this->active;
 $value = $this->driver->query($sql);
 }
}
