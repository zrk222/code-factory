<?php
// framework sample: one hit per framework rule.

// --- WordPress ---
$id = $_GET['id'];
$rows = $wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE ID = $id");   // WP-002

echo $_GET['name'];                                    // WP-001
echo esc_html($_GET['safe']);                          // safe, must NOT fire

wp_redirect($_GET['next']);                            // WP-003

if (isset($_POST['save'])) {
    update_option('my_opt', $_POST['value']);          // WP-004 + WP-005
}

if (current_user_can('manage_options')) {
    update_option('ok_opt', 'x');                      // safe cap, still WP-004 in range
}

$url = add_query_arg('page', $_GET['page'], $base);    // WP-006
$st  = maybe_unserialize($_GET['state']);              // WP-007

// --- Laravel ---
$q = DB::raw($_GET['col']);                            // LAR-001
$r = $db->whereRaw("x = " . $_POST['v']);              // LAR-001
echo $_POST['bio'];                                    // LAR-002
return redirect()->to($_GET['url']);                   // LAR-003
$guarded = [];                                          // LAR-004
$dsn = env('DB_HOST', 'localhost');                    // LAR-005

// --- Symfony ---
$res = $conn->executeQuery("SELECT * FROM t WHERE a = " . $_GET['a']);  // SYM-001
echo $twig->render('t', ['v' => $_GET['v']|raw]);      // SYM-002
$obj = unserialize($request->get('payload'));          // SYM-003
$env = $_GET['APP_ENV'];                               // SYM-004
