<?php
// phprt sample: every high-severity class on purpose.
// include $_GET['page']  <-- in a comment, must NOT fire

$page = $_GET['page'];
include $page . '.php';                                   // RCE-001

eval($_POST['code']);                                     // RCE-002

call_user_func($_GET['action']);                          // RCE-003

system('ls ' . $_GET['dir']);                             // RCE-004

$data = unserialize(base64_decode($_COOKIE['state']));    // RCE-007

$body = file_get_contents($_GET['file']);                 // FILE-001
file_put_contents($_POST['target'], $body);               // FILE-001

$id = $_GET['id'];
$res = $db->query("SELECT * FROM users WHERE id = " . $id);  // SQL-001
$name = $_POST['name'];
$res2 = $db->query("SELECT * FROM users WHERE name = '{$_POST['name']}'"); // SQL-002
$sql = "SELECT * FROM t ORDER BY " . $_GET['sort'];        // SQL-003

echo $_GET['q'];                                          // XSS-001
echo htmlspecialchars($_GET['safe'], ENT_QUOTES);         // must NOT fire

$hash = md5($password);                                   // AUTH-002
if ($stored == $token) { }                                // AUTH-001
$reset = mt_rand();                                       // AUTH-003
setcookie('sid', $sid);                                   // AUTH-005

$api_key = 'sk_live_hardcoded_123456';                    // CRYPT-001
$enc = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $k, $p, MCRYPT_MODE_ECB); // CRYPT-002

$ch = curl_init();
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);          // CRYPT-004

ini_set('display_errors', 1);                             // HARD-001
chmod($dir, 0777);                                        // HARD-005
extract($_GET);                                           // HARD-003
?>
<input value="<?php echo $_GET['v']; ?>">                <!-- XSS-002 -->
<?php
// --- safe controls ---
$stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?');
$stmt->execute([(int) $_GET['id']]);
if (hash_equals($known, $given)) { }
$out = password_hash($pw, PASSWORD_DEFAULT);
$r = random_int(1, 1000);
$f = fopen($safePath, 'r');
