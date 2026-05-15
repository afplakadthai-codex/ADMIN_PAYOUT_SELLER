<?php
/**
 * Seller payout administration.
 *
 * Security notes:
 * - All mutations are POST-only and require a CSRF token.
 * - Payout rejection is delegated exclusively to bv_seller_balance_reject_payout().
 * - Mark-paid is superadmin/owner-only and requires a payment reference.
 * - Admin balance adjustments are delegated exclusively to bv_seller_balance_admin_adjust().
 * - Pending releases always re-read the current pending balance server-side.
 */

$guardFiles = [
    __DIR__ . '/_guard.php',
    __DIR__ . '/admin_auth.php',
    dirname(__DIR__) . '/includes/admin_auth.php',
    dirname(__DIR__) . '/includes/auth_admin.php',
];

foreach ($guardFiles as $guardFile) {
    if (is_file($guardFile)) {
        require_once $guardFile;
    }
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$sellerBalanceHelper = dirname(__DIR__) . '/includes/seller_balance.php';
if (is_file($sellerBalanceHelper)) {
    require_once $sellerBalanceHelper;
}
$sellerBalanceHelperAvailable = is_file($sellerBalanceHelper);

if (!function_exists('h')) {
    function h($value)
    {
        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('money_fmt')) {
    function money_fmt($amount, $currency = 'USD')
    {
        $amount = (float) $amount;
        $currency = strtoupper((string) $currency ?: 'USD');
        return $currency . ' ' . number_format($amount, 2, '.', ',');
    }
}

if (!function_exists('bv_seller_payouts_db')) {
    function bv_seller_payouts_db()
    {
        foreach (['pdo', 'db', 'conn', 'mysqli'] as $name) {
            if (isset($GLOBALS[$name]) && $GLOBALS[$name]) {
                return $GLOBALS[$name];
            }
        }

        return null;
    }
}

if (!function_exists('bv_seller_payouts_is_pdo')) {
    function bv_seller_payouts_is_pdo($db)
    {
        return $db instanceof PDO;
    }
}

if (!function_exists('bv_seller_payouts_is_mysqli')) {
    function bv_seller_payouts_is_mysqli($db)
    {
        return $db instanceof mysqli;
    }
}

if (!function_exists('bv_seller_payouts_fetch_all')) {
    function bv_seller_payouts_fetch_all($sql, array $params = [])
    {
        $db = bv_seller_payouts_db();
        if (!$db) {
            return [];
        }

        if (bv_seller_payouts_is_pdo($db)) {
            $stmt = $db->prepare($sql);
            $stmt->execute($params);
            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
        }

        if (bv_seller_payouts_is_mysqli($db)) {
            $stmt = $db->prepare($sql);
            if (!$stmt) {
                return [];
            }
            if ($params) {
                $types = '';
                foreach ($params as $param) {
                    $types .= is_int($param) ? 'i' : (is_float($param) ? 'd' : 's');
                }
                $stmt->bind_param($types, ...$params);
            }
            $stmt->execute();
            $result = $stmt->get_result();
            return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
        }

        return [];
    }
}

if (!function_exists('bv_seller_payouts_fetch_one')) {
    function bv_seller_payouts_fetch_one($sql, array $params = [])
    {
        $rows = bv_seller_payouts_fetch_all($sql, $params);
        return $rows[0] ?? null;
    }
}

if (!function_exists('table_exists')) {
    function table_exists($table)
    {
        $table = (string) $table;
        if ($table === '') {
            return false;
        }

        $row = bv_seller_payouts_fetch_one('SHOW TABLES LIKE ?', [$table]);
        return (bool) $row;
    }
}

if (!function_exists('column_exists')) {
    function column_exists($table, $column)
    {
        $table = (string) $table;
        $column = (string) $column;
        if ($table === '' || $column === '') {
            return false;
        }

        $row = bv_seller_payouts_fetch_one('SHOW COLUMNS FROM `' . str_replace('`', '``', $table) . '` LIKE ?', [$column]);
        return (bool) $row;
    }
}

if (!function_exists('seller_label')) {
    function seller_label($seller)
    {
        if (is_array($seller)) {
            foreach (['seller_name', 'name', 'business_name', 'store_name', 'email', 'seller_id', 'id'] as $key) {
                if (isset($seller[$key]) && $seller[$key] !== '') {
                    return (string) $seller[$key];
                }
            }
        }

        return 'Seller';
    }
}

if (!function_exists('status_badge_class')) {
    function status_badge_class($status)
    {
        $status = strtolower((string) $status);
        if (in_array($status, ['approved', 'paid', 'completed', 'success'], true)) {
            return 'badge-success';
        }
        if (in_array($status, ['rejected', 'failed', 'cancelled', 'canceled'], true)) {
            return 'badge-danger';
        }
        if (in_array($status, ['pending', 'requested'], true)) {
            return 'badge-warning';
        }

        return 'badge-secondary';
    }
}

if (!function_exists('bv_seller_payouts_admin_role')) {
    function bv_seller_payouts_admin_role()
    {
        foreach (['admin_role', 'role', 'user_role'] as $key) {
            if (!empty($_SESSION[$key])) {
                return strtolower((string) $_SESSION[$key]);
            }
        }

        if (!empty($_SESSION['admin']) && is_array($_SESSION['admin'])) {
            foreach (['role', 'admin_role', 'type'] as $key) {
                if (!empty($_SESSION['admin'][$key])) {
                    return strtolower((string) $_SESSION['admin'][$key]);
                }
            }
        }

        return '';
    }
}

if (!function_exists('bv_seller_payouts_current_admin_id')) {
    function bv_seller_payouts_current_admin_id()
    {
        foreach (['admin_id', 'user_id', 'id'] as $key) {
            if (!empty($_SESSION[$key])) {
                return (int) $_SESSION[$key];
            }
        }

        if (!empty($_SESSION['admin']) && is_array($_SESSION['admin'])) {
            foreach (['id', 'admin_id', 'user_id'] as $key) {
                if (!empty($_SESSION['admin'][$key])) {
                    return (int) $_SESSION['admin'][$key];
                }
            }
        }

        return 0;
    }
}

if (!function_exists('bv_seller_payouts_is_authorized_admin')) {
    function bv_seller_payouts_is_authorized_admin()
    {
        $role = bv_seller_payouts_admin_role();
        if (in_array($role, ['superadmin', 'owner', 'admin'], true)) {
            return true;
        }

        return !empty($_SESSION['admin_logged_in']) || !empty($_SESSION['is_admin']) || !empty($_SESSION['admin']);
    }
}

if (!function_exists('bv_seller_payouts_is_owner')) {
    function bv_seller_payouts_is_owner()
    {
        return in_array(bv_seller_payouts_admin_role(), ['superadmin', 'owner'], true);
    }
}

if (!bv_seller_payouts_is_authorized_admin()) {
    http_response_code(403);
    echo 'Forbidden';
    exit;
}

if (empty($_SESSION['seller_payouts_csrf'])) {
    $_SESSION['seller_payouts_csrf'] = bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['seller_payouts_csrf'];
$messages = $_SESSION['seller_payouts_flash']['messages'] ?? [];
$errors = $_SESSION['seller_payouts_flash']['errors'] ?? [];
unset($_SESSION['seller_payouts_flash']);


if (!function_exists('bv_seller_payouts_flash')) {
    function bv_seller_payouts_flash($type, $message)
    {
        $type = $type === 'error' ? 'errors' : 'messages';
        if (!isset($_SESSION['seller_payouts_flash'][$type]) || !is_array($_SESSION['seller_payouts_flash'][$type])) {
            $_SESSION['seller_payouts_flash'][$type] = [];
        }
        $_SESSION['seller_payouts_flash'][$type][] = (string) $message;
    }
}

if (!function_exists('bv_seller_payouts_redirect')) {
    function bv_seller_payouts_redirect()
    {
        header('Location: seller_payouts.php', true, 303);
        exit;
    }
}


if (!function_exists('bv_seller_payouts_require_csrf')) {
    function bv_seller_payouts_require_csrf()
    {
        $token = $_POST['csrf_token'] ?? '';
        if (!is_string($token) || !hash_equals($_SESSION['seller_payouts_csrf'] ?? '', $token)) {
            throw new RuntimeException('Invalid CSRF token.');
        }
    }
}

if (!function_exists('bv_seller_payouts_balance_value')) {
    function bv_seller_payouts_balance_value($balance, array $keys, $default = 0.0)
    {
        if (is_array($balance)) {
            foreach ($keys as $key) {
                if (array_key_exists($key, $balance) && is_numeric($balance[$key])) {
                    return (float) $balance[$key];
                }
            }
        } elseif (is_object($balance)) {
            foreach ($keys as $key) {
                if (isset($balance->{$key}) && is_numeric($balance->{$key})) {
                    return (float) $balance->{$key};
                }
            }
        }

        return (float) $default;
    }
}

if (!function_exists('bv_seller_payouts_read_balance')) {
    function bv_seller_payouts_read_balance($sellerId)
    {
        $sellerId = (int) $sellerId;
        if ($sellerId <= 0) {
           return [
                'available' => 0.0,
                'pending' => 0.0,
                'locked' => 0.0,
                'paid_out' => 0.0,
                'total' => 0.0,
            ];
 }

        if (!function_exists('bv_seller_balance_get')) {
            throw new RuntimeException('Seller balance source-of-truth helper is unavailable.');
        }

        $balance = bv_seller_balance_get($sellerId);
        return [
            'available' => bv_seller_payouts_balance_value($balance, ['available', 'available_balance', 'balance', 'current_balance']),
            'pending' => max(0.0, bv_seller_payouts_balance_value($balance, ['pending', 'pending_balance', 'pending_amount'])),
            'locked' => bv_seller_payouts_balance_value($balance, ['locked', 'locked_balance', 'held', 'hold_balance']),
            'paid_out' => bv_seller_payouts_balance_value($balance, ['paid_out', 'paidout', 'paid_out_balance', 'total_paid_out', 'payouts_paid']),
            'total' => bv_seller_payouts_balance_value($balance, ['total', 'total_balance', 'lifetime_total']),
        ];
    }
} 

if (!function_exists('bv_seller_payouts_read_pending_balance')) {
    function bv_seller_payouts_read_pending_balance($sellerId)
    {
        $balance = bv_seller_payouts_read_balance($sellerId);
        return max(0.0, (float) ($balance['pending'] ?? 0.0));
    }
}

if (!function_exists('bv_seller_payouts_release_pending_balance')) {
    function bv_seller_payouts_release_pending_balance($sellerId, $amount)
    {
        if (!function_exists('bv_seller_balance_release_pending')) {
            throw new RuntimeException('Pending balance release helper is unavailable.');
        }

        return bv_seller_balance_release_pending((int) $sellerId, (float) $amount, bv_seller_payouts_current_admin_id());
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        bv_seller_payouts_require_csrf();
        $action = (string) ($_POST['action'] ?? '');


        if (!$sellerBalanceHelperAvailable) {
            throw new RuntimeException('Seller balance helper is missing; payout actions are disabled.');
        }
		
		
        if ($action === 'approve_request') {
            if (!function_exists('bv_seller_balance_approve_payout')) {
                throw new RuntimeException('Payout approval helper is unavailable.');
            }

            $requestId = (int) ($_POST['request_id'] ?? 0);
            if ($requestId <= 0) {
                throw new RuntimeException('Invalid payout request.');
            }

            bv_seller_balance_approve_payout($requestId, bv_seller_payouts_current_admin_id());
            bv_seller_payouts_flash('message', 'Payout request approved.');
        } elseif ($action === 'reject_request') {
            if (!function_exists('bv_seller_balance_reject_payout')) {
                throw new RuntimeException('Payout rejection helper is unavailable.');
            }

            $requestId = (int) ($_POST['request_id'] ?? 0);
            $adminNote = trim((string) ($_POST['admin_note'] ?? ''));
            if ($requestId <= 0) {
                throw new RuntimeException('Invalid payout request.');
            }
            if ($adminNote === '') {
                throw new RuntimeException('Admin note is required to reject a payout request.');
            }

            bv_seller_balance_reject_payout($requestId, $adminNote, bv_seller_payouts_current_admin_id());
            bv_seller_payouts_flash('message', 'Payout request rejected.'); 
        } elseif ($action === 'mark_paid') {
            if (!bv_seller_payouts_is_owner()) {
                throw new RuntimeException('Only superadmin/owner users can mark payouts paid.');
            }
            if (!function_exists('bv_seller_balance_mark_payout_paid')) {
                throw new RuntimeException('Mark-paid helper is unavailable.');
            }

            $requestId = (int) ($_POST['request_id'] ?? 0);
            $paymentReference = trim((string) ($_POST['payment_reference'] ?? ''));
            if ($requestId <= 0) {
                throw new RuntimeException('Invalid payout request.');
            }
            if ($paymentReference === '') {
                throw new RuntimeException('Payment reference is required.');
            }

            bv_seller_balance_mark_payout_paid($requestId, $paymentReference, bv_seller_payouts_current_admin_id());
             bv_seller_payouts_flash('message', 'Payout marked paid.');
        } elseif ($action === 'release_pending') {
            if (!bv_seller_payouts_is_owner()) {
                throw new RuntimeException('Only superadmin/owner users can release pending balances.');
            }
            if (!function_exists('bv_seller_balance_release_pending') || !function_exists('bv_seller_balance_get')) {
                throw new RuntimeException('Pending balance release helpers are unavailable.');
            }

            $sellerId = (int) ($_POST['seller_id'] ?? 0);
            if ($sellerId <= 0) {
                throw new RuntimeException('Invalid seller.');
            }

            $pendingBalance = bv_seller_payouts_read_pending_balance($sellerId);
            if ($pendingBalance <= 0) {
                throw new RuntimeException('No pending balance is available to release.');
            }

            bv_seller_payouts_release_pending_balance($sellerId, $pendingBalance);
            bv_seller_payouts_flash('message', 'Pending balance released.');
        } elseif ($action === 'adjust_balance') {
            if (!bv_seller_payouts_is_owner()) {
                throw new RuntimeException('Only superadmin/owner users can adjust balances.');
            }
            if (!function_exists('bv_seller_balance_admin_adjust')) {
                throw new RuntimeException('Admin balance adjustment helper is unavailable.');
            }

            $sellerId = (int) ($_POST['seller_id'] ?? 0);
            $amount = (float) ($_POST['amount'] ?? 0);
            $reason = trim((string) ($_POST['reason'] ?? ''));
            if ($sellerId <= 0) {
                throw new RuntimeException('Invalid seller.');
            }
            if ($amount == 0.0) {
                throw new RuntimeException('Adjustment amount must not be zero.');
            }
            if ($reason === '') {
                throw new RuntimeException('Adjustment reason is required.');
            }

            bv_seller_balance_admin_adjust($sellerId, $amount, $reason, bv_seller_payouts_current_admin_id());
             bv_seller_payouts_flash('message', 'Seller balance adjusted.');
        } else {
            throw new RuntimeException('Unknown action.');
        }
    } catch (Throwable $e) {
        bv_seller_payouts_flash('error', $e->getMessage());
    }
	
    bv_seller_payouts_redirect();	
}

$payoutRequests = [];
$hasPayouts = table_exists('seller_payout_requests');
if ($hasPayouts) {
    $columns = ['id', 'seller_id', 'amount', 'status', 'created_at'];
    $select = [];
    foreach ($columns as $column) {
        if (column_exists('seller_payout_requests', $column)) {
            $select[] = '`' . $column . '`';
        }
    }
    if ($select) {
        $payoutRequests = bv_seller_payouts_fetch_all('SELECT ' . implode(', ', $select) . ' FROM `seller_payout_requests` ORDER BY `' . (column_exists('seller_payout_requests', 'created_at') ? 'created_at' : 'id') . '` DESC LIMIT 100');
    }
}

$sellers = [];
foreach (['sellers', 'seller_balances', 'seller_balance'] as $table) {
    if (!table_exists($table)) {
        continue;
    }

    $sellerIdColumn = column_exists($table, 'seller_id') ? 'seller_id' : (column_exists($table, 'id') ? 'id' : (column_exists($table, 'user_id') ? 'user_id' : null));
    if (!$sellerIdColumn) {
        continue;
    }

    $select = ['`' . $sellerIdColumn . '` AS seller_id'];
    foreach (['name', 'seller_name', 'business_name', 'store_name', 'email'] as $column) {
        if (column_exists($table, $column)) {
            $select[] = '`' . $column . '`';
        }
    }
    $sellers = bv_seller_payouts_fetch_all('SELECT ' . implode(', ', $select) . ' FROM `' . $table . '` ORDER BY `' . $sellerIdColumn . '` DESC LIMIT 200');
    if ($sellers) {
        break;
    }
}

$actionsEnabled = $sellerBalanceHelperAvailable;
$isSuperAdmin = bv_seller_payouts_is_owner();
$approveAvailable = $actionsEnabled && $hasPayouts && function_exists('bv_seller_balance_approve_payout');
$rejectAvailable = $actionsEnabled && $hasPayouts && function_exists('bv_seller_balance_reject_payout');
$canMarkPaid = $actionsEnabled && $isSuperAdmin && function_exists('bv_seller_balance_mark_payout_paid');
$adjustBalanceAvailable = $actionsEnabled && $isSuperAdmin && function_exists('bv_seller_balance_admin_adjust');
$releasePendingAvailable = $actionsEnabled && $isSuperAdmin && function_exists('bv_seller_balance_release_pending') && function_exists('bv_seller_balance_get');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Seller Payouts</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 24px; color: #222; }
        table { border-collapse: collapse; width: 100%; margin: 18px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
        th { background: #f7f7f7; }
        .alert { border-radius: 4px; margin: 12px 0; padding: 10px 12px; }
        .alert-success { background: #e8f6ee; border: 1px solid #b8e2c7; }
        .alert-warning { background: #fff8e1; border: 1px solid #f0d98c; }
        .alert-danger { background: #fdecea; border: 1px solid #f3b6b1; }
        .badge { border-radius: 12px; display: inline-block; font-size: 12px; padding: 3px 8px; }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-secondary { background: #e2e3e5; color: #383d41; }
        form.inline { display: inline-block; margin: 0 4px 4px 0; }
        input, select, button, textarea { margin: 3px 0; padding: 6px; }
        button[disabled] { cursor: not-allowed; opacity: .55; }
        .panel { border: 1px solid #ddd; border-radius: 4px; margin: 18px 0; padding: 14px; }
    </style>
</head>
<body>
    <h1>Seller Payouts</h1>

    <?php foreach ($messages as $message): ?>
        <div class="alert alert-success"><?php echo h($message); ?></div>
    <?php endforeach; ?>

    <?php foreach ($errors as $error): ?>
        <div class="alert alert-danger"><?php echo h($error); ?></div>
    <?php endforeach; ?>

    <?php if (!$sellerBalanceHelperAvailable): ?>
        <div class="alert alert-warning">Seller balance helper is missing; payout actions are disabled.</div>

    <?php endif; ?>

    <?php if (!$approveAvailable): ?>
        <div class="alert alert-warning">Approve is disabled because bv_seller_balance_approve_payout() is unavailable.</div>
    <?php endif; ?>
	
   <?php if (!$rejectAvailable): ?>
        <div class="alert alert-warning">Reject is disabled because bv_seller_balance_reject_payout() is unavailable.</div>
    <?php endif; ?>	

    <?php if (!function_exists('bv_seller_balance_mark_payout_paid')): ?>
        <div class="alert alert-warning">Mark Paid is disabled because bv_seller_balance_mark_payout_paid() is unavailable.</div>
    <?php elseif (!$isSuperAdmin): ?>
        <div class="alert alert-warning">Mark Paid is available only to superadmin/owner users.</div>
    <?php endif; ?>

    <h2>Payout Requests</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Seller</th>
                <th>Amount</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
        <?php if (!$payoutRequests): ?>
            <tr><td colspan="6">No payout requests found.</td></tr>
        <?php endif; ?>
        <?php foreach ($payoutRequests as $request): ?>
            <?php
            $status = strtolower((string) ($request['status'] ?? ''));
            $requestId = (int) ($request['id'] ?? 0);
            ?>
            <tr>
                <td><?php echo h($request['id'] ?? ''); ?></td>
                <td><?php echo h($request['seller_id'] ?? ''); ?></td>
                <td><?php echo h(money_fmt($request['amount'] ?? 0)); ?></td>
                <td><span class="badge <?php echo h(status_badge_class($status)); ?>"><?php echo h($status ?: 'unknown'); ?></span></td>
                <td><?php echo h($request['created_at'] ?? ''); ?></td>
                <td>
                    <form class="inline" method="post">
                    <?php if (in_array($status, ['pending', 'requested'], true)): ?>
                        <form class="inline" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                            <input type="hidden" name="action" value="approve_request">
                            <input type="hidden" name="request_id" value="<?php echo h($requestId); ?>">
                            <button type="submit" <?php echo $approveAvailable ? '' : 'disabled'; ?>>Approve</button>
                        </form>

                        <form class="inline" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                            <input type="hidden" name="action" value="reject_request">
                            <input type="hidden" name="request_id" value="<?php echo h($requestId); ?>">
                            <input type="text" name="admin_note" placeholder="Admin note" required>
                            <button type="submit" <?php echo $rejectAvailable ? '' : 'disabled'; ?>>Reject</button>
                        </form>
                    <?php elseif ($status === 'approved'): ?>
                        <form class="inline" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                            <input type="hidden" name="action" value="mark_paid">
                            <input type="hidden" name="request_id" value="<?php echo h($requestId); ?>">
                            <input type="text" name="payment_reference" placeholder="Payment reference" required>
                            <button type="submit" <?php echo $canMarkPaid ? '' : 'disabled'; ?>>Mark Paid</button>
                        </form>
                    <?php else: ?>
                        <span class="badge <?php echo h(status_badge_class($status)); ?>"><?php echo h($status ?: 'unknown'); ?></span>
                    <?php endif; ?> 
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <h2>Seller Balances</h2>
    <table>
        <thead>
            <tr>
                <th>Seller</th>
                <th>Pending Balance</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
        <?php if (!$sellers): ?>
            <tr><td colspan="7">No sellers found.</td></tr>
        <?php endif; ?>
        <?php foreach ($sellers as $seller): ?>
            <?php
            $sellerId = (int) ($seller['seller_id'] ?? 0);
            try {
                 $sellerBalance = bv_seller_payouts_read_balance($sellerId); 
            } catch (Throwable $e) {
                 $sellerBalance = [
                    'available' => 0.0,
                    'pending' => 0.0,
                    'locked' => 0.0,
                    'paid_out' => 0.0,
                    'total' => 0.0,
                ]; 
            }
            $pendingBalance = (float) ($sellerBalance['pending'] ?? 0.0);			
            ?>
            <tr>
                <td><?php echo h(seller_label($seller)); ?> (#<?php echo h($sellerId); ?>)</td>
                <td><?php echo h(money_fmt($sellerBalance['available'] ?? 0)); ?></td>
                <td><?php echo h(money_fmt($sellerBalance['pending'] ?? 0)); ?></td>
                <td><?php echo h(money_fmt($sellerBalance['locked'] ?? 0)); ?></td>
                <td><?php echo h(money_fmt($sellerBalance['paid_out'] ?? 0)); ?></td>
                <td><?php echo h(money_fmt($sellerBalance['total'] ?? 0)); ?></td>
                <td>
                    <form class="inline" method="post">
                        <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                        <input type="hidden" name="action" value="release_pending">
                        <input type="hidden" name="seller_id" value="<?php echo h($sellerId); ?>">
                        <button type="submit" <?php echo $releasePendingAvailable && $pendingBalance > 0 ? '' : 'disabled'; ?>>Release Pending</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <?php if ($adjustBalanceAvailable): ?>
        <div class="panel">
            <h2>Adjust Balance</h2>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">
                <input type="hidden" name="action" value="adjust_balance">
                <label>
                    Seller ID<br>
                    <input type="number" name="seller_id" min="1" required>
                </label><br>
                <label>
                    Amount<br>
                    <input type="number" name="amount" step="0.01" required>
                </label><br>
                <label>
                    Reason<br>
                    <textarea name="reason" required></textarea>
                </label><br>
                <button type="submit">Adjust Balance</button>
            </form>
        </div>
    <?php else: ?>
        <div class="alert alert-warning">Adjust Balance is hidden because bv_seller_balance_admin_adjust() is unavailable.</div>
    <?php endif; ?>
</body>
</html>
