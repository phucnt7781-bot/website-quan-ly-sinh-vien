<?php
function auth_login(): void {
    if (current_user()) redirect('dashboard');
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verify_csrf();
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $q = db()->prepare('SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?');
        $q->execute([$username]); $u = $q->fetch();
        if ($u && password_verify($password, $u['password_hash'])) {
            session_regenerate_id(true);
            unset($u['password_hash']); $_SESSION['user'] = $u;
            redirect('dashboard');
        }
        $error = 'Tên đăng nhập hoặc mật khẩu không đúng.';
    }
    render('login', ['error' => $error]);
}
function auth_logout(): void {
    require_login(); must_post();
    $_SESSION = []; session_regenerate_id(true);
    flash('Đã đăng xuất.'); redirect('login');
}
