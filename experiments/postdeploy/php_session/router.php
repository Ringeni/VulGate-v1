<?php
// Ordinary application contract: upload integrity and advertised session progress.
session_start();
$files = [];
foreach ($_FILES as $field => $file) {
    $files[] = [
        'field' => $field, 'name' => $file['name'], 'size' => $file['size'],
        'error' => $file['error'],
        'sha256' => $file['error'] === UPLOAD_ERR_OK ? hash_file('sha256', $file['tmp_name']) : null
    ];
}
$progress_name = ini_get('session.upload_progress.name');
if ($progress_name === false || $progress_name === '') {
    $progress_name = 'PHP_SESSION_UPLOAD_PROGRESS';
}
$progress_prefix = ini_get('session.upload_progress.prefix');
if ($progress_prefix === false) {
    $progress_prefix = 'upload_progress_';
}
$progress_id = $_POST[$progress_name] ?? '';
$progress_key = $progress_prefix . $progress_id;
$progress = ($progress_id !== '' && isset($_SESSION[$progress_key])) ? $_SESSION[$progress_key] : null;
$result = [
    'message' => $_POST['message'] ?? '',
    'files' => $files,
    'progress_present' => is_array($progress),
    'progress_done' => is_array($progress) ? $progress['done'] : null,
    'progress_file_count' => is_array($progress) ? count($progress['files']) : 0,
    'progress_bytes' => is_array($progress) ? $progress['bytes_processed'] : null,
];
session_write_close();
header('Content-Type: application/json');
echo json_encode($result);
