<?php
/**
 *  2009-2026 Tecnoacquisti.com
 *
 *  For support feel free to contact us on our website at http://www.tecnoacquisti.com
 *
 *  @author    Arte e Informatica <helpdesk@tecnoacquisti.com>
 *  @copyright 2009-2026 Arte e Informatica
 *  @license   https://opensource.org/licenses/MIT  MIT License
 *  @version   1.0.0
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class Tecno_Xss_Hotfix extends Module
{
    // Smarty token: closing brace is part of the tag, so these two strings do NOT overlap
    const VULNERABLE_TOKEN = '{$thread->email}';
    const PATCHED_TOKEN    = '{$thread->email|escape:\'html\':\'UTF-8\'}';

    // Validate.php isEmail() — PS >= 8.0.2: regex mode flag
    const VALIDATE_VULNERABLE = "'mode' => 'loose',";
    const VALIDATE_PATCHED    = "'mode' => 'strict',";

    // Validate.php isEmail() — PS 1.7 (egulias EmailValidator): inject guard before return
    const VALIDATE_VULNERABLE_17 = 'return !empty($email) && (new EmailValidator())->isValid(';
    const VALIDATE_PATCHED_17    = "if (!empty(\$email) && preg_match('/[<>\"]/', \$email)) { return false; }\n        return !empty(\$email) && (new EmailValidator())->isValid(";
    const VALIDATE_PATCHED_17_SENTINEL = "preg_match('/[<>\"]/', \$email)";

    const BACKUP_SUFFIX = '.tecno-hotfix-backup';

    public function __construct()
    {
        $this->name          = 'tecno_xss_hotfix';
        $this->tab           = 'administration';
        $this->version       = '1.1.0';
        $this->author        = 'Tecnoacquisti.com';
        $this->need_instance = 0;
        $this->bootstrap     = true;

        parent::__construct();

        $this->displayName = $this->l('XSS Hotfix GHSA-w9f3-qc75-qgx9');
        $this->description = $this->l('Security patch for stored XSS in Customer Threads BO (CVE 9.3/10, CWE-79)');
        $this->ps_versions_compliancy = ['min' => '1.7.0.0', 'max' => '9.99.99'];
    }

    public function install()
    {
        if (!parent::install()) {
            return false;
        }
        $this->applyPatches();
        return true;
    }

    public function uninstall()
    {
        // Patch on template is INTENTIONALLY permanent: removing the module does NOT revert the fix.
        return parent::uninstall();
    }

    // -------------------------------------------------------------------------
    // Path helpers  (prefixed to avoid conflicts with ModuleCore method names)
    // -------------------------------------------------------------------------

    protected function getXssTplPath()
    {
        // _PS_ADMIN_DIR_ is only defined in HTTP admin context, never in CLI
        if (!defined('_PS_ADMIN_DIR_')) {
            return '';
        }
        return _PS_ADMIN_DIR_ . '/themes/default/template/controllers/customer_threads/helpers/view/view.tpl';
    }

    protected function getValidateClassPath()
    {
        return _PS_ROOT_DIR_ . '/classes/Validate.php';
    }

    protected function getOverrideClassPath()
    {
        return _PS_ROOT_DIR_ . '/override/classes/Validate.php';
    }

    // -------------------------------------------------------------------------
    // Override detection
    // -------------------------------------------------------------------------

    protected function hasIsEmailOverride()
    {
        $path = $this->getOverrideClassPath();
        if (!file_exists($path)) {
            return false;
        }
        $content = @file_get_contents($path);
        return $content !== false && (bool) preg_match('/function\s+isEmail\s*\(/', $content);
    }

    // -------------------------------------------------------------------------
    // Patching logic
    // -------------------------------------------------------------------------

    /**
     * Patch the BO customer_threads view template.
     * Replaces ALL bare {$thread->email} with the escaped version.
     * Creates a .tecno-hotfix-backup before writing.
     *
     * @return array{status:string, message:string}
     */
    protected function patchTemplate()
    {
        $path = $this->getXssTplPath();

        if ($path === '') {
            return ['status' => 'skipped_cli', 'message' => $this->l('Template patch skipped: _PS_ADMIN_DIR_ not available in CLI context. Open the module configuration page in the Back-Office to apply.')];
        }
        if (!file_exists($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('File not found: %s'), $path)];
        }
        if (!is_writable($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('File not writable: %s'), $path)];
        }

        $content = file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot read: %s'), $path)];
        }

        // Already patched or different version — both are safe states
        if (strpos($content, self::VULNERABLE_TOKEN) === false) {
            return ['status' => 'already_patched', 'message' => $this->l('Template: vulnerable token not found (already patched or different PS version).')];
        }

        $backupPath = $path . self::BACKUP_SUFFIX;
        if (!copy($path, $backupPath)) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot create backup: %s'), $backupPath)];
        }

        $patched = str_replace(self::VULNERABLE_TOKEN, self::PATCHED_TOKEN, $content);
        if (file_put_contents($path, $patched) === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot write patched file: %s'), $path)];
        }

        return ['status' => 'patched', 'message' => sprintf($this->l('Template patched successfully. Backup: %s'), $backupPath)];
    }

    /**
     * Patch Validate.php isEmail() regex mode: loose → strict.
     * Only executed for PS >= 8.0.2 AND when no isEmail() override exists.
     *
     * @return array{status:string, message:string}
     */
    protected function patchValidate()
    {
        if ($this->hasIsEmailOverride()) {
            return [
                'status'  => 'skipped_override',
                'message' => sprintf(
                    $this->l('Skipped: isEmail() override detected in %s. Apply the fix manually (see below).'),
                    $this->getOverrideClassPath()
                ),
            ];
        }

        $path = $this->getValidateClassPath();

        if (!file_exists($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('Validate.php not found: %s'), $path)];
        }
        if (!is_writable($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('Validate.php not writable: %s'), $path)];
        }

        $content = file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot read Validate.php: %s'), $path)];
        }

        $isOld = version_compare(_PS_VERSION_, '8.0.2', '<');
        $vulnerable = $isOld ? self::VALIDATE_VULNERABLE_17 : self::VALIDATE_VULNERABLE;
        $patched    = $isOld ? self::VALIDATE_PATCHED_17    : self::VALIDATE_PATCHED;

        if (strpos($content, $vulnerable) === false) {
            return ['status' => 'already_patched', 'message' => $this->l('Validate.php: token not found (already patched or different PS version).')];
        }

        $backupPath = $path . self::BACKUP_SUFFIX;
        if (!copy($path, $backupPath)) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot create backup: %s'), $backupPath)];
        }

        $newContent = str_replace($vulnerable, $patched, $content);
        if (file_put_contents($path, $newContent) === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot write Validate.php: %s'), $path)];
        }

        return ['status' => 'patched', 'message' => sprintf($this->l('Validate.php patched successfully. Backup: %s'), $backupPath)];
    }

    /**
     * Apply both patches and clear Smarty cache if at least one patch was written.
     *
     * @return array
     */
    public function applyPatches()
    {
        $results = [
            'template' => $this->patchTemplate(),
            'validate' => $this->patchValidate(),
        ];

        if ($results['template']['status'] === 'patched' || $results['validate']['status'] === 'patched') {
            Tools::clearSmartyCache();
            Tools::clearCache();
        }

        return $results;
    }

    // -------------------------------------------------------------------------
    // Read-only status checks (used by getContent to show current state)
    // -------------------------------------------------------------------------

    protected function getTemplatePatchStatus()
    {
        $path = $this->getXssTplPath();
        if ($path === '') {
            return ['status' => 'unknown', 'message' => $this->l('Status not available in CLI context.')];
        }
        if (!file_exists($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('File not found: %s'), $path)];
        }
        $content = @file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot read: %s'), $path)];
        }
        if (strpos($content, self::PATCHED_TOKEN) !== false) {
            return ['status' => 'patched', 'message' => $this->l('Template patched correctly.')];
        }
        if (strpos($content, self::VULNERABLE_TOKEN) !== false) {
            return ['status' => 'vulnerable', 'message' => $this->l('Template is VULNERABLE — patch not yet applied!')];
        }
        return ['status' => 'unknown', 'message' => $this->l('Template: cannot determine status (tokens not found in file).')];
    }

    protected function getValidatePatchStatus()
    {
        if ($this->hasIsEmailOverride()) {
            return ['status' => 'skipped_override', 'message' => $this->l('Override present — manual fix required (see below).')];
        }
        $path = $this->getValidateClassPath();
        if (!file_exists($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('File not found: %s'), $path)];
        }
        $content = @file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot read: %s'), $path)];
        }
        $isOld = version_compare(_PS_VERSION_, '8.0.2', '<');
        if ($isOld) {
            if (strpos($content, self::VALIDATE_PATCHED_17_SENTINEL) !== false) {
                return ['status' => 'patched', 'message' => $this->l('Validate.php patched correctly (PS 1.7 guard injected).')];
            }
            if (strpos($content, self::VALIDATE_VULNERABLE_17) !== false) {
                return ['status' => 'vulnerable', 'message' => $this->l('Validate.php is VULNERABLE — patch not yet applied!')];
            }
        } else {
            if (strpos($content, self::VALIDATE_PATCHED) !== false) {
                return ['status' => 'patched', 'message' => $this->l('Validate.php patched correctly.')];
            }
            if (strpos($content, self::VALIDATE_VULNERABLE) !== false) {
                return ['status' => 'vulnerable', 'message' => $this->l('Validate.php is VULNERABLE — patch not yet applied!')];
            }
        }
        return ['status' => 'unknown', 'message' => $this->l('Validate.php: cannot determine status.')];
    }

    // -------------------------------------------------------------------------
    // Manual fix snippet
    // -------------------------------------------------------------------------

    /**
     * Returns the PHP code snippet to display when automatic Validate.php patching
     * is not possible (old PS or isEmail() override present).
     */
    protected function getManualFixCode($hasOverride)
    {
        if ($hasOverride) {
            // Override file exists: user must add the check there
            return <<<'PHPCODE'
// In override/classes/Validate.php — add this at the top of the isEmail() body:

public static function isEmail($email)
{
    // XSS guard: reject addresses containing double-quote (GHSA-w9f3-qc75-qgx9)
    if (strpos($email, '"') !== false) {
        return false;
    }
    return parent::isEmail($email);
}
PHPCODE;
        }

        // Old PS without override: user must edit core directly
        return <<<'PHPCODE'
// In classes/Validate.php — add these lines at the very top of the isEmail() method body,
// BEFORE any existing return statement:

// XSS guard: reject addresses containing double-quote (GHSA-w9f3-qc75-qgx9)
if (strpos($email, '"') !== false) {
    return false;
}
PHPCODE;
    }

    // -------------------------------------------------------------------------
    // Back-office configuration page
    // -------------------------------------------------------------------------

    public function getContent()
    {
        // All navigation is POST-based (action="" forms) to stay on the Symfony
        // module-configure URL in PS8/9 without manually constructing it.

        // Show forensic page when the dedicated submit buttons are present
        if (Tools::isSubmit('go_forensic_scan') || Tools::isSubmit('run_forensic_scan')) {
            return $this->renderForensicScan();
        }

        $patchResults = null;
        if (Tools::isSubmit('apply_patches')) {
            $patchResults = $this->applyPatches();
        }

        $hasOverride  = $this->hasIsEmailOverride();
        $psVersion    = _PS_VERSION_;
        $needsManual  = $hasOverride; // only manual if override present; PS 1.7 is now auto-patched

        $this->context->smarty->assign([
            'ps_version'       => $psVersion,
            'has_override'     => $hasOverride,
            'override_path'    => $this->getOverrideClassPath(),
            'needs_manual_fix' => $needsManual,
            'is_old_ps'        => false,
            'manual_fix_code'  => $this->getManualFixCode($hasOverride),
            'template_status'  => $this->getTemplatePatchStatus(),
            'validate_status'  => $this->getValidatePatchStatus(),
            'patch_results'    => $patchResults,
        ]);

        return $this->display(__FILE__, 'views/templates/admin/status.tpl');
    }

    // -------------------------------------------------------------------------
    // Forensic scan — DB-only IoC analysis
    // -------------------------------------------------------------------------

    protected function renderForensicScan()
    {
        $scanResults = null;
        if (Tools::isSubmit('run_forensic_scan')) {
            $scanResults = $this->runForensicScan();
        }

        $this->context->smarty->assign([
            'scan_results' => $scanResults,
        ]);

        return $this->display(__FILE__, 'views/templates/admin/forensic.tpl');
    }

    /**
     * Query all PS tables involved in GHSA-w9f3-qc75-qgx9 for XSS IoC patterns.
     * Uses only Db::getInstance() + _DB_PREFIX_: works on any PS installation.
     *
     * @return array{total_hits:int, scanned_at:string, sections:array}
     */
    protected function runForensicScan()
    {
        $db  = Db::getInstance();
        $pfx = _DB_PREFIX_;

        // XSS IoC conditions applied to email columns
        $emailWhere =
            "email LIKE '%<%'"
            . " OR email LIKE '%>%'"
            . " OR email LIKE '%\"%'"
            . " OR email LIKE '%script%'"
            . " OR email LIKE '%javascript:%'"
            . " OR email LIKE '%onerror=%'"
            . " OR email LIKE '%onload=%'"
            . " OR email LIKE '%onfocus=%'"
            . " OR email LIKE '%onmouse%'"
            . " OR email LIKE '%document.%'"
            . " OR email LIKE '%cookie%'"
            . " OR email LIKE '%eval(%'";

        $sections  = [];
        $totalHits = 0;

        // ── 1. ps_customer — registered accounts ──────────────────────────
        $sections['customers'] = $this->scanTable($db, "
            SELECT id_customer AS id, email, date_add, active, deleted
            FROM `{$pfx}customer`
            WHERE {$emailWhere}
            ORDER BY date_add DESC
            LIMIT 200
        ", [
            'label'    => $this->l('Registered accounts (ps_customer)'),
            'critical' => false,
            'columns'  => ['ID', $this->l('Email'), $this->l('Registered'), $this->l('Active'), $this->l('Deleted')],
            'fields'   => ['id', 'email', 'date_add', 'active', 'deleted'],
        ]);

        // ── 2. ps_customer_thread — PRIMARY ATTACK VECTOR ─────────────────
        // This is the email rendered verbatim in the vulnerable BO template
        $sections['threads'] = $this->scanTable($db, "
            SELECT id_customer_thread AS id, email, date_add, status
            FROM `{$pfx}customer_thread`
            WHERE {$emailWhere}
            ORDER BY date_add DESC
            LIMIT 200
        ", [
            'label'    => $this->l('Contact-form threads — PRIMARY VECTOR (ps_customer_thread)'),
            'critical' => true,
            'columns'  => ['ID', $this->l('Email'), $this->l('Date'), $this->l('Status')],
            'fields'   => ['id', 'email', 'date_add', 'status'],
        ]);

        // ── 3. ps_customer_message — message body ─────────────────────────
        $sections['messages'] = $this->scanTable($db, "
            SELECT m.id_customer_message AS id,
                   t.email,
                   m.date_add,
                   LEFT(m.message, 160) AS message_snippet
            FROM `{$pfx}customer_message` m
            INNER JOIN `{$pfx}customer_thread` t
                    ON m.id_customer_thread = t.id_customer_thread
            WHERE m.message LIKE '%<script%'
               OR m.message LIKE '%javascript:%'
               OR m.message LIKE '%onerror=%'
               OR m.message LIKE '%document.cookie%'
            ORDER BY m.date_add DESC
            LIMIT 100
        ", [
            'label'    => $this->l('Message bodies (ps_customer_message)'),
            'critical' => false,
            'columns'  => ['ID', $this->l('From'), $this->l('Date'), $this->l('Snippet')],
            'fields'   => ['id', 'email', 'date_add', 'message_snippet'],
        ]);

        // ── 4. ps_employee — informational: list all admin accounts ────────
        // Not an IoC count but essential post-exploitation check
        $sections['employees'] = $this->scanTable($db, "
            SELECT id_employee AS id,
                   CONCAT(firstname, ' ', lastname) AS name,
                   email,
                   id_profile,
                   active
            FROM `{$pfx}employee`
            ORDER BY id_employee DESC
            LIMIT 50
        ", [
            'label'       => $this->l('Admin accounts — verify no unauthorized additions (ps_employee)'),
            'critical'    => false,
            'informational' => true,
            'columns'     => ['ID', $this->l('Name'), $this->l('Email'), $this->l('Profile'), $this->l('Active')],
            'fields'      => ['id', 'name', 'email', 'id_profile', 'active'],
        ]);

        // Count IoC hits (employees are informational, excluded)
        foreach (['customers', 'threads', 'messages'] as $key) {
            $totalHits += count($sections[$key]['rows']);
        }

        return [
            'total_hits' => $totalHits,
            'scanned_at' => date('Y-m-d H:i:s'),
            'sections'   => $sections,
        ];
    }

    /**
     * Run a single SELECT query and return a normalised section array.
     *
     * @param  Db     $db
     * @param  string $sql
     * @param  array  $meta  label, critical, columns, fields[, informational]
     * @return array
     */
    protected function scanTable(Db $db, $sql, array $meta)
    {
        $base = array_merge([
            'label'         => '',
            'critical'      => false,
            'informational' => false,
            'columns'       => [],
            'fields'        => [],
            'rows'          => [],
            'error'         => null,
        ], $meta);

        try {
            $rows = $db->executeS($sql);
            $base['rows'] = $rows ?: [];
        } catch (Exception $e) {
            $base['error'] = $e->getMessage();
        }

        return $base;
    }
}
