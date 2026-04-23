# Changelog

All notable changes to `tecno_xss_hotfix` are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.1.0] — 2026-04-23

### Added
- **PS 1.7 automatic patching** — `isEmail()` in PS 1.7 uses `egulias/email-validator` with `RFCValidation` (different code path from PS 8+). The module now injects a `preg_match('/[<>"]/', $email)` guard before the `EmailValidator` call, making the patch fully automatic on PS 1.7 without manual intervention.
- **Forensic DB scan** — new admin page that scans `ps_customer`, `ps_customer_thread`, `ps_customer_message` and `ps_employee` for XSS indicators of compromise. Accessible from the patch status page via *Run Forensic DB Scan*.
- **Guided remediation panel** — when the forensic scan finds hits, a structured four-step guide is shown inline (containment, log analysis, exfiltration check, clean-up).
- `ps_employee` always listed in scan results as an informational section to allow manual review of admin accounts.

### Changed
- All Back-Office navigation converted to POST forms with `action=""` — eliminates PS9 Symfony routing errors that occurred when constructing URLs from `AdminController::$currentIndex`.
- `$needs_manual_fix` flag now depends only on the presence of an `isEmail()` override, not on PS version.
- `ps_employee` query: removed non-existent `date_add` column (not present in any PS version); results now ordered by `id_employee DESC`.

### Fixed
- **HTTP 500 on PS9 (dev mode)** — `{$apply_url}` Smarty variable was removed from `getContent()` assigns but still referenced in `status.tpl`; PS9 promotes PHP Warnings to `ErrorException`. Fixed by changing the apply form to `action=""`.
- **`getTemplatePath()` signature conflict** — child method `getTemplatePath()` collided with `ModuleCore::getTemplatePath($template)` (public, one parameter). Renamed internal helpers to `getXssTplPath()`, `getValidateClassPath()`, `getOverrideClassPath()`.
- **`_PS_ADMIN_DIR_` fatal error during CLI install** — constant is only defined in HTTP admin context. Guard added in `getXssTplPath()` returning `''`; `patchTemplate()` returns `skipped_cli` status when path is empty.

### Removed
- `forensic_scan.sh` — standalone bash script removed from module directory to comply with PrestaShop module validation rules. Equivalent guidance is now provided as inline documentation in the forensic scan page.

---

## [1.0.0] — 2026-04-22

### Added
- Initial release.
- Automatic patch for `view.tpl`: adds `|escape:'html':'UTF-8'` to `{$thread->email}` in the Back-Office Customer Threads template.
- Automatic patch for `classes/Validate.php` (PS ≥ 8.0.2, no override present): changes `isEmail()` regex mode from `'loose'` to `'strict'`, rejecting email addresses with double-quote characters.
- Override detection: if `override/classes/Validate.php` contains `isEmail()`, automatic patching is skipped and the manual fix snippet is displayed.
- Backup files created with `.tecno-hotfix-backup` extension before any write.
- Smarty cache cleared after successful patch application.
- Patch status page showing current state of both patched files with color-coded badges.
- Template patch is permanent and intentionally not reverted on module uninstall.
- PS compliancy declared for 1.7.0.0 – 9.99.99.
