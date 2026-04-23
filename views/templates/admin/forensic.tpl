{*
 *  2009-2026 Tecnoacquisti.com
 *
 *  For support feel free to contact us on our website at http://www.tecnoacquisti.com
 *
 *  @author    Arte e Informatica <helpdesk@tecnoacquisti.com>
 *  @copyright 2009-2026 Arte e Informatica
 *  @license   https://opensource.org/licenses/MIT  MIT License
 *  @version   1.0.0
 *}

<div class="panel">
    <div class="panel-heading">
        <i class="icon-search"></i>
        {l s='Forensic DB Scan — GHSA-w9f3-qc75-qgx9' mod='tecno_xss_hotfix'}
        &nbsp;
        <form action="" method="post" style="display:inline;float:right">
            <button type="submit" name="back_to_status" value="1" class="btn btn-default btn-sm">
                <i class="icon-arrow-left"></i>
                {l s='Back to Patch Status' mod='tecno_xss_hotfix'}
            </button>
        </form>
    </div>

    <div class="panel-body">

        {* ── Intro / run form ───────────────────────────────────────────── *}
        {if !$scan_results}

            <div class="alert alert-info">
                <strong>{l s='What this scan checks:' mod='tecno_xss_hotfix'}</strong>
                <ul class="mb-0" style="margin:6px 0 0 0;padding-left:18px">
                    <li><code>ps_customer.email</code> — {l s='registered accounts with malicious email' mod='tecno_xss_hotfix'}</li>
                    <li><code>ps_customer_thread.email</code> — <strong>{l s='PRIMARY VECTOR' mod='tecno_xss_hotfix'}</strong>: {l s='contact-form threads whose email was rendered verbatim in the BO' mod='tecno_xss_hotfix'}</li>
                    <li><code>ps_customer_message.message</code> — {l s='XSS patterns in message bodies' mod='tecno_xss_hotfix'}</li>
                    <li><code>ps_employee</code> — {l s='all admin accounts (verify no unauthorized additions)' mod='tecno_xss_hotfix'}</li>
                </ul>
            </div>

            <form action="" method="post">
                <button type="submit" name="run_forensic_scan" value="1" class="btn btn-danger btn-lg">
                    <i class="icon-search"></i>
                    {l s='Run Forensic Scan Now' mod='tecno_xss_hotfix'}
                </button>
            </form>

        {else}

            {* ── Verdict banner ──────────────────────────────────────────── *}
            {if $scan_results.total_hits > 0}
                <div class="alert alert-danger">
                    <h4 style="margin-top:0">
                        <i class="icon-warning-sign"></i>
                        {l s='POTENTIAL EXPLOITATION DETECTED' mod='tecno_xss_hotfix'}
                        &mdash;
                        {$scan_results.total_hits|intval} {l s='suspicious record(s) found' mod='tecno_xss_hotfix'}
                    </h4>
                    <p>{l s='Review the tables below and follow the remediation steps at the bottom of this page.' mod='tecno_xss_hotfix'}</p>
                    <p>
                        <strong>{l s='Immediate actions:' mod='tecno_xss_hotfix'}</strong>
                        {l s='(1) Reset all admin passwords. (2) Rotate _COOKIE_KEY_ and _COOKIE_IV_. (3) Invalidate admin sessions: UPDATE ps_employee SET cookie_token="". (4) Review ps_employee for unauthorized accounts.' mod='tecno_xss_hotfix'}
                    </p>
                </div>
            {else}
                <div class="alert alert-success">
                    <i class="icon-check"></i>
                    <strong>{l s='No IoC indicators found in the database.' mod='tecno_xss_hotfix'}</strong>
                    {l s='No malicious email patterns detected in the scanned tables.' mod='tecno_xss_hotfix'}
                </div>
            {/if}

            <p class="help-block">
                <i class="icon-clock-o"></i>
                {l s='Scanned at:' mod='tecno_xss_hotfix'} {$scan_results.scanned_at|escape:'html':'UTF-8'}
            </p>

            {* ── Results per section ─────────────────────────────────────── *}
            {foreach $scan_results.sections as $key => $section}

                {assign var='row_count' value=$section.rows|count}
                {assign var='is_info'   value=$section.informational}
                {assign var='has_error' value=$section.error}

                {* Section header color:
                   - error     → danger
                   - IoC hits  → danger (critical) / warning (non-critical)
                   - info list → always info
                   - clean     → success *}
                {if $has_error}
                    {assign var='panel_class' value='danger'}
                {elseif $is_info}
                    {assign var='panel_class' value='info'}
                {elseif $row_count > 0}
                    {if $section.critical}
                        {assign var='panel_class' value='danger'}
                    {else}
                        {assign var='panel_class' value='warning'}
                    {/if}
                {else}
                    {assign var='panel_class' value='success'}
                {/if}

                <div class="panel panel-{$panel_class|escape:'html':'UTF-8'}" style="margin-top:16px">
                    <div class="panel-heading">
                        {if $has_error}
                            <i class="icon-exclamation-circle"></i>
                        {elseif $is_info}
                            <i class="icon-info-circle"></i>
                        {elseif $row_count > 0}
                            <i class="icon-warning-sign"></i>
                        {else}
                            <i class="icon-check"></i>
                        {/if}
                        {$section.label|escape:'html':'UTF-8'}
                        {if !$is_info}
                            &nbsp;<span class="badge">{$row_count|intval}</span>
                        {else}
                            &nbsp;<span class="badge">{$row_count|intval} {l s='accounts' mod='tecno_xss_hotfix'}</span>
                        {/if}
                    </div>

                    {if $has_error}
                        <div class="panel-body">
                            <span class="text-danger">{l s='Query error:' mod='tecno_xss_hotfix'} {$section.error|escape:'html':'UTF-8'}</span>
                        </div>

                    {elseif $row_count == 0 && !$is_info}
                        <div class="panel-body">
                            <span class="text-success">
                                <i class="icon-check"></i> {l s='No suspicious records found.' mod='tecno_xss_hotfix'}
                            </span>
                        </div>

                    {else}
                        <div class="table-responsive">
                            <table class="table table-bordered table-hover" style="font-size:13px">
                                <thead>
                                    <tr>
                                        {foreach $section.columns as $col}
                                            <th>{$col|escape:'html':'UTF-8'}</th>
                                        {/foreach}
                                    </tr>
                                </thead>
                                <tbody>
                                    {foreach $section.rows as $row}
                                        <tr class="{if !$is_info && $section.critical}danger{elseif !$is_info}warning{/if}">
                                            {foreach $section.fields as $field}
                                                <td>
                                                    {if $field == 'email' || $field == 'message_snippet'}
                                                        <span style="word-break:break-all;font-family:monospace;color:#c0392b;font-weight:bold">
                                                            {$row[$field]|escape:'html':'UTF-8'}
                                                        </span>
                                                    {else}
                                                        {$row[$field]|escape:'html':'UTF-8'}
                                                    {/if}
                                                </td>
                                            {/foreach}
                                        </tr>
                                    {/foreach}
                                </tbody>
                            </table>
                        </div>
                        {if $is_info}
                            <div class="panel-body" style="padding-top:0;border-top:1px solid #ddd">
                                <p class="help-block" style="margin:8px 0 0 0">
                                    <i class="icon-info-circle"></i>
                                    {l s='This list is shown for manual review only — it is not an indicator of compromise. Verify that all accounts are known and authorized. If you find unexpected accounts, delete them immediately and rotate all admin passwords.' mod='tecno_xss_hotfix'}
                                </p>
                            </div>
                        {/if}
                    {/if}

                </div>{* /panel *}

            {/foreach}

            {* ── Re-scan + back buttons ──────────────────────────────────── *}
            <form action="" method="post" style="margin-top:16px">
                <button type="submit" name="run_forensic_scan" value="1" class="btn btn-default">
                    <i class="icon-refresh"></i>
                    {l s='Re-run Scan' mod='tecno_xss_hotfix'}
                </button>
                &nbsp;
                <button type="submit" name="back_to_status" value="1" class="btn btn-default">
                    <i class="icon-arrow-left"></i>
                    {l s='Back to Patch Status' mod='tecno_xss_hotfix'}
                </button>
            </form>

            {* ── Next steps if hits found ─────────────────────────────────── *}
            {if $scan_results.total_hits > 0}
                <div class="panel panel-warning" style="margin-top:20px">
                    <div class="panel-heading">
                        <i class="icon-warning-sign"></i>
                        <strong>{l s='What to do next' mod='tecno_xss_hotfix'}</strong>
                    </div>
                    <div class="panel-body">

                        <h5 style="margin-top:0"><i class="icon-key"></i> {l s='1. Immediate containment' mod='tecno_xss_hotfix'}</h5>
                        <ul>
                            <li>{l s='Reset all admin passwords from Back-Office > Team > Employees.' mod='tecno_xss_hotfix'}</li>
                            <li>{l s='Rotate _COOKIE_KEY_ and _COOKIE_IV_ in app/config/parameters.php (PS 8/9) or config/settings.inc.php (PS 1.7).' mod='tecno_xss_hotfix'}</li>
                            <li>{l s='Invalidate active admin sessions by running this SQL on your database:' mod='tecno_xss_hotfix'}
                                <pre style="margin:6px 0 0 0;background:#f5f5f5;padding:8px;border-radius:4px">UPDATE ps_employee SET cookie_token = '';</pre>
                            </li>
                            <li>{l s='Review the Admin accounts list above: delete any employee you do not recognise.' mod='tecno_xss_hotfix'}</li>
                        </ul>

                        <h5><i class="icon-search"></i> {l s='2. Access log analysis' mod='tecno_xss_hotfix'}</h5>
                        <ul>
                            <li>{l s='Search your Apache/Nginx access logs for requests to the admin Customer Threads page made around the time the suspicious records were created.' mod='tecno_xss_hotfix'}</li>
                            <li>{l s='Look for unexpected IPs hitting the admin area, especially POST requests to admin controllers shortly after a contact-form submission.' mod='tecno_xss_hotfix'}</li>
                            <li>{l s='Check rotated/compressed log archives (.gz) as the attack may predate the current log file.' mod='tecno_xss_hotfix'}</li>
                            <li>{l s='Useful grep pattern (replace ps-admin with your admin folder name):' mod='tecno_xss_hotfix'}
                                <pre style="margin:6px 0 0 0;background:#f5f5f5;padding:8px;border-radius:4px">grep -i "customer_thread\|CustomerThread" /var/log/apache2/access.log</pre>
                            </li>
                        </ul>

                        <h5><i class="icon-exchange"></i> {l s='3. Check for exfiltration endpoints' mod='tecno_xss_hotfix'}</h5>
                        <ul>
                            <li>{l s='The typical payload sends the admin cookie to an attacker-controlled URL via fetch() or XMLHttpRequest. Search your logs for requests to external domains made from the server side (e.g. via allow_url_fopen or cURL hooks).' mod='tecno_xss_hotfix'}</li>
                            <li>{l s='Check ps_configuration for unexpected changes to shop URL, email settings, or payment module parameters.' mod='tecno_xss_hotfix'}</li>
                            <li>{l s='Review recently modified files on the server (within a few days of the suspicious record date):' mod='tecno_xss_hotfix'}
                                <pre style="margin:6px 0 0 0;background:#f5f5f5;padding:8px;border-radius:4px">find /var/www/html -name "*.php" -newer /var/www/html/index.php -not -path "*/cache/*" -not -path "*/var/*"</pre>
                            </li>
                        </ul>

                        <h5><i class="icon-trash"></i> {l s='4. Clean up' mod='tecno_xss_hotfix'}</h5>
                        <ul>
                            <li>{l s='Delete the suspicious records found above (after taking note of them for your incident report).' mod='tecno_xss_hotfix'}</li>
                            <li>{l s='Ensure the patch has been applied (green status on the Patch Status page) so new attempts are rejected at the validation layer.' mod='tecno_xss_hotfix'}</li>
                        </ul>

                    </div>
                </div>
            {/if}

        {/if}{* end if scan_results *}

    </div>{* /panel-body *}
</div>{* /panel *}
