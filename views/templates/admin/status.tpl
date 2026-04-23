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
        <i class="icon-shield"></i>
        {l s='Security Hotfix — GHSA-w9f3-qc75-qgx9' mod='tecno_xss_hotfix'}
        <span class="badge badge-danger" style="margin-left:8px;">CVE 9.3 / CWE-79</span>
    </div>

    <div class="panel-body">

        {* ── Info banner ─────────────────────────────────────────────────── *}
        <div class="alert alert-info">
            <strong>{l s='What this module fixes:' mod='tecno_xss_hotfix'}</strong>
            {l s='Stored XSS via customer email field in the Back-Office Customer Threads view. An attacker registers with a crafted email containing HTML/JS (e.g.' mod='tecno_xss_hotfix'}
            <code>&lt;script&gt;...&lt;/script&gt;@example.com</code>)
            {l s='and steals the admin session cookie when the thread is opened.' mod='tecno_xss_hotfix'}
        </div>

        {* ── Environment overview ────────────────────────────────────────── *}
        <h4>{l s='Environment' mod='tecno_xss_hotfix'}</h4>
        <table class="table table-bordered" style="width:auto">
            <tr>
                <th>{l s='PrestaShop version' mod='tecno_xss_hotfix'}</th>
                <td><strong>{$ps_version|escape:'html':'UTF-8'}</strong></td>
            </tr>
            <tr>
                <th>{l s='isEmail() override' mod='tecno_xss_hotfix'}</th>
                <td>
                    {if $has_override}
                        <span class="label label-warning">
                            {l s='YES' mod='tecno_xss_hotfix'}
                        </span>
                        &nbsp;
                        <code>{$override_path|escape:'html':'UTF-8'}</code>
                    {else}
                        <span class="label label-success">{l s='NO' mod='tecno_xss_hotfix'}</span>
                    {/if}
                </td>
            </tr>
        </table>

        {* ── Results of last "Apply" click ──────────────────────────────── *}
        {if $patch_results}
            <h4>{l s='Last Apply Result' mod='tecno_xss_hotfix'}</h4>

            {assign var='tr' value=$patch_results.template}
            <div class="alert alert-{if $tr.status == 'patched'}success{elseif $tr.status == 'error'}danger{else}warning{/if}">
                <strong>{l s='view.tpl:' mod='tecno_xss_hotfix'}</strong>
                {$tr.message|escape:'html':'UTF-8'}
            </div>

            {assign var='vr' value=$patch_results.validate}
            <div class="alert alert-{if $vr.status == 'patched'}success{elseif $vr.status == 'error'}danger{elseif $vr.status == 'not_applicable' || $vr.status == 'skipped_override'}info{else}warning{/if}">
                <strong>{l s='Validate.php:' mod='tecno_xss_hotfix'}</strong>
                {$vr.message|escape:'html':'UTF-8'}
            </div>
        {/if}

        {* ── Current patch status ────────────────────────────────────────── *}
        <h4>{l s='Current Patch Status' mod='tecno_xss_hotfix'}</h4>

        {assign var='ts' value=$template_status}
        <div class="alert alert-{if $ts.status == 'patched'}success{elseif $ts.status == 'vulnerable'}danger{elseif $ts.status == 'error'}danger{else}warning{/if}">
            <i class="icon-{if $ts.status == 'patched'}check{elseif $ts.status == 'vulnerable'}warning-sign{else}question-sign{/if}"></i>
            <strong>{l s='view.tpl:' mod='tecno_xss_hotfix'}</strong>
            {$ts.message|escape:'html':'UTF-8'}
        </div>

        {assign var='vs' value=$validate_status}
        <div class="alert alert-{if $vs.status == 'patched'}success{elseif $vs.status == 'vulnerable'}danger{elseif $vs.status == 'error'}danger{elseif $vs.status == 'not_applicable' || $vs.status == 'skipped_override'}info{else}warning{/if}">
            <i class="icon-{if $vs.status == 'patched'}check{elseif $vs.status == 'vulnerable'}warning-sign{elseif $vs.status == 'not_applicable' || $vs.status == 'skipped_override'}info-sign{else}question-sign{/if}"></i>
            <strong>{l s='Validate.php:' mod='tecno_xss_hotfix'}</strong>
            {$vs.message|escape:'html':'UTF-8'}
        </div>

        {* ── Manual fix instructions ─────────────────────────────────────── *}
        {if $needs_manual_fix}
            <div class="alert alert-warning">
                <h4 style="margin-top:0">
                    <i class="icon-warning-sign"></i>
                    {l s='Manual Fix Required for isEmail()' mod='tecno_xss_hotfix'}
                </h4>

                {if $is_old_ps}
                    <p>
                        {l s='PS version is below 8.0.2: automatic Validate.php patching is not applied because the fix targets a code path that does not exist in this version. Add the double-quote rejection check manually to' mod='tecno_xss_hotfix'}
                        <strong>classes/Validate.php</strong>:
                    </p>
                {/if}

                {if $has_override}
                    <p>
                        {l s='An isEmail() override was detected. The module cannot safely modify the override file. Apply the fix in your override instead:' mod='tecno_xss_hotfix'}
                    </p>
                {/if}

                <pre style="background:#f5f5f5;padding:12px;border:1px solid #ddd;border-radius:4px;white-space:pre-wrap;word-break:break-all;">{$manual_fix_code|escape:'html':'UTF-8'}</pre>
            </div>
        {/if}

        {* ── Apply / Re-apply button ──────────────────────────────────────── *}
        <form action="" method="post">
            <button type="submit" name="apply_patches" class="btn btn-primary">
                <i class="icon-cogs"></i>
                {l s='Apply / Re-apply Patches' mod='tecno_xss_hotfix'}
            </button>
        </form>

        {* ── Forensic scan shortcut ──────────────────────────────────────── *}
        <hr style="margin:20px 0">
        <h4>
            <i class="icon-search"></i>
            {l s='Was the vulnerability exploited?' mod='tecno_xss_hotfix'}
        </h4>
        <p class="help-block">
            {l s='Scan the database tables involved in this CVE for XSS indicators of compromise (malicious email patterns in ps_customer, ps_customer_thread, ps_customer_message).' mod='tecno_xss_hotfix'}
        </p>
        <form action="" method="post">
            <button type="submit" name="go_forensic_scan" value="1" class="btn btn-warning">
                <i class="icon-search"></i>
                {l s='Run Forensic DB Scan' mod='tecno_xss_hotfix'}
            </button>
        </form>

        {* ── Footer note ─────────────────────────────────────────────────── *}
        <p class="help-block" style="margin-top:16px">
            <i class="icon-info-circle"></i>
            {l s='The template patch is PERMANENT and will NOT be reverted if this module is uninstalled. Backup files are saved with the .tecno-hotfix-backup extension next to the original file.' mod='tecno_xss_hotfix'}
        </p>

    </div>{* /panel-body *}
</div>{* /panel *}
