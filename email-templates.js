'use strict';

/**
 * Escapes a string for safe interpolation into HTML.
 */
function escapeHtml(str) {
    return String(str == null ? '' : str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * Builds the GDREVIEW dark-themed transactional email used for both the
 * registration verification code and the password reset code.
 *
 * @param {Object} opts
 * @param {string} opts.code            The 6-digit code (or similar) to display.
 * @param {string} [opts.headline]      Big headline under the logo.
 * @param {string} [opts.intro]         One or two sentence explanation shown above the code.
 * @param {number} [opts.expiresMinutes] Code validity window, in minutes.
 * @param {string} [opts.preheader]     Hidden preview text shown in inbox lists.
 * @returns {string} full HTML document
 */
function buildCodeEmail(opts) {
    const {
        code,
        headline = 'Confirm Your Email',
        intro = "We received a request to verify your email address and complete your GDREVIEW registration. Enter the code below to continue.",
        expiresMinutes = 10,
        preheader = 'Your GDREVIEW verification code is ready — enter it to continue. This code expires soon, so use it right away.',
        ip = null,
    } = opts || {};

    const safeCode = escapeHtml(code);
    const safeHeadline = escapeHtml(headline);
    const safeIntro = escapeHtml(intro);
    const safePreheader = escapeHtml(preheader);
    const safeMinutes = escapeHtml(String(expiresMinutes));
    const safeIp = ip ? escapeHtml(ip) : null;
    const requestedAt = new Date().toUTCString().replace(' GMT', ' UTC');

    const securityLine = safeIp
        ? `<p style="margin:10px 0 0 0; font-family:'Courier New', Courier, monospace; font-size:12px; line-height:18px; color:#585858;">Request origin: ${safeIp} &middot; ${escapeHtml(requestedAt)}</p>`
        : '';

    return `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="color-scheme" content="dark light">
<meta name="supported-color-schemes" content="dark light">
<title>${safeHeadline}</title>
<!--[if mso]>
<noscript>
<xml>
<o:OfficeDocumentSettings>
<o:PixelsPerInch>96</o:PixelsPerInch>
</o:OfficeDocumentSettings>
</xml>
</noscript>
<style>
  table {border-collapse: collapse;}
  td, th, div, p, a, span {font-family: Arial, Helvetica, sans-serif;}
</style>
<![endif]-->
<style>
  html, body { margin:0 !important; padding:0 !important; height:100% !important; width:100% !important; background-color:#0a0a0a; }
  * { -ms-text-size-adjust:100%; -webkit-text-size-adjust:100%; }
  div[style*="margin: 16px 0"] { margin:0 !important; }
  table, td { mso-table-lspace:0pt; mso-table-rspace:0pt; }
  img { border:0; height:auto; line-height:100%; outline:none; text-decoration:none; -ms-interpolation-mode:bicubic; }
  a[x-apple-data-detectors] { color:inherit !important; text-decoration:none !important; font-size:inherit !important; font-family:inherit !important; font-weight:inherit !important; line-height:inherit !important; }
  #MessageViewBody a { color:inherit; text-decoration:none; }
  p { margin:0; }

  @media only screen and (max-width:600px) {
    .gd-wrapper { width:100% !important; }
    .gd-container { width:100% !important; }
    .gd-px { padding-left:20px !important; padding-right:20px !important; }
    .gd-code-value { font-size:34px !important; letter-spacing:8px !important; }
    .gd-h1 { font-size:22px !important; }
    .gd-logo-text { font-size:20px !important; }
  }
</style>
</head>
<body style="margin:0; padding:0; background-color:#0a0a0a; width:100%;">
<div style="display:none; max-height:0; overflow:hidden; mso-hide:all; font-size:1px; line-height:1px; color:#0a0a0a; opacity:0;">
  ${safePreheader}
&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0a0a0a;">
  <tr>
    <td align="center" style="padding:40px 16px;">

      <!--[if mso]>
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"><tr><td>
      <![endif]-->
      <table role="presentation" class="gd-container" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px; max-width:600px; background-color:#111111;">

        <!-- Top accent line -->
        <tr>
          <td style="height:3px; line-height:3px; font-size:0; background-color:#f4f4f4;">&nbsp;</td>
        </tr>

        <!-- Logo -->
        <tr>
          <td align="center" class="gd-px" style="padding:40px 32px 28px 32px;">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td style="font-family:'Archivo Black', Arial Black, Arial, sans-serif; font-size:22px; font-weight:900; letter-spacing:1px; color:#f4f4f4; text-transform:uppercase;" class="gd-logo-text">
                  GD<span style="color:#6b6b6b;">REVIEW</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Divider -->
        <tr>
          <td style="padding:0 32px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr><td style="border-top:1px solid #262626; font-size:0; line-height:0;">&nbsp;</td></tr>
            </table>
          </td>
        </tr>

        <!-- Headline -->
        <tr>
          <td align="center" class="gd-px" style="padding:40px 40px 8px 40px;">
            <p class="gd-h1" style="margin:0; font-family:'Archivo Black', Arial Black, Arial, sans-serif; font-size:26px; line-height:1.25; font-weight:900; letter-spacing:-0.3px; color:#f4f4f4; text-transform:uppercase;">
              ${safeHeadline}
            </p>
          </td>
        </tr>

        <!-- Greeting / body copy -->
        <tr>
          <td align="center" class="gd-px" style="padding:14px 44px 0 44px;">
            <p style="margin:0; font-family:Arial, Helvetica, sans-serif; font-size:15px; line-height:24px; color:#a3a3a3;">
              Hi there,
            </p>
            <p style="margin:14px 0 0 0; font-family:Arial, Helvetica, sans-serif; font-size:15px; line-height:24px; color:#a3a3a3;">
              ${safeIntro}
            </p>
          </td>
        </tr>

        <!-- Code card -->
        <tr>
          <td align="center" class="gd-px" style="padding:34px 32px 10px 32px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#161616; border:1px solid #2b2b2b; border-radius:14px;">
              <tr>
                <td align="center" style="padding:32px 24px;">
                  <p style="margin:0 0 14px 0; font-family:'Courier New', Courier, monospace; font-size:11px; line-height:1; letter-spacing:3px; text-transform:uppercase; color:#6b6b6b;">
                    Your Verification Code
                  </p>
                  <p class="gd-code-value" style="margin:0; font-family:'Courier New', Courier, monospace; font-size:44px; line-height:1.1; font-weight:700; letter-spacing:14px; color:#ffffff;">
                    ${safeCode}
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Expiry note -->
        <tr>
          <td align="center" class="gd-px" style="padding:20px 44px 0 44px;">
            <p style="margin:0; font-family:Arial, Helvetica, sans-serif; font-size:13px; line-height:20px; color:#6b6b6b;">
              This code expires in <span style="color:#c9c9c9; font-weight:bold;">${safeMinutes} minutes</span>. Please don't share it with anyone.
            </p>
          </td>
        </tr>

        <!-- Security notice -->
        <tr>
          <td align="center" class="gd-px" style="padding:28px 44px 0 44px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-left:2px solid #333333;">
              <tr>
                <td style="padding:2px 0 2px 16px; text-align:left;">
                  <p style="margin:0; font-family:Arial, Helvetica, sans-serif; font-size:13px; line-height:20px; color:#6b6b6b;">
                    Didn't request this? No action is needed — you can safely ignore this email and your account will remain unaffected.
                  </p>
                  ${securityLine}
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Spacer -->
        <tr>
          <td style="padding-top:44px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr><td style="border-top:1px solid #202020; font-size:0; line-height:0;">&nbsp;</td></tr>
            </table>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td align="center" class="gd-px" style="padding:28px 40px 8px 40px;">
            <p style="margin:0; font-family:Arial, Helvetica, sans-serif; font-size:11px; line-height:18px; color:#5a5a5a;">
              To help ensure you receive emails from GDREVIEW, please add
              <a href="mailto:noreply@gdreview.com" style="color:#8f8f8f; text-decoration:underline;">noreply@gdreview.com</a>
              to your address book or safe sender list.
            </p>
            <p style="margin:12px 0 0 0; font-family:Arial, Helvetica, sans-serif; font-size:11px; line-height:18px; color:#5a5a5a;">
              We respect your privacy and your email address. We will never sell, rent, or share your personal information with third parties without your consent.
            </p>
            <p style="margin:12px 0 0 0; font-family:Arial, Helvetica, sans-serif; font-size:11px; line-height:18px; color:#5a5a5a;">
              Official emails from GDREVIEW will always address you by your account name. They will never include file attachments, request sensitive personal information via email, or contain links to websites other than
              <a href="https://gdreview.com" style="color:#8f8f8f; text-decoration:underline;">https://gdreview.com</a>.
            </p>
          </td>
        </tr>

        <!-- Bottom divider + copyright -->
        <tr>
          <td align="center" class="gd-px" style="padding:20px 40px 34px 40px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr><td style="border-top:1px solid #202020; font-size:0; line-height:0; padding-bottom:18px;">&nbsp;</td></tr>
            </table>
            <p style="margin:0; font-family:Arial, Helvetica, sans-serif; font-size:11px; line-height:18px; color:#4a4a4a;">
              <a href="https://gdreview.com" style="color:#4a4a4a; text-decoration:none;">https://gdreview.com</a>
            </p>
            <p style="margin:4px 0 0 0; font-family:Arial, Helvetica, sans-serif; font-size:11px; line-height:18px; color:#4a4a4a;">
              &copy; ${new Date().getFullYear()} GDREVIEW Inc. All rights reserved.
            </p>
          </td>
        </tr>

      </table>
      <!--[if mso]>
      </td></tr></table>
      <![endif]-->

    </td>
  </tr>
</table>
</body>
</html>`;
}

/**
 * Plain-text fallback for clients that strip HTML.
 */
function buildCodeEmailText({ code, headline = 'Confirm Your Email', intro, expiresMinutes = 10, ip = null }) {
    const lines = [
        `GDREVIEW — ${headline}`,
        '',
        intro || `Your GDREVIEW verification code:`,
        '',
        `Code: ${code}`,
        '',
        `This code expires in ${expiresMinutes} minutes. Please don't share it with anyone.`,
        `Didn't request this? You can safely ignore this email.`,
    ];
    if (ip) lines.push(`Request origin: ${ip} · ${new Date().toUTCString().replace(' GMT', ' UTC')}`);
    lines.push('', 'https://gdreview.com', `© ${new Date().getFullYear()} GDREVIEW Inc. All rights reserved.`);
    return lines.join('\n');
}

module.exports = { buildCodeEmail, buildCodeEmailText };
