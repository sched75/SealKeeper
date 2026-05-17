// Package mailtemplates owns the admin-editable email bodies.
//
// PRD: FR-C.69..75 (admin surface) + FR-B.14..19 (mail shape). System
// defaults are kept here in code so a brand-new install can issue mails
// without an admin touching anything; the DB carries overrides per
// (kind, language). When a row is missing the default kicks in.
//
// The templating engine is Go's stdlib:
//   - text/template for the plain-text body and the subject line
//   - html/template for the HTML body — auto-escaping kept on, no `html`
//     pipeline tricks exposed to admins.
//
// Variables surfaced to templates are documented in Vars below (FR-C.72).
package mailtemplates

// Kind enumerates the supported template types.
type Kind string

const (
	// KindRevealLink is the email sent after POST /api/v1/request. It
	// carries the single-use reveal URL (FR-B.14..19).
	KindRevealLink Kind = "reveal_link"
	// KindPostConsultation is the optional notification mail sent after
	// the user opens the reveal page (FR-B.39..41). The system default is
	// shipped here; the matching wiring lands when the consultation
	// notification feature ships.
	KindPostConsultation Kind = "post_consultation"
)

// AllKinds returns every kind known to the package. Used by the admin
// list page so we can render rows for templates the operator hasn't
// customised yet.
func AllKinds() []Kind { return []Kind{KindRevealLink, KindPostConsultation} }

// SupportedLanguages returns the language codes the package ships defaults
// for. Admins can upload overrides for any string; only these two are
// guaranteed to have a system fallback.
func SupportedLanguages() []string { return []string{"en", "fr"} }

// defaults is the in-memory map of system templates.
//
// The keys are (kind, language). Lookup falls through to "en" when the
// requested language is missing, and to the empty string for the
// post-consultation kind (which doesn't ship a v0.1 default yet — the
// admin can still author one).
var defaults = map[Kind]map[string]systemDefault{
	KindRevealLink: {
		"en": {
			Subject: "Your SealKeeper password proposals",
			Text:    revealTextEN,
			HTML:    revealHTMLEN,
		},
		"fr": {
			Subject: "Vos propositions de mot de passe SealKeeper",
			Text:    revealTextFR,
			HTML:    revealHTMLFR,
		},
	},
	KindPostConsultation: {
		"en": {
			Subject: "Your SealKeeper password has been consulted",
			Text:    consultTextEN,
			HTML:    consultHTMLEN,
		},
		"fr": {
			Subject: "Votre mot de passe SealKeeper a été consulté",
			Text:    consultTextFR,
			HTML:    consultHTMLFR,
		},
	},
}

type systemDefault struct {
	Subject string
	Text    string
	HTML    string
}

// ---- Reveal-link templates -------------------------------------------------

const revealTextFR = `Bonjour,

Vous avez demandé un mot de passe via {{ .InstanceName }}.

Cliquez sur le lien ci-dessous pour voir vos propositions :
{{ .RevealURL }}

Validité : {{ .ValidityMinutes }} minutes à compter de l'envoi de cet email.
Usage unique : ce lien ne fonctionne qu'une seule fois.

Si vous n'avez pas demandé ce mot de passe, ignorez cet email.

Cordialement,
{{ .InstanceName }}
`

const revealHTMLFR = `<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>{{ .InstanceName }}</title></head>
<body style="font-family: Georgia, 'EB Garamond', serif; background:#F4EFE6; margin:0; padding:2rem 1rem; color:#1A1814;">
<table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" style="max-width:540px;width:100%;background:#FBF7EE;border:1px solid #E5DFD0;border-radius:2px">
<tr><td style="padding:1.75rem 1.5rem">
<h2 style="margin:0 0 0.75rem;color:#7A1F2B;font-family:Georgia,'EB Garamond',serif;font-weight:600;font-size:1.5rem;letter-spacing:-0.01em">{{ .InstanceName }}</h2>
<p style="margin:0.5rem 0;font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Vous avez demandé un mot de passe via {{ .InstanceName }}.</p>
<p style="text-align:center; margin: 2rem 0;">
  <a href="{{ .RevealURL }}"
     style="background:#7A1F2B; color:#F4EFE6; text-decoration:none; padding:0.7rem 1.4rem; border-radius:2px; display:inline-block; font-family:-apple-system,system-ui,'Segoe UI',sans-serif; font-weight:500; letter-spacing:0.01em">
    Voir mes propositions
  </a>
</p>
<p style="font-size:0.875rem;color:#7A7670;font-family:-apple-system,system-ui,'Segoe UI',sans-serif">
  Validité : {{ .ValidityMinutes }} minutes à compter de l'envoi de cet email.<br>
  Usage unique : ce lien ne fonctionne qu'une seule fois.
</p>
<p style="font-size:0.875rem;color:#7A7670;font-family:-apple-system,system-ui,'Segoe UI',sans-serif">
  Si vous n'avez pas demandé ce mot de passe, ignorez simplement cet email.
</p>
{{ if .ContactURL }}<p style="font-size:0.875rem;color:#7A7670;font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Besoin d'aide ? <a href="{{ .ContactURL }}" style="color:#1E2D45">{{ .ContactURL }}</a></p>{{ end }}
<hr style="border:0; border-top:1px solid #E5DFD0; margin:1.75rem 0;">
<p style="font-size:0.75rem; color:#7A7670; font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Powered by SealKeeper · open source · AGPL v3</p>
</td></tr></table>
</body></html>
`

const revealTextEN = `Hello,

You requested a password through {{ .InstanceName }}.

Click the link below to view your proposals:
{{ .RevealURL }}

Validity: {{ .ValidityMinutes }} minutes from the time this email was sent.
Single use: this link will only work once.

If you did not make this request, simply ignore this email.

Sincerely,
{{ .InstanceName }}
`

const revealHTMLEN = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{ .InstanceName }}</title></head>
<body style="font-family: Georgia, 'EB Garamond', serif; background:#F4EFE6; margin:0; padding:2rem 1rem; color:#1A1814;">
<table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" style="max-width:540px;width:100%;background:#FBF7EE;border:1px solid #E5DFD0;border-radius:2px">
<tr><td style="padding:1.75rem 1.5rem">
<h2 style="margin:0 0 0.75rem;color:#7A1F2B;font-family:Georgia,'EB Garamond',serif;font-weight:600;font-size:1.5rem;letter-spacing:-0.01em">{{ .InstanceName }}</h2>
<p style="margin:0.5rem 0;font-family:-apple-system,system-ui,'Segoe UI',sans-serif">You requested a password through {{ .InstanceName }}.</p>
<p style="text-align:center; margin: 2rem 0;">
  <a href="{{ .RevealURL }}"
     style="background:#7A1F2B; color:#F4EFE6; text-decoration:none; padding:0.7rem 1.4rem; border-radius:2px; display:inline-block; font-family:-apple-system,system-ui,'Segoe UI',sans-serif; font-weight:500; letter-spacing:0.01em">
    View my proposals
  </a>
</p>
<p style="font-size:0.875rem;color:#7A7670;font-family:-apple-system,system-ui,'Segoe UI',sans-serif">
  Validity: {{ .ValidityMinutes }} minutes from this email.<br>
  Single use: this link only works once.
</p>
<p style="font-size:0.875rem;color:#7A7670;font-family:-apple-system,system-ui,'Segoe UI',sans-serif">
  If you did not make this request, simply ignore this email.
</p>
{{ if .ContactURL }}<p style="font-size:0.875rem;color:#7A7670;font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Need help? <a href="{{ .ContactURL }}" style="color:#1E2D45">{{ .ContactURL }}</a></p>{{ end }}
<hr style="border:0; border-top:1px solid #E5DFD0; margin:1.75rem 0;">
<p style="font-size:0.75rem; color:#7A7670; font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Powered by SealKeeper · open source · AGPL v3</p>
</td></tr></table>
</body></html>
`

// ---- Post-consultation templates (FR-B.39..41) -----------------------------

const consultTextFR = `Bonjour,

Votre mot de passe SealKeeper a été consulté :

Date    : {{ .ConsultedAt }}
IP      : {{ .ConsultedIP }}
Navigateur : {{ .ConsultedUserAgent }}

Si cette consultation vous est inconnue, contactez votre administrateur :
{{ .ContactURL }}

Cordialement,
{{ .InstanceName }}
`

const consultHTMLFR = `<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>{{ .InstanceName }}</title></head>
<body style="font-family: Georgia, 'EB Garamond', serif; background:#F4EFE6; margin:0; padding:2rem 1rem; color:#1A1814;">
<table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" style="max-width:540px;width:100%;background:#FBF7EE;border:1px solid #E5DFD0;border-radius:2px">
<tr><td style="padding:1.75rem 1.5rem">
<h2 style="margin:0 0 0.75rem;color:#7A1F2B;font-family:Georgia,'EB Garamond',serif;font-weight:600;font-size:1.5rem;letter-spacing:-0.01em">{{ .InstanceName }}</h2>
<p style="font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Votre mot de passe SealKeeper a été consulté.</p>
<ul style="font-family:-apple-system,system-ui,'Segoe UI',sans-serif">
  <li><strong>Date :</strong> {{ .ConsultedAt }}</li>
  <li><strong>IP :</strong> {{ .ConsultedIP }}</li>
  <li><strong>Navigateur :</strong> {{ .ConsultedUserAgent }}</li>
</ul>
{{ if .ContactURL }}<p style="font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Si cette consultation vous est inconnue, contactez votre administrateur : <a href="{{ .ContactURL }}" style="color:#1E2D45">{{ .ContactURL }}</a></p>{{ end }}
<hr style="border:0; border-top:1px solid #E5DFD0; margin:1.75rem 0;">
<p style="font-size:0.75rem; color:#7A7670; font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Powered by SealKeeper · open source · AGPL v3</p>
</td></tr></table>
</body></html>
`

const consultTextEN = `Hello,

Your SealKeeper password has been consulted:

Date       : {{ .ConsultedAt }}
IP         : {{ .ConsultedIP }}
User agent : {{ .ConsultedUserAgent }}

If you don't recognise this access, contact your administrator:
{{ .ContactURL }}

Sincerely,
{{ .InstanceName }}
`

const consultHTMLEN = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{ .InstanceName }}</title></head>
<body style="font-family: Georgia, 'EB Garamond', serif; background:#F4EFE6; margin:0; padding:2rem 1rem; color:#1A1814;">
<table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" style="max-width:540px;width:100%;background:#FBF7EE;border:1px solid #E5DFD0;border-radius:2px">
<tr><td style="padding:1.75rem 1.5rem">
<h2 style="margin:0 0 0.75rem;color:#7A1F2B;font-family:Georgia,'EB Garamond',serif;font-weight:600;font-size:1.5rem;letter-spacing:-0.01em">{{ .InstanceName }}</h2>
<p style="font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Your SealKeeper password has been consulted.</p>
<ul style="font-family:-apple-system,system-ui,'Segoe UI',sans-serif">
  <li><strong>Date:</strong> {{ .ConsultedAt }}</li>
  <li><strong>IP:</strong> {{ .ConsultedIP }}</li>
  <li><strong>User agent:</strong> {{ .ConsultedUserAgent }}</li>
</ul>
{{ if .ContactURL }}<p style="font-family:-apple-system,system-ui,'Segoe UI',sans-serif">If you don't recognise this access, contact your administrator: <a href="{{ .ContactURL }}" style="color:#1E2D45">{{ .ContactURL }}</a></p>{{ end }}
<hr style="border:0; border-top:1px solid #E5DFD0; margin:1.75rem 0;">
<p style="font-size:0.75rem; color:#7A7670; font-family:-apple-system,system-ui,'Segoe UI',sans-serif">Powered by SealKeeper · open source · AGPL v3</p>
</td></tr></table>
</body></html>
`
