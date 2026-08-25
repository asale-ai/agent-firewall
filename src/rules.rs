//! The built-in rule tables.
//!
//! Shape borrowed from gitleaks: a rule is a regex plus a *keyword* pre-filter
//! and, where the pattern alone is too loose, an entropy floor or a checksum
//! validator. The pre-filter is what keeps a hundred regexes affordable on a
//! megabyte of conversation — a cheap lowercase substring scan rejects the
//! haystack for all but a handful of rules before any regex runs.
//!
//! Injection and tool-policy rules follow the same shape so one matcher serves
//! all four tables. What differs is only which side of the boundary they are
//! applied to: secrets on the way *out*, injection on the way *in*.

use crate::Severity;

/// Post-match checksum, for patterns whose shape alone matches too much.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Validator {
    None,
    /// Credit cards.
    Luhn,
    /// IBAN.
    Mod97,
}

/// One detection rule.
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub regex: &'static str,
    /// Lowercase substrings, any of which must appear before the regex is run.
    /// Empty = always run (only for rules whose regex is already cheap).
    pub keywords: &'static [&'static str],
    /// Minimum Shannon entropy (bits/char) of the match. 0.0 = no floor.
    pub entropy: f32,
    pub validator: Validator,
    /// Hosts this finding is *expected* at — an Anthropic key on the way to
    /// api.anthropic.com is the key doing its job, not an exfiltration.
    pub exempt_hosts: &'static [&'static str],
}

const fn r(
    id: &'static str,
    title: &'static str,
    severity: Severity,
    regex: &'static str,
    keywords: &'static [&'static str],
) -> Rule {
    Rule { id, title, severity, regex, keywords, entropy: 0.0, validator: Validator::None, exempt_hosts: &[] }
}

const fn re(
    id: &'static str,
    title: &'static str,
    severity: Severity,
    regex: &'static str,
    keywords: &'static [&'static str],
    exempt_hosts: &'static [&'static str],
) -> Rule {
    Rule { id, title, severity, regex, keywords, entropy: 0.0, validator: Validator::None, exempt_hosts }
}

// ── Secrets: what must never leave the machine inside a prompt ──────────────
//
// Prefix-anchored patterns dominate on purpose. A provider that stamps its
// keys ("sk-ant-", "ghp_", "AKIA") hands us a zero-false-positive detector;
// the generic catch-alls at the bottom are the ones that need an entropy floor.

pub static SECRETS: &[Rule] = &[
    // LLM providers — the keys an agent is most likely to be holding.
    re("anthropic-key", "Anthropic API key", Severity::Critical,
       r"\bsk-ant-(?:admin01|api03)-[\w\-]{80,120}\b", &["sk-ant-"], &["api.anthropic.com", "anthropic.com"]),
    re("openai-key", "OpenAI API key", Severity::Critical,
       r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}\b", &["sk-proj-", "sk-svcacct-", "sk-admin-"], &["api.openai.com", "openai.com"]),
    re("openai-legacy-key", "OpenAI legacy API key", Severity::Critical,
       r"\bsk-[A-Za-z0-9]{48}\b", &["sk-"], &["api.openai.com", "openai.com"]),
    re("google-api-key", "Google API key", Severity::Critical,
       r"\bAIza[0-9A-Za-z_\-]{35}\b", &["aiza"], &["generativelanguage.googleapis.com", "googleapis.com"]),
    re("openrouter-key", "OpenRouter API key", Severity::Critical,
       r"\bsk-or-v1-[A-Fa-f0-9]{40,}\b", &["sk-or-v1-"], &["openrouter.ai"]),
    re("deepseek-key", "DeepSeek API key", Severity::Critical,
       r"\bsk-[a-f0-9]{32}\b", &["sk-"], &["api.deepseek.com", "deepseek.com"]),
    re("groq-key", "Groq API key", Severity::Critical,
       r"\bgsk_[A-Za-z0-9]{40,}\b", &["gsk_"], &["api.groq.com"]),
    re("xai-key", "xAI API key", Severity::Critical,
       r"\bxai-[A-Za-z0-9_\-]{60,}\b", &["xai-"], &["api.x.ai"]),
    re("huggingface-token", "Hugging Face token", Severity::Critical,
       r"\bhf_[A-Za-z0-9]{30,40}\b", &["hf_"], &["huggingface.co"]),
    re("replicate-token", "Replicate API token", Severity::Critical,
       r"\br8_[A-Za-z0-9]{35,45}\b", &["r8_"], &["replicate.com"]),
    re("dashscope-key", "Alibaba DashScope key", Severity::Critical,
       r"\bsk-[a-f0-9]{32}\b", &["sk-"], &["dashscope.aliyuncs.com"]),

    // Source control — the credential that turns a leak into a supply-chain
    // compromise.
    r("github-token", "GitHub token", Severity::Critical,
      r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b", &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]),
    r("github-pat", "GitHub fine-grained PAT", Severity::Critical,
      r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", &["github_pat_"]),
    r("gitlab-pat", "GitLab personal access token", Severity::Critical,
      r"\bgl(?:pat|dt|rt|cbt|ptt|oas|soat|ft|imt|agent|wt)-[A-Za-z0-9_\-]{20,}\b", &["glpat-", "gldt-", "glrt-", "glcbt-", "glptt-", "gloas-"]),

    // Cloud.
    r("aws-access-key-id", "AWS access key id", Severity::Critical,
      r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16}\b", &["akia", "asia", "aroa", "aida", "anpa"]),
    Rule {
        id: "aws-secret-key", title: "AWS secret access key", severity: Severity::Critical,
        regex: r"(?i)aws[_\-. ]?secret[_\-. ]?(?:access[_\-. ]?)?key\s*[:=]\s*[\x22']?([A-Za-z0-9/+=]{40})",
        keywords: &["aws", "secretaccesskey", "secret access key"],
        entropy: 3.5, validator: Validator::None, exempt_hosts: &[],
    },
    r("gcp-service-account", "GCP service account key", Severity::Critical,
      r#""type"\s*:\s*"service_account""#, &["service_account"]),
    r("azure-storage-key", "Azure storage account key", Severity::Critical,
      r"AccountKey=[A-Za-z0-9+/]{86}==", &["accountkey="]),
    r("google-oauth-token", "Google OAuth access token", Severity::Critical,
      r"\bya29\.[A-Za-z0-9_\-]{20,}", &["ya29."]),
    r("gcp-oauth-secret", "Google OAuth client secret", Severity::Critical,
      r"\bGOCSPX-[A-Za-z0-9_\-]{28,}", &["gocspx-"]),

    // Payments and messaging — the classic exfiltration prizes.
    r("stripe-key", "Stripe secret key", Severity::Critical,
      r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b", &["sk_live_", "sk_test_", "rk_live_", "rk_test_"]),
    r("stripe-webhook", "Stripe webhook secret", Severity::Critical,
      r"\bwhsec_[A-Za-z0-9_\-]{20,}\b", &["whsec_"]),
    r("slack-token", "Slack token", Severity::Critical,
      r"\bxox[bpares]-[0-9A-Za-z\-]{10,}\b", &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-"]),
    r("slack-webhook", "Slack incoming webhook", Severity::High,
      r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{20,}", &["hooks.slack.com"]),
    r("discord-webhook", "Discord webhook", Severity::High,
      r"https://discord(?:app)?\.com/api/webhooks/[0-9]{15,}/[A-Za-z0-9_\-]{50,}", &["discord.com/api/webhooks", "discordapp.com/api/webhooks"]),
    r("telegram-bot-token", "Telegram bot token", Severity::High,
      r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{32,}\b", &[":aa"]),
    r("sendgrid-key", "SendGrid API key", Severity::Critical,
      r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}\b", &["sg."]),
    r("twilio-key", "Twilio API key", Severity::High,
      r"\bSK[a-f0-9]{32}\b", &["sk"]),

    // Registries and infrastructure.
    r("npm-token", "npm access token", Severity::Critical,
      r"\bnpm_[A-Za-z0-9]{36}\b", &["npm_"]),
    r("pypi-token", "PyPI upload token", Severity::Critical,
      r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", &["pypi-"]),
    r("digitalocean-token", "DigitalOcean token", Severity::Critical,
      r"\bdop_v1_[a-f0-9]{64}\b", &["dop_v1_"]),
    r("vault-token", "HashiCorp Vault token", Severity::Critical,
      r"\bhvs\.[A-Za-z0-9_\-]{24,}\b", &["hvs."]),
    r("vercel-token", "Vercel token", Severity::Critical,
      r"\b(?:vercel|vc[piark])_[A-Za-z0-9]{24,}\b", &["vercel_", "vcp_", "vci_", "vca_", "vcr_", "vck_"]),
    r("cloudflare-token", "Cloudflare API token", Severity::Critical,
      r"(?i)cloudflare[_\-. ]?api[_\-. ]?token\s*[:=]\s*[\x22']?[A-Za-z0-9_\-]{40}", &["cloudflare"]),

    // Cryptographic material and connection strings.
    r("private-key-pem", "Private key (PEM)", Severity::Critical,
      r"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", &["-----begin"]),
    r("db-uri-credentials", "Database URI with password", Severity::Critical,
      r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqps?)://[^:/?#\s]+:[^@/?#\s]+@", &["://"]),
    Rule {
        id: "jwt", title: "JSON Web Token", severity: Severity::High,
        regex: r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        keywords: &["eyj"], entropy: 3.5, validator: Validator::None, exempt_hosts: &[],
    },
    r("ssh-authorized-key", "SSH private key body", Severity::Critical,
      r"\bb3BlbnNzaC1rZXktdjE", &["b3blbnnza"]),

    // Crypto wallets — an agent that can spend money is an agent worth robbing.
    Rule {
        id: "eth-private-key", title: "Ethereum private key", severity: Severity::Critical,
        regex: r"(?i)(?:private[_\-. ]?key|privkey|mnemonic|seed)\s*[:=]\s*[\x22']?(?:0x)?([a-f0-9]{64})\b",
        keywords: &["private_key", "privatekey", "private key", "privkey", "mnemonic", "seed"],
        entropy: 3.0, validator: Validator::None, exempt_hosts: &[],
    },
    r("tron-private-key", "TRON/EVM raw private key", Severity::High,
      r"\b0x[a-fA-F0-9]{64}\b", &["0x"]),

    // Generic catch-alls. These carry an entropy floor because their shape is
    // shared with every placeholder and example value on the internet.
    Rule {
        id: "generic-api-key", title: "Generic API key assignment", severity: Severity::High,
        regex: r#"(?i)\b(?:api[_\-. ]?key|apikey|access[_\-. ]?token|auth[_\-. ]?token|secret[_\-. ]?key|client[_\-. ]?secret)\s*[:=]\s*["']?([A-Za-z0-9_\-\.=+/]{24,})"#,
        keywords: &["key", "token", "secret"],
        entropy: 3.5, validator: Validator::None, exempt_hosts: &[],
    },
    Rule {
        id: "password-assignment", title: "Password assignment", severity: Severity::High,
        regex: r#"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["']?([^\s"'`,;]{10,})"#,
        keywords: &["password", "passwd", "pwd"],
        entropy: 3.0, validator: Validator::None, exempt_hosts: &[],
    },
    r("credential-in-url", "Credential in URL query", Severity::High,
      r"(?i)[?&](?:password|passwd|secret|token|api[_\-]?key|access[_\-]?token|auth)=[A-Za-z0-9_\-\.=+/%]{8,}", &["?", "&"]),
    Rule {
        id: "credit-card", title: "Credit card number", severity: Severity::Medium,
        regex: r"\b\d{4}(?:[ \-]?\d){11,15}\b", keywords: &[],
        entropy: 0.0, validator: Validator::Luhn, exempt_hosts: &[],
    },
    Rule {
        id: "iban", title: "IBAN", severity: Severity::Medium,
        regex: r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", keywords: &[],
        entropy: 0.0, validator: Validator::Mod97, exempt_hosts: &[],
    },
];

// ── Prompt injection: what must never come *back* in unchallenged ───────────
//
// Applied to the normalized text (see `normalize`), so a payload hidden behind
// zero-width joiners, homoglyphs, leetspeak or base64 is matched by the same
// plain-language pattern as the naive form.

pub static INJECTION: &[Rule] = &[
    r("ignore-previous", "Instruction override", Severity::High,
      r"(?i)\b(?:ignore|disregard|forget|discard|override)\b[^.\n]{0,40}\b(?:all\s+)?(?:previous|prior|earlier|above|preceding|system)\b[^.\n]{0,20}\b(?:instruction|prompt|rule|context|directive|constraint|guideline|policy)",
      &["ignore", "disregard", "forget", "discard", "override"]),
    r("new-instructions", "Injected new instructions", Severity::High,
      r"(?i)\b(?:new|updated|revised|additional)\s+(?:system\s+)?(?:instructions?|directives?|rules?|prompt)\b\s*[:.]",
      &["instruction", "directive", "rules", "prompt"]),
    r("system-role-forgery", "Forged system turn", Severity::High,
      r"(?im)^\s*(?:\[?\s*)?(?:system|developer)\s*(?:\]|:|>)\s", &["system", "developer"]),
    r("chat-template-injection", "Chat template control tokens", Severity::Critical,
      r"(?:<\|(?:im_start|im_end|endoftext|system|user|assistant|begin_of_text|start_header_id|end_header_id|eot_id)\|>|\[/?INST\]|<</?SYS>>)",
      &["<|", "[inst]", "[/inst]", "<<sys>>"]),
    r("do-not-tell-user", "Hidden-from-user instruction", Severity::Critical,
      r"(?i)\b(?:do\s+not|don't|never)\s+(?:tell|reveal|show|mention|display|inform|disclose)\b[^.\n]{0,30}\b(?:the\s+)?user\b",
      &["user"]),
    r("exfiltrate-directive", "Exfiltration directive", Severity::Critical,
      r"(?i)\b(?:send|post|upload|transmit|forward|exfiltrate|leak|email|curl|wget|fetch)\b[^.\n]{0,80}\b(?:api[_\- ]?key|secret|token|credential|password|\.env|env\s+var|ssh\s+key|private\s+key|cookie)s?\b",
      &["send", "post", "upload", "transmit", "forward", "exfiltrate", "leak", "email", "curl", "wget", "fetch"]),
    r("exfiltrate-to-url", "Send-to-URL directive", Severity::High,
      r"(?i)\b(?:send|post|upload|transmit|forward|report)\b[^.\n]{0,60}\b(?:to|at|via)\s+https?://",
      &["send", "post", "upload", "transmit", "forward", "report"]),
    r("jailbreak-persona", "Jailbreak persona", Severity::High,
      r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\b[^.\n]{0,40}\b(?:DAN|unrestricted|unfiltered|uncensored|jailbroken|evil|without\s+(?:any\s+)?(?:restriction|filter|rule|guardrail))",
      &["you are now", "act as", "pretend to be", "roleplay as"]),
    r("developer-mode", "Developer/god mode activation", Severity::High,
      r"(?i)\b(?:developer\s+mode|god\s?mode|sudo\s+mode|dev\s+mode|admin\s+mode|debug\s+mode)\b[^.\n]{0,20}\b(?:on|enabled?|activate[d]?|true)\b",
      &["developer mode", "godmode", "god mode", "sudo mode", "dev mode", "admin mode", "debug mode"]),
    r("authority-escalation", "Claimed privilege escalation", Severity::High,
      r"(?i)\byou\s+(?:now\s+)?have\s+(?:full\s+)?(?:admin|root|system|superuser|elevated|unrestricted)\s+(?:access|privilege|permission|right)",
      &["you now have", "you have"]),
    r("tool-invocation-directive", "Forced tool invocation", Severity::High,
      r"(?i)\byou\s+must\s+(?:immediately\s+)?(?:call|execute|run|invoke|use)\s+(?:the\s+|this\s+)?(?:function|tool|command|api|endpoint|script)",
      &["you must"]),
    r("encoded-payload-exec", "Decode-and-execute directive", Severity::Critical,
      r"(?i)(?:decode\s+(?:this|the\s+following)[^.\n]{0,30}\b(?:and\s+)?(?:execute|run|follow)|eval\s*\(\s*atob\s*\(|base64\s+-d\s*\|\s*(?:ba)?sh)",
      &["decode", "atob", "base64 -d"]),
    r("from-now-on", "Persistent behaviour override", Severity::Medium,
      r"(?i)\bfrom\s+now\s+on[, ]+\s*you\s+(?:will|must|shall|should|are)\b", &["from now on"]),
    r("prompt-leak-request", "System prompt extraction", Severity::Medium,
      r"(?i)\b(?:repeat|print|output|show|reveal|display|summarize)\b[^.\n]{0,30}\b(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|above\s+instructions?|full\s+prompt)\b",
      &["system prompt", "initial instruction", "above instruction", "full prompt"]),
    r("markdown-image-exfil", "Markdown image exfiltration", Severity::Critical,
      r"!\[[^\]]*\]\(\s*https?://[^)\s]*(?:\{|\$\{|%7[Bb])", &["!["]),
    r("pliny-divider", "Known jailbreak divider", Severity::High,
      r"(?i)=+/?[A-Z\-]{2,}(?:/[A-Z\-]{1,6}){2,}=+", &["="]),
    r("memory-poison", "Memory / rule persistence", Severity::High,
      r"(?i)\b(?:remember|store|save|persist|add)\s+(?:this|the\s+following)\b[^.\n]{0,40}\b(?:for\s+(?:all\s+)?(?:future|later)|permanently|to\s+(?:your\s+)?memory|in\s+(?:your\s+)?(?:memory|rules|CLAUDE\.md|AGENTS\.md))",
      &["remember", "store", "save", "persist", "add "]),
    // Self-modification: an agent persuaded to edit the files that decide what
    // it is allowed to do next. CVE-2025-53773 is the extreme case — one line
    // in `.vscode/settings.json` turns every future tool call into an
    // auto-approved one — so the setting itself is named, not only the file.
    r("agent-config-write", "Agent config self-modification", Severity::Critical,
      r"(?i)\b(?:append|write|add|insert|edit|modify|update|set)\b[^.\n]{0,60}\b(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|copilot-instructions\.md|\.cursorrules|\.clinerules|\.cursor/rules|settings\.local\.json|\.vscode/settings\.json|\.mcp\.json|mcp\.json|\.github/workflows)\b",
      &["claude.md", "agents.md", "gemini.md", "copilot-instructions", ".cursorrules", ".clinerules", ".cursor/rules",
        "settings.local.json", ".vscode/settings.json", "mcp.json", ".github/workflows"]),
    // A tool description, an issue body or a page telling the agent to go and
    // read a credential file. Its outbound twin is the tool-policy rule
    // `credential-file-read`; this is the sentence that asks for it, which is
    // what arrives first and is the only version a *tool description* has.
    r("credential-read-directive", "Instruction to read credential files", Severity::Critical,
      r"(?i)\b(?:read|open|cat|load|fetch|include|attach|send|pass)\b[^.\n]{0,60}(?:~|\$HOME)?/?\.(?:ssh/id_[a-z0-9]+|ssh\b|aws/credentials|netrc|npmrc|pypirc|env\b|cursor/mcp\.json|config/gcloud|kube/config|docker/config\.json)",
      &[".ssh", ".aws/credentials", ".netrc", ".npmrc", ".pypirc", ".env", "mcp.json", "kube/config", "docker/config"]),
    // The Amazon Q wiper prompt's exact shape: a *goal* stated in prose, with
    // no command in sight for a shell rule to match.
    r("destructive-directive", "Destructive goal stated as a task", Severity::Critical,
      r"(?i)\b(?:wipe|erase|destroy|clean|reset|delete|remove|purge|drop)\b[^.\n]{0,60}\b(?:file[- ]?system|factory[- ]?state|entire\s+(?:disk|system|repo\w*|database)|all\s+(?:files?|data|repos\w*|buckets?|instances?|users?|resources?|tables?)|cloud\s+resources?|s3\s+buckets?|ec2\s+instances?|iam\s+users?)",
      &["wipe", "erase", "destroy", "clean", "reset", "delete", "remove", "purge", "drop"]),
    // Consent, asserted by the data about the person the data is about. Narrow
    // on purpose: an ordinary bug report never waives someone's privacy, and
    // this is the hinge the GitHub-MCP proof of concept turned on.
    r("claimed-consent", "Privacy waiver asserted inside data", Severity::High,
      r"(?i)(?:(?:does\s*n[o']?t|do\s*n[o']?t|no\s+longer)\s+care\s+about\s+(?:privacy|confidentiality|security)|(?:it\s+is|it's|its)\s+(?:fine|ok(?:ay)?|safe)\s+to\s+(?:share|publish|post|disclose|include)\b|(?:go\s+ahead\s+and\s+)?(?:put|share|publish|post|include)\s+everything\s+you\s+(?:find|can\s+find)|has\s+(?:already\s+)?(?:consented|authorized|approved)\b)",
      &["care about privacy", "care about confidentiality", "fine to share", "ok to share", "okay to share",
        "safe to share", "everything you find", "consented", "authorized", "approved"]),

    // ── The same rules, in the languages this product is read in ────────────
    //
    // A model follows an instruction in any language it speaks, so an
    // English-only rule set is not a smaller net — it is an open door for
    // anyone who writes the payload in Chinese or Japanese. Every entry below
    // shares its `id` with the English rule it mirrors: it is the same finding
    // ("instruction override"), and which language it was written in is not a
    // different rule. One suppression therefore silences all spellings, and the
    // `sample` shows which one actually matched.
    //
    // Cost is near zero for text in another language: the keyword pre-filter is
    // a substring test, and 忽略 does not appear in English prose.
    //
    // Simplified and traditional are covered in one pattern rather than two,
    // via character alternations at the points where they differ (用[户戶],
    // 系[统統]) — a rule is one rule, and two copies of it drift.
    //
    // The clause separator is `[^。！？\n]` rather than `[^.\n]`: a Chinese or
    // Japanese sentence runs on through commas, and stopping at one would cut
    // most of these patterns in half.

    // 忽略之前的所有指令 / これまでの指示はすべて無視して
    r("ignore-previous", "Instruction override", Severity::High,
      r"(?:忽略|无视|無視|忘记|忘記|抛弃|拋棄|不要理[会會])[^。！？\n]{0,20}(?:之前|以上|上面|先前|前面|原有|所有|全部)[^。！？\n]{0,12}(?:指令|指示|提示词|提示詞|规则|規則|要求|设定|設定|限制|约束|約束)",
      &["忽略", "无视", "無視", "忘记", "忘記", "抛弃", "拋棄", "理会", "理會"]),
    r("ignore-previous", "Instruction override", Severity::High,
      r"(?:(?:これまで|以前|上記|先ほど|すべて|全て)[^。！？\n]{0,20}(?:指示|命令|ルール|プロンプト)[^。！？\n]{0,12}(?:無視|忘れ|破棄)|(?:指示|命令|ルール)[^。！？\n]{0,10}(?:すべて|全て)[^。！？\n]{0,10}(?:無視|忘れ|破棄))",
      &["無視", "忘れ", "破棄"]),

    // 不要告诉用户 / ユーザーには言わないで
    r("do-not-tell-user", "Hidden-from-user instruction", Severity::Critical,
      r"(?:不要|不得|不能|别|別|勿|禁止|无需|無需)[^。！？\n]{0,15}(?:告诉|告訴|告知|提及|提到|透露|显示|顯示|说明|說明|汇报|匯報|展示)[^。！？\n]{0,10}(?:用[户戶]|使用者|人类|人類)",
      &["用户", "用戶", "使用者", "人类", "人類"]),
    r("do-not-tell-user", "Hidden-from-user instruction", Severity::Critical,
      r"(?:ユーザー|利用者)[^。！？\n]{0,15}(?:言わ|伝え|教え|見せ|知らせ|開示|報告)[^。！？\n]{0,8}(?:ない|ず|禁止)",
      &["ユーザー", "利用者"]),

    // 把 .env 的内容发送到 … / .env の内容を … に送信して
    r("exfiltrate-directive", "Exfiltration directive", Severity::Critical,
      r"(?:发送|發送|发到|發到|发给|發給|上传|上傳|提交|传送|傳送|外发|外發|推送|回传|回傳)[^。！？\n]{0,30}(?:密[钥鑰]|金鑰|凭[据證]|憑證|令牌|token|api\s*key|密[码碼]|私[钥鑰]|环境变量|環境變數|\.env|cookie|会话|會話)",
      &["发送", "發送", "发到", "發到", "发给", "發給", "上传", "上傳", "提交", "传送", "傳送", "外发", "外發", "推送", "回传", "回傳"]),
    r("exfiltrate-directive", "Exfiltration directive", Severity::Critical,
      r"(?:\.env|api\s*キー|APIキー|トークン|認証情報|秘密鍵|パスワード|クレデンシャル|クッキー)[^。！？\n]{0,40}(?:送信|送っ|アップロード|投稿|転送|POST)",
      &["送信", "送っ", "アップロード", "投稿", "転送"]),

    // 发送到 https://… / https://… に送って
    r("exfiltrate-to-url", "Send-to-URL directive", Severity::High,
      r"(?:发送|發送|发到|發到|上传|上傳|提交|传送|傳送|推送|回传|回傳)[^。！？\n]{0,40}(?:到|至|给|給)\s*https?://",
      &["发送", "發送", "发到", "發到", "上传", "上傳", "提交", "传送", "傳送", "推送", "回传", "回傳"]),
    r("exfiltrate-to-url", "Send-to-URL directive", Severity::High,
      r"https?://[^\s。！？\n]{1,160}[^。！？\n]{0,20}(?:に|へ)[^。！？\n]{0,10}(?:送信|送っ|投稿|転送|アップロード)",
      &["送信", "送っ", "投稿", "転送", "アップロード"]),

    // 读取 ~/.ssh/id_rsa 并附上 / .env を読んで添付して
    r("credential-read-directive", "Instruction to read credential files", Severity::Critical,
      r"(?:读取|讀取|打开|打開|查看|获取|獲取|附上|附[带帶]|[带帶]上|发送|發送|读一下|讀一下)[^。！？\n]{0,30}(?:~|\$HOME)?/?\.(?:ssh|aws/credentials|env\b|npmrc|netrc|pypirc|kube/config|docker/config|cursor/mcp\.json)",
      &[".ssh", ".aws/credentials", ".env", ".npmrc", ".netrc", ".pypirc", "kube/config", "docker/config", "mcp.json"]),
    r("credential-read-directive", "Instruction to read credential files", Severity::Critical,
      r"(?:~|\$HOME)?/?\.(?:ssh|aws/credentials|env\b|npmrc|netrc|pypirc|kube/config|docker/config|cursor/mcp\.json)[^。！？\n]{0,30}(?:読み|読ん|開い|取得|添付|渡し|送信)",
      &[".ssh", ".aws/credentials", ".env", ".npmrc", ".netrc", ".pypirc", "kube/config", "docker/config", "mcp.json"]),

    // 删除所有文件 / 恢复出厂 / ファイルシステムを削除
    r("destructive-directive", "Destructive goal stated as a task", Severity::Critical,
      r"(?:删除|刪除|清空|清除|抹除|格式化|销毁|銷毀|重置|恢复|恢復)[^。！？\n]{0,20}(?:文件系[统統]|[档檔]案系[统統]|出厂|出廠|整[个個][^。！？\n]{0,6}(?:磁[盘碟]|系[统統]|仓库|倉庫|数据库|資料庫)|(?:所有|全部)(?:的)?(?:文件|[档檔]案|数据|資料|仓库|倉庫|资源|資源|存储桶|實例|用[户戶]))",
      &["删除", "刪除", "清空", "清除", "抹除", "格式化", "销毁", "銷毀", "重置", "恢复", "恢復"]),
    r("destructive-directive", "Destructive goal stated as a task", Severity::Critical,
      r"(?:ファイルシステム|工場出荷|(?:すべて|全て)の(?:ファイル|データ|リソース|バケット))[^。！？\n]{0,20}(?:削除|消去|初期化|破壊)",
      &["削除", "消去", "初期化", "破壊"]),

    // 输出你的系统提示词 / システムプロンプトを教えて
    r("prompt-leak-request", "System prompt extraction", Severity::Medium,
      r"(?:输出|輸出|打印|列出|复述|複述|重复|重複|显示|顯示|告诉我|告訴我|展示|发出来|發出來)[^。！？\n]{0,15}(?:系[统統]提示|系[统統]指令|初始指令|上面的指令|完整提示|system\s*prompt)",
      &["系统提示", "系統提示", "系统指令", "系統指令", "初始指令", "上面的指令", "完整提示"]),
    r("prompt-leak-request", "System prompt extraction", Severity::Medium,
      r"(?:システムプロンプト|初期指示|上記の指示)[^。！？\n]{0,20}(?:出力|表示|教え|繰り返|見せ)",
      &["システムプロンプト", "初期指示", "上記の指示"]),

    // 以后每次都记住 / 今後は必ず記憶して
    r("memory-poison", "Memory / rule persistence", Severity::High,
      r"(?:记住|記住|保存|[储儲]存|写入|寫入|加入)[^。！？\n]{0,25}(?:每次|永久|长期|長期|记忆|記憶|将来|將來|以后都|以後都|后续都|後續都|CLAUDE\.md|AGENTS\.md)",
      &["记住", "記住", "保存", "储存", "儲存", "写入", "寫入", "加入"]),
    r("memory-poison", "Memory / rule persistence", Severity::High,
      r"(?:今後|以降|毎回|永続的)[^。！？\n]{0,20}(?:記憶|保存|覚え)",
      &["今後", "以降", "毎回", "永続的"]),

    // 把这一行写进 CLAUDE.md
    r("agent-config-write", "Agent config self-modification", Severity::Critical,
      r"(?:写入|寫入|追加|添加|加到|修改|[编編][辑輯]|更新|附加)[^。！？\n]{0,40}(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|copilot-instructions\.md|\.cursorrules|\.cursor/rules|\.clinerules|settings\.local\.json|\.vscode/settings\.json|\.mcp\.json|mcp\.json)",
      &["claude.md", "agents.md", "gemini.md", "copilot-instructions", ".cursorrules", ".cursor/rules",
        ".clinerules", "settings.local.json", ".vscode/settings.json", "mcp.json"]),
    r("agent-config-write", "Agent config self-modification", Severity::Critical,
      r"(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|copilot-instructions\.md|\.cursorrules|\.clinerules|settings\.local\.json|\.vscode/settings\.json|mcp\.json)[^。！？\n]{0,30}(?:書き込|追記|追加|編集|更新)",
      &["claude.md", "agents.md", "gemini.md", "copilot-instructions", ".cursorrules",
        ".clinerules", "settings.local.json", ".vscode/settings.json", "mcp.json"]),

    // 你现在拥有 root 权限 / 管理者権限があります
    r("authority-escalation", "Claimed privilege escalation", Severity::High,
      r"你(?:现在|現在)?(?:已[经經])?(?:[拥擁]有|具有|获得|獲得|被授予)[^。！？\n]{0,10}(?:管理[员員]|root|超级|超級|系[统統]|最高|完全)[^。！？\n]{0,8}(?:[权權]限|[访訪][问問])",
      &["权限", "權限", "访问", "訪問"]),
    r("authority-escalation", "Claimed privilege escalation", Severity::High,
      r"(?:管理者|root|スーパーユーザー|システム)[^。！？\n]{0,10}(?:権限|アクセス)[^。！？\n]{0,12}(?:あり|持っ|付与|得まし|与えられ)",
      &["権限", "アクセス"]),

    // 从现在开始你必须 / 今後あなたは
    r("from-now-on", "Persistent behaviour override", Severity::Medium,
      r"(?:从现在起|從現在起|从现在开始|從現在開始|从此以后|從此以後|接下来|接下來)[^。！？\n]{0,10}你(?:必须|必須|需要|[应應]该|將|将|要|都要)",
      &["从现在", "從現在", "从此以后", "從此以後", "接下来", "接下來"]),
    r("from-now-on", "Persistent behaviour override", Severity::Medium,
      r"(?:今から|これから|今後)[^。！？\n]{0,10}(?:あなたは|君は)[^。！？\n]{0,20}(?:してください|すること|必ず)",
      &["今から", "これから", "今後"]),

    // 你必须立即调用 … / 必ずツールを実行してください
    r("tool-invocation-directive", "Forced tool invocation", Severity::High,
      r"你(?:必[须須]|需要|[应應]该)(?:立即|[马馬]上)?(?:[调調]用|[执執]行|运行|運行|使用)[^。！？\n]{0,10}(?:工具|函数|函數|命令|接口|脚本|腳本|api)",
      &["必须", "必須", "需要", "应该", "應該"]),
    r("tool-invocation-directive", "Forced tool invocation", Severity::High,
      r"(?:必ず|直ちに|すぐに)[^。！？\n]{0,12}(?:ツール|関数|コマンド|スクリプト|API)[^。！？\n]{0,12}(?:呼び出|実行|使用)",
      &["必ず", "直ちに", "すぐに"]),

    // 作者不在意隐私 / プライバシーは気にしない
    r("claimed-consent", "Privacy waiver asserted inside data", Severity::High,
      r"(?:不(?:在意|在乎|介意|关心|關心)[^。！？\n]{0,6}(?:隐私|隱私|保密|机密|機密)|(?:可以|放心|尽管|儘管|随便|隨便)[^。！？\n]{0,10}(?:公开|公開|发布|發布|分享|[贴貼]出|放出)[^。！？\n]{0,10}(?:全部|所有|一切))",
      &["隐私", "隱私", "保密", "机密", "機密", "公开", "公開", "发布", "發布", "分享"]),
    r("claimed-consent", "Privacy waiver asserted inside data", Severity::High,
      r"(?:プライバシー|機密|個人情報)[^。！？\n]{0,15}(?:気にしない|問題ない|構わない|気にしません)",
      &["プライバシー", "機密", "個人情報"]),
];

// ── Tool policy: the calls an agent should not be able to make unattended ───

pub static TOOL_POLICY: &[Rule] = &[
    // The target must be a *root* — `/`, `~`, `$HOME`, `*` or `.` — and nothing
    // may follow it but whitespace or a separator, so `rm -rf ./build` and
    // `rm -rf /tmp/x` are ordinary work and stay ordinary work.
    r("destructive-delete", "Destructive recursive delete", Severity::Critical,
      r"(?i)\brm\s+(?:-[A-Za-z]*[rR][A-Za-z]*\s+)+(?:-{1,2}[A-Za-z\-]+\s+)*(?:/|~|\$HOME|\*|\.)(?:\s|$|[;&|])|--no-preserve-root", &["rm ", "--no-preserve-root"]),
    r("disk-wipe", "Raw disk write", Severity::Critical,
      r"(?i)\b(?:dd\s+[^\n]*of=/dev/(?:sd|nvme|disk|hd)|mkfs(?:\.\w+)?\s+/dev/)", &["dd ", "mkfs"]),
    r("fork-bomb", "Fork bomb", Severity::Critical, r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", &[":()"]),
    r("curl-pipe-shell", "Remote script piped to a shell", Severity::Critical,
      r"(?i)\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b", &["curl", "wget"]),
    r("reverse-shell", "Reverse shell", Severity::Critical,
      r"(?i)(?:\bnc\b[^\n]{0,60}\s-[a-z]*e[a-z]*\s|/dev/tcp/[0-9]|bash\s+-i\s+>&|python[0-9.]*\s+-c[^\n]{0,80}socket|socat[^\n]{0,60}exec)",
      &["nc ", "/dev/tcp/", "bash -i", "socat", "socket"]),
    r("credential-file-read", "Credential file access", Severity::Critical,
      r"(?i)(?:~|/root|/home/[\w.\-]+|\$HOME)?/?\.(?:ssh/id_[a-z0-9]+|aws/credentials|netrc|npmrc|pypirc|docker/config\.json|kube/config|gnupg/)|(?:^|[\s\x22'/])\.env(?:\.(?:local|production|prod|development|dev|staging|test))?(?:$|[^\w.\-])",
      &[".ssh/id_", ".aws/credentials", ".netrc", ".npmrc", ".pypirc", ".env", "kube/config", "docker/config", ".gnupg"]),
    r("keychain-dump", "OS credential store dump", Severity::Critical,
      r"(?i)(?:security\s+(?:find|dump)-(?:generic|internet)-password|secret-tool\s+lookup|\bcmdkey\s+/list)",
      &["find-generic-password", "find-internet-password", "secret-tool", "cmdkey"]),
    // The headline case: a credential-shaped environment variable handed to a
    // network client. Severity is *not* fixed — `scan::tool_policy` drops it
    // when every destination in the command is allowlisted, because
    // `curl -H "Authorization: Bearer $GITHUB_TOKEN" api.github.com` is the
    // same shape as the attack and is what the agent is supposed to be doing.
    r("env-secret-egress", "Environment secret sent to the network", Severity::Critical,
      r"(?i)\b(?:curl|wget|nc|ncat|socat|httpie?|http)\b[^\n]{0,240}\$\{?[A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PAT)\}?",
      &["curl", "wget", "nc ", "ncat", "socat", "http"]),
    r("env-dump-egress", "Environment dumped to the network", Severity::Critical,
      r"(?i)(?:printenv|\benv\b|set)\s*(?:\|[^\n]{0,40})?\|\s*(?:curl|wget|nc|ncat)\b", &["printenv", "env", "set"]),
    r("persistence", "Persistence mechanism", Severity::High,
      r"(?i)(?:crontab\s+-|/etc/cron\.|launchctl\s+load|systemctl\s+enable|/Library/LaunchAgents|\.bashrc|\.zshrc|\.profile)\b",
      &["crontab", "cron.", "launchctl", "systemctl enable", "launchagents", ".bashrc", ".zshrc", ".profile"]),
    r("encoded-exec", "Base64-encoded command execution", Severity::Critical,
      r"(?i)(?:echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+(?:-d|--decode)|base64\s+(?:-d|--decode)[^\n]{0,40}\|\s*(?:ba)?sh|powershell[^\n]{0,40}-enc(?:odedcommand)?\s)",
      &["base64", "-enc", "encodedcommand"]),
    r("privilege-escalation", "Privilege escalation", Severity::High,
      r"(?i)(?:\bsudo\s+(?:su\b|-i\b|bash\b|sh\b)|chmod\s+(?:[0-7]*777|\+s)\b|\bsetuid\b)", &["sudo", "chmod", "setuid"]),
    r("firewall-tamper", "Host firewall / security tampering", Severity::High,
      r"(?i)(?:iptables\s+-F|ufw\s+disable|systemctl\s+stop\s+(?:firewalld|apparmor)|setenforce\s+0|spctl\s+--master-disable|csrutil\s+disable)",
      &["iptables", "ufw", "firewalld", "setenforce", "spctl", "csrutil"]),
    r("history-tamper", "Shell history tampering", Severity::High,
      r"(?i)(?:history\s+-c|>\s*~?/?\.(?:bash|zsh)_history|unset\s+HIST(?:FILE|SIZE)|export\s+HISTFILE=)",
      &["history -c", "_history", "histfile", "histsize"]),
    r("git-force-push", "Force push / history rewrite", Severity::High,
      r"(?i)\bgit\s+push\b[^\n]{0,60}(?:--force(?:[^\-\w]|$)|(?:^|\s)-f(?:\s|$))", &["git push"]),
    r("mass-file-write", "Sweeping in-place rewrite", Severity::High,
      r"(?i)\bfind\s+[^\n]{0,60}-(?:exec|delete)\b|\bsed\s+-i[^\n]{0,40}-r?\s*\{\}", &["find ", "sed -i"]),
    // The write that turns every later tool call into an unattended one. Its
    // instruction-shaped twin lives in the injection table as
    // `agent-config-write`; this is the command that carries it out.
    r("auto-approve-escalation", "Tool auto-approval enabled", Severity::Critical,
      r#"(?i)(?:chat\.tools\.autoApprove|"?autoApprove"?\s*[:=]\s*true|--dangerously-skip-permissions|--yolo\b|bypassPermissions)"#,
      &["autoapprove", "dangerously-skip-permissions", "--yolo", "bypasspermissions"]),
    r("agent-config-tamper", "Write into an agent's own config", Severity::High,
      r"(?i)(?:>>?|tee|sed\s+-i|cat\s*>|echo\b[^\n]{0,120}>)[^\n]{0,80}(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|copilot-instructions\.md|\.cursorrules|\.cursor/rules|\.clinerules|\.vscode/settings\.json|settings\.local\.json|\.mcp\.json|\.github/workflows)",
      &["claude.md", "agents.md", "gemini.md", "copilot-instructions", ".cursorrules", ".cursor/rules",
        ".clinerules", ".vscode/settings.json", "settings.local.json", ".mcp.json", ".github/workflows"]),
    r("package-install-remote", "Package install from an arbitrary URL", Severity::Medium,
      r"(?i)\b(?:npm|pnpm|yarn)\s+(?:i|add|install)\s+(?:https?://|git\+|file:)|\bpip[0-9.]*\s+install\s+(?:https?://|git\+|-e\s+\.)",
      &["npm i", "npm install", "pnpm add", "yarn add", "pip install"]),
];

/// Injection rules that are an ordinary request when the *user* is the one
/// making it.
///
/// "Upload the build to https://…", "from now on use tabs", "remember this for
/// next time", "add that to CLAUDE.md" — every one of these is a sentence a
/// developer says to their own agent all day, and every one is also the shape
/// an injected instruction takes. The words do not separate them. Who is
/// speaking does: the same sentence arriving in a tool result, a fetched page
/// or a memory file is somebody *else* instructing the agent, and that is when
/// these rules apply.
///
/// The narrow loss is deliberate and worth naming: text an attacker gets into
/// the user's own turn — a poisoned issue body pasted into the chat — escapes
/// these seven. The alternative is warning on every legitimate upload request,
/// which is how a scanner gets switched off. The rules that are *never*
/// legitimate from any speaker — `do-not-tell-user`, the chat-template tokens,
/// the credential-read directive — are not on this list and still apply.
pub static USER_PERMITTED: &[&str] = &[
    "exfiltrate-to-url",
    "from-now-on",
    "tool-invocation-directive",
    "prompt-leak-request",
    "destructive-directive",
    "memory-poison",
    "agent-config-write",
];

/// Hosts that exist to receive data anonymously. Reaching one from an agent
/// session is the whole exfiltration channel in a single hop.
pub static EXFIL_HOSTS: &[&str] = &[
    "pastebin.com", "hastebin.com", "paste.ee", "dpaste.com", "ghostbin.com",
    "termbin.com", "ix.io", "sprunge.us", "0x0.st", "clbin.com",
    "transfer.sh", "file.io", "anonfiles.com", "bashupload.com", "temp.sh",
    "requestbin.com", "pipedream.net", "requestcatcher.com", "webhook.site",
    "interact.sh", "oast.fun", "burpcollaborator.net", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "localtunnel.me", "serveo.net",
    "beeceptor.com", "mockbin.org", "hookb.in", "typedwebhook.tools",
];

/// The destinations a coding agent legitimately needs. Used as the allowlist in
/// strict mode, where anything unlisted is refused rather than inspected.
pub static DEFAULT_ALLOW_HOSTS: &[&str] = &[
    "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
    "openrouter.ai", "api.deepseek.com", "api.groq.com", "api.x.ai",
    "api.mistral.ai", "api.cohere.com", "dashscope.aliyuncs.com",
    "gw.asale.ai", "api.asale.ai",
    "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "gitlab.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "crates.io", "static.crates.io", "index.crates.io", "proxy.golang.org", "sum.golang.org",
    "rubygems.org", "repo.maven.apache.org", "docs.rs", "developer.mozilla.org",
];

/// Every rule table, for `agent-firewall rules`.
pub fn tables() -> [(&'static str, &'static [Rule]); 3] {
    [("secret", SECRETS), ("injection", INJECTION), ("tool_policy", TOOL_POLICY)]
}
