<?php

/**
 * Catch-all mailbox helper for Roundcube.
 *
 * For mailboxes that receive mail at many different local-parts on a single
 * domain (e.g. `anything@example.com`). On reply, auto-creates a matching
 * Roundcube identity and preselects it as the From address so the reply
 * goes out as the originally-addressed recipient.
 *
 * Optional extras:
 *  - Autologin: synthesise a login POST on every anonymous request.
 *  - Forward Email: when an API key is configured, additionally provision
 *    per-alias SMTP credentials via the Forward Email API on reply.
 *
 * Security note: SMTP passwords are encrypted using Roundcube's des_key.
 * The security of stored credentials depends on des_key remaining secret.
 *
 * @author  teh-hippo
 * @license MIT
 */
class roundcube_catchall extends rcube_plugin
{
    public $task = 'settings|mail';

    /** @var rcmail */
    private $rc;

    /**
     * Plugin initialization.
     */
    public function init()
    {
        $this->rc = rcmail::get_instance();
        $this->load_config('config.inc.php.dist');
        $this->load_config();
        $this->add_texts('localization/', true);

        // Settings UI
        $this->add_hook('preferences_sections_list', [$this, 'preferences_sections']);
        $this->add_hook('preferences_list', [$this, 'preferences_list']);
        $this->add_hook('preferences_save', [$this, 'preferences_save']);

        // Auto-create identity on reply to catch-all address
        $this->add_hook('message_compose', [$this, 'message_compose']);

        // Identity lifecycle
        $this->add_hook('identity_create_after', [$this, 'identity_created']);
        $this->add_hook('identity_delete', [$this, 'identity_deleted']);

        // SMTP credential swap
        $this->add_hook('smtp_connect', [$this, 'smtp_connect']);

        // Register AJAX actions
        $this->register_action('plugin.catchall-fe-test', [$this, 'action_test_api']);
    }

    // =========================================================================
    // Settings
    // =========================================================================

    /**
     * Add Forward Email section to preferences.
     */
    public function preferences_sections($args)
    {
        $args['list']['catchall'] = [
            'id'      => 'catchall',
            'section' => $this->gettext('section_title'),
        ];
        return $args;
    }

    /**
     * Render Forward Email preferences form.
     */
    public function preferences_list($args)
    {
        if ($args['section'] !== 'catchall') {
            return $args;
        }

        $api_key = $this->rc->config->get('catchall_fe_api_key', '');
        $domain  = $this->rc->config->get('catchall_domain', '');
        $auto_create = $this->rc->config->get('catchall_identity_autocreate', true);
        $auto_delete = $this->rc->config->get('catchall_fe_auto_delete', false);
        $catchall_pass = $this->rc->config->get('catchall_fe_catchall_password', '');

        // Decrypt for display (masked)
        $decrypted_key = '';
        if ($api_key) {
            $decrypted_key = $this->rc->decrypt($api_key);
            if ($decrypted_key && strlen($decrypted_key) > 8) {
                $decrypted_key = str_repeat('*', strlen($decrypted_key) - 4)
                    . substr($decrypted_key, -4);
            }
        }

        $masked_pass = '';
        if ($catchall_pass) {
            $decrypted_pass = $this->rc->decrypt($catchall_pass);
            if ($decrypted_pass && strlen($decrypted_pass) > 4) {
                $masked_pass = str_repeat('*', strlen($decrypted_pass) - 4)
                    . substr($decrypted_pass, -4);
            } elseif ($decrypted_pass) {
                $masked_pass = '****';
            }
        }

        // Build clear-password control: checkbox shown only when a password is stored
        $clear_pass_html = '';
        if ($catchall_pass) {
            $clear_pass_html = ' ' . (new html_checkbox([
                'name'  => '_catchall_fe_clear_catchall_password',
                'id'    => 'rcmfd_ca_fe_clear_catchall_password',
                'value' => 1,
            ]))->show(0) . ' <label for="rcmfd_ca_fe_clear_catchall_password">'
                . rcube::Q($this->gettext('clear_password')) . '</label>';
        }

        $args['blocks']['main'] = [
            'name' => $this->gettext('settings_main'),
            'options' => [
                'domain' => [
                    'title'   => $this->gettext('domain'),
                    'content' => (new html_inputfield([
                        'name'        => '_catchall_domain',
                        'id'          => 'rcmfd_ca_domain',
                        'size'        => 40,
                        'placeholder' => 'example.com',
                    ]))->show($domain),
                ],
                'auto_create' => [
                    'title'   => $this->gettext('auto_create'),
                    'content' => (new html_checkbox([
                        'name'  => '_catchall_identity_autocreate',
                        'id'    => 'rcmfd_ca_identity_autocreate',
                        'value' => 1,
                    ]))->show($auto_create ? 1 : 0),
                ],
                'catchall_password' => [
                    'title'   => $this->gettext('catchall_password'),
                    'content' => (new html_inputfield([
                        'name'        => '_catchall_fe_catchall_password',
                        'id'          => 'rcmfd_ca_fe_catchall_password',
                        'size'        => 40,
                        'type'        => 'password',
                        'placeholder' => $masked_pass ?: $this->gettext('catchall_password_placeholder'),
                    ]))->show('') . $clear_pass_html,
                ],
            ],
        ];

        $args['blocks']['fe_api'] = [
            'name' => $this->gettext('settings_fe'),
            'options' => [
                'api_key' => [
                    'title'   => $this->gettext('api_key'),
                    'content' => (new html_inputfield([
                        'name'        => '_catchall_fe_api_key',
                        'id'          => 'rcmfd_ca_fe_api_key',
                        'size'        => 40,
                        'type'        => 'password',
                        'placeholder' => $decrypted_key ?: $this->gettext('api_key_placeholder'),
                    ]))->show(''),
                ],
                'auto_delete' => [
                    'title'   => $this->gettext('auto_delete'),
                    'content' => (new html_checkbox([
                        'name'  => '_catchall_fe_auto_delete',
                        'id'    => 'rcmfd_ca_fe_auto_delete',
                        'value' => 1,
                    ]))->show($auto_delete ? 1 : 0),
                ],
            ],
        ];

        return $args;
    }

    /**
     * Save Forward Email preferences.
     */
    public function preferences_save($args)
    {
        if ($args['section'] !== 'catchall') {
            return $args;
        }

        $api_key = rcube_utils::get_input_string('_catchall_fe_api_key', rcube_utils::INPUT_POST);
        $domain  = rcube_utils::get_input_string('_catchall_domain', rcube_utils::INPUT_POST);
        $auto_create = rcube_utils::get_input_string('_catchall_identity_autocreate', rcube_utils::INPUT_POST);
        $auto_delete = rcube_utils::get_input_string('_catchall_fe_auto_delete', rcube_utils::INPUT_POST);
        $catchall_pass = rcube_utils::get_input_string('_catchall_fe_catchall_password', rcube_utils::INPUT_POST);
        $clear_pass = rcube_utils::get_input_string('_catchall_fe_clear_catchall_password', rcube_utils::INPUT_POST);

        // Only update API key if user entered a new one (not blank)
        if ($api_key !== '') {
            $args['prefs']['catchall_fe_api_key'] = $this->rc->encrypt($api_key);
        }

        // Catch-all password: clear if checkbox checked, update if new value entered
        if ($clear_pass) {
            $args['prefs']['catchall_fe_catchall_password'] = '';
        } elseif ($catchall_pass !== '') {
            $args['prefs']['catchall_fe_catchall_password'] = $this->rc->encrypt($catchall_pass);
        }

        $args['prefs']['catchall_domain']      = trim($domain);
        $args['prefs']['catchall_identity_autocreate'] = (bool) $auto_create;
        $args['prefs']['catchall_fe_auto_delete'] = (bool) $auto_delete;

        return $args;
    }

    // =========================================================================
    // Identity hooks
    // =========================================================================

    /**
     * After a new identity is created, create the alias on Forward Email
     * and generate SMTP credentials.
     */
    public function identity_created($args)
    {
        $email = $args['record']['email'] ?? '';
        $identity_id = $args['id'] ?? null;

        rcube::console("catchall: identity_created hook fired (email={$email}, id={$identity_id})");

        if ($email && $identity_id) {
            $this->provision_credentials((string) $identity_id, $email);
        }

        return $args;
    }

    /**
     * When an identity is deleted, optionally remove the alias.
     */
    public function identity_deleted($args)
    {
        $identity_id = (string) $args['id'];
        $auto_delete = $this->rc->config->get('catchall_fe_auto_delete', false);

        if (!$auto_delete) {
            $this->remove_smtp_credentials($identity_id);
            return $args;
        }

        $api_key = $this->get_api_key();
        $domain  = $this->get_domain();

        if (!$api_key || !$domain) {
            $this->remove_smtp_credentials($identity_id);
            return $args;
        }

        // Look up identity email from stored credentials
        $creds = $this->get_all_smtp_credentials();

        if (isset($creds[$identity_id])) {
            $email = $creds[$identity_id]['username'] ?? '';
            $parts = explode('@', $email);
            if (count($parts) === 2 && strtolower($parts[1]) === strtolower($domain)) {
                try {
                    $alias = $this->api_find_alias($api_key, $domain, $parts[0]);
                    if ($alias && !empty($alias['id'])) {
                        $this->api_delete_alias($api_key, $domain, $alias['id']);
                        rcube::console("catchall: deleted alias {$email}");
                    }
                } catch (Exception $e) {
                    rcube::raise_error([
                        'code' => 500,
                        'message' => 'catchall: delete failed - ' . $e->getMessage(),
                    ], true, false);
                }
            }
        }

        $this->remove_smtp_credentials($identity_id);
        return $args;
    }

    // =========================================================================
    // Compose hook — auto-create identity for catch-all replies
    // =========================================================================

    /**
     * When composing a reply or forward, detect the original recipient address
     * from X-Original-To / Delivered-To headers. If no identity exists for that
     * address, auto-create one (which triggers identity_create_after to provision
     * the alias + SMTP credentials) so the user replies as the catch-all address.
     */
    public function message_compose($args)
    {
        // Only auto-create identities if explicitly enabled (default: true for backwards compat)
        if (!$this->rc->config->get('catchall_identity_autocreate', true)) {
            return $args;
        }

        $domain = $this->get_domain();
        $api_key = $this->get_api_key();

        // api_key is optional. When absent we operate in "shared credential"
        // mode: the user has a wildcard alias on Forward Email whose SMTP
        // credentials are used for all outbound (typically via autologin).
        // In that mode we still auto-create Roundcube identities so the
        // compose form preselects the right From address, but we don't
        // touch the Forward Email API.

        // Only act on replies/forwards — use specific param keys to avoid
        // false positives from draft editing which also has a uid
        $reply_uid   = $args['param']['reply_uid'] ?? null;
        $forward_uid = $args['param']['forward_uid'] ?? null;
        $uid         = $reply_uid ?: $forward_uid;

        if (!$uid) {
            return $args;
        }

        $mbox = $args['param']['mailbox'] ?? 'INBOX';

        // Fetch the original message headers
        $storage = $this->rc->get_storage();
        // Ensure non-standard headers (X-Original-To, Delivered-To) are fetched.
        // Without this, $headers->others is empty for these fields.
        $storage->set_options(['fetch_headers' => 'X-Original-To Delivered-To']);
        $headers = $storage->get_message_headers($uid, $mbox);

        if (!$headers) {
            return $args;
        }

        // Look for the delivered-to address in headers
        // rcube_message_header stores non-standard headers in $others (lowercase keys)
        $delivered_to = null;
        foreach (['x-original-to', 'delivered-to'] as $hdr) {
            $val = $headers->others[$hdr] ?? null;
            if ($val) {
                $delivered_to = is_array($val) ? $val[0] : $val;
                $delivered_to = trim($delivered_to);
                break;
            }
        }

        if (!$delivered_to) {
            return $args;
        }

        $parts = explode('@', $delivered_to);
        if (count($parts) !== 2) {
            return $args;
        }

        // If a domain is configured, restrict to it. Otherwise, treat every
        // Delivered-To / X-Original-To as the catch-all scope — the fact
        // that the message landed in this mailbox is sufficient proof.
        if ($domain && strtolower($parts[1]) !== strtolower($domain)) {
            return $args;
        }

        // Check if an identity already exists for this address
        $identities = $this->rc->user->list_identities();
        foreach ($identities as $ident) {
            if (strtolower($ident['email']) === strtolower($delivered_to)) {
                // Identity exists — preselect it as sender and, in API mode,
                // ensure its SMTP credentials are still valid.
                if ($api_key) {
                    $this->ensure_credentials((string) $ident['identity_id'], $ident['email']);
                }
                $args['param']['from'] = $delivered_to;
                return $args;
            }
        }

        // insert_identity in Roundcube 10 does not fire identity_create_after —
        // we call provision_credentials explicitly below after insert_identity.
        $identity_data = [
            'email'    => $delivered_to,
            'name'     => '',
            'standard' => 0,
        ];

        try {
            $identity_id = $this->rc->user->insert_identity($identity_data);
        } catch (Exception $e) {
            rcube::raise_error([
                'code' => 500,
                'message' => 'catchall: insert_identity failed - ' . $e->getMessage(),
            ], true, false);
            return $args;
        }

        if ($identity_id) {
            rcube::console("catchall: auto-created identity for {$delivered_to}");

            if ($api_key) {
                // API mode — provision a dedicated alias + SMTP creds on
                // Forward Email. rcube_user::insert_identity does not fire
                // identity_create_after in Roundcube 10 (only the settings
                // flow does), so we call provision_credentials directly.
                $creds = $this->provision_credentials((string) $identity_id, $delivered_to);

                if ($creds === null) {
                    // Provisioning failed — roll back the orphaned identity so we
                    // retry cleanly next time rather than leaving a dead identity.
                    try {
                        $this->rc->user->delete_identity((int) $identity_id);
                    } catch (Exception $e) {
                        rcube::raise_error([
                            'code' => 500,
                            'message' => 'catchall: rollback delete_identity failed - ' . $e->getMessage(),
                        ], true, false);
                    }
                    return $args;
                }
            }
            // Shared mode — no API call. smtp_connect will fall through to
            // Roundcube's default auth (the logged-in wildcard credentials),
            // which Forward Email accepts for any From on the domain.

            // Set this identity as the sender for the compose
            // Use 'from' (email address) — Roundcube matches it against identities
            $args['param']['from'] = $delivered_to;
        }

        return $args;
    }

    // =========================================================================
    // SMTP credential swap
    // =========================================================================

    /**
     * Before SMTP connect, swap credentials if we have stored ones for
     * the sending identity.
     */
    public function smtp_connect($args)
    {
        // Get identity from compose data
        $identity_id = rcube_utils::get_input_string('_from', rcube_utils::INPUT_POST);
        if (!$identity_id) {
            return $args;
        }

        $identity = $this->rc->user->get_identity((int) $identity_id);
        if (!$identity) {
            return $args;
        }

        $identity_email = strtolower($identity['email'] ?? '');

        // 1. Per-alias stored credentials (highest priority)
        $creds = $this->get_smtp_credentials((string) $identity_id);
        if ($creds) {
            $args['smtp_user'] = $creds['username'];
            $args['smtp_pass'] = $creds['password'];
            rcube::console("catchall: using per-alias SMTP credentials for {$creds['username']}");
            return $args;
        }

        // 2. If identity matches the authenticated mailbox, default auth works
        $login_user = strtolower((string) $this->rc->user->get_username());
        if ($identity_email === $login_user) {
            return $args;
        }

        // 3. Catch-all password for other same-domain identities
        $domain = $this->get_domain();
        $catchall_pass = $this->get_catchall_password();
        if ($catchall_pass && $domain) {
            $parts = explode('@', $identity_email);
            if (count($parts) === 2 && strtolower($parts[1]) === strtolower($domain)) {
                $args['smtp_user'] = $identity_email;
                $args['smtp_pass'] = $catchall_pass;
                rcube::console("catchall: using catch-all password for {$identity_email}");
                return $args;
            }
        }

        // 4. Default Roundcube SMTP auth (fallthrough)
        rcube::console("catchall: no SMTP credentials for identity {$identity_id} ({$identity_email}), using default auth");
        return $args;
    }

    /**
     * Provision SMTP credentials for an identity on demand.
     * Creates the alias on Forward Email if needed and generates a password.
     *
     * @return array|null {username, password} or null on failure
     */
    private function provision_credentials(string $identity_id, string $email): ?array
    {
        $api_key = $this->get_api_key();
        $domain  = $this->get_domain();

        if (!$email || !$api_key || !$domain) {
            return null;
        }

        $parts = explode('@', $email);
        if (count($parts) !== 2 || strtolower($parts[1]) !== strtolower($domain)) {
            return null;
        }
        $local_part = $parts[0];

        // RFC 5322 dot-atom: conservatively allow alnum and common punctuation.
        // Rejects whitespace, quoted-strings, slashes, and other characters
        // that would be unsafe to pass to the API or confuse the server.
        if (!preg_match('/^[A-Za-z0-9!#$%&\'*+\/=?^_`{|}~.-]+$/', $local_part)) {
            return null;
        }

        try {
            $alias = $this->api_find_alias($api_key, $domain, $local_part);

            if (!$alias) {
                $alias = $this->api_create_alias($api_key, $domain, $local_part);
                if (!$alias || empty($alias['id'])) {
                    return null;
                }
            }

            $creds = $this->api_generate_password($api_key, $domain, $alias['id']);
            if ($creds && !empty($creds['password'])) {
                $this->store_smtp_credentials($identity_id, $email, $creds['password']);
                rcube::console("catchall: auto-provisioned SMTP credentials for {$email}");
                return [
                    'username' => $email,
                    'password' => $creds['password'],
                ];
            }
        } catch (Exception $e) {
            rcube::raise_error([
                'code' => 500,
                'message' => 'catchall: auto-provision failed - ' . $e->getMessage(),
            ], true, false);
        }

        return null;
    }

    /**
     * Ensure SMTP credentials exist for an identity, provisioning if needed.
     * Safe to call during compose (not during SMTP connect).
     */
    private function ensure_credentials(string $identity_id, string $email): void
    {
        $creds = $this->get_smtp_credentials($identity_id);
        if ($creds) {
            return;
        }

        rcube::console("catchall: pre-provisioning credentials for {$email}");
        $this->provision_credentials($identity_id, $email);
    }

    // =========================================================================
    // AJAX actions
    // =========================================================================

    /**
     * Test API key validity.
     */
    public function action_test_api()
    {
        $api_key = $this->get_api_key();
        $domain  = $this->get_domain();

        if (!$api_key || !$domain) {
            $this->rc->output->command('display_message', $this->gettext('api_key_missing'), 'error');
            $this->rc->output->send();
            return;
        }

        try {
            $aliases = $this->api_list_aliases($api_key, $domain);
            $count = is_array($aliases) ? count($aliases) : 0;
            $msg = sprintf($this->gettext('api_test_success'), $domain, $count);
            $this->rc->output->command('display_message', $msg, 'confirmation');
        } catch (Exception $e) {
            $this->rc->output->command('display_message', $e->getMessage(), 'error');
        }

        $this->rc->output->send();
    }

    // =========================================================================
    // Forward Email API calls
    // =========================================================================

    /**
     * List all aliases for a domain.
     */
    private function api_list_aliases(string $api_key, string $domain): array
    {
        $response = $this->api_request('GET', "/v1/domains/{$domain}/aliases", $api_key);
        return $response ?: [];
    }

    /**
     * Find an alias by local part (server-side filtered).
     */
    private function api_find_alias(string $api_key, string $domain, string $local_part): ?array
    {
        $path = "/v1/domains/{$domain}/aliases?" . http_build_query(['name' => $local_part]);
        $response = $this->api_request('GET', $path, $api_key);
        if (is_array($response)) {
            foreach ($response as $alias) {
                if (($alias['name'] ?? '') === $local_part) {
                    return $alias;
                }
            }
        }
        return null;
    }

    /**
     * Create a new alias.
     */
    private function api_create_alias(string $api_key, string $domain, string $local_part): ?array
    {
        return $this->api_request('POST', "/v1/domains/{$domain}/aliases", $api_key, [
            'name'     => $local_part,
            'has_imap' => 0,
        ]);
    }

    /**
     * Generate SMTP password for an alias.
     */
    private function api_generate_password(string $api_key, string $domain, string $alias_id): ?array
    {
        // is_override=true: regenerate even if alias already has a password.
        // Required because Forward Email auto-generates a password on alias
        // creation, so a newly created alias already "has" one from the API's
        // perspective, and subsequent generate-password calls would 400
        // without an override.
        return $this->api_request(
            'POST',
            "/v1/domains/{$domain}/aliases/{$alias_id}/generate-password",
            $api_key,
            ['is_override' => 'true']
        );
    }

    /**
     * Delete an alias.
     */
    private function api_delete_alias(string $api_key, string $domain, string $alias_id): void
    {
        $this->api_request('DELETE', "/v1/domains/{$domain}/aliases/{$alias_id}", $api_key);
    }

    /**
     * Make an API request to Forward Email.
     */
    private function api_request(string $method, string $path, string $api_key, array $data = null): ?array
    {
        $url = 'https://api.forwardemail.net' . $path;

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_USERPWD        => $api_key . ':',
            CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($data !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            }
        } elseif ($method === 'PUT') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
            if ($data !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            }
        } elseif ($method === 'DELETE') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }

        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new Exception("Forward Email API error: {$error}");
        }

        if ($http_code >= 400) {
            $body = json_decode($response, true);
            $msg = $body['message'] ?? "HTTP {$http_code}";
            throw new Exception("Forward Email API: {$msg}");
        }

        if ($response === '' || $response === false) {
            return null;
        }

        return json_decode($response, true);
    }

    // =========================================================================
    // Credential storage (user prefs)
    // =========================================================================

    /**
     * Store SMTP credentials for an identity.
     */
    private function store_smtp_credentials(string $identity_id, string $username, string $password): void
    {
        $creds = $this->get_all_smtp_credentials();
        $creds[$identity_id] = [
            'username' => $username,
            'password' => $this->rc->encrypt($password),
        ];
        $this->rc->user->save_prefs(['catchall_fe_smtp_credentials' => $creds]);
    }

    /**
     * Get SMTP credentials for an identity.
     */
    private function get_smtp_credentials(string $identity_id): ?array
    {
        $creds = $this->get_all_smtp_credentials();
        if (!isset($creds[$identity_id])) {
            return null;
        }

        $entry = $creds[$identity_id];
        return [
            'username' => $entry['username'],
            'password' => $this->rc->decrypt($entry['password']),
        ];
    }

    /**
     * Remove SMTP credentials for an identity.
     */
    private function remove_smtp_credentials(string $identity_id): void
    {
        $creds = $this->get_all_smtp_credentials();
        if (!isset($creds[$identity_id])) {
            return;
        }
        unset($creds[$identity_id]);
        $this->rc->user->save_prefs(['catchall_fe_smtp_credentials' => $creds]);
    }

    /**
     * Get all stored SMTP credentials.
     */
    private function get_all_smtp_credentials(): array
    {
        return $this->rc->config->get('catchall_fe_smtp_credentials', []);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Get decrypted API key.
     */
    private function get_api_key(): ?string
    {
        $encrypted = $this->rc->config->get('catchall_fe_api_key', '');
        if ($encrypted) {
            // User has a stored key — use it exclusively; never fall back silently
            // on decryption failure (surfaces des_key rotation / prefs corruption).
            $decrypted = $this->rc->decrypt($encrypted);
            return $decrypted ?: null;
        }

        // No user-level key — fall back to plaintext admin config
        // (used when the plugin is provisioned via add-on/admin configuration).
        $plain = $this->rc->config->get('catchall_fe_api_key_plain', '');
        return $plain ?: null;
    }

    /**
     * Get configured domain, falling back to the logged-in user's email domain.
     */
    private function get_domain(): ?string
    {
        $domain = $this->rc->config->get('catchall_domain', '');
        if ($domain) {
            return $domain;
        }

        $candidate = '';
        if ($this->rc->user && method_exists($this->rc->user, 'get_username')) {
            $candidate = (string) $this->rc->user->get_username();
        }
        if ($candidate && ($at = strrpos($candidate, '@')) !== false) {
            $derived = substr($candidate, $at + 1);
            return $derived ?: null;
        }
        return null;
    }

    /**
     * Get decrypted catch-all password.
     * Priority: encrypted user pref → plaintext admin config → null.
     */
    private function get_catchall_password(): ?string
    {
        $encrypted = $this->rc->config->get('catchall_fe_catchall_password', '');
        if ($encrypted) {
            $decrypted = $this->rc->decrypt($encrypted);
            return $decrypted ?: null;
        }

        $plain = $this->rc->config->get('catchall_fe_catchall_password_plain', '');
        return $plain ?: null;
    }
}
