# Roundcube Catch-all Plugin

Roundcube plugin for **catch-all mailboxes** — inboxes that receive mail at
many different local-parts on a domain (e.g. `anything@example.com`).

## What it does

- **Identity auto-create on reply** — when you reply to a message that was
  delivered to `foo@example.com`, the plugin creates a matching Roundcube
  identity (if missing) and preselects it as the `From:` header so your
  reply goes out as `foo@`, not the base mailbox address.
- **Optional autologin** — when configured, synthesises a login POST on every
  anonymous request so users never see the login form. Intended for single-
  tenant deployments gated by an outer auth layer (e.g. Home Assistant Ingress,
  reverse proxy SSO).
- **Optional [Forward Email](https://forwardemail.net) integration** — when
  an API key is set, the plugin additionally provisions per-alias SMTP
  credentials via the Forward Email API so each reply authenticates as
  its own alias.

## Installation

### Via Composer (once published)

```bash
composer require teh-hippo/roundcube-catchall
```

Then add `roundcube_catchall` to the `plugins` array in your Roundcube config.

### Manual

```bash
cd /path/to/roundcube/plugins
git clone https://github.com/teh-hippo/roundcube-catchall.git roundcube_catchall
```

Add `roundcube_catchall` to `$config['plugins']` in `config/config.inc.php`.

## Configuration

Minimum (shared-credential mode):

```php
$config['catchall_domain'] = 'example.com';
$config['catchall_identity_autocreate'] = true;
```

With autologin:

```php
$config['catchall_autologin']      = true;
$config['catchall_autologin_user'] = 'inbox@example.com';
$config['catchall_autologin_pass'] = '…';
```

With Forward Email per-alias provisioning:

```php
$config['catchall_fe_api_key_plain'] = '…';
$config['catchall_fe_auto_delete']   = false;
```

Users can also set per-user Forward Email preferences under Settings →
Catch-all in the Roundcube UI.

## Requirements

- Roundcube 1.6+
- PHP 8.0+ with curl extension (Forward Email features only)

## License

MIT
