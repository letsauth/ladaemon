# Integrating OpenID clients with Portier

In this document, we collect instructions for how to integrate various
off-the-shelf OpenID Connect client software with Portier.

## General configuration

The public Portier broker is at: `https://broker.portier.io` (sometimes called
the 'issuer')

Many clients are able to partially autoconfigure based on a JSON 'discovery
document'. If not, you can hopefully cross-reference fields manually with this
JSON. You can find the Portier discovery document at:
[`/.well-known/openid-configuration`](https://broker.portier.io/.well-known/openid-configuration)

You will likely be asked for a 'client ID' or 'audience'. In Portier, the
client ID is the origin of your site. For example, if your redirect URL is
`http://localhost:8080/verify`, your origin is `http://localhost:8080` (no
trailing slash).

If a 'client secret' is required, you may fill this with a dummy value.

Portier normally uses the OAuth2 'implicit flow', but many OpenID clients only
support the 'authorization code flow'. For compatibility, this implementation
supports both, but if you have the option, implicit flow is preferred.

Portier requires clients use a 'nonce'. If you see an option for it, enable it.

## OAuth2 Proxy

Website: https://oauth2-proxy.github.io/oauth2-proxy/

Requires version 7.1.3 or newer.

Example configuration:

```
provider = "oidc"
provider_display_name = "Portier"
oidc_issuer_url = "https://broker.portier.io"
insecure_oidc_skip_nonce = false

client_id = "https://example.com"
client_secret = "UNUSED"
```

## Keycloak

Website: https://www.keycloak.org/

Portier can be used as an Identity Provider in Keycloak. Add an 'OpenID Connect
v1.0' provider, and scroll to the bottom of the form to find the import
controls. Import from the following URL:
`https://broker.portier.io/.well-known/openid-configuration`

For 'Client ID', fill in the origin of your site. For example, a local test
installation of Keycloak might use `http://localhost:8081` (no trailing slash).

For 'Client Secret', fill in a dummy value, e.g.: `UNUSED`

In addition, the following values are recommended:

- 'Alias': `portier`
- 'Display Name': `Portier`
- 'Trust Email': On
- 'Pass login_hint': On
