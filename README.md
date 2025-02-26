# Traefik Forward Auth Body Plugin

A Traefik plugin that extends the built-in ForwardAuth middleware to support forwarding request bodies during authentication. This plugin is particularly useful when your authentication service needs to inspect the request body to make authorization decisions.

## Features

- Forwards request bodies to the authentication service
- Configurable body size limits
- Preserves request methods (optional)
- Configurable header forwarding
- Support for regex-based header filtering
- X-Forwarded headers handling
- Location header preservation for redirects
- Trust forward header option

## Configuration

### Static Configuration

To use this plugin, you need to enable it in your Traefik static configuration:

```yaml
experimental:
  plugins:
    traefik-forward-auth-body:
      moduleName: github.com/jonathaanhs/traefik-forward-auth-body
      version: v1.0.0
```

### Dynamic Configuration

The plugin can be configured using the following options:

```yaml
http:
  middlewares:
    my-forward-auth:
      plugin:
        traefik-forward-auth-body:
          forwardAuthURL: http://auth-service:9000/auth
          maxBodySize: 1048576  # 1MB limit (optional, -1 for no limit)
          preserveRequestMethod: true  # optional
          authResponseHeaders:  # optional
            - X-Auth-User
            - X-Auth-Role
          authResponseHeadersRegex: "^X-Auth-.*"  # optional
          authRequestHeaders:  # optional
            - Authorization
          trustForwardHeader: false  # optional
          headerField: X-Auth-User  # optional
          preserveLocationHeader: false  # optional
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `forwardAuthURL` | String | "" | URL of the authentication service (required) |
| `maxBodySize` | Int64 | -1 | Maximum allowed request body size in bytes (-1 for no limit) |
| `preserveRequestMethod` | Bool | false | Whether to preserve the original request method when forwarding to auth service |
| `authResponseHeaders` | []String | [] | List of headers to forward from auth response |
| `authResponseHeadersRegex` | String | "" | Regex pattern for headers to forward from auth response |
| `authRequestHeaders` | []String | [] | List of headers to forward to auth service |
| `trustForwardHeader` | Bool | false | Whether to trust X-Forwarded-* headers |
| `headerField` | String | "" | Header field to forward |
| `preserveLocationHeader` | Bool | false | Whether to preserve Location header in redirects |

## Example Usage

Here's an example of how to use the plugin with Docker labels:

```yaml
services:
  my-service:
    labels:
      - "traefik.enable=true"
      - "traefik.http.middlewares.my-auth.plugin.traefik-forward-auth-body.forwardAuthURL=http://auth-service:9000/auth"
      - "traefik.http.middlewares.my-auth.plugin.traefik-forward-auth-body.maxBodySize=1048576"
      - "traefik.http.middlewares.my-auth.plugin.traefik-forward-auth-body.preserveRequestMethod=true"
      - "traefik.http.middlewares.my-auth.plugin.traefik-forward-auth-body.authResponseHeaders=X-Auth-User,X-Auth-Role"
      - "traefik.http.routers.my-service.middlewares=my-auth"
```

## Development

### Prerequisites

- Go 1.21 or later
- Make

### Building and Testing

```bash
# Run tests
make test

# Run linter
make lint

# Run Yaegi tests
make yaegi_test
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 