# Traefik Forward Auth Body Plugin

A Traefik plugin that forwards request bodies during forward authentication requests. This plugin extends Traefik's forward authentication capabilities by ensuring that request bodies are properly forwarded to the authentication service.

## Features

- Forwards the original request body to the authentication service
- Preserves request headers
- Forwards authentication service response headers
- Maintains request body for the subsequent request after authentication

## Configuration

### Static Configuration

To enable the plugin in your Traefik static configuration:

```yaml
experimental:
  plugins:
    forward-auth-body:
      moduleName: github.com/jonathaanhs/traefik-forward-auth-body
      version: v1.0.0
```

### Dynamic Configuration

Configure the plugin in your dynamic configuration:

```yaml
http:
  middlewares:
    my-forward-auth:
      plugin:
        forward-auth-body:
          forwardAuthURL: http://auth-service:9000/auth
```

Or using Docker labels:

```yaml
labels:
  - "traefik.http.middlewares.my-forward-auth.plugin.forward-auth-body.forwardAuthURL=http://auth-service:9000/auth"
```

## Development

### Requirements

- Go 1.21+
- Traefik v3.0+

### Building and Testing

```bash
# Run tests
go test -v ./...

# Run tests with coverage
go test -v -cover ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 