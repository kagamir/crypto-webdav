## Supported tags

- latest

## Usage

Mount the htpasswd file to `/htpasswd`, where the specified username and password are provided, and the username is the directory for the user. Mount the storage file directory to `/upload` for persistence.

Example:

```bash
docker run --restart always -v /somewhere/dav:/upload \
	-v /somewhere/htpasswd:/htpasswd \
	-p 8080:8080 --name crypto-webdav -itd kagamir/crypto-webdav
```

Suggest using reverse proxy software to enable HTTPS.

