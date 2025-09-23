## Supported tags

- latest


## Usage

### linux
```bash
export WEBDAV_ADDRESS=0.0.0.0:8080
export WEBDAV_HTPASSWD_FILE=/htpasswd
./crypto-webdav-linux-amd64
```

### windows
```powershell
$env:WEBDAV_ADDRESS="0.0.0.0:8080"
$env:WEBDAV_HTPASSWD_FILE="C:\path\to\htpasswd"
.\crypto-webdav-windows-amd64.exe
```


## Docker

Mount the htpasswd file to `/htpasswd`, where the specified username and password are provided, and the username is the directory for the user. Mount the storage file directory to `/upload` for persistence.

Example:

```bash
docker build -t crypto-webdav .
docker run --restart always -v /somewhere/dav:/upload \
	-v /somewhere/htpasswd:/htpasswd \
	-e WEBDAV_ADDRESS=0.0.0.0:8080 \
	-e WEBDAV_HTPASSWD_FILE=/htpasswd \
	-p 8080:8080 --name crypto-webdav -d crypto-webdav
```

Suggest using reverse proxy software to enable HTTPS.

## TODO
- [ ] File name encryption
- [ ] User password file storage optimization
