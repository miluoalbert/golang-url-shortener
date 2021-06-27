rm -rf docker_releases
mkdir docker_releases
go build -o docker_releases/golang-url-shortener ./cmd/golang-url-shortener

docker build -t miluoabt/golang_url_shortener -f build/Dockerfile.amd64 .