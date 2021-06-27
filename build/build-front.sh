cd web && yarn install
yarn build
rm build/static/**/*.map
cd ..
go get -v github.com/gobuffalo/packr/v2/packr2
cd cmd/golang-url-shortener && packr2
cd ../..