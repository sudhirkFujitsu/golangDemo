# simaple OAuth server

install the necessary dependencies using below command 
github.com/golang-jwt/jwt/v4

Build the Go binary and test:
```bash
go build

./server
```
it will run the web app server on port 8080

please use following credentials in basic auth while executing the authorised api endpoints

| Username  | Password  |
|---------- |---------- |
| sudhier   | password  |
| sudhier1  | password1 |

the server also includes an Introspection endpoint to check the validity of the tokens 

the URL will be accessible on local using below URL
1. http://localhost:8080/ -- returns a welcome message without authentication
2. http://localhost:8080/token -- returns the token and can be decoded in https://jwt.io/ it gives the information after decrypting the token
