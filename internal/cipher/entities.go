package cipher

type Cipher interface {
	Crypt(request *Request) (*Response, error)
	Decrypt(request *Request) (*Response, error)
}

type Request struct {
	SecretKey string
	Value     string
}

type Response struct {
	Value string
}
