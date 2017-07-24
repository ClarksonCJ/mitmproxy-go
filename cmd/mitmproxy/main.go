package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"

	"bytes"

	"crypto/tls"
	"crypto/x509"

	"github.com/braintree/manners"
	"github.com/elazarl/goproxy"
)

var (
	port     = flag.Int("port", 8080, "Port to listen on")
	host     = flag.String("only-host", "", "Restrict logging to a single host")
	certfile = flag.String("certfile", "cert.pem", "Path to certificate file")
	keyfile  = flag.String("keyfile", "localhost.pem", "Path to private key file")
)

func main() {
	flag.Parse()

	caCert, err := ioutil.ReadFile(*certfile)
	if err != nil {
		panic(err)
	}
	caKey, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		panic(err)
	}
	setCA(caCert, caKey)

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	addListener(proxy)

	sigs := make(chan os.Signal)
	signal.Notify(sigs, os.Kill, os.Interrupt)

	go func() {
		<-sigs
		log.Print("Exitting.....")
		manners.Close()
	}()

	log.Printf("Listening on port %v", *port)
	log.Fatal(manners.ListenAndServe(fmt.Sprintf(":%v", *port), proxy))
}

func addListener(proxy *goproxy.ProxyHttpServer) {
	var onRequest *goproxy.ReqProxyConds
	if *host != "" {
		onRequest = proxy.OnRequest(goproxy.DstHostIs(*host))
	} else {
		onRequest = proxy.OnRequest()
	}

	onRequest.HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return goproxy.MitmConnect, host
	})

	onRequest.DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.Logf("Request Headers: %+v", req.Header)
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			ctx.Logf("Error Reading body")
			return nil, nil
		}

		defer req.Body.Close()
		ctx.Logf("Request Body '%v'", string(body))
		req.Body = ioutil.NopCloser(bytes.NewReader(body))

		return req, nil
	})
}

func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}
