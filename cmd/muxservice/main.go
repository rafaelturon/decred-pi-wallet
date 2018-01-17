// Experimental SSL Tests
// --------------------------------------------------------------------------------------------------
// 1) Generate manually certificates cert.pem and key.pem using template 'localhost.conf' and scripts:
// https://unix.stackexchange.com/questions/288517/how-to-make-self-signed-certificate-for-localhost
// 2) Implement SSL support in cmd/muxservice/main.go using references bellow:
// https://www.kaihag.com/https-and-go/
// https://github.com/kabukky/httpscerts/blob/master/httpscerts.go
// Other reference: https://github.com/denji/golang-tls
// --------------------------------------------------------------------------------------------------
// Suggestion - Implement a Certificate Authority:
// https://random-notes-of-a-sysadmin.blogspot.com.br/2016/06/howto-setup-fips-compliant-root.html
// https://www.medo64.com/2017/03/creating-your-own-certificate-authority/
// https://andrewlock.net/creating-and-trusting-a-self-signed-certificate-on-linux-for-use-in-kestrel-and-asp-net-core/

package muxservice

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/rpcclient"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gorilla/mux"
	"github.com/rafaelturon/decred-pi-wallet/config"
	"github.com/rs/cors"
	"github.com/urfave/negroni"
)

const (
	privKeyPath      = "rpc.key"
	pubKeyPath       = "rpc.cert"
	pemKeyPath       = "key.pem"
	pemCertPath      = "cert.pem"
	userName         = "Decred Pi Wallet"
	tokenTimeoutHour = 10
)

var (
	validFrom = ""
	validFor  = 365 * 24 * time.Hour
	isCA      = true
	corsArray = []string{"http://localhost"}
	verifyKey *ecdsa.PublicKey
	ecdsaKey  *ecdsa.PrivateKey
	cfg       *config.Config
	client    *rpcclient.Client
	logger    = config.MuxsLog
)

func logFatal(err error) {
	if err != nil {
		logger.Critical(err)
	}
}

func initKeys() error {
	dcrwalletHomeDir := dcrutil.AppDataDir("dcrwallet", false)

	logger.Debugf("Reading private key %s", privKeyPath)
	signBytes, err := ioutil.ReadFile(filepath.Join(dcrwalletHomeDir, privKeyPath))
	logFatal(err)

	ecdsaKey, err = jwt.ParseECPrivateKeyFromPEM(signBytes)
	logFatal(err)

	logger.Debugf("Reading public key %s", pubKeyPath)
	verifyBytes, err := ioutil.ReadFile(filepath.Join(dcrwalletHomeDir, pubKeyPath))
	logFatal(err)

	verifyKey, err = jwt.ParseECPublicKeyFromPEM(verifyBytes)
	logFatal(err)

	logger.Debugf("Reading private certificate %s", pemKeyPath)
	pemSignBytes, err := ioutil.ReadFile(pemKeyPath)
	if err != nil {
		err = generatePrivateCertificate(pemSignBytes)
		logFatal(err)
	}

	return err
}

func generatePrivateCertificate(signBytes []byte) error {
	var err error
	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			logger.Criticalf("Failed to parse creation date: %s\n", err)
			return err
		}
	}

	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Criticalf("failed to generate serial number: %s", err)
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{userName},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(cfg.APIListen, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(ecdsaKey), ecdsaKey)
	if err != nil {
		logFatal(err)
	}

	certOut, err := os.Create(pemCertPath)
	if err != nil {
		logger.Criticalf("failed to open "+pemCertPath+" for writing: %s", err)
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	logger.Debug("written cert.pem\n")

	keyOut, err := os.OpenFile(pemKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logger.Criticalf("failed to open "+pemKeyPath+" for writing:", err)
		return err
	}

	b, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		logger.Criticalf("Unable to marshal ECDSA private key: %v", err)
		return err
	}

	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	keyOut.Close()
	logger.Debug("written key.pem")

	return nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func checkSSL(certPath string, keyPath string) error {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return err
	} else if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return err
	}
	return nil
}

// UserCredentials stores data to login
type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// User basic information
type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Response API calls
type Response struct {
	Data string `json:"data"`
}

// Token is JWT object string
type Token struct {
	Token string `json:"token"`
}

func startServer() {
	router := mux.NewRouter()
	router.HandleFunc("/about", aboutHandler)
	router.HandleFunc("/login", loginHandler)

	// Static route
	sRoutes := mux.NewRouter().PathPrefix("/web").Subrouter().StrictSlash(true)

	// API middleware
	apiRoutes := mux.NewRouter().PathPrefix("/api").Subrouter().StrictSlash(true)
	apiRoutes.HandleFunc("/balance", balanceHandler)
	apiRoutes.HandleFunc("/tickets", ticketsHandler)

	// CORS options
	c := cors.New(cors.Options{
		AllowedOrigins: corsArray,
	})

	// Create static route negroni handler
	router.PathPrefix("/web").Handler(negroni.New(
		negroni.NewStatic(http.Dir(".")),
		negroni.Wrap(sRoutes),
	))

	// Create a new negroni for the api middleware
	router.PathPrefix("/api").Handler(negroni.New(
		negroni.HandlerFunc(validateTokenMiddleware),
		negroni.Wrap(apiRoutes),
		c,
	))

	logger.Infof("Listening API at %s", cfg.APIListen)
	// Bind to a port and pass our router in
	logger.Critical(http.ListenAndServeTLS(cfg.APIListen, pemCertPath, pemKeyPath, router))
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Version: " + config.Version()))
}

func balanceHandler(w http.ResponseWriter, r *http.Request) {
	t, err := GetBalance()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error getting Balance")
		logger.Errorf("Error getting balance %v", err)
		logFatal(err)
	}
	jsonResponse(t, w)
}

func ticketsHandler(w http.ResponseWriter, r *http.Request) {
	t, err := GetTickets()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error getting Tickets")
		logger.Errorf("Error getting tickets %v", err)
		logFatal(err)
	}
	jsonResponse(t, w)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user UserCredentials

	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Error in request")
		logger.Errorf("Error in request %v", err)
		return
	}

	if user.Username != cfg.APIKey || user.Password != cfg.APISecret {
		w.WriteHeader(http.StatusForbidden)
		fmt.Println("Error logging in")
		fmt.Fprint(w, "Invalid credentials")
		logger.Warnf("Invalid credentials %v", err)
		return
	}

	token := jwt.New(jwt.SigningMethodES512)
	claims := make(jwt.MapClaims)
	claims["admin"] = true
	claims["name"] = userName
	claims["exp"] = time.Now().Add(cfg.APITokenDuration).Unix()
	claims["iat"] = time.Now().Unix()
	token.Claims = claims

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error extracting the key")
		logger.Errorf("Error extracting the key %v", err)
		logFatal(err)
	}

	tokenString, err := token.SignedString(ecdsaKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while signing the token")
		logger.Errorf("Error while signing the token %v", err)
		logFatal(err)
	}

	response := Token{tokenString}
	jsonResponse(response, w)

}

func validateTokenMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})

	if err == nil {
		if token.Valid {
			next(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Token is not valid")
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Unauthorized access to this resource")
	}

}

func jsonResponse(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func main() {

}

// Start HTTP request multiplexer service
func Start(tcfg *config.Config, tclient *rpcclient.Client) {
	cfg = tcfg
	client = tclient
	config.InitLogRotator(cfg.LogFile)
	UseLogger(logger)
	logger.Infof("APIKey %s", cfg.APIKey)
	err := initKeys()
	if err == nil {
		startServer()
	}

	// Get the current block count.
	/*blockCount, err := client.GetBlockCount()
	if err != nil {
		config.DcrpLog.Errorf("Error counting blocks %v", err)
	}
	config.DcrpLog.Infof("Last Block: %d", blockCount)
	*/
}
