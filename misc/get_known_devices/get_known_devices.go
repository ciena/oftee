package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
)

// App is the application configuration and runtime information
type App struct {
	ShowHelp bool   `envconfig:"HELP" default:"false" desc:"show this message"`
	OFTeeAPI string `envconfig:"OFTEE_API" default:"http://127.0.0.1:8002" desc:"HOST:PORT on which to connect to OFTEE REST API"`
}

func main() {
	var app App

	var flags flag.FlagSet
	err := flags.Parse(os.Args[1:])
	if err != nil {
		if err = envconfig.Usage("", &(app)); err != nil {
			log.
				WithError(err).
				Fatal("Unable to display usage information")
		}
		return
	}

	err = envconfig.Process("", &app)
	if err != nil {
		log.WithError(err).Fatal("Unable to parse application configuration")
	}
	if app.ShowHelp {
		if err = envconfig.Usage("", &(app)); err != nil {
			log.
				WithError(err).
				Fatal("Unable to display usage information")
		}
		return
	}

	resp, err := http.Get(fmt.Sprintf("%s/oftee", app.OFTeeAPI))
	if err != nil {
		log.
			WithFields(log.Fields{
				"oftee": app.OFTeeAPI,
			}).
			WithError(err).
			Fatal("Unable to connect to oftee API end point")
	} else if int(resp.StatusCode/100) != 2 {
		log.
			WithFields(log.Fields{
				"oftee":         app.OFTeeAPI,
				"response-code": resp.StatusCode,
				"response":      resp.Status,
			}).
			Fatal("Non success code returned from oftee")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.
			WithFields(log.Fields{
				"oftee": app.OFTeeAPI,
			}).
			WithError(err).
			Fatal("Unable to read response from oftee")
	}
	fmt.Print(string(data))
}
