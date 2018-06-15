// This package implements the oftee API that can be used for injecting
// packets to the open flow devices
package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ciena/oftee/injector"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// Define DPID mapping actions
type MappingAction uint8

const (
	MAP_ACTION_NONE   MappingAction = 0x0
	MAP_ACTION_ADD    MappingAction = 1 << 0
	MAP_ACTION_DELETE MappingAction = 1 << 1
)

// Used to associate a DPID with an injecting packet processor
type DpidMapping struct {
	Action MappingAction
	Dpid   uint64
	Inject *injector.Injector
}

// OFTEE API
type Api struct {
	DpidMappingListener chan DpidMapping
	ListenOn            string

	injectors map[uint64]*injector.Injector
	router    *mux.Router
	lock      sync.RWMutex
}

// Used to create a HTTP response that lists all the known DPIDs
type DevicesResponse struct {
	Devices []string `json:"devices"`
}

// Returns an list of DPIDs known to the system as a JSON array
func (api *Api) ListDevicesHandler(resp http.ResponseWriter, req *http.Request) {

	// Create the response object
	api.lock.RLock()
	data := DevicesResponse{
		Devices: make([]string, len(api.injectors)),
	}
	i := 0
	for key, _ := range api.injectors {
		data.Devices[i] = fmt.Sprintf("of:0x%016x", key)
		i += 1
	}
	api.lock.RUnlock()

	// Convert it to bytes and return it
	bytes, err := json.Marshal(data)
	if err != nil {
		http.Error(resp,
			fmt.Sprintf("Unable to marshal device list : %s", err.Error()),
			http.StatusInternalServerError)
		return
	}
	resp.Write(bytes)
}

// Handles an HTTP request to packet out to a given switch port. The payload to
// the request should be the []byte of a OpenFlow packet out message, including
// the open flow header, the packet out header, and the packet.
func (api *Api) PacketOutHandler(resp http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	// Parse the URL for the target device's DPID
	vars := mux.Vars(req)
	log.WithFields(log.Fields{
		"dpid": vars["dpid"],
	}).Debug("Packet out request recieved")
	dpid, err := strconv.ParseUint(vars["dpid"], 0, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"dpid": vars["dpid"],
		}).Warn("Unable to parse given DPID")
		http.Error(resp, fmt.Sprintf("DPID doesn't reference a device, '%s' : %s", vars["dpid"], err), http.StatusNotFound)
		return
	}
	api.lock.RLock()
	inject, ok := api.injectors[uint64(dpid)]
	api.lock.RUnlock()

	// If DPID doesn't exist in mapping, then 404
	if !ok {
		log.WithFields(log.Fields{
			"dpid": vars["dpid"],
		}).Warn("Unable to find packet injector for DPID, unknown device")
		http.Error(resp, fmt.Sprintf("DPID not found, '%s'", vars["dpid"]), http.StatusNotFound)
		return
	}

	// Read the OpenFlow message from the body
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}

	// Inject the packet
	inject.Inject(data)
}

// Loop that listens for updates of DPID mappings
func (api *Api) dpidMappingUpdates() {
	for {
		mapping := <-api.DpidMappingListener

		switch mapping.Action {
		case MAP_ACTION_ADD:
			log.WithFields(log.Fields{
				"dpid": fmt.Sprintf("0x%016x", mapping.Dpid),
			}).Debug("Adding device mapping")
			api.lock.Lock()
			api.injectors[mapping.Dpid] = mapping.Inject
			api.lock.Unlock()
		case MAP_ACTION_DELETE:
			log.WithFields(log.Fields{
				"dpid": fmt.Sprintf("0x%016x", mapping.Dpid),
			}).Debug("Deleting device mapping")
			api.lock.Lock()
			delete(api.injectors, mapping.Dpid)
			api.lock.Unlock()
		default:
			log.WithFields(log.Fields{
				"dpid":   fmt.Sprintf("0x%016x", mapping.Dpid),
				"action": mapping.Action,
			}).Warn("Received unknown device mapping action")
		}
	}
}

// Properly instantiates a new API instance.
func NewApi(listenOn string) *Api {
	api := &Api{
		ListenOn:            listenOn,
		router:              mux.NewRouter(),
		injectors:           make(map[uint64]*injector.Injector),
		DpidMappingListener: make(chan DpidMapping),
	}

	api.router.
		HandleFunc("/oftee/{dpid}", api.PacketOutHandler).
		Methods("POST").
		Headers("Content-type", "application/octet-stream")
	api.router.
		HandleFunc("/oftee", api.ListDevicesHandler).
		Methods("GET")
	http.Handle("/", api.router)
	return api
}

func (api *Api) ListenAndServe() {

	// TODO It is good Go practice to handle structures that arrive
	// "unitialized". This should be done here, so NewApi does not "have" to
	// be called.

	srv := &http.Server{
		Addr: api.ListenOn,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// Start the DPID update listener
	log.Debug("Start API listening for device DPID information")
	go api.dpidMappingUpdates()

	log.WithFields(log.Fields{
		"connect-point": api.ListenOn,
	}).Debug("Listening for REST API requests")
	log.Fatal(srv.ListenAndServe())
}
