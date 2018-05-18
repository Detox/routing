# Detox routing [![Travis CI](https://img.shields.io/travis/Detox/routing/master.svg?label=Travis%20CI)](https://travis-ci.org/Detox/routing)
Anonymous routing implementation for Detox project.

This is a domain-specific implementation of anonymous routing functionality with simple API.
It is built on top of [Ronion](https://github.com/nazar-pc/ronion) framework and uses `@detox/crypto` for cryptographic needs.
Still agnostic to transport layer.

## How to install
```
npm install @detox/routing
```

## How to use
Node.js:
```javascript
var detox_routing = require('@detox/routing')

detox_routing.ready(function () {
    // Do stuff
});
```
Browser:
```javascript
requirejs(['@detox/routing'], function (detox_routing) {
    detox_routing.ready(function () {
        // Do stuff
    });
})
```

## API
### detox_routing.ready(callback)
* `callback` - Callback function that is called when library is ready for use

### detox_routing.Router(dht_private_key : Uint8Array, max_pending_segments = 10 : number) : detox_routing.Router
Constructor for Router object, offers anonymous routing functionality based on [Ronion](https://github.com/nazar-pc/ronion) spec and reference implementation with just a few high-level APIs available for the user.

* `dht_private_key` - X25519 private key that corresponds to Ed25519 key used in `DHT` constructor (from `@detox/dht` package)
* `max_pending_segments` - How much segments can be in pending state per one address

### detox_routing.Router.process_packet(node_id : Uint8Array, packet : Uint8Array)
Process routing packet coming from node with specified ID.

### detox_routing.Router.construct_routing_path(nodes : Uint8Array[]) : Promise
Construct routing path through specified nodes.

* `nodes` - IDs of the nodes through which routing path must be constructed, last node in the list is responder

Returned promise will resolve with ID of the route or will be rejected if path construction fails.

### detox_routing.Router.destroy_routing_path(node_id : Uint8Array, route_id : Uint8Array)
Destroy routing path constructed earlier.

* `node_id` - first node in routing path
* `route_id` - identifier returned during routing path construction

### detox_routing.Router.get_max_packet_data_size() : number
Max data size that will fit into single packet without fragmentation

### detox_routing.Router.send_data(node_id : Uint8Array, route_id : Uint8Array, command : number, data : Uint8Array)
Send data to the responder on specified routing path.

* `node_id` - first node in routing path
* `route_id` - identifier returned during routing path construction
* `command` - command for data, can be any number from the range `0..245`
* `data` - data being sent

### detox_routing.Router.destroy()
Destroy all of the routing path constructed earlier.

### detox_routing.Router.on(event: string, callback: Function) : detox_routing.Router
Register event handler.

### detox_routing.Router.once(event: string, callback: Function) : detox_routing.Router
Register one-time event handler (just `on()` + `off()` under the hood).

### detox_routing.Router.off(event: string[, callback: Function]) : detox_routing.Router
Unregister event handler.

### Event: activity
Payload consists of two `Uint8Array` arguments: `node_id` and `route_id`.
Event is fired when packet is sent/received from/to `address` with segment ID `segment_id`.

This event can be used to track when packets are flowing on certain `address` and `segment_id` and decide when to consider routing path as inactive and destroy it.

### Event: send
Payload consists of two `Uint8Array` arguments: `node_id` and `packet`.
Event is fired when `packet` needs to be sent to `node_id` node.

### Event: data
Payload consists of four arguments, all of which except `command` are `Uint8Array`: `node_id`, `route_id`, `command` and `data`.

Event is fired when `data` were received from the responder with specified `command` on routing path with started at `node_id` with `route_id`.

### detox_routing.MAX_DATA_SIZE : number
Constant that defines max data size supported for sending by Router as command data.

## Contribution
Feel free to create issues and send pull requests (for big changes create an issue first and link it from the PR), they are highly appreciated!

When reading LiveScript code make sure to configure 1 tab to be 4 spaces (GitHub uses 8 by default), otherwise code might be hard to read.

## License
Free Public License 1.0.0 / Zero Clause BSD License

https://opensource.org/licenses/FPL-1.0.0

https://tldrlegal.com/license/bsd-0-clause-license
