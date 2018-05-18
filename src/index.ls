/**
 * @package Detox routing
 * @author  Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @license 0BSD
 */
# Length of Ed25519 public key in bytes
const PUBLIC_KEY_LENGTH				= 32
# ChaChaPoly+BLAKE2b
const MAC_LENGTH					= 16
# Max time in seconds allowed for routing path segment creation after which creation is considered failed
const ROUTING_PATH_SEGMENT_TIMEOUT	= 10
# 3 bytes (2 for multiplexer and 1 for command) smaller than packet size on peer connection in order to avoid fragmentation when sending over peer connection
const ROUTER_PACKET_SIZE			= 512 - 3

function Wrapper (detox-crypto, detox-transport, detox-utils, ronion, fixed-size-multiplexer, async-eventer)
	are_arrays_equal	= detox-utils['are_arrays_equal']
	concat_arrays		= detox-utils['concat_arrays']
	ArrayMap			= detox-utils['ArrayMap']
	timeoutSet			= detox-utils['timeoutSet']
	MAX_DATA_SIZE		= detox-transport['MAX_DATA_SIZE']
	/**
	 * @constructor
	 *
	 * @param {!Uint8Array}	dht_private_key			X25519 private key that corresponds to Ed25519 key used in `DHT` constructor (from `@detox/dht` package)
	 * @param {number}		max_pending_segments	How much segments can be in pending state per one address
	 *
	 * @return {!Router}
	 *
	 * @throws {Error}
	 */
	!function Router (dht_private_key, max_pending_segments = 10)
		if !(@ instanceof Router)
			return new Router(dht_private_key, max_pending_segments)
		async-eventer.call(@)

		@_encryptor_instances		= ArrayMap()
		@_rewrapper_instances		= ArrayMap()
		@_last_node_in_routing_path	= ArrayMap()
		@_multiplexers				= ArrayMap()
		@_demultiplexers			= ArrayMap()
		@_established_routing_paths	= ArrayMap()
		@_ronion					= ronion(ROUTER_PACKET_SIZE, PUBLIC_KEY_LENGTH, MAC_LENGTH, max_pending_segments)
			.'on'('activity', (address, segment_id) !~>
				@'fire'('activity', address, segment_id)
			)
			.'on'('create_request', (address, segment_id, command_data) !~>
				if @_destroyed
					return
				source_id	= concat_arrays([address, segment_id])
				if @_encryptor_instances.has(source_id)
					# Something wrong is happening, refuse to handle
					return
				encryptor_instance	= detox-crypto['Encryptor'](false, dht_private_key)
				try
					encryptor_instance['put_handshake_message'](command_data)
				catch
					return
				@_ronion['create_response'](address, segment_id, encryptor_instance['get_handshake_message']())
				# At this point we simply assume that initiator received our response
				@_ronion['confirm_incoming_segment_established'](address, segment_id)
				# Make sure each chunk after encryption will fit perfectly into transport packet
				@_multiplexers.set(source_id, fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
				@_demultiplexers.set(source_id, fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
				if !encryptor_instance['ready']()
					return
				rewrapper_instance					= encryptor_instance['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
				encryptor_instances					= ArrayMap()
				encryptor_instances.set(address, encryptor_instance)
				rewrapper_instances					= ArrayMap()
				rewrapper_instances.set(address, rewrapper_instance)
				@_encryptor_instances.set(source_id, encryptor_instances)
				@_rewrapper_instances.set(source_id, rewrapper_instances)
				@_last_node_in_routing_path.set(source_id, address)
			)
			.'on'('send', (address, packet) !~>
				@'fire'('send', address, packet)
			)
			.'on'('data', (address, segment_id, target_address, command, command_data) !~>
				if @_destroyed
					return
				source_id					= concat_arrays([address, segment_id])
				last_node_in_routing_path	= @_last_node_in_routing_path.get(source_id)
				if !are_arrays_equal(target_address, last_node_in_routing_path)
					# We only accept data back from responder
					return
				demultiplexer				= @_demultiplexers.get(source_id)
				if !demultiplexer
					return
				demultiplexer['feed'](command_data)
				# Data are always more or equal to block size, so no need to do `while` loop
				if demultiplexer['have_more_data']()
					data	= demultiplexer['get_data']()
					@'fire'('data', address, segment_id, command, data)
			)
			.'on'('encrypt', (data) !~>
				if @_destroyed
					return
				address				= data['address']
				segment_id			= data['segment_id']
				target_address		= data['target_address']
				plaintext			= data['plaintext']
				source_id			= concat_arrays([address, segment_id])
				encryptor_instance	= @_encryptor_instances.get(source_id)?.get(target_address)
				if !encryptor_instance || !encryptor_instance['ready']()
					return
				data['ciphertext']	= encryptor_instance['encrypt'](plaintext)
			)
			.'on'('decrypt', (data) !~>
				if @_destroyed
					return
				address				= data['address']
				segment_id			= data['segment_id']
				target_address		= data['target_address']
				ciphertext			= data['ciphertext']
				source_id			= concat_arrays([address, segment_id])
				encryptor_instance	= @_encryptor_instances.get(source_id)?.get(target_address)
				if !encryptor_instance || !encryptor_instance['ready']()
					return
				# This can legitimately throw exceptions if ciphertext is not targeted at this node
				try
					data['plaintext']	= encryptor_instance['decrypt'](ciphertext)
				catch
					/**
					 * Since we don't use all of Ronion features and only send data between initiator and responder, we can destroy unnecessary encryptor
					 * instances and don't even try to decrypt anything, which makes data forwarding less CPU intensive
					 */
					encryptor_instance['destroy']()
					@_encryptor_instances.get(source_id).delete(target_address)
			)
			.'on'('wrap', (data) !~>
				if @_destroyed
					return
				address				= data['address']
				segment_id			= data['segment_id']
				target_address		= data['target_address']
				unwrapped			= data['unwrapped']
				source_id			= concat_arrays([address, segment_id])
				rewrapper_instance	= @_rewrapper_instances.get(source_id)?.get(target_address)?[0]
				if !rewrapper_instance
					return
				data['wrapped']	= rewrapper_instance['wrap'](unwrapped)
			)
			.'on'('unwrap', (data) !~>
				if @_destroyed
					return
				address				= data['address']
				segment_id			= data['segment_id']
				target_address		= data['target_address']
				wrapped				= data['wrapped']
				source_id			= concat_arrays([address, segment_id])
				rewrapper_instance	= @_rewrapper_instances.get(source_id)?.get(target_address)?[1]
				if !rewrapper_instance
					return
				data['unwrapped']	= rewrapper_instance['unwrap'](wrapped)
			)
		@_max_packet_data_size	= @_ronion['get_max_command_data_length']()

	Router:: =
		/**
		 * Process routing packet coming from node with specified ID
		 *
		 * @param {!Uint8Array} node_id
		 * @param {!Uint8Array} packet
		 */
		'process_packet' : (node_id, packet) !->
			if @_destroyed
				return
			@_ronion['process_packet'](node_id, packet)
		/**
		 * Construct routing path through specified nodes
		 *
		 * @param {!Array<!Uint8Array>} nodes IDs of the nodes through which routing path must be constructed, last node in the list is responder
		 *
		 * @return {!Promise} Will resolve with ID of the route or will be rejected if path construction fails
		 */
		'construct_routing_path' : (nodes) ->
			if @_destroyed
				return Promise.reject()
			nodes	= nodes.slice() # Do not modify source array
			new Promise (resolve, reject) !~>
				last_node_in_routing_path				= nodes[* - 1]
				first_node								= nodes.shift()
				encryptor_instances						= ArrayMap()
				rewrapper_instances						= ArrayMap()
				fail									= !~>
					@_destroy_routing_path(first_node, route_id)
					reject('Routing path creation failed')
				# Establishing first segment
				x25519_public_key						= detox-crypto['convert_public_key'](first_node)
				if !x25519_public_key
					fail()
					return
				first_node_encryptor_instance			= detox-crypto['Encryptor'](true, x25519_public_key)
				encryptor_instances.set(first_node, first_node_encryptor_instance)
				!~function create_response_handler (address, segment_id, command_data)
					if !are_arrays_equal(first_node, address) || !are_arrays_equal(route_id, segment_id)
						return
					clearTimeout(segment_establishment_timeout)
					@_ronion['off']('create_response', create_response_handler)
					try
						first_node_encryptor_instance['put_handshake_message'](command_data)
					catch
						fail()
						return
					if !first_node_encryptor_instance['ready']()
						fail()
						return
					rewrapper_instances.set(
						first_node
						first_node_encryptor_instance['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
					)
					@_ronion['confirm_outgoing_segment_established'](first_node, route_id)
					# Make sure each chunk after encryption will fit perfectly into transport packet
					@_multiplexers.set(source_id, fixed-size-multiplexer['Multiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
					@_demultiplexers.set(source_id, fixed-size-multiplexer['Demultiplexer'](MAX_DATA_SIZE, @_max_packet_data_size))
					# Successfully established first segment, extending routing path further
					var current_node, current_node_encryptor_instance, segment_extension_timeout
					!~function extend_request
						if !nodes.length
							@_established_routing_paths.set(source_id, [first_node, route_id])
							resolve(route_id)
							return
						!~function extend_response_handler (address, segment_id, command_data)
							if !are_arrays_equal(first_node, address) || !are_arrays_equal(route_id, segment_id)
								return
							@_ronion['off']('extend_response', extend_response_handler)
							clearTimeout(segment_extension_timeout)
							# If last node in routing path clearly said extension failed - no need to do something else here
							if !command_data.length
								fail()
								return
							try
								current_node_encryptor_instance['put_handshake_message'](command_data)
							catch
								fail()
								return
							if !current_node_encryptor_instance['ready']()
								fail()
								return
							rewrapper_instances.set(
								current_node
								current_node_encryptor_instance['get_rewrapper_keys']().map(detox-crypto['Rewrapper'])
							)
							@_ronion['confirm_extended_path'](first_node, route_id)
							# Successfully extended routing path by one more segment, continue extending routing path further
							extend_request()
						@_ronion['on']('extend_response', extend_response_handler)
						current_node					:= nodes.shift()
						x25519_public_key				= detox-crypto['convert_public_key'](current_node)
						if !x25519_public_key
							fail()
							return
						current_node_encryptor_instance	:= detox-crypto['Encryptor'](true, x25519_public_key)
						encryptor_instances.set(current_node, current_node_encryptor_instance)
						segment_extension_timeout		:= timeoutSet(ROUTING_PATH_SEGMENT_TIMEOUT, !~>
							@_ronion['off']('extend_response', extend_response_handler)
							fail()
						)
						@_ronion['extend_request'](first_node, route_id, current_node, current_node_encryptor_instance['get_handshake_message']())
					extend_request()
				@_ronion['on']('create_response', create_response_handler)
				segment_establishment_timeout	= timeoutSet(ROUTING_PATH_SEGMENT_TIMEOUT, !~>
					@_ronion['off']('create_response', create_response_handler)
					fail()
				)
				route_id						= @_ronion['create_request'](first_node, first_node_encryptor_instance['get_handshake_message']())
				source_id						= concat_arrays([first_node, route_id])
				@_encryptor_instances.set(source_id, encryptor_instances)
				@_rewrapper_instances.set(source_id, rewrapper_instances)
				@_last_node_in_routing_path.set(source_id, last_node_in_routing_path)
		/**
		 * Destroy routing path constructed earlier
		 *
		 * @param {!Uint8Array} node_id		First node in routing path
		 * @param {!Uint8Array} route_id	Identifier returned during routing path construction
		 */
		'destroy_routing_path' : (node_id, route_id) !->
			@_destroy_routing_path(node_id, route_id)
		/**
		 * Max data size that will fit into single packet without fragmentation
		 *
		 * @return {number}
		 */
		'get_max_packet_data_size' : ->
			@_max_packet_data_size
		/**
		 * Send data to the responder on specified routing path
		 *
		 * @param {!Uint8Array}	node_id		First node in routing path
		 * @param {!Uint8Array}	route_id	Identifier returned during routing path construction
		 * @param {number}		command		Command from range `0..245`
		 * @param {!Uint8Array}	data
		 */
		'send_data' : (node_id, route_id, command, data) !->
			if @_destroyed
				return
			if data.length > MAX_DATA_SIZE
				return
			source_id		= concat_arrays([node_id, route_id])
			target_address	= @_last_node_in_routing_path.get(source_id)
			multiplexer		= @_multiplexers.get(source_id)
			if !multiplexer
				return
			multiplexer['feed'](data)
			while multiplexer['have_more_blocks']()
				data_block	= multiplexer['get_block']()
				@_ronion['data'](node_id, route_id, target_address, command, data_block)
		/**
		 * Destroy all of the routing path constructed earlier
		 */
		'destroy' : !->
			if @_destroyed
				return
			@_destroyed = true
			@_established_routing_paths.forEach ([address, segment_id]) !~>
				@_destroy_routing_path(address, segment_id)
		/**
		 * @param {!Uint8Array} address
		 * @param {!Uint8Array} segment_id
		 */
		_destroy_routing_path : (address, segment_id) !->
			source_id			= concat_arrays([address, segment_id])
			encryptor_instances	= @_encryptor_instances.get(source_id)
			if !encryptor_instances
				return
			encryptor_instances.forEach (encryptor_instance) !->
				encryptor_instance['destroy']()
			@_encryptor_instances.delete(source_id)
			@_rewrapper_instances.delete(source_id)
			@_last_node_in_routing_path.delete(source_id)
			@_multiplexers.delete(source_id)
			@_demultiplexers.delete(source_id)
			@_established_routing_paths.delete(source_id)
	Router:: = Object.assign(Object.create(async-eventer::), Router::)
	Object.defineProperty(Router::, 'constructor', {value: Router})
	{
		'ready'			: detox-crypto['ready']
		'Router'		: Router
		'MAX_DATA_SIZE'	: MAX_DATA_SIZE
	}

if typeof define == 'function' && define['amd']
	# AMD
	define(['@detox/crypto', '@detox/transport', '@detox/utils', 'ronion', 'fixed-size-multiplexer', 'async-eventer'], Wrapper)
else if typeof exports == 'object'
	# CommonJS
	module.exports = Wrapper(require('@detox/crypto'), require('@detox/transport'), require('@detox/utils'), require('ronion'), require('fixed-size-multiplexer'), require('async-eventer'))
else
	# Browser globals
	@'detox_transport' = Wrapper(@'detox_crypto', @'detox_transport', @'detox_utils', @'ronion', @'fixed_size_multiplexer', @'async_eventer')
