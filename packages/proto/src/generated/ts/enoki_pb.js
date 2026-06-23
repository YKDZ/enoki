/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars*/
import $protobuf from "protobufjs/minimal.js";

// Common aliases
const $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;

// Exported root namespace
const $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

export const enoki = $root.enoki = (() => {

    /**
     * Namespace enoki.
     * @exports enoki
     * @namespace
     */
    const enoki = {};

    enoki.v1 = (function() {

        /**
         * Namespace v1.
         * @memberof enoki
         * @namespace
         */
        const v1 = {};

        v1.Inventory = (function() {

            /**
             * Properties of an Inventory.
             * @memberof enoki.v1
             * @interface IInventory
             * @property {string|null} [hostname] Inventory hostname
             * @property {string|null} [os] Inventory os
             * @property {string|null} [kernel] Inventory kernel
             * @property {string|null} [architecture] Inventory architecture
             * @property {number|null} [cpuCount] Inventory cpuCount
             * @property {Long|null} [memoryTotalBytes] Inventory memoryTotalBytes
             * @property {Array.<enoki.v1.IFilesystemInventory>|null} [filesystems] Inventory filesystems
             * @property {Array.<enoki.v1.INetworkInterfaceInventory>|null} [networkInterfaces] Inventory networkInterfaces
             * @property {string|null} [probeVersion] Inventory probeVersion
             * @property {string|null} [cpuModel] Inventory cpuModel
             * @property {number|null} [processCount] Inventory processCount
             * @property {number|null} [threadCount] Inventory threadCount
             * @property {Long|null} [cpuCacheL3Bytes] Inventory cpuCacheL3Bytes
             * @property {number|null} [cpuBaseFrequencyMhz] Inventory cpuBaseFrequencyMhz
             * @property {number|null} [cpuSocketCount] Inventory cpuSocketCount
             * @property {number|null} [cpuPhysicalCount] Inventory cpuPhysicalCount
             * @property {enoki.v1.ICollectorCapabilities|null} [collectorCapabilities] Inventory collectorCapabilities
             */

            /**
             * Constructs a new Inventory.
             * @memberof enoki.v1
             * @classdesc Represents an Inventory.
             * @implements IInventory
             * @constructor
             * @param {enoki.v1.IInventory=} [properties] Properties to set
             */
            function Inventory(properties) {
                this.filesystems = [];
                this.networkInterfaces = [];
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * Inventory hostname.
             * @member {string} hostname
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.hostname = "";

            /**
             * Inventory os.
             * @member {string} os
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.os = "";

            /**
             * Inventory kernel.
             * @member {string} kernel
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.kernel = "";

            /**
             * Inventory architecture.
             * @member {string} architecture
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.architecture = "";

            /**
             * Inventory cpuCount.
             * @member {number} cpuCount
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.cpuCount = 0;

            /**
             * Inventory memoryTotalBytes.
             * @member {Long} memoryTotalBytes
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.memoryTotalBytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * Inventory filesystems.
             * @member {Array.<enoki.v1.IFilesystemInventory>} filesystems
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.filesystems = $util.emptyArray;

            /**
             * Inventory networkInterfaces.
             * @member {Array.<enoki.v1.INetworkInterfaceInventory>} networkInterfaces
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.networkInterfaces = $util.emptyArray;

            /**
             * Inventory probeVersion.
             * @member {string} probeVersion
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.probeVersion = "";

            /**
             * Inventory cpuModel.
             * @member {string} cpuModel
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.cpuModel = "";

            /**
             * Inventory processCount.
             * @member {number} processCount
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.processCount = 0;

            /**
             * Inventory threadCount.
             * @member {number} threadCount
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.threadCount = 0;

            /**
             * Inventory cpuCacheL3Bytes.
             * @member {Long} cpuCacheL3Bytes
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.cpuCacheL3Bytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * Inventory cpuBaseFrequencyMhz.
             * @member {number} cpuBaseFrequencyMhz
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.cpuBaseFrequencyMhz = 0;

            /**
             * Inventory cpuSocketCount.
             * @member {number} cpuSocketCount
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.cpuSocketCount = 0;

            /**
             * Inventory cpuPhysicalCount.
             * @member {number} cpuPhysicalCount
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.cpuPhysicalCount = 0;

            /**
             * Inventory collectorCapabilities.
             * @member {enoki.v1.ICollectorCapabilities|null|undefined} collectorCapabilities
             * @memberof enoki.v1.Inventory
             * @instance
             */
            Inventory.prototype.collectorCapabilities = null;

            /**
             * Creates a new Inventory instance using the specified properties.
             * @function create
             * @memberof enoki.v1.Inventory
             * @static
             * @param {enoki.v1.IInventory=} [properties] Properties to set
             * @returns {enoki.v1.Inventory} Inventory instance
             */
            Inventory.create = function create(properties) {
                return new Inventory(properties);
            };

            /**
             * Encodes the specified Inventory message. Does not implicitly {@link enoki.v1.Inventory.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.Inventory
             * @static
             * @param {enoki.v1.IInventory} message Inventory message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            Inventory.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.hostname != null && Object.hasOwnProperty.call(message, "hostname"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.hostname);
                if (message.os != null && Object.hasOwnProperty.call(message, "os"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.os);
                if (message.kernel != null && Object.hasOwnProperty.call(message, "kernel"))
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.kernel);
                if (message.architecture != null && Object.hasOwnProperty.call(message, "architecture"))
                    writer.uint32(/* id 4, wireType 2 =*/34).string(message.architecture);
                if (message.cpuCount != null && Object.hasOwnProperty.call(message, "cpuCount"))
                    writer.uint32(/* id 5, wireType 0 =*/40).uint32(message.cpuCount);
                if (message.memoryTotalBytes != null && Object.hasOwnProperty.call(message, "memoryTotalBytes"))
                    writer.uint32(/* id 6, wireType 0 =*/48).uint64(message.memoryTotalBytes);
                if (message.filesystems != null && message.filesystems.length)
                    for (let i = 0; i < message.filesystems.length; ++i)
                        $root.enoki.v1.FilesystemInventory.encode(message.filesystems[i], writer.uint32(/* id 7, wireType 2 =*/58).fork(), q + 1).ldelim();
                if (message.networkInterfaces != null && message.networkInterfaces.length)
                    for (let i = 0; i < message.networkInterfaces.length; ++i)
                        $root.enoki.v1.NetworkInterfaceInventory.encode(message.networkInterfaces[i], writer.uint32(/* id 8, wireType 2 =*/66).fork(), q + 1).ldelim();
                if (message.probeVersion != null && Object.hasOwnProperty.call(message, "probeVersion"))
                    writer.uint32(/* id 9, wireType 2 =*/74).string(message.probeVersion);
                if (message.cpuModel != null && Object.hasOwnProperty.call(message, "cpuModel"))
                    writer.uint32(/* id 10, wireType 2 =*/82).string(message.cpuModel);
                if (message.processCount != null && Object.hasOwnProperty.call(message, "processCount"))
                    writer.uint32(/* id 11, wireType 0 =*/88).uint32(message.processCount);
                if (message.threadCount != null && Object.hasOwnProperty.call(message, "threadCount"))
                    writer.uint32(/* id 12, wireType 0 =*/96).uint32(message.threadCount);
                if (message.cpuCacheL3Bytes != null && Object.hasOwnProperty.call(message, "cpuCacheL3Bytes"))
                    writer.uint32(/* id 13, wireType 0 =*/104).uint64(message.cpuCacheL3Bytes);
                if (message.cpuBaseFrequencyMhz != null && Object.hasOwnProperty.call(message, "cpuBaseFrequencyMhz"))
                    writer.uint32(/* id 14, wireType 0 =*/112).uint32(message.cpuBaseFrequencyMhz);
                if (message.cpuSocketCount != null && Object.hasOwnProperty.call(message, "cpuSocketCount"))
                    writer.uint32(/* id 15, wireType 0 =*/120).uint32(message.cpuSocketCount);
                if (message.cpuPhysicalCount != null && Object.hasOwnProperty.call(message, "cpuPhysicalCount"))
                    writer.uint32(/* id 16, wireType 0 =*/128).uint32(message.cpuPhysicalCount);
                if (message.collectorCapabilities != null && Object.hasOwnProperty.call(message, "collectorCapabilities"))
                    $root.enoki.v1.CollectorCapabilities.encode(message.collectorCapabilities, writer.uint32(/* id 17, wireType 2 =*/138).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified Inventory message, length delimited. Does not implicitly {@link enoki.v1.Inventory.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.Inventory
             * @static
             * @param {enoki.v1.IInventory} message Inventory message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            Inventory.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes an Inventory message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.Inventory
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.Inventory} Inventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            Inventory.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.Inventory();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.hostname = reader.string();
                            break;
                        }
                    case 2: {
                            message.os = reader.string();
                            break;
                        }
                    case 3: {
                            message.kernel = reader.string();
                            break;
                        }
                    case 4: {
                            message.architecture = reader.string();
                            break;
                        }
                    case 5: {
                            message.cpuCount = reader.uint32();
                            break;
                        }
                    case 6: {
                            message.memoryTotalBytes = reader.uint64();
                            break;
                        }
                    case 7: {
                            if (!(message.filesystems && message.filesystems.length))
                                message.filesystems = [];
                            message.filesystems.push($root.enoki.v1.FilesystemInventory.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    case 8: {
                            if (!(message.networkInterfaces && message.networkInterfaces.length))
                                message.networkInterfaces = [];
                            message.networkInterfaces.push($root.enoki.v1.NetworkInterfaceInventory.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    case 9: {
                            message.probeVersion = reader.string();
                            break;
                        }
                    case 10: {
                            message.cpuModel = reader.string();
                            break;
                        }
                    case 11: {
                            message.processCount = reader.uint32();
                            break;
                        }
                    case 12: {
                            message.threadCount = reader.uint32();
                            break;
                        }
                    case 13: {
                            message.cpuCacheL3Bytes = reader.uint64();
                            break;
                        }
                    case 14: {
                            message.cpuBaseFrequencyMhz = reader.uint32();
                            break;
                        }
                    case 15: {
                            message.cpuSocketCount = reader.uint32();
                            break;
                        }
                    case 16: {
                            message.cpuPhysicalCount = reader.uint32();
                            break;
                        }
                    case 17: {
                            message.collectorCapabilities = $root.enoki.v1.CollectorCapabilities.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes an Inventory message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.Inventory
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.Inventory} Inventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            Inventory.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies an Inventory message.
             * @function verify
             * @memberof enoki.v1.Inventory
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            Inventory.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.hostname != null && Object.hasOwnProperty.call(message, "hostname"))
                    if (!$util.isString(message.hostname))
                        return "hostname: string expected";
                if (message.os != null && Object.hasOwnProperty.call(message, "os"))
                    if (!$util.isString(message.os))
                        return "os: string expected";
                if (message.kernel != null && Object.hasOwnProperty.call(message, "kernel"))
                    if (!$util.isString(message.kernel))
                        return "kernel: string expected";
                if (message.architecture != null && Object.hasOwnProperty.call(message, "architecture"))
                    if (!$util.isString(message.architecture))
                        return "architecture: string expected";
                if (message.cpuCount != null && Object.hasOwnProperty.call(message, "cpuCount"))
                    if (!$util.isInteger(message.cpuCount))
                        return "cpuCount: integer expected";
                if (message.memoryTotalBytes != null && Object.hasOwnProperty.call(message, "memoryTotalBytes"))
                    if (!$util.isInteger(message.memoryTotalBytes) && !(message.memoryTotalBytes && $util.isInteger(message.memoryTotalBytes.low) && $util.isInteger(message.memoryTotalBytes.high)))
                        return "memoryTotalBytes: integer|Long expected";
                if (message.filesystems != null && Object.hasOwnProperty.call(message, "filesystems")) {
                    if (!Array.isArray(message.filesystems))
                        return "filesystems: array expected";
                    for (let i = 0; i < message.filesystems.length; ++i) {
                        let error = $root.enoki.v1.FilesystemInventory.verify(message.filesystems[i], long + 1);
                        if (error)
                            return "filesystems." + error;
                    }
                }
                if (message.networkInterfaces != null && Object.hasOwnProperty.call(message, "networkInterfaces")) {
                    if (!Array.isArray(message.networkInterfaces))
                        return "networkInterfaces: array expected";
                    for (let i = 0; i < message.networkInterfaces.length; ++i) {
                        let error = $root.enoki.v1.NetworkInterfaceInventory.verify(message.networkInterfaces[i], long + 1);
                        if (error)
                            return "networkInterfaces." + error;
                    }
                }
                if (message.probeVersion != null && Object.hasOwnProperty.call(message, "probeVersion"))
                    if (!$util.isString(message.probeVersion))
                        return "probeVersion: string expected";
                if (message.cpuModel != null && Object.hasOwnProperty.call(message, "cpuModel"))
                    if (!$util.isString(message.cpuModel))
                        return "cpuModel: string expected";
                if (message.processCount != null && Object.hasOwnProperty.call(message, "processCount"))
                    if (!$util.isInteger(message.processCount))
                        return "processCount: integer expected";
                if (message.threadCount != null && Object.hasOwnProperty.call(message, "threadCount"))
                    if (!$util.isInteger(message.threadCount))
                        return "threadCount: integer expected";
                if (message.cpuCacheL3Bytes != null && Object.hasOwnProperty.call(message, "cpuCacheL3Bytes"))
                    if (!$util.isInteger(message.cpuCacheL3Bytes) && !(message.cpuCacheL3Bytes && $util.isInteger(message.cpuCacheL3Bytes.low) && $util.isInteger(message.cpuCacheL3Bytes.high)))
                        return "cpuCacheL3Bytes: integer|Long expected";
                if (message.cpuBaseFrequencyMhz != null && Object.hasOwnProperty.call(message, "cpuBaseFrequencyMhz"))
                    if (!$util.isInteger(message.cpuBaseFrequencyMhz))
                        return "cpuBaseFrequencyMhz: integer expected";
                if (message.cpuSocketCount != null && Object.hasOwnProperty.call(message, "cpuSocketCount"))
                    if (!$util.isInteger(message.cpuSocketCount))
                        return "cpuSocketCount: integer expected";
                if (message.cpuPhysicalCount != null && Object.hasOwnProperty.call(message, "cpuPhysicalCount"))
                    if (!$util.isInteger(message.cpuPhysicalCount))
                        return "cpuPhysicalCount: integer expected";
                if (message.collectorCapabilities != null && Object.hasOwnProperty.call(message, "collectorCapabilities")) {
                    let error = $root.enoki.v1.CollectorCapabilities.verify(message.collectorCapabilities, long + 1);
                    if (error)
                        return "collectorCapabilities." + error;
                }
                return null;
            };

            /**
             * Creates an Inventory message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.Inventory
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.Inventory} Inventory
             */
            Inventory.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.Inventory)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.Inventory: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.Inventory();
                if (object.hostname != null)
                    message.hostname = String(object.hostname);
                if (object.os != null)
                    message.os = String(object.os);
                if (object.kernel != null)
                    message.kernel = String(object.kernel);
                if (object.architecture != null)
                    message.architecture = String(object.architecture);
                if (object.cpuCount != null)
                    message.cpuCount = object.cpuCount >>> 0;
                if (object.memoryTotalBytes != null)
                    if ($util.Long)
                        message.memoryTotalBytes = $util.Long.fromValue(object.memoryTotalBytes, true);
                    else if (typeof object.memoryTotalBytes === "string")
                        message.memoryTotalBytes = parseInt(object.memoryTotalBytes, 10);
                    else if (typeof object.memoryTotalBytes === "number")
                        message.memoryTotalBytes = object.memoryTotalBytes;
                    else if (typeof object.memoryTotalBytes === "object")
                        message.memoryTotalBytes = new $util.LongBits(object.memoryTotalBytes.low >>> 0, object.memoryTotalBytes.high >>> 0).toNumber(true);
                if (object.filesystems) {
                    if (!Array.isArray(object.filesystems))
                        throw TypeError(".enoki.v1.Inventory.filesystems: array expected");
                    message.filesystems = [];
                    for (let i = 0; i < object.filesystems.length; ++i) {
                        if (!$util.isObject(object.filesystems[i]))
                            throw TypeError(".enoki.v1.Inventory.filesystems: object expected");
                        message.filesystems[i] = $root.enoki.v1.FilesystemInventory.fromObject(object.filesystems[i], long + 1);
                    }
                }
                if (object.networkInterfaces) {
                    if (!Array.isArray(object.networkInterfaces))
                        throw TypeError(".enoki.v1.Inventory.networkInterfaces: array expected");
                    message.networkInterfaces = [];
                    for (let i = 0; i < object.networkInterfaces.length; ++i) {
                        if (!$util.isObject(object.networkInterfaces[i]))
                            throw TypeError(".enoki.v1.Inventory.networkInterfaces: object expected");
                        message.networkInterfaces[i] = $root.enoki.v1.NetworkInterfaceInventory.fromObject(object.networkInterfaces[i], long + 1);
                    }
                }
                if (object.probeVersion != null)
                    message.probeVersion = String(object.probeVersion);
                if (object.cpuModel != null)
                    message.cpuModel = String(object.cpuModel);
                if (object.processCount != null)
                    message.processCount = object.processCount >>> 0;
                if (object.threadCount != null)
                    message.threadCount = object.threadCount >>> 0;
                if (object.cpuCacheL3Bytes != null)
                    if ($util.Long)
                        message.cpuCacheL3Bytes = $util.Long.fromValue(object.cpuCacheL3Bytes, true);
                    else if (typeof object.cpuCacheL3Bytes === "string")
                        message.cpuCacheL3Bytes = parseInt(object.cpuCacheL3Bytes, 10);
                    else if (typeof object.cpuCacheL3Bytes === "number")
                        message.cpuCacheL3Bytes = object.cpuCacheL3Bytes;
                    else if (typeof object.cpuCacheL3Bytes === "object")
                        message.cpuCacheL3Bytes = new $util.LongBits(object.cpuCacheL3Bytes.low >>> 0, object.cpuCacheL3Bytes.high >>> 0).toNumber(true);
                if (object.cpuBaseFrequencyMhz != null)
                    message.cpuBaseFrequencyMhz = object.cpuBaseFrequencyMhz >>> 0;
                if (object.cpuSocketCount != null)
                    message.cpuSocketCount = object.cpuSocketCount >>> 0;
                if (object.cpuPhysicalCount != null)
                    message.cpuPhysicalCount = object.cpuPhysicalCount >>> 0;
                if (object.collectorCapabilities != null) {
                    if (!$util.isObject(object.collectorCapabilities))
                        throw TypeError(".enoki.v1.Inventory.collectorCapabilities: object expected");
                    message.collectorCapabilities = $root.enoki.v1.CollectorCapabilities.fromObject(object.collectorCapabilities, long + 1);
                }
                return message;
            };

            /**
             * Creates a plain object from an Inventory message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.Inventory
             * @static
             * @param {enoki.v1.Inventory} message Inventory
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            Inventory.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.arrays || options.defaults) {
                    object.filesystems = [];
                    object.networkInterfaces = [];
                }
                if (options.defaults) {
                    object.hostname = "";
                    object.os = "";
                    object.kernel = "";
                    object.architecture = "";
                    object.cpuCount = 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.memoryTotalBytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.memoryTotalBytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    object.probeVersion = "";
                    object.cpuModel = "";
                    object.processCount = 0;
                    object.threadCount = 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.cpuCacheL3Bytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.cpuCacheL3Bytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    object.cpuBaseFrequencyMhz = 0;
                    object.cpuSocketCount = 0;
                    object.cpuPhysicalCount = 0;
                    object.collectorCapabilities = null;
                }
                if (message.hostname != null && Object.hasOwnProperty.call(message, "hostname"))
                    object.hostname = message.hostname;
                if (message.os != null && Object.hasOwnProperty.call(message, "os"))
                    object.os = message.os;
                if (message.kernel != null && Object.hasOwnProperty.call(message, "kernel"))
                    object.kernel = message.kernel;
                if (message.architecture != null && Object.hasOwnProperty.call(message, "architecture"))
                    object.architecture = message.architecture;
                if (message.cpuCount != null && Object.hasOwnProperty.call(message, "cpuCount"))
                    object.cpuCount = message.cpuCount;
                if (message.memoryTotalBytes != null && Object.hasOwnProperty.call(message, "memoryTotalBytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.memoryTotalBytes = typeof message.memoryTotalBytes === "number" ? BigInt(message.memoryTotalBytes) : $util.Long.fromBits(message.memoryTotalBytes.low >>> 0, message.memoryTotalBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.memoryTotalBytes === "number")
                        object.memoryTotalBytes = options.longs === String ? String(message.memoryTotalBytes) : message.memoryTotalBytes;
                    else
                        object.memoryTotalBytes = options.longs === String ? $util.Long.prototype.toString.call(message.memoryTotalBytes) : options.longs === Number ? new $util.LongBits(message.memoryTotalBytes.low >>> 0, message.memoryTotalBytes.high >>> 0).toNumber(true) : message.memoryTotalBytes;
                if (message.filesystems && message.filesystems.length) {
                    object.filesystems = [];
                    for (let j = 0; j < message.filesystems.length; ++j)
                        object.filesystems[j] = $root.enoki.v1.FilesystemInventory.toObject(message.filesystems[j], options, q + 1);
                }
                if (message.networkInterfaces && message.networkInterfaces.length) {
                    object.networkInterfaces = [];
                    for (let j = 0; j < message.networkInterfaces.length; ++j)
                        object.networkInterfaces[j] = $root.enoki.v1.NetworkInterfaceInventory.toObject(message.networkInterfaces[j], options, q + 1);
                }
                if (message.probeVersion != null && Object.hasOwnProperty.call(message, "probeVersion"))
                    object.probeVersion = message.probeVersion;
                if (message.cpuModel != null && Object.hasOwnProperty.call(message, "cpuModel"))
                    object.cpuModel = message.cpuModel;
                if (message.processCount != null && Object.hasOwnProperty.call(message, "processCount"))
                    object.processCount = message.processCount;
                if (message.threadCount != null && Object.hasOwnProperty.call(message, "threadCount"))
                    object.threadCount = message.threadCount;
                if (message.cpuCacheL3Bytes != null && Object.hasOwnProperty.call(message, "cpuCacheL3Bytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.cpuCacheL3Bytes = typeof message.cpuCacheL3Bytes === "number" ? BigInt(message.cpuCacheL3Bytes) : $util.Long.fromBits(message.cpuCacheL3Bytes.low >>> 0, message.cpuCacheL3Bytes.high >>> 0, true).toBigInt();
                    else if (typeof message.cpuCacheL3Bytes === "number")
                        object.cpuCacheL3Bytes = options.longs === String ? String(message.cpuCacheL3Bytes) : message.cpuCacheL3Bytes;
                    else
                        object.cpuCacheL3Bytes = options.longs === String ? $util.Long.prototype.toString.call(message.cpuCacheL3Bytes) : options.longs === Number ? new $util.LongBits(message.cpuCacheL3Bytes.low >>> 0, message.cpuCacheL3Bytes.high >>> 0).toNumber(true) : message.cpuCacheL3Bytes;
                if (message.cpuBaseFrequencyMhz != null && Object.hasOwnProperty.call(message, "cpuBaseFrequencyMhz"))
                    object.cpuBaseFrequencyMhz = message.cpuBaseFrequencyMhz;
                if (message.cpuSocketCount != null && Object.hasOwnProperty.call(message, "cpuSocketCount"))
                    object.cpuSocketCount = message.cpuSocketCount;
                if (message.cpuPhysicalCount != null && Object.hasOwnProperty.call(message, "cpuPhysicalCount"))
                    object.cpuPhysicalCount = message.cpuPhysicalCount;
                if (message.collectorCapabilities != null && Object.hasOwnProperty.call(message, "collectorCapabilities"))
                    object.collectorCapabilities = $root.enoki.v1.CollectorCapabilities.toObject(message.collectorCapabilities, options, q + 1);
                return object;
            };

            /**
             * Converts this Inventory to JSON.
             * @function toJSON
             * @memberof enoki.v1.Inventory
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            Inventory.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for Inventory
             * @function getTypeUrl
             * @memberof enoki.v1.Inventory
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            Inventory.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.Inventory";
            };

            return Inventory;
        })();

        v1.FilesystemInventory = (function() {

            /**
             * Properties of a FilesystemInventory.
             * @memberof enoki.v1
             * @interface IFilesystemInventory
             * @property {string|null} [mountPoint] FilesystemInventory mountPoint
             * @property {string|null} [filesystemType] FilesystemInventory filesystemType
             * @property {Long|null} [totalBytes] FilesystemInventory totalBytes
             * @property {Long|null} [availableBytes] FilesystemInventory availableBytes
             */

            /**
             * Constructs a new FilesystemInventory.
             * @memberof enoki.v1
             * @classdesc Represents a FilesystemInventory.
             * @implements IFilesystemInventory
             * @constructor
             * @param {enoki.v1.IFilesystemInventory=} [properties] Properties to set
             */
            function FilesystemInventory(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * FilesystemInventory mountPoint.
             * @member {string} mountPoint
             * @memberof enoki.v1.FilesystemInventory
             * @instance
             */
            FilesystemInventory.prototype.mountPoint = "";

            /**
             * FilesystemInventory filesystemType.
             * @member {string} filesystemType
             * @memberof enoki.v1.FilesystemInventory
             * @instance
             */
            FilesystemInventory.prototype.filesystemType = "";

            /**
             * FilesystemInventory totalBytes.
             * @member {Long} totalBytes
             * @memberof enoki.v1.FilesystemInventory
             * @instance
             */
            FilesystemInventory.prototype.totalBytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * FilesystemInventory availableBytes.
             * @member {Long} availableBytes
             * @memberof enoki.v1.FilesystemInventory
             * @instance
             */
            FilesystemInventory.prototype.availableBytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * Creates a new FilesystemInventory instance using the specified properties.
             * @function create
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {enoki.v1.IFilesystemInventory=} [properties] Properties to set
             * @returns {enoki.v1.FilesystemInventory} FilesystemInventory instance
             */
            FilesystemInventory.create = function create(properties) {
                return new FilesystemInventory(properties);
            };

            /**
             * Encodes the specified FilesystemInventory message. Does not implicitly {@link enoki.v1.FilesystemInventory.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {enoki.v1.IFilesystemInventory} message FilesystemInventory message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            FilesystemInventory.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.mountPoint != null && Object.hasOwnProperty.call(message, "mountPoint"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.mountPoint);
                if (message.filesystemType != null && Object.hasOwnProperty.call(message, "filesystemType"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.filesystemType);
                if (message.totalBytes != null && Object.hasOwnProperty.call(message, "totalBytes"))
                    writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.totalBytes);
                if (message.availableBytes != null && Object.hasOwnProperty.call(message, "availableBytes"))
                    writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.availableBytes);
                return writer;
            };

            /**
             * Encodes the specified FilesystemInventory message, length delimited. Does not implicitly {@link enoki.v1.FilesystemInventory.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {enoki.v1.IFilesystemInventory} message FilesystemInventory message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            FilesystemInventory.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a FilesystemInventory message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.FilesystemInventory} FilesystemInventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            FilesystemInventory.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.FilesystemInventory();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.mountPoint = reader.string();
                            break;
                        }
                    case 2: {
                            message.filesystemType = reader.string();
                            break;
                        }
                    case 3: {
                            message.totalBytes = reader.uint64();
                            break;
                        }
                    case 4: {
                            message.availableBytes = reader.uint64();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a FilesystemInventory message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.FilesystemInventory} FilesystemInventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            FilesystemInventory.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a FilesystemInventory message.
             * @function verify
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            FilesystemInventory.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.mountPoint != null && Object.hasOwnProperty.call(message, "mountPoint"))
                    if (!$util.isString(message.mountPoint))
                        return "mountPoint: string expected";
                if (message.filesystemType != null && Object.hasOwnProperty.call(message, "filesystemType"))
                    if (!$util.isString(message.filesystemType))
                        return "filesystemType: string expected";
                if (message.totalBytes != null && Object.hasOwnProperty.call(message, "totalBytes"))
                    if (!$util.isInteger(message.totalBytes) && !(message.totalBytes && $util.isInteger(message.totalBytes.low) && $util.isInteger(message.totalBytes.high)))
                        return "totalBytes: integer|Long expected";
                if (message.availableBytes != null && Object.hasOwnProperty.call(message, "availableBytes"))
                    if (!$util.isInteger(message.availableBytes) && !(message.availableBytes && $util.isInteger(message.availableBytes.low) && $util.isInteger(message.availableBytes.high)))
                        return "availableBytes: integer|Long expected";
                return null;
            };

            /**
             * Creates a FilesystemInventory message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.FilesystemInventory} FilesystemInventory
             */
            FilesystemInventory.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.FilesystemInventory)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.FilesystemInventory: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.FilesystemInventory();
                if (object.mountPoint != null)
                    message.mountPoint = String(object.mountPoint);
                if (object.filesystemType != null)
                    message.filesystemType = String(object.filesystemType);
                if (object.totalBytes != null)
                    if ($util.Long)
                        message.totalBytes = $util.Long.fromValue(object.totalBytes, true);
                    else if (typeof object.totalBytes === "string")
                        message.totalBytes = parseInt(object.totalBytes, 10);
                    else if (typeof object.totalBytes === "number")
                        message.totalBytes = object.totalBytes;
                    else if (typeof object.totalBytes === "object")
                        message.totalBytes = new $util.LongBits(object.totalBytes.low >>> 0, object.totalBytes.high >>> 0).toNumber(true);
                if (object.availableBytes != null)
                    if ($util.Long)
                        message.availableBytes = $util.Long.fromValue(object.availableBytes, true);
                    else if (typeof object.availableBytes === "string")
                        message.availableBytes = parseInt(object.availableBytes, 10);
                    else if (typeof object.availableBytes === "number")
                        message.availableBytes = object.availableBytes;
                    else if (typeof object.availableBytes === "object")
                        message.availableBytes = new $util.LongBits(object.availableBytes.low >>> 0, object.availableBytes.high >>> 0).toNumber(true);
                return message;
            };

            /**
             * Creates a plain object from a FilesystemInventory message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {enoki.v1.FilesystemInventory} message FilesystemInventory
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            FilesystemInventory.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.mountPoint = "";
                    object.filesystemType = "";
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.totalBytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.totalBytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.availableBytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.availableBytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                }
                if (message.mountPoint != null && Object.hasOwnProperty.call(message, "mountPoint"))
                    object.mountPoint = message.mountPoint;
                if (message.filesystemType != null && Object.hasOwnProperty.call(message, "filesystemType"))
                    object.filesystemType = message.filesystemType;
                if (message.totalBytes != null && Object.hasOwnProperty.call(message, "totalBytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.totalBytes = typeof message.totalBytes === "number" ? BigInt(message.totalBytes) : $util.Long.fromBits(message.totalBytes.low >>> 0, message.totalBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.totalBytes === "number")
                        object.totalBytes = options.longs === String ? String(message.totalBytes) : message.totalBytes;
                    else
                        object.totalBytes = options.longs === String ? $util.Long.prototype.toString.call(message.totalBytes) : options.longs === Number ? new $util.LongBits(message.totalBytes.low >>> 0, message.totalBytes.high >>> 0).toNumber(true) : message.totalBytes;
                if (message.availableBytes != null && Object.hasOwnProperty.call(message, "availableBytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.availableBytes = typeof message.availableBytes === "number" ? BigInt(message.availableBytes) : $util.Long.fromBits(message.availableBytes.low >>> 0, message.availableBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.availableBytes === "number")
                        object.availableBytes = options.longs === String ? String(message.availableBytes) : message.availableBytes;
                    else
                        object.availableBytes = options.longs === String ? $util.Long.prototype.toString.call(message.availableBytes) : options.longs === Number ? new $util.LongBits(message.availableBytes.low >>> 0, message.availableBytes.high >>> 0).toNumber(true) : message.availableBytes;
                return object;
            };

            /**
             * Converts this FilesystemInventory to JSON.
             * @function toJSON
             * @memberof enoki.v1.FilesystemInventory
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            FilesystemInventory.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for FilesystemInventory
             * @function getTypeUrl
             * @memberof enoki.v1.FilesystemInventory
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            FilesystemInventory.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.FilesystemInventory";
            };

            return FilesystemInventory;
        })();

        v1.NetworkInterfaceInventory = (function() {

            /**
             * Properties of a NetworkInterfaceInventory.
             * @memberof enoki.v1
             * @interface INetworkInterfaceInventory
             * @property {string|null} [name] NetworkInterfaceInventory name
             * @property {Array.<string>|null} [addresses] NetworkInterfaceInventory addresses
             */

            /**
             * Constructs a new NetworkInterfaceInventory.
             * @memberof enoki.v1
             * @classdesc Represents a NetworkInterfaceInventory.
             * @implements INetworkInterfaceInventory
             * @constructor
             * @param {enoki.v1.INetworkInterfaceInventory=} [properties] Properties to set
             */
            function NetworkInterfaceInventory(properties) {
                this.addresses = [];
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * NetworkInterfaceInventory name.
             * @member {string} name
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @instance
             */
            NetworkInterfaceInventory.prototype.name = "";

            /**
             * NetworkInterfaceInventory addresses.
             * @member {Array.<string>} addresses
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @instance
             */
            NetworkInterfaceInventory.prototype.addresses = $util.emptyArray;

            /**
             * Creates a new NetworkInterfaceInventory instance using the specified properties.
             * @function create
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {enoki.v1.INetworkInterfaceInventory=} [properties] Properties to set
             * @returns {enoki.v1.NetworkInterfaceInventory} NetworkInterfaceInventory instance
             */
            NetworkInterfaceInventory.create = function create(properties) {
                return new NetworkInterfaceInventory(properties);
            };

            /**
             * Encodes the specified NetworkInterfaceInventory message. Does not implicitly {@link enoki.v1.NetworkInterfaceInventory.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {enoki.v1.INetworkInterfaceInventory} message NetworkInterfaceInventory message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            NetworkInterfaceInventory.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.name);
                if (message.addresses != null && message.addresses.length)
                    for (let i = 0; i < message.addresses.length; ++i)
                        writer.uint32(/* id 2, wireType 2 =*/18).string(message.addresses[i]);
                return writer;
            };

            /**
             * Encodes the specified NetworkInterfaceInventory message, length delimited. Does not implicitly {@link enoki.v1.NetworkInterfaceInventory.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {enoki.v1.INetworkInterfaceInventory} message NetworkInterfaceInventory message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            NetworkInterfaceInventory.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a NetworkInterfaceInventory message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.NetworkInterfaceInventory} NetworkInterfaceInventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            NetworkInterfaceInventory.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.NetworkInterfaceInventory();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.name = reader.string();
                            break;
                        }
                    case 2: {
                            if (!(message.addresses && message.addresses.length))
                                message.addresses = [];
                            message.addresses.push(reader.string());
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a NetworkInterfaceInventory message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.NetworkInterfaceInventory} NetworkInterfaceInventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            NetworkInterfaceInventory.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a NetworkInterfaceInventory message.
             * @function verify
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            NetworkInterfaceInventory.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    if (!$util.isString(message.name))
                        return "name: string expected";
                if (message.addresses != null && Object.hasOwnProperty.call(message, "addresses")) {
                    if (!Array.isArray(message.addresses))
                        return "addresses: array expected";
                    for (let i = 0; i < message.addresses.length; ++i)
                        if (!$util.isString(message.addresses[i]))
                            return "addresses: string[] expected";
                }
                return null;
            };

            /**
             * Creates a NetworkInterfaceInventory message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.NetworkInterfaceInventory} NetworkInterfaceInventory
             */
            NetworkInterfaceInventory.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.NetworkInterfaceInventory)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.NetworkInterfaceInventory: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.NetworkInterfaceInventory();
                if (object.name != null)
                    message.name = String(object.name);
                if (object.addresses) {
                    if (!Array.isArray(object.addresses))
                        throw TypeError(".enoki.v1.NetworkInterfaceInventory.addresses: array expected");
                    message.addresses = [];
                    for (let i = 0; i < object.addresses.length; ++i)
                        message.addresses[i] = String(object.addresses[i]);
                }
                return message;
            };

            /**
             * Creates a plain object from a NetworkInterfaceInventory message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {enoki.v1.NetworkInterfaceInventory} message NetworkInterfaceInventory
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            NetworkInterfaceInventory.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.arrays || options.defaults)
                    object.addresses = [];
                if (options.defaults)
                    object.name = "";
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    object.name = message.name;
                if (message.addresses && message.addresses.length) {
                    object.addresses = [];
                    for (let j = 0; j < message.addresses.length; ++j)
                        object.addresses[j] = message.addresses[j];
                }
                return object;
            };

            /**
             * Converts this NetworkInterfaceInventory to JSON.
             * @function toJSON
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            NetworkInterfaceInventory.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for NetworkInterfaceInventory
             * @function getTypeUrl
             * @memberof enoki.v1.NetworkInterfaceInventory
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            NetworkInterfaceInventory.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.NetworkInterfaceInventory";
            };

            return NetworkInterfaceInventory;
        })();

        v1.CollectorAvailability = (function() {

            /**
             * Properties of a CollectorAvailability.
             * @memberof enoki.v1
             * @interface ICollectorAvailability
             * @property {boolean|null} [available] CollectorAvailability available
             */

            /**
             * Constructs a new CollectorAvailability.
             * @memberof enoki.v1
             * @classdesc Represents a CollectorAvailability.
             * @implements ICollectorAvailability
             * @constructor
             * @param {enoki.v1.ICollectorAvailability=} [properties] Properties to set
             */
            function CollectorAvailability(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * CollectorAvailability available.
             * @member {boolean} available
             * @memberof enoki.v1.CollectorAvailability
             * @instance
             */
            CollectorAvailability.prototype.available = false;

            /**
             * Creates a new CollectorAvailability instance using the specified properties.
             * @function create
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {enoki.v1.ICollectorAvailability=} [properties] Properties to set
             * @returns {enoki.v1.CollectorAvailability} CollectorAvailability instance
             */
            CollectorAvailability.create = function create(properties) {
                return new CollectorAvailability(properties);
            };

            /**
             * Encodes the specified CollectorAvailability message. Does not implicitly {@link enoki.v1.CollectorAvailability.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {enoki.v1.ICollectorAvailability} message CollectorAvailability message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            CollectorAvailability.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.available != null && Object.hasOwnProperty.call(message, "available"))
                    writer.uint32(/* id 1, wireType 0 =*/8).bool(message.available);
                return writer;
            };

            /**
             * Encodes the specified CollectorAvailability message, length delimited. Does not implicitly {@link enoki.v1.CollectorAvailability.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {enoki.v1.ICollectorAvailability} message CollectorAvailability message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            CollectorAvailability.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a CollectorAvailability message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.CollectorAvailability} CollectorAvailability
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            CollectorAvailability.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.CollectorAvailability();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.available = reader.bool();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a CollectorAvailability message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.CollectorAvailability} CollectorAvailability
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            CollectorAvailability.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a CollectorAvailability message.
             * @function verify
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            CollectorAvailability.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.available != null && Object.hasOwnProperty.call(message, "available"))
                    if (typeof message.available !== "boolean")
                        return "available: boolean expected";
                return null;
            };

            /**
             * Creates a CollectorAvailability message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.CollectorAvailability} CollectorAvailability
             */
            CollectorAvailability.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.CollectorAvailability)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.CollectorAvailability: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.CollectorAvailability();
                if (object.available != null)
                    message.available = Boolean(object.available);
                return message;
            };

            /**
             * Creates a plain object from a CollectorAvailability message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {enoki.v1.CollectorAvailability} message CollectorAvailability
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            CollectorAvailability.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults)
                    object.available = false;
                if (message.available != null && Object.hasOwnProperty.call(message, "available"))
                    object.available = message.available;
                return object;
            };

            /**
             * Converts this CollectorAvailability to JSON.
             * @function toJSON
             * @memberof enoki.v1.CollectorAvailability
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            CollectorAvailability.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for CollectorAvailability
             * @function getTypeUrl
             * @memberof enoki.v1.CollectorAvailability
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            CollectorAvailability.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.CollectorAvailability";
            };

            return CollectorAvailability;
        })();

        v1.OfficialCollectorCapabilities = (function() {

            /**
             * Properties of an OfficialCollectorCapabilities.
             * @memberof enoki.v1
             * @interface IOfficialCollectorCapabilities
             * @property {enoki.v1.ICollectorAvailability|null} [cpu] OfficialCollectorCapabilities cpu
             * @property {enoki.v1.ICollectorAvailability|null} [memory] OfficialCollectorCapabilities memory
             * @property {enoki.v1.ICollectorAvailability|null} [disk] OfficialCollectorCapabilities disk
             * @property {enoki.v1.ICollectorAvailability|null} [network] OfficialCollectorCapabilities network
             * @property {enoki.v1.ICollectorAvailability|null} [load] OfficialCollectorCapabilities load
             * @property {enoki.v1.ICollectorAvailability|null} [uptime] OfficialCollectorCapabilities uptime
             * @property {enoki.v1.ICollectorAvailability|null} [temperature] OfficialCollectorCapabilities temperature
             * @property {enoki.v1.ICollectorAvailability|null} [battery] OfficialCollectorCapabilities battery
             * @property {enoki.v1.ICollectorAvailability|null} [diskHealth] OfficialCollectorCapabilities diskHealth
             */

            /**
             * Constructs a new OfficialCollectorCapabilities.
             * @memberof enoki.v1
             * @classdesc Represents an OfficialCollectorCapabilities.
             * @implements IOfficialCollectorCapabilities
             * @constructor
             * @param {enoki.v1.IOfficialCollectorCapabilities=} [properties] Properties to set
             */
            function OfficialCollectorCapabilities(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * OfficialCollectorCapabilities cpu.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} cpu
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.cpu = null;

            /**
             * OfficialCollectorCapabilities memory.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} memory
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.memory = null;

            /**
             * OfficialCollectorCapabilities disk.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} disk
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.disk = null;

            /**
             * OfficialCollectorCapabilities network.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} network
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.network = null;

            /**
             * OfficialCollectorCapabilities load.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} load
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.load = null;

            /**
             * OfficialCollectorCapabilities uptime.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} uptime
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.uptime = null;

            /**
             * OfficialCollectorCapabilities temperature.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} temperature
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.temperature = null;

            /**
             * OfficialCollectorCapabilities battery.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} battery
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.battery = null;

            /**
             * OfficialCollectorCapabilities diskHealth.
             * @member {enoki.v1.ICollectorAvailability|null|undefined} diskHealth
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             */
            OfficialCollectorCapabilities.prototype.diskHealth = null;

            /**
             * Creates a new OfficialCollectorCapabilities instance using the specified properties.
             * @function create
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {enoki.v1.IOfficialCollectorCapabilities=} [properties] Properties to set
             * @returns {enoki.v1.OfficialCollectorCapabilities} OfficialCollectorCapabilities instance
             */
            OfficialCollectorCapabilities.create = function create(properties) {
                return new OfficialCollectorCapabilities(properties);
            };

            /**
             * Encodes the specified OfficialCollectorCapabilities message. Does not implicitly {@link enoki.v1.OfficialCollectorCapabilities.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {enoki.v1.IOfficialCollectorCapabilities} message OfficialCollectorCapabilities message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            OfficialCollectorCapabilities.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.cpu != null && Object.hasOwnProperty.call(message, "cpu"))
                    $root.enoki.v1.CollectorAvailability.encode(message.cpu, writer.uint32(/* id 1, wireType 2 =*/10).fork(), q + 1).ldelim();
                if (message.memory != null && Object.hasOwnProperty.call(message, "memory"))
                    $root.enoki.v1.CollectorAvailability.encode(message.memory, writer.uint32(/* id 2, wireType 2 =*/18).fork(), q + 1).ldelim();
                if (message.disk != null && Object.hasOwnProperty.call(message, "disk"))
                    $root.enoki.v1.CollectorAvailability.encode(message.disk, writer.uint32(/* id 3, wireType 2 =*/26).fork(), q + 1).ldelim();
                if (message.network != null && Object.hasOwnProperty.call(message, "network"))
                    $root.enoki.v1.CollectorAvailability.encode(message.network, writer.uint32(/* id 4, wireType 2 =*/34).fork(), q + 1).ldelim();
                if (message.load != null && Object.hasOwnProperty.call(message, "load"))
                    $root.enoki.v1.CollectorAvailability.encode(message.load, writer.uint32(/* id 5, wireType 2 =*/42).fork(), q + 1).ldelim();
                if (message.uptime != null && Object.hasOwnProperty.call(message, "uptime"))
                    $root.enoki.v1.CollectorAvailability.encode(message.uptime, writer.uint32(/* id 6, wireType 2 =*/50).fork(), q + 1).ldelim();
                if (message.temperature != null && Object.hasOwnProperty.call(message, "temperature"))
                    $root.enoki.v1.CollectorAvailability.encode(message.temperature, writer.uint32(/* id 7, wireType 2 =*/58).fork(), q + 1).ldelim();
                if (message.battery != null && Object.hasOwnProperty.call(message, "battery"))
                    $root.enoki.v1.CollectorAvailability.encode(message.battery, writer.uint32(/* id 8, wireType 2 =*/66).fork(), q + 1).ldelim();
                if (message.diskHealth != null && Object.hasOwnProperty.call(message, "diskHealth"))
                    $root.enoki.v1.CollectorAvailability.encode(message.diskHealth, writer.uint32(/* id 9, wireType 2 =*/74).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified OfficialCollectorCapabilities message, length delimited. Does not implicitly {@link enoki.v1.OfficialCollectorCapabilities.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {enoki.v1.IOfficialCollectorCapabilities} message OfficialCollectorCapabilities message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            OfficialCollectorCapabilities.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes an OfficialCollectorCapabilities message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.OfficialCollectorCapabilities} OfficialCollectorCapabilities
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            OfficialCollectorCapabilities.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.OfficialCollectorCapabilities();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.cpu = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 2: {
                            message.memory = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 3: {
                            message.disk = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 4: {
                            message.network = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 5: {
                            message.load = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 6: {
                            message.uptime = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 7: {
                            message.temperature = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 8: {
                            message.battery = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 9: {
                            message.diskHealth = $root.enoki.v1.CollectorAvailability.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes an OfficialCollectorCapabilities message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.OfficialCollectorCapabilities} OfficialCollectorCapabilities
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            OfficialCollectorCapabilities.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies an OfficialCollectorCapabilities message.
             * @function verify
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            OfficialCollectorCapabilities.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.cpu != null && Object.hasOwnProperty.call(message, "cpu")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.cpu, long + 1);
                    if (error)
                        return "cpu." + error;
                }
                if (message.memory != null && Object.hasOwnProperty.call(message, "memory")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.memory, long + 1);
                    if (error)
                        return "memory." + error;
                }
                if (message.disk != null && Object.hasOwnProperty.call(message, "disk")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.disk, long + 1);
                    if (error)
                        return "disk." + error;
                }
                if (message.network != null && Object.hasOwnProperty.call(message, "network")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.network, long + 1);
                    if (error)
                        return "network." + error;
                }
                if (message.load != null && Object.hasOwnProperty.call(message, "load")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.load, long + 1);
                    if (error)
                        return "load." + error;
                }
                if (message.uptime != null && Object.hasOwnProperty.call(message, "uptime")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.uptime, long + 1);
                    if (error)
                        return "uptime." + error;
                }
                if (message.temperature != null && Object.hasOwnProperty.call(message, "temperature")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.temperature, long + 1);
                    if (error)
                        return "temperature." + error;
                }
                if (message.battery != null && Object.hasOwnProperty.call(message, "battery")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.battery, long + 1);
                    if (error)
                        return "battery." + error;
                }
                if (message.diskHealth != null && Object.hasOwnProperty.call(message, "diskHealth")) {
                    let error = $root.enoki.v1.CollectorAvailability.verify(message.diskHealth, long + 1);
                    if (error)
                        return "diskHealth." + error;
                }
                return null;
            };

            /**
             * Creates an OfficialCollectorCapabilities message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.OfficialCollectorCapabilities} OfficialCollectorCapabilities
             */
            OfficialCollectorCapabilities.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.OfficialCollectorCapabilities)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.OfficialCollectorCapabilities: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.OfficialCollectorCapabilities();
                if (object.cpu != null) {
                    if (!$util.isObject(object.cpu))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.cpu: object expected");
                    message.cpu = $root.enoki.v1.CollectorAvailability.fromObject(object.cpu, long + 1);
                }
                if (object.memory != null) {
                    if (!$util.isObject(object.memory))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.memory: object expected");
                    message.memory = $root.enoki.v1.CollectorAvailability.fromObject(object.memory, long + 1);
                }
                if (object.disk != null) {
                    if (!$util.isObject(object.disk))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.disk: object expected");
                    message.disk = $root.enoki.v1.CollectorAvailability.fromObject(object.disk, long + 1);
                }
                if (object.network != null) {
                    if (!$util.isObject(object.network))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.network: object expected");
                    message.network = $root.enoki.v1.CollectorAvailability.fromObject(object.network, long + 1);
                }
                if (object.load != null) {
                    if (!$util.isObject(object.load))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.load: object expected");
                    message.load = $root.enoki.v1.CollectorAvailability.fromObject(object.load, long + 1);
                }
                if (object.uptime != null) {
                    if (!$util.isObject(object.uptime))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.uptime: object expected");
                    message.uptime = $root.enoki.v1.CollectorAvailability.fromObject(object.uptime, long + 1);
                }
                if (object.temperature != null) {
                    if (!$util.isObject(object.temperature))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.temperature: object expected");
                    message.temperature = $root.enoki.v1.CollectorAvailability.fromObject(object.temperature, long + 1);
                }
                if (object.battery != null) {
                    if (!$util.isObject(object.battery))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.battery: object expected");
                    message.battery = $root.enoki.v1.CollectorAvailability.fromObject(object.battery, long + 1);
                }
                if (object.diskHealth != null) {
                    if (!$util.isObject(object.diskHealth))
                        throw TypeError(".enoki.v1.OfficialCollectorCapabilities.diskHealth: object expected");
                    message.diskHealth = $root.enoki.v1.CollectorAvailability.fromObject(object.diskHealth, long + 1);
                }
                return message;
            };

            /**
             * Creates a plain object from an OfficialCollectorCapabilities message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {enoki.v1.OfficialCollectorCapabilities} message OfficialCollectorCapabilities
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            OfficialCollectorCapabilities.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.cpu = null;
                    object.memory = null;
                    object.disk = null;
                    object.network = null;
                    object.load = null;
                    object.uptime = null;
                    object.temperature = null;
                    object.battery = null;
                    object.diskHealth = null;
                }
                if (message.cpu != null && Object.hasOwnProperty.call(message, "cpu"))
                    object.cpu = $root.enoki.v1.CollectorAvailability.toObject(message.cpu, options, q + 1);
                if (message.memory != null && Object.hasOwnProperty.call(message, "memory"))
                    object.memory = $root.enoki.v1.CollectorAvailability.toObject(message.memory, options, q + 1);
                if (message.disk != null && Object.hasOwnProperty.call(message, "disk"))
                    object.disk = $root.enoki.v1.CollectorAvailability.toObject(message.disk, options, q + 1);
                if (message.network != null && Object.hasOwnProperty.call(message, "network"))
                    object.network = $root.enoki.v1.CollectorAvailability.toObject(message.network, options, q + 1);
                if (message.load != null && Object.hasOwnProperty.call(message, "load"))
                    object.load = $root.enoki.v1.CollectorAvailability.toObject(message.load, options, q + 1);
                if (message.uptime != null && Object.hasOwnProperty.call(message, "uptime"))
                    object.uptime = $root.enoki.v1.CollectorAvailability.toObject(message.uptime, options, q + 1);
                if (message.temperature != null && Object.hasOwnProperty.call(message, "temperature"))
                    object.temperature = $root.enoki.v1.CollectorAvailability.toObject(message.temperature, options, q + 1);
                if (message.battery != null && Object.hasOwnProperty.call(message, "battery"))
                    object.battery = $root.enoki.v1.CollectorAvailability.toObject(message.battery, options, q + 1);
                if (message.diskHealth != null && Object.hasOwnProperty.call(message, "diskHealth"))
                    object.diskHealth = $root.enoki.v1.CollectorAvailability.toObject(message.diskHealth, options, q + 1);
                return object;
            };

            /**
             * Converts this OfficialCollectorCapabilities to JSON.
             * @function toJSON
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            OfficialCollectorCapabilities.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for OfficialCollectorCapabilities
             * @function getTypeUrl
             * @memberof enoki.v1.OfficialCollectorCapabilities
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            OfficialCollectorCapabilities.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.OfficialCollectorCapabilities";
            };

            return OfficialCollectorCapabilities;
        })();

        v1.CollectorCapabilities = (function() {

            /**
             * Properties of a CollectorCapabilities.
             * @memberof enoki.v1
             * @interface ICollectorCapabilities
             * @property {enoki.v1.IOfficialCollectorCapabilities|null} [official] CollectorCapabilities official
             */

            /**
             * Constructs a new CollectorCapabilities.
             * @memberof enoki.v1
             * @classdesc Represents a CollectorCapabilities.
             * @implements ICollectorCapabilities
             * @constructor
             * @param {enoki.v1.ICollectorCapabilities=} [properties] Properties to set
             */
            function CollectorCapabilities(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * CollectorCapabilities official.
             * @member {enoki.v1.IOfficialCollectorCapabilities|null|undefined} official
             * @memberof enoki.v1.CollectorCapabilities
             * @instance
             */
            CollectorCapabilities.prototype.official = null;

            /**
             * Creates a new CollectorCapabilities instance using the specified properties.
             * @function create
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {enoki.v1.ICollectorCapabilities=} [properties] Properties to set
             * @returns {enoki.v1.CollectorCapabilities} CollectorCapabilities instance
             */
            CollectorCapabilities.create = function create(properties) {
                return new CollectorCapabilities(properties);
            };

            /**
             * Encodes the specified CollectorCapabilities message. Does not implicitly {@link enoki.v1.CollectorCapabilities.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {enoki.v1.ICollectorCapabilities} message CollectorCapabilities message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            CollectorCapabilities.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.official != null && Object.hasOwnProperty.call(message, "official"))
                    $root.enoki.v1.OfficialCollectorCapabilities.encode(message.official, writer.uint32(/* id 1, wireType 2 =*/10).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified CollectorCapabilities message, length delimited. Does not implicitly {@link enoki.v1.CollectorCapabilities.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {enoki.v1.ICollectorCapabilities} message CollectorCapabilities message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            CollectorCapabilities.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a CollectorCapabilities message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.CollectorCapabilities} CollectorCapabilities
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            CollectorCapabilities.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.CollectorCapabilities();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.official = $root.enoki.v1.OfficialCollectorCapabilities.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a CollectorCapabilities message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.CollectorCapabilities} CollectorCapabilities
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            CollectorCapabilities.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a CollectorCapabilities message.
             * @function verify
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            CollectorCapabilities.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.official != null && Object.hasOwnProperty.call(message, "official")) {
                    let error = $root.enoki.v1.OfficialCollectorCapabilities.verify(message.official, long + 1);
                    if (error)
                        return "official." + error;
                }
                return null;
            };

            /**
             * Creates a CollectorCapabilities message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.CollectorCapabilities} CollectorCapabilities
             */
            CollectorCapabilities.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.CollectorCapabilities)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.CollectorCapabilities: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.CollectorCapabilities();
                if (object.official != null) {
                    if (!$util.isObject(object.official))
                        throw TypeError(".enoki.v1.CollectorCapabilities.official: object expected");
                    message.official = $root.enoki.v1.OfficialCollectorCapabilities.fromObject(object.official, long + 1);
                }
                return message;
            };

            /**
             * Creates a plain object from a CollectorCapabilities message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {enoki.v1.CollectorCapabilities} message CollectorCapabilities
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            CollectorCapabilities.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults)
                    object.official = null;
                if (message.official != null && Object.hasOwnProperty.call(message, "official"))
                    object.official = $root.enoki.v1.OfficialCollectorCapabilities.toObject(message.official, options, q + 1);
                return object;
            };

            /**
             * Converts this CollectorCapabilities to JSON.
             * @function toJSON
             * @memberof enoki.v1.CollectorCapabilities
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            CollectorCapabilities.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for CollectorCapabilities
             * @function getTypeUrl
             * @memberof enoki.v1.CollectorCapabilities
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            CollectorCapabilities.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.CollectorCapabilities";
            };

            return CollectorCapabilities;
        })();

        v1.ProbeRegistrationRequest = (function() {

            /**
             * Properties of a ProbeRegistrationRequest.
             * @memberof enoki.v1
             * @interface IProbeRegistrationRequest
             * @property {string|null} [enrollmentToken] ProbeRegistrationRequest enrollmentToken
             * @property {enoki.v1.IInventory|null} [inventory] ProbeRegistrationRequest inventory
             * @property {string|null} [probePublicKeyPem] ProbeRegistrationRequest probePublicKeyPem
             */

            /**
             * Constructs a new ProbeRegistrationRequest.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeRegistrationRequest.
             * @implements IProbeRegistrationRequest
             * @constructor
             * @param {enoki.v1.IProbeRegistrationRequest=} [properties] Properties to set
             */
            function ProbeRegistrationRequest(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeRegistrationRequest enrollmentToken.
             * @member {string} enrollmentToken
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @instance
             */
            ProbeRegistrationRequest.prototype.enrollmentToken = "";

            /**
             * ProbeRegistrationRequest inventory.
             * @member {enoki.v1.IInventory|null|undefined} inventory
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @instance
             */
            ProbeRegistrationRequest.prototype.inventory = null;

            /**
             * ProbeRegistrationRequest probePublicKeyPem.
             * @member {string} probePublicKeyPem
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @instance
             */
            ProbeRegistrationRequest.prototype.probePublicKeyPem = "";

            /**
             * Creates a new ProbeRegistrationRequest instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {enoki.v1.IProbeRegistrationRequest=} [properties] Properties to set
             * @returns {enoki.v1.ProbeRegistrationRequest} ProbeRegistrationRequest instance
             */
            ProbeRegistrationRequest.create = function create(properties) {
                return new ProbeRegistrationRequest(properties);
            };

            /**
             * Encodes the specified ProbeRegistrationRequest message. Does not implicitly {@link enoki.v1.ProbeRegistrationRequest.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {enoki.v1.IProbeRegistrationRequest} message ProbeRegistrationRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeRegistrationRequest.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.enrollmentToken != null && Object.hasOwnProperty.call(message, "enrollmentToken"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.enrollmentToken);
                if (message.inventory != null && Object.hasOwnProperty.call(message, "inventory"))
                    $root.enoki.v1.Inventory.encode(message.inventory, writer.uint32(/* id 2, wireType 2 =*/18).fork(), q + 1).ldelim();
                if (message.probePublicKeyPem != null && Object.hasOwnProperty.call(message, "probePublicKeyPem"))
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.probePublicKeyPem);
                return writer;
            };

            /**
             * Encodes the specified ProbeRegistrationRequest message, length delimited. Does not implicitly {@link enoki.v1.ProbeRegistrationRequest.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {enoki.v1.IProbeRegistrationRequest} message ProbeRegistrationRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeRegistrationRequest.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeRegistrationRequest message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeRegistrationRequest} ProbeRegistrationRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeRegistrationRequest.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeRegistrationRequest();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.enrollmentToken = reader.string();
                            break;
                        }
                    case 2: {
                            message.inventory = $root.enoki.v1.Inventory.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 3: {
                            message.probePublicKeyPem = reader.string();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeRegistrationRequest message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeRegistrationRequest} ProbeRegistrationRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeRegistrationRequest.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeRegistrationRequest message.
             * @function verify
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeRegistrationRequest.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.enrollmentToken != null && Object.hasOwnProperty.call(message, "enrollmentToken"))
                    if (!$util.isString(message.enrollmentToken))
                        return "enrollmentToken: string expected";
                if (message.inventory != null && Object.hasOwnProperty.call(message, "inventory")) {
                    let error = $root.enoki.v1.Inventory.verify(message.inventory, long + 1);
                    if (error)
                        return "inventory." + error;
                }
                if (message.probePublicKeyPem != null && Object.hasOwnProperty.call(message, "probePublicKeyPem"))
                    if (!$util.isString(message.probePublicKeyPem))
                        return "probePublicKeyPem: string expected";
                return null;
            };

            /**
             * Creates a ProbeRegistrationRequest message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeRegistrationRequest} ProbeRegistrationRequest
             */
            ProbeRegistrationRequest.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeRegistrationRequest)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeRegistrationRequest: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeRegistrationRequest();
                if (object.enrollmentToken != null)
                    message.enrollmentToken = String(object.enrollmentToken);
                if (object.inventory != null) {
                    if (!$util.isObject(object.inventory))
                        throw TypeError(".enoki.v1.ProbeRegistrationRequest.inventory: object expected");
                    message.inventory = $root.enoki.v1.Inventory.fromObject(object.inventory, long + 1);
                }
                if (object.probePublicKeyPem != null)
                    message.probePublicKeyPem = String(object.probePublicKeyPem);
                return message;
            };

            /**
             * Creates a plain object from a ProbeRegistrationRequest message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {enoki.v1.ProbeRegistrationRequest} message ProbeRegistrationRequest
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeRegistrationRequest.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.enrollmentToken = "";
                    object.inventory = null;
                    object.probePublicKeyPem = "";
                }
                if (message.enrollmentToken != null && Object.hasOwnProperty.call(message, "enrollmentToken"))
                    object.enrollmentToken = message.enrollmentToken;
                if (message.inventory != null && Object.hasOwnProperty.call(message, "inventory"))
                    object.inventory = $root.enoki.v1.Inventory.toObject(message.inventory, options, q + 1);
                if (message.probePublicKeyPem != null && Object.hasOwnProperty.call(message, "probePublicKeyPem"))
                    object.probePublicKeyPem = message.probePublicKeyPem;
                return object;
            };

            /**
             * Converts this ProbeRegistrationRequest to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeRegistrationRequest.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeRegistrationRequest
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeRegistrationRequest
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeRegistrationRequest.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeRegistrationRequest";
            };

            return ProbeRegistrationRequest;
        })();

        v1.ProbeRegistrationResponse = (function() {

            /**
             * Properties of a ProbeRegistrationResponse.
             * @memberof enoki.v1
             * @interface IProbeRegistrationResponse
             * @property {string|null} [probeId] ProbeRegistrationResponse probeId
             * @property {string|null} [probeSecret] ProbeRegistrationResponse probeSecret
             * @property {Long|null} [serverTimeMs] ProbeRegistrationResponse serverTimeMs
             * @property {enoki.v1.IProbeConfigurationResponse|null} [initialConfiguration] ProbeRegistrationResponse initialConfiguration
             */

            /**
             * Constructs a new ProbeRegistrationResponse.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeRegistrationResponse.
             * @implements IProbeRegistrationResponse
             * @constructor
             * @param {enoki.v1.IProbeRegistrationResponse=} [properties] Properties to set
             */
            function ProbeRegistrationResponse(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeRegistrationResponse probeId.
             * @member {string} probeId
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @instance
             */
            ProbeRegistrationResponse.prototype.probeId = "";

            /**
             * ProbeRegistrationResponse probeSecret.
             * @member {string} probeSecret
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @instance
             */
            ProbeRegistrationResponse.prototype.probeSecret = "";

            /**
             * ProbeRegistrationResponse serverTimeMs.
             * @member {Long} serverTimeMs
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @instance
             */
            ProbeRegistrationResponse.prototype.serverTimeMs = $util.Long ? $util.Long.fromBits(0,0,false) : 0;

            /**
             * ProbeRegistrationResponse initialConfiguration.
             * @member {enoki.v1.IProbeConfigurationResponse|null|undefined} initialConfiguration
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @instance
             */
            ProbeRegistrationResponse.prototype.initialConfiguration = null;

            /**
             * Creates a new ProbeRegistrationResponse instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {enoki.v1.IProbeRegistrationResponse=} [properties] Properties to set
             * @returns {enoki.v1.ProbeRegistrationResponse} ProbeRegistrationResponse instance
             */
            ProbeRegistrationResponse.create = function create(properties) {
                return new ProbeRegistrationResponse(properties);
            };

            /**
             * Encodes the specified ProbeRegistrationResponse message. Does not implicitly {@link enoki.v1.ProbeRegistrationResponse.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {enoki.v1.IProbeRegistrationResponse} message ProbeRegistrationResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeRegistrationResponse.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.probeId);
                if (message.probeSecret != null && Object.hasOwnProperty.call(message, "probeSecret"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.probeSecret);
                if (message.serverTimeMs != null && Object.hasOwnProperty.call(message, "serverTimeMs"))
                    writer.uint32(/* id 3, wireType 0 =*/24).int64(message.serverTimeMs);
                if (message.initialConfiguration != null && Object.hasOwnProperty.call(message, "initialConfiguration"))
                    $root.enoki.v1.ProbeConfigurationResponse.encode(message.initialConfiguration, writer.uint32(/* id 4, wireType 2 =*/34).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified ProbeRegistrationResponse message, length delimited. Does not implicitly {@link enoki.v1.ProbeRegistrationResponse.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {enoki.v1.IProbeRegistrationResponse} message ProbeRegistrationResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeRegistrationResponse.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeRegistrationResponse message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeRegistrationResponse} ProbeRegistrationResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeRegistrationResponse.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeRegistrationResponse();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.probeId = reader.string();
                            break;
                        }
                    case 2: {
                            message.probeSecret = reader.string();
                            break;
                        }
                    case 3: {
                            message.serverTimeMs = reader.int64();
                            break;
                        }
                    case 4: {
                            message.initialConfiguration = $root.enoki.v1.ProbeConfigurationResponse.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeRegistrationResponse message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeRegistrationResponse} ProbeRegistrationResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeRegistrationResponse.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeRegistrationResponse message.
             * @function verify
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeRegistrationResponse.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    if (!$util.isString(message.probeId))
                        return "probeId: string expected";
                if (message.probeSecret != null && Object.hasOwnProperty.call(message, "probeSecret"))
                    if (!$util.isString(message.probeSecret))
                        return "probeSecret: string expected";
                if (message.serverTimeMs != null && Object.hasOwnProperty.call(message, "serverTimeMs"))
                    if (!$util.isInteger(message.serverTimeMs) && !(message.serverTimeMs && $util.isInteger(message.serverTimeMs.low) && $util.isInteger(message.serverTimeMs.high)))
                        return "serverTimeMs: integer|Long expected";
                if (message.initialConfiguration != null && Object.hasOwnProperty.call(message, "initialConfiguration")) {
                    let error = $root.enoki.v1.ProbeConfigurationResponse.verify(message.initialConfiguration, long + 1);
                    if (error)
                        return "initialConfiguration." + error;
                }
                return null;
            };

            /**
             * Creates a ProbeRegistrationResponse message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeRegistrationResponse} ProbeRegistrationResponse
             */
            ProbeRegistrationResponse.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeRegistrationResponse)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeRegistrationResponse: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeRegistrationResponse();
                if (object.probeId != null)
                    message.probeId = String(object.probeId);
                if (object.probeSecret != null)
                    message.probeSecret = String(object.probeSecret);
                if (object.serverTimeMs != null)
                    if ($util.Long)
                        message.serverTimeMs = $util.Long.fromValue(object.serverTimeMs, false);
                    else if (typeof object.serverTimeMs === "string")
                        message.serverTimeMs = parseInt(object.serverTimeMs, 10);
                    else if (typeof object.serverTimeMs === "number")
                        message.serverTimeMs = object.serverTimeMs;
                    else if (typeof object.serverTimeMs === "object")
                        message.serverTimeMs = new $util.LongBits(object.serverTimeMs.low >>> 0, object.serverTimeMs.high >>> 0).toNumber();
                if (object.initialConfiguration != null) {
                    if (!$util.isObject(object.initialConfiguration))
                        throw TypeError(".enoki.v1.ProbeRegistrationResponse.initialConfiguration: object expected");
                    message.initialConfiguration = $root.enoki.v1.ProbeConfigurationResponse.fromObject(object.initialConfiguration, long + 1);
                }
                return message;
            };

            /**
             * Creates a plain object from a ProbeRegistrationResponse message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {enoki.v1.ProbeRegistrationResponse} message ProbeRegistrationResponse
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeRegistrationResponse.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.probeId = "";
                    object.probeSecret = "";
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, false);
                        object.serverTimeMs = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.serverTimeMs = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    object.initialConfiguration = null;
                }
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    object.probeId = message.probeId;
                if (message.probeSecret != null && Object.hasOwnProperty.call(message, "probeSecret"))
                    object.probeSecret = message.probeSecret;
                if (message.serverTimeMs != null && Object.hasOwnProperty.call(message, "serverTimeMs"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.serverTimeMs = typeof message.serverTimeMs === "number" ? BigInt(message.serverTimeMs) : $util.Long.fromBits(message.serverTimeMs.low >>> 0, message.serverTimeMs.high >>> 0, false).toBigInt();
                    else if (typeof message.serverTimeMs === "number")
                        object.serverTimeMs = options.longs === String ? String(message.serverTimeMs) : message.serverTimeMs;
                    else
                        object.serverTimeMs = options.longs === String ? $util.Long.prototype.toString.call(message.serverTimeMs) : options.longs === Number ? new $util.LongBits(message.serverTimeMs.low >>> 0, message.serverTimeMs.high >>> 0).toNumber() : message.serverTimeMs;
                if (message.initialConfiguration != null && Object.hasOwnProperty.call(message, "initialConfiguration"))
                    object.initialConfiguration = $root.enoki.v1.ProbeConfigurationResponse.toObject(message.initialConfiguration, options, q + 1);
                return object;
            };

            /**
             * Converts this ProbeRegistrationResponse to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeRegistrationResponse.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeRegistrationResponse
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeRegistrationResponse
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeRegistrationResponse.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeRegistrationResponse";
            };

            return ProbeRegistrationResponse;
        })();

        v1.ProbeReportRequest = (function() {

            /**
             * Properties of a ProbeReportRequest.
             * @memberof enoki.v1
             * @interface IProbeReportRequest
             * @property {string|null} [probeId] ProbeReportRequest probeId
             * @property {string|null} [bootId] ProbeReportRequest bootId
             * @property {Long|null} [sequenceStart] ProbeReportRequest sequenceStart
             * @property {Long|null} [sequenceEnd] ProbeReportRequest sequenceEnd
             * @property {string|null} [inventoryHash] ProbeReportRequest inventoryHash
             * @property {string|null} [probeConfigurationVersion] ProbeReportRequest probeConfigurationVersion
             * @property {Array.<enoki.v1.IMetricSample>|null} [metrics] ProbeReportRequest metrics
             * @property {enoki.v1.IInventory|null} [inventory] ProbeReportRequest inventory
             * @property {enoki.v1.IProbeConfigurationError|null} [probeConfigurationError] ProbeReportRequest probeConfigurationError
             * @property {Array.<enoki.v1.IProbeOperationAcknowledgement>|null} [operationAcknowledgements] ProbeReportRequest operationAcknowledgements
             * @property {Array.<enoki.v1.IProbeOperationStatus>|null} [operationStatuses] ProbeReportRequest operationStatuses
             */

            /**
             * Constructs a new ProbeReportRequest.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeReportRequest.
             * @implements IProbeReportRequest
             * @constructor
             * @param {enoki.v1.IProbeReportRequest=} [properties] Properties to set
             */
            function ProbeReportRequest(properties) {
                this.metrics = [];
                this.operationAcknowledgements = [];
                this.operationStatuses = [];
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeReportRequest probeId.
             * @member {string} probeId
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.probeId = "";

            /**
             * ProbeReportRequest bootId.
             * @member {string} bootId
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.bootId = "";

            /**
             * ProbeReportRequest sequenceStart.
             * @member {Long} sequenceStart
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.sequenceStart = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * ProbeReportRequest sequenceEnd.
             * @member {Long} sequenceEnd
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.sequenceEnd = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * ProbeReportRequest inventoryHash.
             * @member {string} inventoryHash
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.inventoryHash = "";

            /**
             * ProbeReportRequest probeConfigurationVersion.
             * @member {string} probeConfigurationVersion
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.probeConfigurationVersion = "";

            /**
             * ProbeReportRequest metrics.
             * @member {Array.<enoki.v1.IMetricSample>} metrics
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.metrics = $util.emptyArray;

            /**
             * ProbeReportRequest inventory.
             * @member {enoki.v1.IInventory|null|undefined} inventory
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.inventory = null;

            /**
             * ProbeReportRequest probeConfigurationError.
             * @member {enoki.v1.IProbeConfigurationError|null|undefined} probeConfigurationError
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.probeConfigurationError = null;

            /**
             * ProbeReportRequest operationAcknowledgements.
             * @member {Array.<enoki.v1.IProbeOperationAcknowledgement>} operationAcknowledgements
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.operationAcknowledgements = $util.emptyArray;

            /**
             * ProbeReportRequest operationStatuses.
             * @member {Array.<enoki.v1.IProbeOperationStatus>} operationStatuses
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             */
            ProbeReportRequest.prototype.operationStatuses = $util.emptyArray;

            /**
             * Creates a new ProbeReportRequest instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {enoki.v1.IProbeReportRequest=} [properties] Properties to set
             * @returns {enoki.v1.ProbeReportRequest} ProbeReportRequest instance
             */
            ProbeReportRequest.create = function create(properties) {
                return new ProbeReportRequest(properties);
            };

            /**
             * Encodes the specified ProbeReportRequest message. Does not implicitly {@link enoki.v1.ProbeReportRequest.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {enoki.v1.IProbeReportRequest} message ProbeReportRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeReportRequest.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.probeId);
                if (message.bootId != null && Object.hasOwnProperty.call(message, "bootId"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.bootId);
                if (message.sequenceStart != null && Object.hasOwnProperty.call(message, "sequenceStart"))
                    writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.sequenceStart);
                if (message.sequenceEnd != null && Object.hasOwnProperty.call(message, "sequenceEnd"))
                    writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.sequenceEnd);
                if (message.inventoryHash != null && Object.hasOwnProperty.call(message, "inventoryHash"))
                    writer.uint32(/* id 5, wireType 2 =*/42).string(message.inventoryHash);
                if (message.probeConfigurationVersion != null && Object.hasOwnProperty.call(message, "probeConfigurationVersion"))
                    writer.uint32(/* id 6, wireType 2 =*/50).string(message.probeConfigurationVersion);
                if (message.metrics != null && message.metrics.length)
                    for (let i = 0; i < message.metrics.length; ++i)
                        $root.enoki.v1.MetricSample.encode(message.metrics[i], writer.uint32(/* id 7, wireType 2 =*/58).fork(), q + 1).ldelim();
                if (message.inventory != null && Object.hasOwnProperty.call(message, "inventory"))
                    $root.enoki.v1.Inventory.encode(message.inventory, writer.uint32(/* id 8, wireType 2 =*/66).fork(), q + 1).ldelim();
                if (message.probeConfigurationError != null && Object.hasOwnProperty.call(message, "probeConfigurationError"))
                    $root.enoki.v1.ProbeConfigurationError.encode(message.probeConfigurationError, writer.uint32(/* id 9, wireType 2 =*/74).fork(), q + 1).ldelim();
                if (message.operationAcknowledgements != null && message.operationAcknowledgements.length)
                    for (let i = 0; i < message.operationAcknowledgements.length; ++i)
                        $root.enoki.v1.ProbeOperationAcknowledgement.encode(message.operationAcknowledgements[i], writer.uint32(/* id 10, wireType 2 =*/82).fork(), q + 1).ldelim();
                if (message.operationStatuses != null && message.operationStatuses.length)
                    for (let i = 0; i < message.operationStatuses.length; ++i)
                        $root.enoki.v1.ProbeOperationStatus.encode(message.operationStatuses[i], writer.uint32(/* id 11, wireType 2 =*/90).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified ProbeReportRequest message, length delimited. Does not implicitly {@link enoki.v1.ProbeReportRequest.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {enoki.v1.IProbeReportRequest} message ProbeReportRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeReportRequest.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeReportRequest message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeReportRequest} ProbeReportRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeReportRequest.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeReportRequest();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.probeId = reader.string();
                            break;
                        }
                    case 2: {
                            message.bootId = reader.string();
                            break;
                        }
                    case 3: {
                            message.sequenceStart = reader.uint64();
                            break;
                        }
                    case 4: {
                            message.sequenceEnd = reader.uint64();
                            break;
                        }
                    case 5: {
                            message.inventoryHash = reader.string();
                            break;
                        }
                    case 6: {
                            message.probeConfigurationVersion = reader.string();
                            break;
                        }
                    case 7: {
                            if (!(message.metrics && message.metrics.length))
                                message.metrics = [];
                            message.metrics.push($root.enoki.v1.MetricSample.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    case 8: {
                            message.inventory = $root.enoki.v1.Inventory.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 9: {
                            message.probeConfigurationError = $root.enoki.v1.ProbeConfigurationError.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 10: {
                            if (!(message.operationAcknowledgements && message.operationAcknowledgements.length))
                                message.operationAcknowledgements = [];
                            message.operationAcknowledgements.push($root.enoki.v1.ProbeOperationAcknowledgement.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    case 11: {
                            if (!(message.operationStatuses && message.operationStatuses.length))
                                message.operationStatuses = [];
                            message.operationStatuses.push($root.enoki.v1.ProbeOperationStatus.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeReportRequest message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeReportRequest} ProbeReportRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeReportRequest.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeReportRequest message.
             * @function verify
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeReportRequest.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    if (!$util.isString(message.probeId))
                        return "probeId: string expected";
                if (message.bootId != null && Object.hasOwnProperty.call(message, "bootId"))
                    if (!$util.isString(message.bootId))
                        return "bootId: string expected";
                if (message.sequenceStart != null && Object.hasOwnProperty.call(message, "sequenceStart"))
                    if (!$util.isInteger(message.sequenceStart) && !(message.sequenceStart && $util.isInteger(message.sequenceStart.low) && $util.isInteger(message.sequenceStart.high)))
                        return "sequenceStart: integer|Long expected";
                if (message.sequenceEnd != null && Object.hasOwnProperty.call(message, "sequenceEnd"))
                    if (!$util.isInteger(message.sequenceEnd) && !(message.sequenceEnd && $util.isInteger(message.sequenceEnd.low) && $util.isInteger(message.sequenceEnd.high)))
                        return "sequenceEnd: integer|Long expected";
                if (message.inventoryHash != null && Object.hasOwnProperty.call(message, "inventoryHash"))
                    if (!$util.isString(message.inventoryHash))
                        return "inventoryHash: string expected";
                if (message.probeConfigurationVersion != null && Object.hasOwnProperty.call(message, "probeConfigurationVersion"))
                    if (!$util.isString(message.probeConfigurationVersion))
                        return "probeConfigurationVersion: string expected";
                if (message.metrics != null && Object.hasOwnProperty.call(message, "metrics")) {
                    if (!Array.isArray(message.metrics))
                        return "metrics: array expected";
                    for (let i = 0; i < message.metrics.length; ++i) {
                        let error = $root.enoki.v1.MetricSample.verify(message.metrics[i], long + 1);
                        if (error)
                            return "metrics." + error;
                    }
                }
                if (message.inventory != null && Object.hasOwnProperty.call(message, "inventory")) {
                    let error = $root.enoki.v1.Inventory.verify(message.inventory, long + 1);
                    if (error)
                        return "inventory." + error;
                }
                if (message.probeConfigurationError != null && Object.hasOwnProperty.call(message, "probeConfigurationError")) {
                    let error = $root.enoki.v1.ProbeConfigurationError.verify(message.probeConfigurationError, long + 1);
                    if (error)
                        return "probeConfigurationError." + error;
                }
                if (message.operationAcknowledgements != null && Object.hasOwnProperty.call(message, "operationAcknowledgements")) {
                    if (!Array.isArray(message.operationAcknowledgements))
                        return "operationAcknowledgements: array expected";
                    for (let i = 0; i < message.operationAcknowledgements.length; ++i) {
                        let error = $root.enoki.v1.ProbeOperationAcknowledgement.verify(message.operationAcknowledgements[i], long + 1);
                        if (error)
                            return "operationAcknowledgements." + error;
                    }
                }
                if (message.operationStatuses != null && Object.hasOwnProperty.call(message, "operationStatuses")) {
                    if (!Array.isArray(message.operationStatuses))
                        return "operationStatuses: array expected";
                    for (let i = 0; i < message.operationStatuses.length; ++i) {
                        let error = $root.enoki.v1.ProbeOperationStatus.verify(message.operationStatuses[i], long + 1);
                        if (error)
                            return "operationStatuses." + error;
                    }
                }
                return null;
            };

            /**
             * Creates a ProbeReportRequest message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeReportRequest} ProbeReportRequest
             */
            ProbeReportRequest.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeReportRequest)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeReportRequest: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeReportRequest();
                if (object.probeId != null)
                    message.probeId = String(object.probeId);
                if (object.bootId != null)
                    message.bootId = String(object.bootId);
                if (object.sequenceStart != null)
                    if ($util.Long)
                        message.sequenceStart = $util.Long.fromValue(object.sequenceStart, true);
                    else if (typeof object.sequenceStart === "string")
                        message.sequenceStart = parseInt(object.sequenceStart, 10);
                    else if (typeof object.sequenceStart === "number")
                        message.sequenceStart = object.sequenceStart;
                    else if (typeof object.sequenceStart === "object")
                        message.sequenceStart = new $util.LongBits(object.sequenceStart.low >>> 0, object.sequenceStart.high >>> 0).toNumber(true);
                if (object.sequenceEnd != null)
                    if ($util.Long)
                        message.sequenceEnd = $util.Long.fromValue(object.sequenceEnd, true);
                    else if (typeof object.sequenceEnd === "string")
                        message.sequenceEnd = parseInt(object.sequenceEnd, 10);
                    else if (typeof object.sequenceEnd === "number")
                        message.sequenceEnd = object.sequenceEnd;
                    else if (typeof object.sequenceEnd === "object")
                        message.sequenceEnd = new $util.LongBits(object.sequenceEnd.low >>> 0, object.sequenceEnd.high >>> 0).toNumber(true);
                if (object.inventoryHash != null)
                    message.inventoryHash = String(object.inventoryHash);
                if (object.probeConfigurationVersion != null)
                    message.probeConfigurationVersion = String(object.probeConfigurationVersion);
                if (object.metrics) {
                    if (!Array.isArray(object.metrics))
                        throw TypeError(".enoki.v1.ProbeReportRequest.metrics: array expected");
                    message.metrics = [];
                    for (let i = 0; i < object.metrics.length; ++i) {
                        if (!$util.isObject(object.metrics[i]))
                            throw TypeError(".enoki.v1.ProbeReportRequest.metrics: object expected");
                        message.metrics[i] = $root.enoki.v1.MetricSample.fromObject(object.metrics[i], long + 1);
                    }
                }
                if (object.inventory != null) {
                    if (!$util.isObject(object.inventory))
                        throw TypeError(".enoki.v1.ProbeReportRequest.inventory: object expected");
                    message.inventory = $root.enoki.v1.Inventory.fromObject(object.inventory, long + 1);
                }
                if (object.probeConfigurationError != null) {
                    if (!$util.isObject(object.probeConfigurationError))
                        throw TypeError(".enoki.v1.ProbeReportRequest.probeConfigurationError: object expected");
                    message.probeConfigurationError = $root.enoki.v1.ProbeConfigurationError.fromObject(object.probeConfigurationError, long + 1);
                }
                if (object.operationAcknowledgements) {
                    if (!Array.isArray(object.operationAcknowledgements))
                        throw TypeError(".enoki.v1.ProbeReportRequest.operationAcknowledgements: array expected");
                    message.operationAcknowledgements = [];
                    for (let i = 0; i < object.operationAcknowledgements.length; ++i) {
                        if (!$util.isObject(object.operationAcknowledgements[i]))
                            throw TypeError(".enoki.v1.ProbeReportRequest.operationAcknowledgements: object expected");
                        message.operationAcknowledgements[i] = $root.enoki.v1.ProbeOperationAcknowledgement.fromObject(object.operationAcknowledgements[i], long + 1);
                    }
                }
                if (object.operationStatuses) {
                    if (!Array.isArray(object.operationStatuses))
                        throw TypeError(".enoki.v1.ProbeReportRequest.operationStatuses: array expected");
                    message.operationStatuses = [];
                    for (let i = 0; i < object.operationStatuses.length; ++i) {
                        if (!$util.isObject(object.operationStatuses[i]))
                            throw TypeError(".enoki.v1.ProbeReportRequest.operationStatuses: object expected");
                        message.operationStatuses[i] = $root.enoki.v1.ProbeOperationStatus.fromObject(object.operationStatuses[i], long + 1);
                    }
                }
                return message;
            };

            /**
             * Creates a plain object from a ProbeReportRequest message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {enoki.v1.ProbeReportRequest} message ProbeReportRequest
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeReportRequest.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.arrays || options.defaults) {
                    object.metrics = [];
                    object.operationAcknowledgements = [];
                    object.operationStatuses = [];
                }
                if (options.defaults) {
                    object.probeId = "";
                    object.bootId = "";
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.sequenceStart = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.sequenceStart = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.sequenceEnd = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.sequenceEnd = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    object.inventoryHash = "";
                    object.probeConfigurationVersion = "";
                    object.inventory = null;
                    object.probeConfigurationError = null;
                }
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    object.probeId = message.probeId;
                if (message.bootId != null && Object.hasOwnProperty.call(message, "bootId"))
                    object.bootId = message.bootId;
                if (message.sequenceStart != null && Object.hasOwnProperty.call(message, "sequenceStart"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.sequenceStart = typeof message.sequenceStart === "number" ? BigInt(message.sequenceStart) : $util.Long.fromBits(message.sequenceStart.low >>> 0, message.sequenceStart.high >>> 0, true).toBigInt();
                    else if (typeof message.sequenceStart === "number")
                        object.sequenceStart = options.longs === String ? String(message.sequenceStart) : message.sequenceStart;
                    else
                        object.sequenceStart = options.longs === String ? $util.Long.prototype.toString.call(message.sequenceStart) : options.longs === Number ? new $util.LongBits(message.sequenceStart.low >>> 0, message.sequenceStart.high >>> 0).toNumber(true) : message.sequenceStart;
                if (message.sequenceEnd != null && Object.hasOwnProperty.call(message, "sequenceEnd"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.sequenceEnd = typeof message.sequenceEnd === "number" ? BigInt(message.sequenceEnd) : $util.Long.fromBits(message.sequenceEnd.low >>> 0, message.sequenceEnd.high >>> 0, true).toBigInt();
                    else if (typeof message.sequenceEnd === "number")
                        object.sequenceEnd = options.longs === String ? String(message.sequenceEnd) : message.sequenceEnd;
                    else
                        object.sequenceEnd = options.longs === String ? $util.Long.prototype.toString.call(message.sequenceEnd) : options.longs === Number ? new $util.LongBits(message.sequenceEnd.low >>> 0, message.sequenceEnd.high >>> 0).toNumber(true) : message.sequenceEnd;
                if (message.inventoryHash != null && Object.hasOwnProperty.call(message, "inventoryHash"))
                    object.inventoryHash = message.inventoryHash;
                if (message.probeConfigurationVersion != null && Object.hasOwnProperty.call(message, "probeConfigurationVersion"))
                    object.probeConfigurationVersion = message.probeConfigurationVersion;
                if (message.metrics && message.metrics.length) {
                    object.metrics = [];
                    for (let j = 0; j < message.metrics.length; ++j)
                        object.metrics[j] = $root.enoki.v1.MetricSample.toObject(message.metrics[j], options, q + 1);
                }
                if (message.inventory != null && Object.hasOwnProperty.call(message, "inventory"))
                    object.inventory = $root.enoki.v1.Inventory.toObject(message.inventory, options, q + 1);
                if (message.probeConfigurationError != null && Object.hasOwnProperty.call(message, "probeConfigurationError"))
                    object.probeConfigurationError = $root.enoki.v1.ProbeConfigurationError.toObject(message.probeConfigurationError, options, q + 1);
                if (message.operationAcknowledgements && message.operationAcknowledgements.length) {
                    object.operationAcknowledgements = [];
                    for (let j = 0; j < message.operationAcknowledgements.length; ++j)
                        object.operationAcknowledgements[j] = $root.enoki.v1.ProbeOperationAcknowledgement.toObject(message.operationAcknowledgements[j], options, q + 1);
                }
                if (message.operationStatuses && message.operationStatuses.length) {
                    object.operationStatuses = [];
                    for (let j = 0; j < message.operationStatuses.length; ++j)
                        object.operationStatuses[j] = $root.enoki.v1.ProbeOperationStatus.toObject(message.operationStatuses[j], options, q + 1);
                }
                return object;
            };

            /**
             * Converts this ProbeReportRequest to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeReportRequest
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeReportRequest.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeReportRequest
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeReportRequest
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeReportRequest.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeReportRequest";
            };

            return ProbeReportRequest;
        })();

        v1.ProbeConfigurationError = (function() {

            /**
             * Properties of a ProbeConfigurationError.
             * @memberof enoki.v1
             * @interface IProbeConfigurationError
             * @property {string|null} [failedVersion] ProbeConfigurationError failedVersion
             * @property {string|null} [errorCode] ProbeConfigurationError errorCode
             * @property {string|null} [message] ProbeConfigurationError message
             */

            /**
             * Constructs a new ProbeConfigurationError.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeConfigurationError.
             * @implements IProbeConfigurationError
             * @constructor
             * @param {enoki.v1.IProbeConfigurationError=} [properties] Properties to set
             */
            function ProbeConfigurationError(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeConfigurationError failedVersion.
             * @member {string} failedVersion
             * @memberof enoki.v1.ProbeConfigurationError
             * @instance
             */
            ProbeConfigurationError.prototype.failedVersion = "";

            /**
             * ProbeConfigurationError errorCode.
             * @member {string} errorCode
             * @memberof enoki.v1.ProbeConfigurationError
             * @instance
             */
            ProbeConfigurationError.prototype.errorCode = "";

            /**
             * ProbeConfigurationError message.
             * @member {string} message
             * @memberof enoki.v1.ProbeConfigurationError
             * @instance
             */
            ProbeConfigurationError.prototype.message = "";

            /**
             * Creates a new ProbeConfigurationError instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {enoki.v1.IProbeConfigurationError=} [properties] Properties to set
             * @returns {enoki.v1.ProbeConfigurationError} ProbeConfigurationError instance
             */
            ProbeConfigurationError.create = function create(properties) {
                return new ProbeConfigurationError(properties);
            };

            /**
             * Encodes the specified ProbeConfigurationError message. Does not implicitly {@link enoki.v1.ProbeConfigurationError.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {enoki.v1.IProbeConfigurationError} message ProbeConfigurationError message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeConfigurationError.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.failedVersion != null && Object.hasOwnProperty.call(message, "failedVersion"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.failedVersion);
                if (message.errorCode != null && Object.hasOwnProperty.call(message, "errorCode"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.errorCode);
                if (message.message != null && Object.hasOwnProperty.call(message, "message"))
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.message);
                return writer;
            };

            /**
             * Encodes the specified ProbeConfigurationError message, length delimited. Does not implicitly {@link enoki.v1.ProbeConfigurationError.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {enoki.v1.IProbeConfigurationError} message ProbeConfigurationError message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeConfigurationError.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeConfigurationError message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeConfigurationError} ProbeConfigurationError
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeConfigurationError.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeConfigurationError();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.failedVersion = reader.string();
                            break;
                        }
                    case 2: {
                            message.errorCode = reader.string();
                            break;
                        }
                    case 3: {
                            message.message = reader.string();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeConfigurationError message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeConfigurationError} ProbeConfigurationError
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeConfigurationError.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeConfigurationError message.
             * @function verify
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeConfigurationError.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.failedVersion != null && Object.hasOwnProperty.call(message, "failedVersion"))
                    if (!$util.isString(message.failedVersion))
                        return "failedVersion: string expected";
                if (message.errorCode != null && Object.hasOwnProperty.call(message, "errorCode"))
                    if (!$util.isString(message.errorCode))
                        return "errorCode: string expected";
                if (message.message != null && Object.hasOwnProperty.call(message, "message"))
                    if (!$util.isString(message.message))
                        return "message: string expected";
                return null;
            };

            /**
             * Creates a ProbeConfigurationError message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeConfigurationError} ProbeConfigurationError
             */
            ProbeConfigurationError.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeConfigurationError)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeConfigurationError: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeConfigurationError();
                if (object.failedVersion != null)
                    message.failedVersion = String(object.failedVersion);
                if (object.errorCode != null)
                    message.errorCode = String(object.errorCode);
                if (object.message != null)
                    message.message = String(object.message);
                return message;
            };

            /**
             * Creates a plain object from a ProbeConfigurationError message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {enoki.v1.ProbeConfigurationError} message ProbeConfigurationError
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeConfigurationError.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.failedVersion = "";
                    object.errorCode = "";
                    object.message = "";
                }
                if (message.failedVersion != null && Object.hasOwnProperty.call(message, "failedVersion"))
                    object.failedVersion = message.failedVersion;
                if (message.errorCode != null && Object.hasOwnProperty.call(message, "errorCode"))
                    object.errorCode = message.errorCode;
                if (message.message != null && Object.hasOwnProperty.call(message, "message"))
                    object.message = message.message;
                return object;
            };

            /**
             * Converts this ProbeConfigurationError to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeConfigurationError
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeConfigurationError.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeConfigurationError
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeConfigurationError
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeConfigurationError.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeConfigurationError";
            };

            return ProbeConfigurationError;
        })();

        v1.MetricSample = (function() {

            /**
             * Properties of a MetricSample.
             * @memberof enoki.v1
             * @interface IMetricSample
             * @property {Long|null} [sequence] MetricSample sequence
             * @property {Long|null} [collectedAtMs] MetricSample collectedAtMs
             * @property {number|null} [cpuPercent] MetricSample cpuPercent
             * @property {Long|null} [memoryUsedBytes] MetricSample memoryUsedBytes
             * @property {number|null} [load_1] MetricSample load_1
             * @property {number|null} [load_5] MetricSample load_5
             * @property {number|null} [load_15] MetricSample load_15
             * @property {Long|null} [uptimeSeconds] MetricSample uptimeSeconds
             * @property {Array.<enoki.v1.IDiskUsageMetric>|null} [disks] MetricSample disks
             * @property {Array.<enoki.v1.INetworkInterfaceMetric>|null} [networkInterfaces] MetricSample networkInterfaces
             * @property {Array.<enoki.v1.ICpuCoreMetric>|null} [cpuCores] MetricSample cpuCores
             * @property {Long|null} [memoryTotalBytes] MetricSample memoryTotalBytes
             * @property {number|null} [cpuUserPercent] MetricSample cpuUserPercent
             * @property {number|null} [cpuSystemPercent] MetricSample cpuSystemPercent
             * @property {number|null} [cpuIowaitPercent] MetricSample cpuIowaitPercent
             * @property {number|null} [cpuStealPercent] MetricSample cpuStealPercent
             * @property {number|null} [cpuIdlePercent] MetricSample cpuIdlePercent
             * @property {Long|null} [memoryCacheBytes] MetricSample memoryCacheBytes
             * @property {Long|null} [swapTotalBytes] MetricSample swapTotalBytes
             * @property {Long|null} [swapUsedBytes] MetricSample swapUsedBytes
             * @property {number|null} [temperatureCelsius] MetricSample temperatureCelsius
             * @property {number|null} [batteryPercent] MetricSample batteryPercent
             * @property {string|null} [batteryState] MetricSample batteryState
             * @property {Array.<enoki.v1.IDiskHealthMetric>|null} [diskHealth] MetricSample diskHealth
             */

            /**
             * Constructs a new MetricSample.
             * @memberof enoki.v1
             * @classdesc Represents a MetricSample.
             * @implements IMetricSample
             * @constructor
             * @param {enoki.v1.IMetricSample=} [properties] Properties to set
             */
            function MetricSample(properties) {
                this.disks = [];
                this.networkInterfaces = [];
                this.cpuCores = [];
                this.diskHealth = [];
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * MetricSample sequence.
             * @member {Long} sequence
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.sequence = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * MetricSample collectedAtMs.
             * @member {Long} collectedAtMs
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.collectedAtMs = $util.Long ? $util.Long.fromBits(0,0,false) : 0;

            /**
             * MetricSample cpuPercent.
             * @member {number|null|undefined} cpuPercent
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.cpuPercent = null;

            /**
             * MetricSample memoryUsedBytes.
             * @member {Long|null|undefined} memoryUsedBytes
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.memoryUsedBytes = null;

            /**
             * MetricSample load_1.
             * @member {number|null|undefined} load_1
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.load_1 = null;

            /**
             * MetricSample load_5.
             * @member {number|null|undefined} load_5
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.load_5 = null;

            /**
             * MetricSample load_15.
             * @member {number|null|undefined} load_15
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.load_15 = null;

            /**
             * MetricSample uptimeSeconds.
             * @member {Long|null|undefined} uptimeSeconds
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.uptimeSeconds = null;

            /**
             * MetricSample disks.
             * @member {Array.<enoki.v1.IDiskUsageMetric>} disks
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.disks = $util.emptyArray;

            /**
             * MetricSample networkInterfaces.
             * @member {Array.<enoki.v1.INetworkInterfaceMetric>} networkInterfaces
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.networkInterfaces = $util.emptyArray;

            /**
             * MetricSample cpuCores.
             * @member {Array.<enoki.v1.ICpuCoreMetric>} cpuCores
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.cpuCores = $util.emptyArray;

            /**
             * MetricSample memoryTotalBytes.
             * @member {Long|null|undefined} memoryTotalBytes
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.memoryTotalBytes = null;

            /**
             * MetricSample cpuUserPercent.
             * @member {number|null|undefined} cpuUserPercent
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.cpuUserPercent = null;

            /**
             * MetricSample cpuSystemPercent.
             * @member {number|null|undefined} cpuSystemPercent
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.cpuSystemPercent = null;

            /**
             * MetricSample cpuIowaitPercent.
             * @member {number|null|undefined} cpuIowaitPercent
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.cpuIowaitPercent = null;

            /**
             * MetricSample cpuStealPercent.
             * @member {number|null|undefined} cpuStealPercent
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.cpuStealPercent = null;

            /**
             * MetricSample cpuIdlePercent.
             * @member {number|null|undefined} cpuIdlePercent
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.cpuIdlePercent = null;

            /**
             * MetricSample memoryCacheBytes.
             * @member {Long|null|undefined} memoryCacheBytes
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.memoryCacheBytes = null;

            /**
             * MetricSample swapTotalBytes.
             * @member {Long|null|undefined} swapTotalBytes
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.swapTotalBytes = null;

            /**
             * MetricSample swapUsedBytes.
             * @member {Long|null|undefined} swapUsedBytes
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.swapUsedBytes = null;

            /**
             * MetricSample temperatureCelsius.
             * @member {number|null|undefined} temperatureCelsius
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.temperatureCelsius = null;

            /**
             * MetricSample batteryPercent.
             * @member {number|null|undefined} batteryPercent
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.batteryPercent = null;

            /**
             * MetricSample batteryState.
             * @member {string|null|undefined} batteryState
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.batteryState = null;

            /**
             * MetricSample diskHealth.
             * @member {Array.<enoki.v1.IDiskHealthMetric>} diskHealth
             * @memberof enoki.v1.MetricSample
             * @instance
             */
            MetricSample.prototype.diskHealth = $util.emptyArray;

            // OneOf field names bound to virtual getters and setters
            let $oneOfFields;

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_cpuPercent", {
                get: $util.oneOfGetter($oneOfFields = ["cpuPercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_memoryUsedBytes", {
                get: $util.oneOfGetter($oneOfFields = ["memoryUsedBytes"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_load_1", {
                get: $util.oneOfGetter($oneOfFields = ["load_1"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_load_5", {
                get: $util.oneOfGetter($oneOfFields = ["load_5"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_load_15", {
                get: $util.oneOfGetter($oneOfFields = ["load_15"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_uptimeSeconds", {
                get: $util.oneOfGetter($oneOfFields = ["uptimeSeconds"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_memoryTotalBytes", {
                get: $util.oneOfGetter($oneOfFields = ["memoryTotalBytes"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_cpuUserPercent", {
                get: $util.oneOfGetter($oneOfFields = ["cpuUserPercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_cpuSystemPercent", {
                get: $util.oneOfGetter($oneOfFields = ["cpuSystemPercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_cpuIowaitPercent", {
                get: $util.oneOfGetter($oneOfFields = ["cpuIowaitPercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_cpuStealPercent", {
                get: $util.oneOfGetter($oneOfFields = ["cpuStealPercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_cpuIdlePercent", {
                get: $util.oneOfGetter($oneOfFields = ["cpuIdlePercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_memoryCacheBytes", {
                get: $util.oneOfGetter($oneOfFields = ["memoryCacheBytes"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_swapTotalBytes", {
                get: $util.oneOfGetter($oneOfFields = ["swapTotalBytes"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_swapUsedBytes", {
                get: $util.oneOfGetter($oneOfFields = ["swapUsedBytes"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_temperatureCelsius", {
                get: $util.oneOfGetter($oneOfFields = ["temperatureCelsius"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_batteryPercent", {
                get: $util.oneOfGetter($oneOfFields = ["batteryPercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(MetricSample.prototype, "_batteryState", {
                get: $util.oneOfGetter($oneOfFields = ["batteryState"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            /**
             * Creates a new MetricSample instance using the specified properties.
             * @function create
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {enoki.v1.IMetricSample=} [properties] Properties to set
             * @returns {enoki.v1.MetricSample} MetricSample instance
             */
            MetricSample.create = function create(properties) {
                return new MetricSample(properties);
            };

            /**
             * Encodes the specified MetricSample message. Does not implicitly {@link enoki.v1.MetricSample.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {enoki.v1.IMetricSample} message MetricSample message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            MetricSample.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.sequence != null && Object.hasOwnProperty.call(message, "sequence"))
                    writer.uint32(/* id 1, wireType 0 =*/8).uint64(message.sequence);
                if (message.collectedAtMs != null && Object.hasOwnProperty.call(message, "collectedAtMs"))
                    writer.uint32(/* id 2, wireType 0 =*/16).int64(message.collectedAtMs);
                if (message.cpuPercent != null && Object.hasOwnProperty.call(message, "cpuPercent"))
                    writer.uint32(/* id 3, wireType 1 =*/25).double(message.cpuPercent);
                if (message.memoryUsedBytes != null && Object.hasOwnProperty.call(message, "memoryUsedBytes"))
                    writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.memoryUsedBytes);
                if (message.load_1 != null && Object.hasOwnProperty.call(message, "load_1"))
                    writer.uint32(/* id 5, wireType 1 =*/41).double(message.load_1);
                if (message.load_5 != null && Object.hasOwnProperty.call(message, "load_5"))
                    writer.uint32(/* id 6, wireType 1 =*/49).double(message.load_5);
                if (message.load_15 != null && Object.hasOwnProperty.call(message, "load_15"))
                    writer.uint32(/* id 7, wireType 1 =*/57).double(message.load_15);
                if (message.uptimeSeconds != null && Object.hasOwnProperty.call(message, "uptimeSeconds"))
                    writer.uint32(/* id 8, wireType 0 =*/64).uint64(message.uptimeSeconds);
                if (message.disks != null && message.disks.length)
                    for (let i = 0; i < message.disks.length; ++i)
                        $root.enoki.v1.DiskUsageMetric.encode(message.disks[i], writer.uint32(/* id 9, wireType 2 =*/74).fork(), q + 1).ldelim();
                if (message.networkInterfaces != null && message.networkInterfaces.length)
                    for (let i = 0; i < message.networkInterfaces.length; ++i)
                        $root.enoki.v1.NetworkInterfaceMetric.encode(message.networkInterfaces[i], writer.uint32(/* id 10, wireType 2 =*/82).fork(), q + 1).ldelim();
                if (message.cpuCores != null && message.cpuCores.length)
                    for (let i = 0; i < message.cpuCores.length; ++i)
                        $root.enoki.v1.CpuCoreMetric.encode(message.cpuCores[i], writer.uint32(/* id 11, wireType 2 =*/90).fork(), q + 1).ldelim();
                if (message.memoryTotalBytes != null && Object.hasOwnProperty.call(message, "memoryTotalBytes"))
                    writer.uint32(/* id 12, wireType 0 =*/96).uint64(message.memoryTotalBytes);
                if (message.cpuUserPercent != null && Object.hasOwnProperty.call(message, "cpuUserPercent"))
                    writer.uint32(/* id 13, wireType 1 =*/105).double(message.cpuUserPercent);
                if (message.cpuSystemPercent != null && Object.hasOwnProperty.call(message, "cpuSystemPercent"))
                    writer.uint32(/* id 14, wireType 1 =*/113).double(message.cpuSystemPercent);
                if (message.cpuIowaitPercent != null && Object.hasOwnProperty.call(message, "cpuIowaitPercent"))
                    writer.uint32(/* id 15, wireType 1 =*/121).double(message.cpuIowaitPercent);
                if (message.cpuStealPercent != null && Object.hasOwnProperty.call(message, "cpuStealPercent"))
                    writer.uint32(/* id 16, wireType 1 =*/129).double(message.cpuStealPercent);
                if (message.cpuIdlePercent != null && Object.hasOwnProperty.call(message, "cpuIdlePercent"))
                    writer.uint32(/* id 17, wireType 1 =*/137).double(message.cpuIdlePercent);
                if (message.memoryCacheBytes != null && Object.hasOwnProperty.call(message, "memoryCacheBytes"))
                    writer.uint32(/* id 18, wireType 0 =*/144).uint64(message.memoryCacheBytes);
                if (message.swapTotalBytes != null && Object.hasOwnProperty.call(message, "swapTotalBytes"))
                    writer.uint32(/* id 19, wireType 0 =*/152).uint64(message.swapTotalBytes);
                if (message.swapUsedBytes != null && Object.hasOwnProperty.call(message, "swapUsedBytes"))
                    writer.uint32(/* id 20, wireType 0 =*/160).uint64(message.swapUsedBytes);
                if (message.temperatureCelsius != null && Object.hasOwnProperty.call(message, "temperatureCelsius"))
                    writer.uint32(/* id 21, wireType 1 =*/169).double(message.temperatureCelsius);
                if (message.batteryPercent != null && Object.hasOwnProperty.call(message, "batteryPercent"))
                    writer.uint32(/* id 22, wireType 0 =*/176).uint32(message.batteryPercent);
                if (message.batteryState != null && Object.hasOwnProperty.call(message, "batteryState"))
                    writer.uint32(/* id 23, wireType 2 =*/186).string(message.batteryState);
                if (message.diskHealth != null && message.diskHealth.length)
                    for (let i = 0; i < message.diskHealth.length; ++i)
                        $root.enoki.v1.DiskHealthMetric.encode(message.diskHealth[i], writer.uint32(/* id 24, wireType 2 =*/194).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified MetricSample message, length delimited. Does not implicitly {@link enoki.v1.MetricSample.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {enoki.v1.IMetricSample} message MetricSample message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            MetricSample.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a MetricSample message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.MetricSample} MetricSample
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            MetricSample.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.MetricSample();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.sequence = reader.uint64();
                            break;
                        }
                    case 2: {
                            message.collectedAtMs = reader.int64();
                            break;
                        }
                    case 3: {
                            message.cpuPercent = reader.double();
                            break;
                        }
                    case 4: {
                            message.memoryUsedBytes = reader.uint64();
                            break;
                        }
                    case 5: {
                            message.load_1 = reader.double();
                            break;
                        }
                    case 6: {
                            message.load_5 = reader.double();
                            break;
                        }
                    case 7: {
                            message.load_15 = reader.double();
                            break;
                        }
                    case 8: {
                            message.uptimeSeconds = reader.uint64();
                            break;
                        }
                    case 9: {
                            if (!(message.disks && message.disks.length))
                                message.disks = [];
                            message.disks.push($root.enoki.v1.DiskUsageMetric.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    case 10: {
                            if (!(message.networkInterfaces && message.networkInterfaces.length))
                                message.networkInterfaces = [];
                            message.networkInterfaces.push($root.enoki.v1.NetworkInterfaceMetric.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    case 11: {
                            if (!(message.cpuCores && message.cpuCores.length))
                                message.cpuCores = [];
                            message.cpuCores.push($root.enoki.v1.CpuCoreMetric.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    case 12: {
                            message.memoryTotalBytes = reader.uint64();
                            break;
                        }
                    case 13: {
                            message.cpuUserPercent = reader.double();
                            break;
                        }
                    case 14: {
                            message.cpuSystemPercent = reader.double();
                            break;
                        }
                    case 15: {
                            message.cpuIowaitPercent = reader.double();
                            break;
                        }
                    case 16: {
                            message.cpuStealPercent = reader.double();
                            break;
                        }
                    case 17: {
                            message.cpuIdlePercent = reader.double();
                            break;
                        }
                    case 18: {
                            message.memoryCacheBytes = reader.uint64();
                            break;
                        }
                    case 19: {
                            message.swapTotalBytes = reader.uint64();
                            break;
                        }
                    case 20: {
                            message.swapUsedBytes = reader.uint64();
                            break;
                        }
                    case 21: {
                            message.temperatureCelsius = reader.double();
                            break;
                        }
                    case 22: {
                            message.batteryPercent = reader.uint32();
                            break;
                        }
                    case 23: {
                            message.batteryState = reader.string();
                            break;
                        }
                    case 24: {
                            if (!(message.diskHealth && message.diskHealth.length))
                                message.diskHealth = [];
                            message.diskHealth.push($root.enoki.v1.DiskHealthMetric.decode(reader, reader.uint32(), undefined, long + 1));
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a MetricSample message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.MetricSample} MetricSample
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            MetricSample.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a MetricSample message.
             * @function verify
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            MetricSample.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                let properties = {};
                if (message.sequence != null && Object.hasOwnProperty.call(message, "sequence"))
                    if (!$util.isInteger(message.sequence) && !(message.sequence && $util.isInteger(message.sequence.low) && $util.isInteger(message.sequence.high)))
                        return "sequence: integer|Long expected";
                if (message.collectedAtMs != null && Object.hasOwnProperty.call(message, "collectedAtMs"))
                    if (!$util.isInteger(message.collectedAtMs) && !(message.collectedAtMs && $util.isInteger(message.collectedAtMs.low) && $util.isInteger(message.collectedAtMs.high)))
                        return "collectedAtMs: integer|Long expected";
                if (message.cpuPercent != null && Object.hasOwnProperty.call(message, "cpuPercent")) {
                    properties._cpuPercent = 1;
                    if (typeof message.cpuPercent !== "number")
                        return "cpuPercent: number expected";
                }
                if (message.memoryUsedBytes != null && Object.hasOwnProperty.call(message, "memoryUsedBytes")) {
                    properties._memoryUsedBytes = 1;
                    if (!$util.isInteger(message.memoryUsedBytes) && !(message.memoryUsedBytes && $util.isInteger(message.memoryUsedBytes.low) && $util.isInteger(message.memoryUsedBytes.high)))
                        return "memoryUsedBytes: integer|Long expected";
                }
                if (message.load_1 != null && Object.hasOwnProperty.call(message, "load_1")) {
                    properties._load_1 = 1;
                    if (typeof message.load_1 !== "number")
                        return "load_1: number expected";
                }
                if (message.load_5 != null && Object.hasOwnProperty.call(message, "load_5")) {
                    properties._load_5 = 1;
                    if (typeof message.load_5 !== "number")
                        return "load_5: number expected";
                }
                if (message.load_15 != null && Object.hasOwnProperty.call(message, "load_15")) {
                    properties._load_15 = 1;
                    if (typeof message.load_15 !== "number")
                        return "load_15: number expected";
                }
                if (message.uptimeSeconds != null && Object.hasOwnProperty.call(message, "uptimeSeconds")) {
                    properties._uptimeSeconds = 1;
                    if (!$util.isInteger(message.uptimeSeconds) && !(message.uptimeSeconds && $util.isInteger(message.uptimeSeconds.low) && $util.isInteger(message.uptimeSeconds.high)))
                        return "uptimeSeconds: integer|Long expected";
                }
                if (message.disks != null && Object.hasOwnProperty.call(message, "disks")) {
                    if (!Array.isArray(message.disks))
                        return "disks: array expected";
                    for (let i = 0; i < message.disks.length; ++i) {
                        let error = $root.enoki.v1.DiskUsageMetric.verify(message.disks[i], long + 1);
                        if (error)
                            return "disks." + error;
                    }
                }
                if (message.networkInterfaces != null && Object.hasOwnProperty.call(message, "networkInterfaces")) {
                    if (!Array.isArray(message.networkInterfaces))
                        return "networkInterfaces: array expected";
                    for (let i = 0; i < message.networkInterfaces.length; ++i) {
                        let error = $root.enoki.v1.NetworkInterfaceMetric.verify(message.networkInterfaces[i], long + 1);
                        if (error)
                            return "networkInterfaces." + error;
                    }
                }
                if (message.cpuCores != null && Object.hasOwnProperty.call(message, "cpuCores")) {
                    if (!Array.isArray(message.cpuCores))
                        return "cpuCores: array expected";
                    for (let i = 0; i < message.cpuCores.length; ++i) {
                        let error = $root.enoki.v1.CpuCoreMetric.verify(message.cpuCores[i], long + 1);
                        if (error)
                            return "cpuCores." + error;
                    }
                }
                if (message.memoryTotalBytes != null && Object.hasOwnProperty.call(message, "memoryTotalBytes")) {
                    properties._memoryTotalBytes = 1;
                    if (!$util.isInteger(message.memoryTotalBytes) && !(message.memoryTotalBytes && $util.isInteger(message.memoryTotalBytes.low) && $util.isInteger(message.memoryTotalBytes.high)))
                        return "memoryTotalBytes: integer|Long expected";
                }
                if (message.cpuUserPercent != null && Object.hasOwnProperty.call(message, "cpuUserPercent")) {
                    properties._cpuUserPercent = 1;
                    if (typeof message.cpuUserPercent !== "number")
                        return "cpuUserPercent: number expected";
                }
                if (message.cpuSystemPercent != null && Object.hasOwnProperty.call(message, "cpuSystemPercent")) {
                    properties._cpuSystemPercent = 1;
                    if (typeof message.cpuSystemPercent !== "number")
                        return "cpuSystemPercent: number expected";
                }
                if (message.cpuIowaitPercent != null && Object.hasOwnProperty.call(message, "cpuIowaitPercent")) {
                    properties._cpuIowaitPercent = 1;
                    if (typeof message.cpuIowaitPercent !== "number")
                        return "cpuIowaitPercent: number expected";
                }
                if (message.cpuStealPercent != null && Object.hasOwnProperty.call(message, "cpuStealPercent")) {
                    properties._cpuStealPercent = 1;
                    if (typeof message.cpuStealPercent !== "number")
                        return "cpuStealPercent: number expected";
                }
                if (message.cpuIdlePercent != null && Object.hasOwnProperty.call(message, "cpuIdlePercent")) {
                    properties._cpuIdlePercent = 1;
                    if (typeof message.cpuIdlePercent !== "number")
                        return "cpuIdlePercent: number expected";
                }
                if (message.memoryCacheBytes != null && Object.hasOwnProperty.call(message, "memoryCacheBytes")) {
                    properties._memoryCacheBytes = 1;
                    if (!$util.isInteger(message.memoryCacheBytes) && !(message.memoryCacheBytes && $util.isInteger(message.memoryCacheBytes.low) && $util.isInteger(message.memoryCacheBytes.high)))
                        return "memoryCacheBytes: integer|Long expected";
                }
                if (message.swapTotalBytes != null && Object.hasOwnProperty.call(message, "swapTotalBytes")) {
                    properties._swapTotalBytes = 1;
                    if (!$util.isInteger(message.swapTotalBytes) && !(message.swapTotalBytes && $util.isInteger(message.swapTotalBytes.low) && $util.isInteger(message.swapTotalBytes.high)))
                        return "swapTotalBytes: integer|Long expected";
                }
                if (message.swapUsedBytes != null && Object.hasOwnProperty.call(message, "swapUsedBytes")) {
                    properties._swapUsedBytes = 1;
                    if (!$util.isInteger(message.swapUsedBytes) && !(message.swapUsedBytes && $util.isInteger(message.swapUsedBytes.low) && $util.isInteger(message.swapUsedBytes.high)))
                        return "swapUsedBytes: integer|Long expected";
                }
                if (message.temperatureCelsius != null && Object.hasOwnProperty.call(message, "temperatureCelsius")) {
                    properties._temperatureCelsius = 1;
                    if (typeof message.temperatureCelsius !== "number")
                        return "temperatureCelsius: number expected";
                }
                if (message.batteryPercent != null && Object.hasOwnProperty.call(message, "batteryPercent")) {
                    properties._batteryPercent = 1;
                    if (!$util.isInteger(message.batteryPercent))
                        return "batteryPercent: integer expected";
                }
                if (message.batteryState != null && Object.hasOwnProperty.call(message, "batteryState")) {
                    properties._batteryState = 1;
                    if (!$util.isString(message.batteryState))
                        return "batteryState: string expected";
                }
                if (message.diskHealth != null && Object.hasOwnProperty.call(message, "diskHealth")) {
                    if (!Array.isArray(message.diskHealth))
                        return "diskHealth: array expected";
                    for (let i = 0; i < message.diskHealth.length; ++i) {
                        let error = $root.enoki.v1.DiskHealthMetric.verify(message.diskHealth[i], long + 1);
                        if (error)
                            return "diskHealth." + error;
                    }
                }
                return null;
            };

            /**
             * Creates a MetricSample message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.MetricSample} MetricSample
             */
            MetricSample.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.MetricSample)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.MetricSample: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.MetricSample();
                if (object.sequence != null)
                    if ($util.Long)
                        message.sequence = $util.Long.fromValue(object.sequence, true);
                    else if (typeof object.sequence === "string")
                        message.sequence = parseInt(object.sequence, 10);
                    else if (typeof object.sequence === "number")
                        message.sequence = object.sequence;
                    else if (typeof object.sequence === "object")
                        message.sequence = new $util.LongBits(object.sequence.low >>> 0, object.sequence.high >>> 0).toNumber(true);
                if (object.collectedAtMs != null)
                    if ($util.Long)
                        message.collectedAtMs = $util.Long.fromValue(object.collectedAtMs, false);
                    else if (typeof object.collectedAtMs === "string")
                        message.collectedAtMs = parseInt(object.collectedAtMs, 10);
                    else if (typeof object.collectedAtMs === "number")
                        message.collectedAtMs = object.collectedAtMs;
                    else if (typeof object.collectedAtMs === "object")
                        message.collectedAtMs = new $util.LongBits(object.collectedAtMs.low >>> 0, object.collectedAtMs.high >>> 0).toNumber();
                if (object.cpuPercent != null)
                    message.cpuPercent = Number(object.cpuPercent);
                if (object.memoryUsedBytes != null)
                    if ($util.Long)
                        message.memoryUsedBytes = $util.Long.fromValue(object.memoryUsedBytes, true);
                    else if (typeof object.memoryUsedBytes === "string")
                        message.memoryUsedBytes = parseInt(object.memoryUsedBytes, 10);
                    else if (typeof object.memoryUsedBytes === "number")
                        message.memoryUsedBytes = object.memoryUsedBytes;
                    else if (typeof object.memoryUsedBytes === "object")
                        message.memoryUsedBytes = new $util.LongBits(object.memoryUsedBytes.low >>> 0, object.memoryUsedBytes.high >>> 0).toNumber(true);
                if (object.load_1 != null)
                    message.load_1 = Number(object.load_1);
                if (object.load_5 != null)
                    message.load_5 = Number(object.load_5);
                if (object.load_15 != null)
                    message.load_15 = Number(object.load_15);
                if (object.uptimeSeconds != null)
                    if ($util.Long)
                        message.uptimeSeconds = $util.Long.fromValue(object.uptimeSeconds, true);
                    else if (typeof object.uptimeSeconds === "string")
                        message.uptimeSeconds = parseInt(object.uptimeSeconds, 10);
                    else if (typeof object.uptimeSeconds === "number")
                        message.uptimeSeconds = object.uptimeSeconds;
                    else if (typeof object.uptimeSeconds === "object")
                        message.uptimeSeconds = new $util.LongBits(object.uptimeSeconds.low >>> 0, object.uptimeSeconds.high >>> 0).toNumber(true);
                if (object.disks) {
                    if (!Array.isArray(object.disks))
                        throw TypeError(".enoki.v1.MetricSample.disks: array expected");
                    message.disks = [];
                    for (let i = 0; i < object.disks.length; ++i) {
                        if (!$util.isObject(object.disks[i]))
                            throw TypeError(".enoki.v1.MetricSample.disks: object expected");
                        message.disks[i] = $root.enoki.v1.DiskUsageMetric.fromObject(object.disks[i], long + 1);
                    }
                }
                if (object.networkInterfaces) {
                    if (!Array.isArray(object.networkInterfaces))
                        throw TypeError(".enoki.v1.MetricSample.networkInterfaces: array expected");
                    message.networkInterfaces = [];
                    for (let i = 0; i < object.networkInterfaces.length; ++i) {
                        if (!$util.isObject(object.networkInterfaces[i]))
                            throw TypeError(".enoki.v1.MetricSample.networkInterfaces: object expected");
                        message.networkInterfaces[i] = $root.enoki.v1.NetworkInterfaceMetric.fromObject(object.networkInterfaces[i], long + 1);
                    }
                }
                if (object.cpuCores) {
                    if (!Array.isArray(object.cpuCores))
                        throw TypeError(".enoki.v1.MetricSample.cpuCores: array expected");
                    message.cpuCores = [];
                    for (let i = 0; i < object.cpuCores.length; ++i) {
                        if (!$util.isObject(object.cpuCores[i]))
                            throw TypeError(".enoki.v1.MetricSample.cpuCores: object expected");
                        message.cpuCores[i] = $root.enoki.v1.CpuCoreMetric.fromObject(object.cpuCores[i], long + 1);
                    }
                }
                if (object.memoryTotalBytes != null)
                    if ($util.Long)
                        message.memoryTotalBytes = $util.Long.fromValue(object.memoryTotalBytes, true);
                    else if (typeof object.memoryTotalBytes === "string")
                        message.memoryTotalBytes = parseInt(object.memoryTotalBytes, 10);
                    else if (typeof object.memoryTotalBytes === "number")
                        message.memoryTotalBytes = object.memoryTotalBytes;
                    else if (typeof object.memoryTotalBytes === "object")
                        message.memoryTotalBytes = new $util.LongBits(object.memoryTotalBytes.low >>> 0, object.memoryTotalBytes.high >>> 0).toNumber(true);
                if (object.cpuUserPercent != null)
                    message.cpuUserPercent = Number(object.cpuUserPercent);
                if (object.cpuSystemPercent != null)
                    message.cpuSystemPercent = Number(object.cpuSystemPercent);
                if (object.cpuIowaitPercent != null)
                    message.cpuIowaitPercent = Number(object.cpuIowaitPercent);
                if (object.cpuStealPercent != null)
                    message.cpuStealPercent = Number(object.cpuStealPercent);
                if (object.cpuIdlePercent != null)
                    message.cpuIdlePercent = Number(object.cpuIdlePercent);
                if (object.memoryCacheBytes != null)
                    if ($util.Long)
                        message.memoryCacheBytes = $util.Long.fromValue(object.memoryCacheBytes, true);
                    else if (typeof object.memoryCacheBytes === "string")
                        message.memoryCacheBytes = parseInt(object.memoryCacheBytes, 10);
                    else if (typeof object.memoryCacheBytes === "number")
                        message.memoryCacheBytes = object.memoryCacheBytes;
                    else if (typeof object.memoryCacheBytes === "object")
                        message.memoryCacheBytes = new $util.LongBits(object.memoryCacheBytes.low >>> 0, object.memoryCacheBytes.high >>> 0).toNumber(true);
                if (object.swapTotalBytes != null)
                    if ($util.Long)
                        message.swapTotalBytes = $util.Long.fromValue(object.swapTotalBytes, true);
                    else if (typeof object.swapTotalBytes === "string")
                        message.swapTotalBytes = parseInt(object.swapTotalBytes, 10);
                    else if (typeof object.swapTotalBytes === "number")
                        message.swapTotalBytes = object.swapTotalBytes;
                    else if (typeof object.swapTotalBytes === "object")
                        message.swapTotalBytes = new $util.LongBits(object.swapTotalBytes.low >>> 0, object.swapTotalBytes.high >>> 0).toNumber(true);
                if (object.swapUsedBytes != null)
                    if ($util.Long)
                        message.swapUsedBytes = $util.Long.fromValue(object.swapUsedBytes, true);
                    else if (typeof object.swapUsedBytes === "string")
                        message.swapUsedBytes = parseInt(object.swapUsedBytes, 10);
                    else if (typeof object.swapUsedBytes === "number")
                        message.swapUsedBytes = object.swapUsedBytes;
                    else if (typeof object.swapUsedBytes === "object")
                        message.swapUsedBytes = new $util.LongBits(object.swapUsedBytes.low >>> 0, object.swapUsedBytes.high >>> 0).toNumber(true);
                if (object.temperatureCelsius != null)
                    message.temperatureCelsius = Number(object.temperatureCelsius);
                if (object.batteryPercent != null)
                    message.batteryPercent = object.batteryPercent >>> 0;
                if (object.batteryState != null)
                    message.batteryState = String(object.batteryState);
                if (object.diskHealth) {
                    if (!Array.isArray(object.diskHealth))
                        throw TypeError(".enoki.v1.MetricSample.diskHealth: array expected");
                    message.diskHealth = [];
                    for (let i = 0; i < object.diskHealth.length; ++i) {
                        if (!$util.isObject(object.diskHealth[i]))
                            throw TypeError(".enoki.v1.MetricSample.diskHealth: object expected");
                        message.diskHealth[i] = $root.enoki.v1.DiskHealthMetric.fromObject(object.diskHealth[i], long + 1);
                    }
                }
                return message;
            };

            /**
             * Creates a plain object from a MetricSample message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {enoki.v1.MetricSample} message MetricSample
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            MetricSample.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.arrays || options.defaults) {
                    object.disks = [];
                    object.networkInterfaces = [];
                    object.cpuCores = [];
                    object.diskHealth = [];
                }
                if (options.defaults) {
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.sequence = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.sequence = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, false);
                        object.collectedAtMs = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.collectedAtMs = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                }
                if (message.sequence != null && Object.hasOwnProperty.call(message, "sequence"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.sequence = typeof message.sequence === "number" ? BigInt(message.sequence) : $util.Long.fromBits(message.sequence.low >>> 0, message.sequence.high >>> 0, true).toBigInt();
                    else if (typeof message.sequence === "number")
                        object.sequence = options.longs === String ? String(message.sequence) : message.sequence;
                    else
                        object.sequence = options.longs === String ? $util.Long.prototype.toString.call(message.sequence) : options.longs === Number ? new $util.LongBits(message.sequence.low >>> 0, message.sequence.high >>> 0).toNumber(true) : message.sequence;
                if (message.collectedAtMs != null && Object.hasOwnProperty.call(message, "collectedAtMs"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.collectedAtMs = typeof message.collectedAtMs === "number" ? BigInt(message.collectedAtMs) : $util.Long.fromBits(message.collectedAtMs.low >>> 0, message.collectedAtMs.high >>> 0, false).toBigInt();
                    else if (typeof message.collectedAtMs === "number")
                        object.collectedAtMs = options.longs === String ? String(message.collectedAtMs) : message.collectedAtMs;
                    else
                        object.collectedAtMs = options.longs === String ? $util.Long.prototype.toString.call(message.collectedAtMs) : options.longs === Number ? new $util.LongBits(message.collectedAtMs.low >>> 0, message.collectedAtMs.high >>> 0).toNumber() : message.collectedAtMs;
                if (message.cpuPercent != null && Object.hasOwnProperty.call(message, "cpuPercent")) {
                    object.cpuPercent = options.json && !isFinite(message.cpuPercent) ? String(message.cpuPercent) : message.cpuPercent;
                    if (options.oneofs)
                        object._cpuPercent = "cpuPercent";
                }
                if (message.memoryUsedBytes != null && Object.hasOwnProperty.call(message, "memoryUsedBytes")) {
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.memoryUsedBytes = typeof message.memoryUsedBytes === "number" ? BigInt(message.memoryUsedBytes) : $util.Long.fromBits(message.memoryUsedBytes.low >>> 0, message.memoryUsedBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.memoryUsedBytes === "number")
                        object.memoryUsedBytes = options.longs === String ? String(message.memoryUsedBytes) : message.memoryUsedBytes;
                    else
                        object.memoryUsedBytes = options.longs === String ? $util.Long.prototype.toString.call(message.memoryUsedBytes) : options.longs === Number ? new $util.LongBits(message.memoryUsedBytes.low >>> 0, message.memoryUsedBytes.high >>> 0).toNumber(true) : message.memoryUsedBytes;
                    if (options.oneofs)
                        object._memoryUsedBytes = "memoryUsedBytes";
                }
                if (message.load_1 != null && Object.hasOwnProperty.call(message, "load_1")) {
                    object.load_1 = options.json && !isFinite(message.load_1) ? String(message.load_1) : message.load_1;
                    if (options.oneofs)
                        object._load_1 = "load_1";
                }
                if (message.load_5 != null && Object.hasOwnProperty.call(message, "load_5")) {
                    object.load_5 = options.json && !isFinite(message.load_5) ? String(message.load_5) : message.load_5;
                    if (options.oneofs)
                        object._load_5 = "load_5";
                }
                if (message.load_15 != null && Object.hasOwnProperty.call(message, "load_15")) {
                    object.load_15 = options.json && !isFinite(message.load_15) ? String(message.load_15) : message.load_15;
                    if (options.oneofs)
                        object._load_15 = "load_15";
                }
                if (message.uptimeSeconds != null && Object.hasOwnProperty.call(message, "uptimeSeconds")) {
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.uptimeSeconds = typeof message.uptimeSeconds === "number" ? BigInt(message.uptimeSeconds) : $util.Long.fromBits(message.uptimeSeconds.low >>> 0, message.uptimeSeconds.high >>> 0, true).toBigInt();
                    else if (typeof message.uptimeSeconds === "number")
                        object.uptimeSeconds = options.longs === String ? String(message.uptimeSeconds) : message.uptimeSeconds;
                    else
                        object.uptimeSeconds = options.longs === String ? $util.Long.prototype.toString.call(message.uptimeSeconds) : options.longs === Number ? new $util.LongBits(message.uptimeSeconds.low >>> 0, message.uptimeSeconds.high >>> 0).toNumber(true) : message.uptimeSeconds;
                    if (options.oneofs)
                        object._uptimeSeconds = "uptimeSeconds";
                }
                if (message.disks && message.disks.length) {
                    object.disks = [];
                    for (let j = 0; j < message.disks.length; ++j)
                        object.disks[j] = $root.enoki.v1.DiskUsageMetric.toObject(message.disks[j], options, q + 1);
                }
                if (message.networkInterfaces && message.networkInterfaces.length) {
                    object.networkInterfaces = [];
                    for (let j = 0; j < message.networkInterfaces.length; ++j)
                        object.networkInterfaces[j] = $root.enoki.v1.NetworkInterfaceMetric.toObject(message.networkInterfaces[j], options, q + 1);
                }
                if (message.cpuCores && message.cpuCores.length) {
                    object.cpuCores = [];
                    for (let j = 0; j < message.cpuCores.length; ++j)
                        object.cpuCores[j] = $root.enoki.v1.CpuCoreMetric.toObject(message.cpuCores[j], options, q + 1);
                }
                if (message.memoryTotalBytes != null && Object.hasOwnProperty.call(message, "memoryTotalBytes")) {
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.memoryTotalBytes = typeof message.memoryTotalBytes === "number" ? BigInt(message.memoryTotalBytes) : $util.Long.fromBits(message.memoryTotalBytes.low >>> 0, message.memoryTotalBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.memoryTotalBytes === "number")
                        object.memoryTotalBytes = options.longs === String ? String(message.memoryTotalBytes) : message.memoryTotalBytes;
                    else
                        object.memoryTotalBytes = options.longs === String ? $util.Long.prototype.toString.call(message.memoryTotalBytes) : options.longs === Number ? new $util.LongBits(message.memoryTotalBytes.low >>> 0, message.memoryTotalBytes.high >>> 0).toNumber(true) : message.memoryTotalBytes;
                    if (options.oneofs)
                        object._memoryTotalBytes = "memoryTotalBytes";
                }
                if (message.cpuUserPercent != null && Object.hasOwnProperty.call(message, "cpuUserPercent")) {
                    object.cpuUserPercent = options.json && !isFinite(message.cpuUserPercent) ? String(message.cpuUserPercent) : message.cpuUserPercent;
                    if (options.oneofs)
                        object._cpuUserPercent = "cpuUserPercent";
                }
                if (message.cpuSystemPercent != null && Object.hasOwnProperty.call(message, "cpuSystemPercent")) {
                    object.cpuSystemPercent = options.json && !isFinite(message.cpuSystemPercent) ? String(message.cpuSystemPercent) : message.cpuSystemPercent;
                    if (options.oneofs)
                        object._cpuSystemPercent = "cpuSystemPercent";
                }
                if (message.cpuIowaitPercent != null && Object.hasOwnProperty.call(message, "cpuIowaitPercent")) {
                    object.cpuIowaitPercent = options.json && !isFinite(message.cpuIowaitPercent) ? String(message.cpuIowaitPercent) : message.cpuIowaitPercent;
                    if (options.oneofs)
                        object._cpuIowaitPercent = "cpuIowaitPercent";
                }
                if (message.cpuStealPercent != null && Object.hasOwnProperty.call(message, "cpuStealPercent")) {
                    object.cpuStealPercent = options.json && !isFinite(message.cpuStealPercent) ? String(message.cpuStealPercent) : message.cpuStealPercent;
                    if (options.oneofs)
                        object._cpuStealPercent = "cpuStealPercent";
                }
                if (message.cpuIdlePercent != null && Object.hasOwnProperty.call(message, "cpuIdlePercent")) {
                    object.cpuIdlePercent = options.json && !isFinite(message.cpuIdlePercent) ? String(message.cpuIdlePercent) : message.cpuIdlePercent;
                    if (options.oneofs)
                        object._cpuIdlePercent = "cpuIdlePercent";
                }
                if (message.memoryCacheBytes != null && Object.hasOwnProperty.call(message, "memoryCacheBytes")) {
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.memoryCacheBytes = typeof message.memoryCacheBytes === "number" ? BigInt(message.memoryCacheBytes) : $util.Long.fromBits(message.memoryCacheBytes.low >>> 0, message.memoryCacheBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.memoryCacheBytes === "number")
                        object.memoryCacheBytes = options.longs === String ? String(message.memoryCacheBytes) : message.memoryCacheBytes;
                    else
                        object.memoryCacheBytes = options.longs === String ? $util.Long.prototype.toString.call(message.memoryCacheBytes) : options.longs === Number ? new $util.LongBits(message.memoryCacheBytes.low >>> 0, message.memoryCacheBytes.high >>> 0).toNumber(true) : message.memoryCacheBytes;
                    if (options.oneofs)
                        object._memoryCacheBytes = "memoryCacheBytes";
                }
                if (message.swapTotalBytes != null && Object.hasOwnProperty.call(message, "swapTotalBytes")) {
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.swapTotalBytes = typeof message.swapTotalBytes === "number" ? BigInt(message.swapTotalBytes) : $util.Long.fromBits(message.swapTotalBytes.low >>> 0, message.swapTotalBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.swapTotalBytes === "number")
                        object.swapTotalBytes = options.longs === String ? String(message.swapTotalBytes) : message.swapTotalBytes;
                    else
                        object.swapTotalBytes = options.longs === String ? $util.Long.prototype.toString.call(message.swapTotalBytes) : options.longs === Number ? new $util.LongBits(message.swapTotalBytes.low >>> 0, message.swapTotalBytes.high >>> 0).toNumber(true) : message.swapTotalBytes;
                    if (options.oneofs)
                        object._swapTotalBytes = "swapTotalBytes";
                }
                if (message.swapUsedBytes != null && Object.hasOwnProperty.call(message, "swapUsedBytes")) {
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.swapUsedBytes = typeof message.swapUsedBytes === "number" ? BigInt(message.swapUsedBytes) : $util.Long.fromBits(message.swapUsedBytes.low >>> 0, message.swapUsedBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.swapUsedBytes === "number")
                        object.swapUsedBytes = options.longs === String ? String(message.swapUsedBytes) : message.swapUsedBytes;
                    else
                        object.swapUsedBytes = options.longs === String ? $util.Long.prototype.toString.call(message.swapUsedBytes) : options.longs === Number ? new $util.LongBits(message.swapUsedBytes.low >>> 0, message.swapUsedBytes.high >>> 0).toNumber(true) : message.swapUsedBytes;
                    if (options.oneofs)
                        object._swapUsedBytes = "swapUsedBytes";
                }
                if (message.temperatureCelsius != null && Object.hasOwnProperty.call(message, "temperatureCelsius")) {
                    object.temperatureCelsius = options.json && !isFinite(message.temperatureCelsius) ? String(message.temperatureCelsius) : message.temperatureCelsius;
                    if (options.oneofs)
                        object._temperatureCelsius = "temperatureCelsius";
                }
                if (message.batteryPercent != null && Object.hasOwnProperty.call(message, "batteryPercent")) {
                    object.batteryPercent = message.batteryPercent;
                    if (options.oneofs)
                        object._batteryPercent = "batteryPercent";
                }
                if (message.batteryState != null && Object.hasOwnProperty.call(message, "batteryState")) {
                    object.batteryState = message.batteryState;
                    if (options.oneofs)
                        object._batteryState = "batteryState";
                }
                if (message.diskHealth && message.diskHealth.length) {
                    object.diskHealth = [];
                    for (let j = 0; j < message.diskHealth.length; ++j)
                        object.diskHealth[j] = $root.enoki.v1.DiskHealthMetric.toObject(message.diskHealth[j], options, q + 1);
                }
                return object;
            };

            /**
             * Converts this MetricSample to JSON.
             * @function toJSON
             * @memberof enoki.v1.MetricSample
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            MetricSample.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for MetricSample
             * @function getTypeUrl
             * @memberof enoki.v1.MetricSample
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            MetricSample.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.MetricSample";
            };

            return MetricSample;
        })();

        v1.CpuCoreMetric = (function() {

            /**
             * Properties of a CpuCoreMetric.
             * @memberof enoki.v1
             * @interface ICpuCoreMetric
             * @property {string|null} [name] CpuCoreMetric name
             * @property {Long|null} [user] CpuCoreMetric user
             * @property {Long|null} [nice] CpuCoreMetric nice
             * @property {Long|null} [system] CpuCoreMetric system
             * @property {Long|null} [idle] CpuCoreMetric idle
             * @property {Long|null} [iowait] CpuCoreMetric iowait
             * @property {Long|null} [irq] CpuCoreMetric irq
             * @property {Long|null} [softirq] CpuCoreMetric softirq
             * @property {Long|null} [steal] CpuCoreMetric steal
             * @property {number|null} [usagePercent] CpuCoreMetric usagePercent
             */

            /**
             * Constructs a new CpuCoreMetric.
             * @memberof enoki.v1
             * @classdesc Represents a CpuCoreMetric.
             * @implements ICpuCoreMetric
             * @constructor
             * @param {enoki.v1.ICpuCoreMetric=} [properties] Properties to set
             */
            function CpuCoreMetric(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * CpuCoreMetric name.
             * @member {string} name
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.name = "";

            /**
             * CpuCoreMetric user.
             * @member {Long} user
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.user = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * CpuCoreMetric nice.
             * @member {Long} nice
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.nice = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * CpuCoreMetric system.
             * @member {Long} system
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.system = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * CpuCoreMetric idle.
             * @member {Long} idle
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.idle = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * CpuCoreMetric iowait.
             * @member {Long} iowait
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.iowait = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * CpuCoreMetric irq.
             * @member {Long} irq
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.irq = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * CpuCoreMetric softirq.
             * @member {Long} softirq
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.softirq = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * CpuCoreMetric steal.
             * @member {Long} steal
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.steal = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * CpuCoreMetric usagePercent.
             * @member {number} usagePercent
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             */
            CpuCoreMetric.prototype.usagePercent = 0;

            /**
             * Creates a new CpuCoreMetric instance using the specified properties.
             * @function create
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {enoki.v1.ICpuCoreMetric=} [properties] Properties to set
             * @returns {enoki.v1.CpuCoreMetric} CpuCoreMetric instance
             */
            CpuCoreMetric.create = function create(properties) {
                return new CpuCoreMetric(properties);
            };

            /**
             * Encodes the specified CpuCoreMetric message. Does not implicitly {@link enoki.v1.CpuCoreMetric.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {enoki.v1.ICpuCoreMetric} message CpuCoreMetric message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            CpuCoreMetric.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.name);
                if (message.user != null && Object.hasOwnProperty.call(message, "user"))
                    writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.user);
                if (message.nice != null && Object.hasOwnProperty.call(message, "nice"))
                    writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.nice);
                if (message.system != null && Object.hasOwnProperty.call(message, "system"))
                    writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.system);
                if (message.idle != null && Object.hasOwnProperty.call(message, "idle"))
                    writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.idle);
                if (message.iowait != null && Object.hasOwnProperty.call(message, "iowait"))
                    writer.uint32(/* id 6, wireType 0 =*/48).uint64(message.iowait);
                if (message.irq != null && Object.hasOwnProperty.call(message, "irq"))
                    writer.uint32(/* id 7, wireType 0 =*/56).uint64(message.irq);
                if (message.softirq != null && Object.hasOwnProperty.call(message, "softirq"))
                    writer.uint32(/* id 8, wireType 0 =*/64).uint64(message.softirq);
                if (message.steal != null && Object.hasOwnProperty.call(message, "steal"))
                    writer.uint32(/* id 9, wireType 0 =*/72).uint64(message.steal);
                if (message.usagePercent != null && Object.hasOwnProperty.call(message, "usagePercent"))
                    writer.uint32(/* id 10, wireType 1 =*/81).double(message.usagePercent);
                return writer;
            };

            /**
             * Encodes the specified CpuCoreMetric message, length delimited. Does not implicitly {@link enoki.v1.CpuCoreMetric.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {enoki.v1.ICpuCoreMetric} message CpuCoreMetric message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            CpuCoreMetric.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a CpuCoreMetric message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.CpuCoreMetric} CpuCoreMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            CpuCoreMetric.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.CpuCoreMetric();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.name = reader.string();
                            break;
                        }
                    case 2: {
                            message.user = reader.uint64();
                            break;
                        }
                    case 3: {
                            message.nice = reader.uint64();
                            break;
                        }
                    case 4: {
                            message.system = reader.uint64();
                            break;
                        }
                    case 5: {
                            message.idle = reader.uint64();
                            break;
                        }
                    case 6: {
                            message.iowait = reader.uint64();
                            break;
                        }
                    case 7: {
                            message.irq = reader.uint64();
                            break;
                        }
                    case 8: {
                            message.softirq = reader.uint64();
                            break;
                        }
                    case 9: {
                            message.steal = reader.uint64();
                            break;
                        }
                    case 10: {
                            message.usagePercent = reader.double();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a CpuCoreMetric message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.CpuCoreMetric} CpuCoreMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            CpuCoreMetric.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a CpuCoreMetric message.
             * @function verify
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            CpuCoreMetric.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    if (!$util.isString(message.name))
                        return "name: string expected";
                if (message.user != null && Object.hasOwnProperty.call(message, "user"))
                    if (!$util.isInteger(message.user) && !(message.user && $util.isInteger(message.user.low) && $util.isInteger(message.user.high)))
                        return "user: integer|Long expected";
                if (message.nice != null && Object.hasOwnProperty.call(message, "nice"))
                    if (!$util.isInteger(message.nice) && !(message.nice && $util.isInteger(message.nice.low) && $util.isInteger(message.nice.high)))
                        return "nice: integer|Long expected";
                if (message.system != null && Object.hasOwnProperty.call(message, "system"))
                    if (!$util.isInteger(message.system) && !(message.system && $util.isInteger(message.system.low) && $util.isInteger(message.system.high)))
                        return "system: integer|Long expected";
                if (message.idle != null && Object.hasOwnProperty.call(message, "idle"))
                    if (!$util.isInteger(message.idle) && !(message.idle && $util.isInteger(message.idle.low) && $util.isInteger(message.idle.high)))
                        return "idle: integer|Long expected";
                if (message.iowait != null && Object.hasOwnProperty.call(message, "iowait"))
                    if (!$util.isInteger(message.iowait) && !(message.iowait && $util.isInteger(message.iowait.low) && $util.isInteger(message.iowait.high)))
                        return "iowait: integer|Long expected";
                if (message.irq != null && Object.hasOwnProperty.call(message, "irq"))
                    if (!$util.isInteger(message.irq) && !(message.irq && $util.isInteger(message.irq.low) && $util.isInteger(message.irq.high)))
                        return "irq: integer|Long expected";
                if (message.softirq != null && Object.hasOwnProperty.call(message, "softirq"))
                    if (!$util.isInteger(message.softirq) && !(message.softirq && $util.isInteger(message.softirq.low) && $util.isInteger(message.softirq.high)))
                        return "softirq: integer|Long expected";
                if (message.steal != null && Object.hasOwnProperty.call(message, "steal"))
                    if (!$util.isInteger(message.steal) && !(message.steal && $util.isInteger(message.steal.low) && $util.isInteger(message.steal.high)))
                        return "steal: integer|Long expected";
                if (message.usagePercent != null && Object.hasOwnProperty.call(message, "usagePercent"))
                    if (typeof message.usagePercent !== "number")
                        return "usagePercent: number expected";
                return null;
            };

            /**
             * Creates a CpuCoreMetric message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.CpuCoreMetric} CpuCoreMetric
             */
            CpuCoreMetric.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.CpuCoreMetric)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.CpuCoreMetric: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.CpuCoreMetric();
                if (object.name != null)
                    message.name = String(object.name);
                if (object.user != null)
                    if ($util.Long)
                        message.user = $util.Long.fromValue(object.user, true);
                    else if (typeof object.user === "string")
                        message.user = parseInt(object.user, 10);
                    else if (typeof object.user === "number")
                        message.user = object.user;
                    else if (typeof object.user === "object")
                        message.user = new $util.LongBits(object.user.low >>> 0, object.user.high >>> 0).toNumber(true);
                if (object.nice != null)
                    if ($util.Long)
                        message.nice = $util.Long.fromValue(object.nice, true);
                    else if (typeof object.nice === "string")
                        message.nice = parseInt(object.nice, 10);
                    else if (typeof object.nice === "number")
                        message.nice = object.nice;
                    else if (typeof object.nice === "object")
                        message.nice = new $util.LongBits(object.nice.low >>> 0, object.nice.high >>> 0).toNumber(true);
                if (object.system != null)
                    if ($util.Long)
                        message.system = $util.Long.fromValue(object.system, true);
                    else if (typeof object.system === "string")
                        message.system = parseInt(object.system, 10);
                    else if (typeof object.system === "number")
                        message.system = object.system;
                    else if (typeof object.system === "object")
                        message.system = new $util.LongBits(object.system.low >>> 0, object.system.high >>> 0).toNumber(true);
                if (object.idle != null)
                    if ($util.Long)
                        message.idle = $util.Long.fromValue(object.idle, true);
                    else if (typeof object.idle === "string")
                        message.idle = parseInt(object.idle, 10);
                    else if (typeof object.idle === "number")
                        message.idle = object.idle;
                    else if (typeof object.idle === "object")
                        message.idle = new $util.LongBits(object.idle.low >>> 0, object.idle.high >>> 0).toNumber(true);
                if (object.iowait != null)
                    if ($util.Long)
                        message.iowait = $util.Long.fromValue(object.iowait, true);
                    else if (typeof object.iowait === "string")
                        message.iowait = parseInt(object.iowait, 10);
                    else if (typeof object.iowait === "number")
                        message.iowait = object.iowait;
                    else if (typeof object.iowait === "object")
                        message.iowait = new $util.LongBits(object.iowait.low >>> 0, object.iowait.high >>> 0).toNumber(true);
                if (object.irq != null)
                    if ($util.Long)
                        message.irq = $util.Long.fromValue(object.irq, true);
                    else if (typeof object.irq === "string")
                        message.irq = parseInt(object.irq, 10);
                    else if (typeof object.irq === "number")
                        message.irq = object.irq;
                    else if (typeof object.irq === "object")
                        message.irq = new $util.LongBits(object.irq.low >>> 0, object.irq.high >>> 0).toNumber(true);
                if (object.softirq != null)
                    if ($util.Long)
                        message.softirq = $util.Long.fromValue(object.softirq, true);
                    else if (typeof object.softirq === "string")
                        message.softirq = parseInt(object.softirq, 10);
                    else if (typeof object.softirq === "number")
                        message.softirq = object.softirq;
                    else if (typeof object.softirq === "object")
                        message.softirq = new $util.LongBits(object.softirq.low >>> 0, object.softirq.high >>> 0).toNumber(true);
                if (object.steal != null)
                    if ($util.Long)
                        message.steal = $util.Long.fromValue(object.steal, true);
                    else if (typeof object.steal === "string")
                        message.steal = parseInt(object.steal, 10);
                    else if (typeof object.steal === "number")
                        message.steal = object.steal;
                    else if (typeof object.steal === "object")
                        message.steal = new $util.LongBits(object.steal.low >>> 0, object.steal.high >>> 0).toNumber(true);
                if (object.usagePercent != null)
                    message.usagePercent = Number(object.usagePercent);
                return message;
            };

            /**
             * Creates a plain object from a CpuCoreMetric message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {enoki.v1.CpuCoreMetric} message CpuCoreMetric
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            CpuCoreMetric.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.name = "";
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.user = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.user = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.nice = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.nice = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.system = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.system = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.idle = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.idle = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.iowait = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.iowait = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.irq = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.irq = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.softirq = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.softirq = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.steal = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.steal = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    object.usagePercent = 0;
                }
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    object.name = message.name;
                if (message.user != null && Object.hasOwnProperty.call(message, "user"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.user = typeof message.user === "number" ? BigInt(message.user) : $util.Long.fromBits(message.user.low >>> 0, message.user.high >>> 0, true).toBigInt();
                    else if (typeof message.user === "number")
                        object.user = options.longs === String ? String(message.user) : message.user;
                    else
                        object.user = options.longs === String ? $util.Long.prototype.toString.call(message.user) : options.longs === Number ? new $util.LongBits(message.user.low >>> 0, message.user.high >>> 0).toNumber(true) : message.user;
                if (message.nice != null && Object.hasOwnProperty.call(message, "nice"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.nice = typeof message.nice === "number" ? BigInt(message.nice) : $util.Long.fromBits(message.nice.low >>> 0, message.nice.high >>> 0, true).toBigInt();
                    else if (typeof message.nice === "number")
                        object.nice = options.longs === String ? String(message.nice) : message.nice;
                    else
                        object.nice = options.longs === String ? $util.Long.prototype.toString.call(message.nice) : options.longs === Number ? new $util.LongBits(message.nice.low >>> 0, message.nice.high >>> 0).toNumber(true) : message.nice;
                if (message.system != null && Object.hasOwnProperty.call(message, "system"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.system = typeof message.system === "number" ? BigInt(message.system) : $util.Long.fromBits(message.system.low >>> 0, message.system.high >>> 0, true).toBigInt();
                    else if (typeof message.system === "number")
                        object.system = options.longs === String ? String(message.system) : message.system;
                    else
                        object.system = options.longs === String ? $util.Long.prototype.toString.call(message.system) : options.longs === Number ? new $util.LongBits(message.system.low >>> 0, message.system.high >>> 0).toNumber(true) : message.system;
                if (message.idle != null && Object.hasOwnProperty.call(message, "idle"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.idle = typeof message.idle === "number" ? BigInt(message.idle) : $util.Long.fromBits(message.idle.low >>> 0, message.idle.high >>> 0, true).toBigInt();
                    else if (typeof message.idle === "number")
                        object.idle = options.longs === String ? String(message.idle) : message.idle;
                    else
                        object.idle = options.longs === String ? $util.Long.prototype.toString.call(message.idle) : options.longs === Number ? new $util.LongBits(message.idle.low >>> 0, message.idle.high >>> 0).toNumber(true) : message.idle;
                if (message.iowait != null && Object.hasOwnProperty.call(message, "iowait"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.iowait = typeof message.iowait === "number" ? BigInt(message.iowait) : $util.Long.fromBits(message.iowait.low >>> 0, message.iowait.high >>> 0, true).toBigInt();
                    else if (typeof message.iowait === "number")
                        object.iowait = options.longs === String ? String(message.iowait) : message.iowait;
                    else
                        object.iowait = options.longs === String ? $util.Long.prototype.toString.call(message.iowait) : options.longs === Number ? new $util.LongBits(message.iowait.low >>> 0, message.iowait.high >>> 0).toNumber(true) : message.iowait;
                if (message.irq != null && Object.hasOwnProperty.call(message, "irq"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.irq = typeof message.irq === "number" ? BigInt(message.irq) : $util.Long.fromBits(message.irq.low >>> 0, message.irq.high >>> 0, true).toBigInt();
                    else if (typeof message.irq === "number")
                        object.irq = options.longs === String ? String(message.irq) : message.irq;
                    else
                        object.irq = options.longs === String ? $util.Long.prototype.toString.call(message.irq) : options.longs === Number ? new $util.LongBits(message.irq.low >>> 0, message.irq.high >>> 0).toNumber(true) : message.irq;
                if (message.softirq != null && Object.hasOwnProperty.call(message, "softirq"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.softirq = typeof message.softirq === "number" ? BigInt(message.softirq) : $util.Long.fromBits(message.softirq.low >>> 0, message.softirq.high >>> 0, true).toBigInt();
                    else if (typeof message.softirq === "number")
                        object.softirq = options.longs === String ? String(message.softirq) : message.softirq;
                    else
                        object.softirq = options.longs === String ? $util.Long.prototype.toString.call(message.softirq) : options.longs === Number ? new $util.LongBits(message.softirq.low >>> 0, message.softirq.high >>> 0).toNumber(true) : message.softirq;
                if (message.steal != null && Object.hasOwnProperty.call(message, "steal"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.steal = typeof message.steal === "number" ? BigInt(message.steal) : $util.Long.fromBits(message.steal.low >>> 0, message.steal.high >>> 0, true).toBigInt();
                    else if (typeof message.steal === "number")
                        object.steal = options.longs === String ? String(message.steal) : message.steal;
                    else
                        object.steal = options.longs === String ? $util.Long.prototype.toString.call(message.steal) : options.longs === Number ? new $util.LongBits(message.steal.low >>> 0, message.steal.high >>> 0).toNumber(true) : message.steal;
                if (message.usagePercent != null && Object.hasOwnProperty.call(message, "usagePercent"))
                    object.usagePercent = options.json && !isFinite(message.usagePercent) ? String(message.usagePercent) : message.usagePercent;
                return object;
            };

            /**
             * Converts this CpuCoreMetric to JSON.
             * @function toJSON
             * @memberof enoki.v1.CpuCoreMetric
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            CpuCoreMetric.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for CpuCoreMetric
             * @function getTypeUrl
             * @memberof enoki.v1.CpuCoreMetric
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            CpuCoreMetric.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.CpuCoreMetric";
            };

            return CpuCoreMetric;
        })();

        v1.DiskUsageMetric = (function() {

            /**
             * Properties of a DiskUsageMetric.
             * @memberof enoki.v1
             * @interface IDiskUsageMetric
             * @property {string|null} [mountPoint] DiskUsageMetric mountPoint
             * @property {string|null} [filesystemType] DiskUsageMetric filesystemType
             * @property {Long|null} [totalBytes] DiskUsageMetric totalBytes
             * @property {Long|null} [usedBytes] DiskUsageMetric usedBytes
             * @property {Long|null} [availableBytes] DiskUsageMetric availableBytes
             * @property {Long|null} [readBytesDelta] DiskUsageMetric readBytesDelta
             * @property {Long|null} [writeBytesDelta] DiskUsageMetric writeBytesDelta
             * @property {number|null} [ioUtilizationPercent] DiskUsageMetric ioUtilizationPercent
             * @property {number|null} [readAwaitMs] DiskUsageMetric readAwaitMs
             * @property {number|null} [writeAwaitMs] DiskUsageMetric writeAwaitMs
             * @property {number|null} [weightedIoPercent] DiskUsageMetric weightedIoPercent
             */

            /**
             * Constructs a new DiskUsageMetric.
             * @memberof enoki.v1
             * @classdesc Represents a DiskUsageMetric.
             * @implements IDiskUsageMetric
             * @constructor
             * @param {enoki.v1.IDiskUsageMetric=} [properties] Properties to set
             */
            function DiskUsageMetric(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * DiskUsageMetric mountPoint.
             * @member {string} mountPoint
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.mountPoint = "";

            /**
             * DiskUsageMetric filesystemType.
             * @member {string} filesystemType
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.filesystemType = "";

            /**
             * DiskUsageMetric totalBytes.
             * @member {Long} totalBytes
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.totalBytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * DiskUsageMetric usedBytes.
             * @member {Long} usedBytes
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.usedBytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * DiskUsageMetric availableBytes.
             * @member {Long} availableBytes
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.availableBytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * DiskUsageMetric readBytesDelta.
             * @member {Long} readBytesDelta
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.readBytesDelta = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * DiskUsageMetric writeBytesDelta.
             * @member {Long} writeBytesDelta
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.writeBytesDelta = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * DiskUsageMetric ioUtilizationPercent.
             * @member {number|null|undefined} ioUtilizationPercent
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.ioUtilizationPercent = null;

            /**
             * DiskUsageMetric readAwaitMs.
             * @member {number|null|undefined} readAwaitMs
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.readAwaitMs = null;

            /**
             * DiskUsageMetric writeAwaitMs.
             * @member {number|null|undefined} writeAwaitMs
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.writeAwaitMs = null;

            /**
             * DiskUsageMetric weightedIoPercent.
             * @member {number|null|undefined} weightedIoPercent
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             */
            DiskUsageMetric.prototype.weightedIoPercent = null;

            // OneOf field names bound to virtual getters and setters
            let $oneOfFields;

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(DiskUsageMetric.prototype, "_ioUtilizationPercent", {
                get: $util.oneOfGetter($oneOfFields = ["ioUtilizationPercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(DiskUsageMetric.prototype, "_readAwaitMs", {
                get: $util.oneOfGetter($oneOfFields = ["readAwaitMs"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(DiskUsageMetric.prototype, "_writeAwaitMs", {
                get: $util.oneOfGetter($oneOfFields = ["writeAwaitMs"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(DiskUsageMetric.prototype, "_weightedIoPercent", {
                get: $util.oneOfGetter($oneOfFields = ["weightedIoPercent"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            /**
             * Creates a new DiskUsageMetric instance using the specified properties.
             * @function create
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {enoki.v1.IDiskUsageMetric=} [properties] Properties to set
             * @returns {enoki.v1.DiskUsageMetric} DiskUsageMetric instance
             */
            DiskUsageMetric.create = function create(properties) {
                return new DiskUsageMetric(properties);
            };

            /**
             * Encodes the specified DiskUsageMetric message. Does not implicitly {@link enoki.v1.DiskUsageMetric.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {enoki.v1.IDiskUsageMetric} message DiskUsageMetric message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            DiskUsageMetric.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.mountPoint != null && Object.hasOwnProperty.call(message, "mountPoint"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.mountPoint);
                if (message.filesystemType != null && Object.hasOwnProperty.call(message, "filesystemType"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.filesystemType);
                if (message.totalBytes != null && Object.hasOwnProperty.call(message, "totalBytes"))
                    writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.totalBytes);
                if (message.usedBytes != null && Object.hasOwnProperty.call(message, "usedBytes"))
                    writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.usedBytes);
                if (message.availableBytes != null && Object.hasOwnProperty.call(message, "availableBytes"))
                    writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.availableBytes);
                if (message.readBytesDelta != null && Object.hasOwnProperty.call(message, "readBytesDelta"))
                    writer.uint32(/* id 6, wireType 0 =*/48).uint64(message.readBytesDelta);
                if (message.writeBytesDelta != null && Object.hasOwnProperty.call(message, "writeBytesDelta"))
                    writer.uint32(/* id 7, wireType 0 =*/56).uint64(message.writeBytesDelta);
                if (message.ioUtilizationPercent != null && Object.hasOwnProperty.call(message, "ioUtilizationPercent"))
                    writer.uint32(/* id 8, wireType 1 =*/65).double(message.ioUtilizationPercent);
                if (message.readAwaitMs != null && Object.hasOwnProperty.call(message, "readAwaitMs"))
                    writer.uint32(/* id 9, wireType 1 =*/73).double(message.readAwaitMs);
                if (message.writeAwaitMs != null && Object.hasOwnProperty.call(message, "writeAwaitMs"))
                    writer.uint32(/* id 10, wireType 1 =*/81).double(message.writeAwaitMs);
                if (message.weightedIoPercent != null && Object.hasOwnProperty.call(message, "weightedIoPercent"))
                    writer.uint32(/* id 11, wireType 1 =*/89).double(message.weightedIoPercent);
                return writer;
            };

            /**
             * Encodes the specified DiskUsageMetric message, length delimited. Does not implicitly {@link enoki.v1.DiskUsageMetric.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {enoki.v1.IDiskUsageMetric} message DiskUsageMetric message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            DiskUsageMetric.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a DiskUsageMetric message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.DiskUsageMetric} DiskUsageMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            DiskUsageMetric.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.DiskUsageMetric();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.mountPoint = reader.string();
                            break;
                        }
                    case 2: {
                            message.filesystemType = reader.string();
                            break;
                        }
                    case 3: {
                            message.totalBytes = reader.uint64();
                            break;
                        }
                    case 4: {
                            message.usedBytes = reader.uint64();
                            break;
                        }
                    case 5: {
                            message.availableBytes = reader.uint64();
                            break;
                        }
                    case 6: {
                            message.readBytesDelta = reader.uint64();
                            break;
                        }
                    case 7: {
                            message.writeBytesDelta = reader.uint64();
                            break;
                        }
                    case 8: {
                            message.ioUtilizationPercent = reader.double();
                            break;
                        }
                    case 9: {
                            message.readAwaitMs = reader.double();
                            break;
                        }
                    case 10: {
                            message.writeAwaitMs = reader.double();
                            break;
                        }
                    case 11: {
                            message.weightedIoPercent = reader.double();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a DiskUsageMetric message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.DiskUsageMetric} DiskUsageMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            DiskUsageMetric.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a DiskUsageMetric message.
             * @function verify
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            DiskUsageMetric.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                let properties = {};
                if (message.mountPoint != null && Object.hasOwnProperty.call(message, "mountPoint"))
                    if (!$util.isString(message.mountPoint))
                        return "mountPoint: string expected";
                if (message.filesystemType != null && Object.hasOwnProperty.call(message, "filesystemType"))
                    if (!$util.isString(message.filesystemType))
                        return "filesystemType: string expected";
                if (message.totalBytes != null && Object.hasOwnProperty.call(message, "totalBytes"))
                    if (!$util.isInteger(message.totalBytes) && !(message.totalBytes && $util.isInteger(message.totalBytes.low) && $util.isInteger(message.totalBytes.high)))
                        return "totalBytes: integer|Long expected";
                if (message.usedBytes != null && Object.hasOwnProperty.call(message, "usedBytes"))
                    if (!$util.isInteger(message.usedBytes) && !(message.usedBytes && $util.isInteger(message.usedBytes.low) && $util.isInteger(message.usedBytes.high)))
                        return "usedBytes: integer|Long expected";
                if (message.availableBytes != null && Object.hasOwnProperty.call(message, "availableBytes"))
                    if (!$util.isInteger(message.availableBytes) && !(message.availableBytes && $util.isInteger(message.availableBytes.low) && $util.isInteger(message.availableBytes.high)))
                        return "availableBytes: integer|Long expected";
                if (message.readBytesDelta != null && Object.hasOwnProperty.call(message, "readBytesDelta"))
                    if (!$util.isInteger(message.readBytesDelta) && !(message.readBytesDelta && $util.isInteger(message.readBytesDelta.low) && $util.isInteger(message.readBytesDelta.high)))
                        return "readBytesDelta: integer|Long expected";
                if (message.writeBytesDelta != null && Object.hasOwnProperty.call(message, "writeBytesDelta"))
                    if (!$util.isInteger(message.writeBytesDelta) && !(message.writeBytesDelta && $util.isInteger(message.writeBytesDelta.low) && $util.isInteger(message.writeBytesDelta.high)))
                        return "writeBytesDelta: integer|Long expected";
                if (message.ioUtilizationPercent != null && Object.hasOwnProperty.call(message, "ioUtilizationPercent")) {
                    properties._ioUtilizationPercent = 1;
                    if (typeof message.ioUtilizationPercent !== "number")
                        return "ioUtilizationPercent: number expected";
                }
                if (message.readAwaitMs != null && Object.hasOwnProperty.call(message, "readAwaitMs")) {
                    properties._readAwaitMs = 1;
                    if (typeof message.readAwaitMs !== "number")
                        return "readAwaitMs: number expected";
                }
                if (message.writeAwaitMs != null && Object.hasOwnProperty.call(message, "writeAwaitMs")) {
                    properties._writeAwaitMs = 1;
                    if (typeof message.writeAwaitMs !== "number")
                        return "writeAwaitMs: number expected";
                }
                if (message.weightedIoPercent != null && Object.hasOwnProperty.call(message, "weightedIoPercent")) {
                    properties._weightedIoPercent = 1;
                    if (typeof message.weightedIoPercent !== "number")
                        return "weightedIoPercent: number expected";
                }
                return null;
            };

            /**
             * Creates a DiskUsageMetric message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.DiskUsageMetric} DiskUsageMetric
             */
            DiskUsageMetric.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.DiskUsageMetric)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.DiskUsageMetric: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.DiskUsageMetric();
                if (object.mountPoint != null)
                    message.mountPoint = String(object.mountPoint);
                if (object.filesystemType != null)
                    message.filesystemType = String(object.filesystemType);
                if (object.totalBytes != null)
                    if ($util.Long)
                        message.totalBytes = $util.Long.fromValue(object.totalBytes, true);
                    else if (typeof object.totalBytes === "string")
                        message.totalBytes = parseInt(object.totalBytes, 10);
                    else if (typeof object.totalBytes === "number")
                        message.totalBytes = object.totalBytes;
                    else if (typeof object.totalBytes === "object")
                        message.totalBytes = new $util.LongBits(object.totalBytes.low >>> 0, object.totalBytes.high >>> 0).toNumber(true);
                if (object.usedBytes != null)
                    if ($util.Long)
                        message.usedBytes = $util.Long.fromValue(object.usedBytes, true);
                    else if (typeof object.usedBytes === "string")
                        message.usedBytes = parseInt(object.usedBytes, 10);
                    else if (typeof object.usedBytes === "number")
                        message.usedBytes = object.usedBytes;
                    else if (typeof object.usedBytes === "object")
                        message.usedBytes = new $util.LongBits(object.usedBytes.low >>> 0, object.usedBytes.high >>> 0).toNumber(true);
                if (object.availableBytes != null)
                    if ($util.Long)
                        message.availableBytes = $util.Long.fromValue(object.availableBytes, true);
                    else if (typeof object.availableBytes === "string")
                        message.availableBytes = parseInt(object.availableBytes, 10);
                    else if (typeof object.availableBytes === "number")
                        message.availableBytes = object.availableBytes;
                    else if (typeof object.availableBytes === "object")
                        message.availableBytes = new $util.LongBits(object.availableBytes.low >>> 0, object.availableBytes.high >>> 0).toNumber(true);
                if (object.readBytesDelta != null)
                    if ($util.Long)
                        message.readBytesDelta = $util.Long.fromValue(object.readBytesDelta, true);
                    else if (typeof object.readBytesDelta === "string")
                        message.readBytesDelta = parseInt(object.readBytesDelta, 10);
                    else if (typeof object.readBytesDelta === "number")
                        message.readBytesDelta = object.readBytesDelta;
                    else if (typeof object.readBytesDelta === "object")
                        message.readBytesDelta = new $util.LongBits(object.readBytesDelta.low >>> 0, object.readBytesDelta.high >>> 0).toNumber(true);
                if (object.writeBytesDelta != null)
                    if ($util.Long)
                        message.writeBytesDelta = $util.Long.fromValue(object.writeBytesDelta, true);
                    else if (typeof object.writeBytesDelta === "string")
                        message.writeBytesDelta = parseInt(object.writeBytesDelta, 10);
                    else if (typeof object.writeBytesDelta === "number")
                        message.writeBytesDelta = object.writeBytesDelta;
                    else if (typeof object.writeBytesDelta === "object")
                        message.writeBytesDelta = new $util.LongBits(object.writeBytesDelta.low >>> 0, object.writeBytesDelta.high >>> 0).toNumber(true);
                if (object.ioUtilizationPercent != null)
                    message.ioUtilizationPercent = Number(object.ioUtilizationPercent);
                if (object.readAwaitMs != null)
                    message.readAwaitMs = Number(object.readAwaitMs);
                if (object.writeAwaitMs != null)
                    message.writeAwaitMs = Number(object.writeAwaitMs);
                if (object.weightedIoPercent != null)
                    message.weightedIoPercent = Number(object.weightedIoPercent);
                return message;
            };

            /**
             * Creates a plain object from a DiskUsageMetric message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {enoki.v1.DiskUsageMetric} message DiskUsageMetric
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            DiskUsageMetric.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.mountPoint = "";
                    object.filesystemType = "";
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.totalBytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.totalBytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.usedBytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.usedBytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.availableBytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.availableBytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.readBytesDelta = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.readBytesDelta = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.writeBytesDelta = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.writeBytesDelta = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                }
                if (message.mountPoint != null && Object.hasOwnProperty.call(message, "mountPoint"))
                    object.mountPoint = message.mountPoint;
                if (message.filesystemType != null && Object.hasOwnProperty.call(message, "filesystemType"))
                    object.filesystemType = message.filesystemType;
                if (message.totalBytes != null && Object.hasOwnProperty.call(message, "totalBytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.totalBytes = typeof message.totalBytes === "number" ? BigInt(message.totalBytes) : $util.Long.fromBits(message.totalBytes.low >>> 0, message.totalBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.totalBytes === "number")
                        object.totalBytes = options.longs === String ? String(message.totalBytes) : message.totalBytes;
                    else
                        object.totalBytes = options.longs === String ? $util.Long.prototype.toString.call(message.totalBytes) : options.longs === Number ? new $util.LongBits(message.totalBytes.low >>> 0, message.totalBytes.high >>> 0).toNumber(true) : message.totalBytes;
                if (message.usedBytes != null && Object.hasOwnProperty.call(message, "usedBytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.usedBytes = typeof message.usedBytes === "number" ? BigInt(message.usedBytes) : $util.Long.fromBits(message.usedBytes.low >>> 0, message.usedBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.usedBytes === "number")
                        object.usedBytes = options.longs === String ? String(message.usedBytes) : message.usedBytes;
                    else
                        object.usedBytes = options.longs === String ? $util.Long.prototype.toString.call(message.usedBytes) : options.longs === Number ? new $util.LongBits(message.usedBytes.low >>> 0, message.usedBytes.high >>> 0).toNumber(true) : message.usedBytes;
                if (message.availableBytes != null && Object.hasOwnProperty.call(message, "availableBytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.availableBytes = typeof message.availableBytes === "number" ? BigInt(message.availableBytes) : $util.Long.fromBits(message.availableBytes.low >>> 0, message.availableBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.availableBytes === "number")
                        object.availableBytes = options.longs === String ? String(message.availableBytes) : message.availableBytes;
                    else
                        object.availableBytes = options.longs === String ? $util.Long.prototype.toString.call(message.availableBytes) : options.longs === Number ? new $util.LongBits(message.availableBytes.low >>> 0, message.availableBytes.high >>> 0).toNumber(true) : message.availableBytes;
                if (message.readBytesDelta != null && Object.hasOwnProperty.call(message, "readBytesDelta"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.readBytesDelta = typeof message.readBytesDelta === "number" ? BigInt(message.readBytesDelta) : $util.Long.fromBits(message.readBytesDelta.low >>> 0, message.readBytesDelta.high >>> 0, true).toBigInt();
                    else if (typeof message.readBytesDelta === "number")
                        object.readBytesDelta = options.longs === String ? String(message.readBytesDelta) : message.readBytesDelta;
                    else
                        object.readBytesDelta = options.longs === String ? $util.Long.prototype.toString.call(message.readBytesDelta) : options.longs === Number ? new $util.LongBits(message.readBytesDelta.low >>> 0, message.readBytesDelta.high >>> 0).toNumber(true) : message.readBytesDelta;
                if (message.writeBytesDelta != null && Object.hasOwnProperty.call(message, "writeBytesDelta"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.writeBytesDelta = typeof message.writeBytesDelta === "number" ? BigInt(message.writeBytesDelta) : $util.Long.fromBits(message.writeBytesDelta.low >>> 0, message.writeBytesDelta.high >>> 0, true).toBigInt();
                    else if (typeof message.writeBytesDelta === "number")
                        object.writeBytesDelta = options.longs === String ? String(message.writeBytesDelta) : message.writeBytesDelta;
                    else
                        object.writeBytesDelta = options.longs === String ? $util.Long.prototype.toString.call(message.writeBytesDelta) : options.longs === Number ? new $util.LongBits(message.writeBytesDelta.low >>> 0, message.writeBytesDelta.high >>> 0).toNumber(true) : message.writeBytesDelta;
                if (message.ioUtilizationPercent != null && Object.hasOwnProperty.call(message, "ioUtilizationPercent")) {
                    object.ioUtilizationPercent = options.json && !isFinite(message.ioUtilizationPercent) ? String(message.ioUtilizationPercent) : message.ioUtilizationPercent;
                    if (options.oneofs)
                        object._ioUtilizationPercent = "ioUtilizationPercent";
                }
                if (message.readAwaitMs != null && Object.hasOwnProperty.call(message, "readAwaitMs")) {
                    object.readAwaitMs = options.json && !isFinite(message.readAwaitMs) ? String(message.readAwaitMs) : message.readAwaitMs;
                    if (options.oneofs)
                        object._readAwaitMs = "readAwaitMs";
                }
                if (message.writeAwaitMs != null && Object.hasOwnProperty.call(message, "writeAwaitMs")) {
                    object.writeAwaitMs = options.json && !isFinite(message.writeAwaitMs) ? String(message.writeAwaitMs) : message.writeAwaitMs;
                    if (options.oneofs)
                        object._writeAwaitMs = "writeAwaitMs";
                }
                if (message.weightedIoPercent != null && Object.hasOwnProperty.call(message, "weightedIoPercent")) {
                    object.weightedIoPercent = options.json && !isFinite(message.weightedIoPercent) ? String(message.weightedIoPercent) : message.weightedIoPercent;
                    if (options.oneofs)
                        object._weightedIoPercent = "weightedIoPercent";
                }
                return object;
            };

            /**
             * Converts this DiskUsageMetric to JSON.
             * @function toJSON
             * @memberof enoki.v1.DiskUsageMetric
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            DiskUsageMetric.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for DiskUsageMetric
             * @function getTypeUrl
             * @memberof enoki.v1.DiskUsageMetric
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            DiskUsageMetric.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.DiskUsageMetric";
            };

            return DiskUsageMetric;
        })();

        v1.DiskHealthMetric = (function() {

            /**
             * Properties of a DiskHealthMetric.
             * @memberof enoki.v1
             * @interface IDiskHealthMetric
             * @property {string|null} [deviceName] DiskHealthMetric deviceName
             * @property {string|null} [model] DiskHealthMetric model
             * @property {string|null} [serialNumber] DiskHealthMetric serialNumber
             * @property {boolean|null} [passed] DiskHealthMetric passed
             * @property {number|null} [temperatureCelsius] DiskHealthMetric temperatureCelsius
             * @property {Long|null} [powerOnHours] DiskHealthMetric powerOnHours
             */

            /**
             * Constructs a new DiskHealthMetric.
             * @memberof enoki.v1
             * @classdesc Represents a DiskHealthMetric.
             * @implements IDiskHealthMetric
             * @constructor
             * @param {enoki.v1.IDiskHealthMetric=} [properties] Properties to set
             */
            function DiskHealthMetric(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * DiskHealthMetric deviceName.
             * @member {string} deviceName
             * @memberof enoki.v1.DiskHealthMetric
             * @instance
             */
            DiskHealthMetric.prototype.deviceName = "";

            /**
             * DiskHealthMetric model.
             * @member {string} model
             * @memberof enoki.v1.DiskHealthMetric
             * @instance
             */
            DiskHealthMetric.prototype.model = "";

            /**
             * DiskHealthMetric serialNumber.
             * @member {string} serialNumber
             * @memberof enoki.v1.DiskHealthMetric
             * @instance
             */
            DiskHealthMetric.prototype.serialNumber = "";

            /**
             * DiskHealthMetric passed.
             * @member {boolean} passed
             * @memberof enoki.v1.DiskHealthMetric
             * @instance
             */
            DiskHealthMetric.prototype.passed = false;

            /**
             * DiskHealthMetric temperatureCelsius.
             * @member {number|null|undefined} temperatureCelsius
             * @memberof enoki.v1.DiskHealthMetric
             * @instance
             */
            DiskHealthMetric.prototype.temperatureCelsius = null;

            /**
             * DiskHealthMetric powerOnHours.
             * @member {Long|null|undefined} powerOnHours
             * @memberof enoki.v1.DiskHealthMetric
             * @instance
             */
            DiskHealthMetric.prototype.powerOnHours = null;

            // OneOf field names bound to virtual getters and setters
            let $oneOfFields;

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(DiskHealthMetric.prototype, "_temperatureCelsius", {
                get: $util.oneOfGetter($oneOfFields = ["temperatureCelsius"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            // Virtual OneOf for proto3 optional field
            Object.defineProperty(DiskHealthMetric.prototype, "_powerOnHours", {
                get: $util.oneOfGetter($oneOfFields = ["powerOnHours"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            /**
             * Creates a new DiskHealthMetric instance using the specified properties.
             * @function create
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {enoki.v1.IDiskHealthMetric=} [properties] Properties to set
             * @returns {enoki.v1.DiskHealthMetric} DiskHealthMetric instance
             */
            DiskHealthMetric.create = function create(properties) {
                return new DiskHealthMetric(properties);
            };

            /**
             * Encodes the specified DiskHealthMetric message. Does not implicitly {@link enoki.v1.DiskHealthMetric.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {enoki.v1.IDiskHealthMetric} message DiskHealthMetric message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            DiskHealthMetric.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.deviceName != null && Object.hasOwnProperty.call(message, "deviceName"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.deviceName);
                if (message.model != null && Object.hasOwnProperty.call(message, "model"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.model);
                if (message.serialNumber != null && Object.hasOwnProperty.call(message, "serialNumber"))
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.serialNumber);
                if (message.passed != null && Object.hasOwnProperty.call(message, "passed"))
                    writer.uint32(/* id 4, wireType 0 =*/32).bool(message.passed);
                if (message.temperatureCelsius != null && Object.hasOwnProperty.call(message, "temperatureCelsius"))
                    writer.uint32(/* id 5, wireType 1 =*/41).double(message.temperatureCelsius);
                if (message.powerOnHours != null && Object.hasOwnProperty.call(message, "powerOnHours"))
                    writer.uint32(/* id 6, wireType 0 =*/48).uint64(message.powerOnHours);
                return writer;
            };

            /**
             * Encodes the specified DiskHealthMetric message, length delimited. Does not implicitly {@link enoki.v1.DiskHealthMetric.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {enoki.v1.IDiskHealthMetric} message DiskHealthMetric message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            DiskHealthMetric.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a DiskHealthMetric message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.DiskHealthMetric} DiskHealthMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            DiskHealthMetric.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.DiskHealthMetric();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.deviceName = reader.string();
                            break;
                        }
                    case 2: {
                            message.model = reader.string();
                            break;
                        }
                    case 3: {
                            message.serialNumber = reader.string();
                            break;
                        }
                    case 4: {
                            message.passed = reader.bool();
                            break;
                        }
                    case 5: {
                            message.temperatureCelsius = reader.double();
                            break;
                        }
                    case 6: {
                            message.powerOnHours = reader.uint64();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a DiskHealthMetric message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.DiskHealthMetric} DiskHealthMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            DiskHealthMetric.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a DiskHealthMetric message.
             * @function verify
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            DiskHealthMetric.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                let properties = {};
                if (message.deviceName != null && Object.hasOwnProperty.call(message, "deviceName"))
                    if (!$util.isString(message.deviceName))
                        return "deviceName: string expected";
                if (message.model != null && Object.hasOwnProperty.call(message, "model"))
                    if (!$util.isString(message.model))
                        return "model: string expected";
                if (message.serialNumber != null && Object.hasOwnProperty.call(message, "serialNumber"))
                    if (!$util.isString(message.serialNumber))
                        return "serialNumber: string expected";
                if (message.passed != null && Object.hasOwnProperty.call(message, "passed"))
                    if (typeof message.passed !== "boolean")
                        return "passed: boolean expected";
                if (message.temperatureCelsius != null && Object.hasOwnProperty.call(message, "temperatureCelsius")) {
                    properties._temperatureCelsius = 1;
                    if (typeof message.temperatureCelsius !== "number")
                        return "temperatureCelsius: number expected";
                }
                if (message.powerOnHours != null && Object.hasOwnProperty.call(message, "powerOnHours")) {
                    properties._powerOnHours = 1;
                    if (!$util.isInteger(message.powerOnHours) && !(message.powerOnHours && $util.isInteger(message.powerOnHours.low) && $util.isInteger(message.powerOnHours.high)))
                        return "powerOnHours: integer|Long expected";
                }
                return null;
            };

            /**
             * Creates a DiskHealthMetric message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.DiskHealthMetric} DiskHealthMetric
             */
            DiskHealthMetric.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.DiskHealthMetric)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.DiskHealthMetric: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.DiskHealthMetric();
                if (object.deviceName != null)
                    message.deviceName = String(object.deviceName);
                if (object.model != null)
                    message.model = String(object.model);
                if (object.serialNumber != null)
                    message.serialNumber = String(object.serialNumber);
                if (object.passed != null)
                    message.passed = Boolean(object.passed);
                if (object.temperatureCelsius != null)
                    message.temperatureCelsius = Number(object.temperatureCelsius);
                if (object.powerOnHours != null)
                    if ($util.Long)
                        message.powerOnHours = $util.Long.fromValue(object.powerOnHours, true);
                    else if (typeof object.powerOnHours === "string")
                        message.powerOnHours = parseInt(object.powerOnHours, 10);
                    else if (typeof object.powerOnHours === "number")
                        message.powerOnHours = object.powerOnHours;
                    else if (typeof object.powerOnHours === "object")
                        message.powerOnHours = new $util.LongBits(object.powerOnHours.low >>> 0, object.powerOnHours.high >>> 0).toNumber(true);
                return message;
            };

            /**
             * Creates a plain object from a DiskHealthMetric message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {enoki.v1.DiskHealthMetric} message DiskHealthMetric
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            DiskHealthMetric.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.deviceName = "";
                    object.model = "";
                    object.serialNumber = "";
                    object.passed = false;
                }
                if (message.deviceName != null && Object.hasOwnProperty.call(message, "deviceName"))
                    object.deviceName = message.deviceName;
                if (message.model != null && Object.hasOwnProperty.call(message, "model"))
                    object.model = message.model;
                if (message.serialNumber != null && Object.hasOwnProperty.call(message, "serialNumber"))
                    object.serialNumber = message.serialNumber;
                if (message.passed != null && Object.hasOwnProperty.call(message, "passed"))
                    object.passed = message.passed;
                if (message.temperatureCelsius != null && Object.hasOwnProperty.call(message, "temperatureCelsius")) {
                    object.temperatureCelsius = options.json && !isFinite(message.temperatureCelsius) ? String(message.temperatureCelsius) : message.temperatureCelsius;
                    if (options.oneofs)
                        object._temperatureCelsius = "temperatureCelsius";
                }
                if (message.powerOnHours != null && Object.hasOwnProperty.call(message, "powerOnHours")) {
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.powerOnHours = typeof message.powerOnHours === "number" ? BigInt(message.powerOnHours) : $util.Long.fromBits(message.powerOnHours.low >>> 0, message.powerOnHours.high >>> 0, true).toBigInt();
                    else if (typeof message.powerOnHours === "number")
                        object.powerOnHours = options.longs === String ? String(message.powerOnHours) : message.powerOnHours;
                    else
                        object.powerOnHours = options.longs === String ? $util.Long.prototype.toString.call(message.powerOnHours) : options.longs === Number ? new $util.LongBits(message.powerOnHours.low >>> 0, message.powerOnHours.high >>> 0).toNumber(true) : message.powerOnHours;
                    if (options.oneofs)
                        object._powerOnHours = "powerOnHours";
                }
                return object;
            };

            /**
             * Converts this DiskHealthMetric to JSON.
             * @function toJSON
             * @memberof enoki.v1.DiskHealthMetric
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            DiskHealthMetric.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for DiskHealthMetric
             * @function getTypeUrl
             * @memberof enoki.v1.DiskHealthMetric
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            DiskHealthMetric.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.DiskHealthMetric";
            };

            return DiskHealthMetric;
        })();

        v1.NetworkInterfaceMetric = (function() {

            /**
             * Properties of a NetworkInterfaceMetric.
             * @memberof enoki.v1
             * @interface INetworkInterfaceMetric
             * @property {string|null} [name] NetworkInterfaceMetric name
             * @property {Long|null} [rxBytes] NetworkInterfaceMetric rxBytes
             * @property {Long|null} [txBytes] NetworkInterfaceMetric txBytes
             * @property {Long|null} [rxBytesDelta] NetworkInterfaceMetric rxBytesDelta
             * @property {Long|null} [txBytesDelta] NetworkInterfaceMetric txBytesDelta
             */

            /**
             * Constructs a new NetworkInterfaceMetric.
             * @memberof enoki.v1
             * @classdesc Represents a NetworkInterfaceMetric.
             * @implements INetworkInterfaceMetric
             * @constructor
             * @param {enoki.v1.INetworkInterfaceMetric=} [properties] Properties to set
             */
            function NetworkInterfaceMetric(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * NetworkInterfaceMetric name.
             * @member {string} name
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @instance
             */
            NetworkInterfaceMetric.prototype.name = "";

            /**
             * NetworkInterfaceMetric rxBytes.
             * @member {Long} rxBytes
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @instance
             */
            NetworkInterfaceMetric.prototype.rxBytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * NetworkInterfaceMetric txBytes.
             * @member {Long} txBytes
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @instance
             */
            NetworkInterfaceMetric.prototype.txBytes = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * NetworkInterfaceMetric rxBytesDelta.
             * @member {Long} rxBytesDelta
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @instance
             */
            NetworkInterfaceMetric.prototype.rxBytesDelta = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * NetworkInterfaceMetric txBytesDelta.
             * @member {Long} txBytesDelta
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @instance
             */
            NetworkInterfaceMetric.prototype.txBytesDelta = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * Creates a new NetworkInterfaceMetric instance using the specified properties.
             * @function create
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {enoki.v1.INetworkInterfaceMetric=} [properties] Properties to set
             * @returns {enoki.v1.NetworkInterfaceMetric} NetworkInterfaceMetric instance
             */
            NetworkInterfaceMetric.create = function create(properties) {
                return new NetworkInterfaceMetric(properties);
            };

            /**
             * Encodes the specified NetworkInterfaceMetric message. Does not implicitly {@link enoki.v1.NetworkInterfaceMetric.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {enoki.v1.INetworkInterfaceMetric} message NetworkInterfaceMetric message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            NetworkInterfaceMetric.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.name);
                if (message.rxBytes != null && Object.hasOwnProperty.call(message, "rxBytes"))
                    writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.rxBytes);
                if (message.txBytes != null && Object.hasOwnProperty.call(message, "txBytes"))
                    writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.txBytes);
                if (message.rxBytesDelta != null && Object.hasOwnProperty.call(message, "rxBytesDelta"))
                    writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.rxBytesDelta);
                if (message.txBytesDelta != null && Object.hasOwnProperty.call(message, "txBytesDelta"))
                    writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.txBytesDelta);
                return writer;
            };

            /**
             * Encodes the specified NetworkInterfaceMetric message, length delimited. Does not implicitly {@link enoki.v1.NetworkInterfaceMetric.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {enoki.v1.INetworkInterfaceMetric} message NetworkInterfaceMetric message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            NetworkInterfaceMetric.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a NetworkInterfaceMetric message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.NetworkInterfaceMetric} NetworkInterfaceMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            NetworkInterfaceMetric.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.NetworkInterfaceMetric();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.name = reader.string();
                            break;
                        }
                    case 2: {
                            message.rxBytes = reader.uint64();
                            break;
                        }
                    case 3: {
                            message.txBytes = reader.uint64();
                            break;
                        }
                    case 4: {
                            message.rxBytesDelta = reader.uint64();
                            break;
                        }
                    case 5: {
                            message.txBytesDelta = reader.uint64();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a NetworkInterfaceMetric message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.NetworkInterfaceMetric} NetworkInterfaceMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            NetworkInterfaceMetric.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a NetworkInterfaceMetric message.
             * @function verify
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            NetworkInterfaceMetric.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    if (!$util.isString(message.name))
                        return "name: string expected";
                if (message.rxBytes != null && Object.hasOwnProperty.call(message, "rxBytes"))
                    if (!$util.isInteger(message.rxBytes) && !(message.rxBytes && $util.isInteger(message.rxBytes.low) && $util.isInteger(message.rxBytes.high)))
                        return "rxBytes: integer|Long expected";
                if (message.txBytes != null && Object.hasOwnProperty.call(message, "txBytes"))
                    if (!$util.isInteger(message.txBytes) && !(message.txBytes && $util.isInteger(message.txBytes.low) && $util.isInteger(message.txBytes.high)))
                        return "txBytes: integer|Long expected";
                if (message.rxBytesDelta != null && Object.hasOwnProperty.call(message, "rxBytesDelta"))
                    if (!$util.isInteger(message.rxBytesDelta) && !(message.rxBytesDelta && $util.isInteger(message.rxBytesDelta.low) && $util.isInteger(message.rxBytesDelta.high)))
                        return "rxBytesDelta: integer|Long expected";
                if (message.txBytesDelta != null && Object.hasOwnProperty.call(message, "txBytesDelta"))
                    if (!$util.isInteger(message.txBytesDelta) && !(message.txBytesDelta && $util.isInteger(message.txBytesDelta.low) && $util.isInteger(message.txBytesDelta.high)))
                        return "txBytesDelta: integer|Long expected";
                return null;
            };

            /**
             * Creates a NetworkInterfaceMetric message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.NetworkInterfaceMetric} NetworkInterfaceMetric
             */
            NetworkInterfaceMetric.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.NetworkInterfaceMetric)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.NetworkInterfaceMetric: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.NetworkInterfaceMetric();
                if (object.name != null)
                    message.name = String(object.name);
                if (object.rxBytes != null)
                    if ($util.Long)
                        message.rxBytes = $util.Long.fromValue(object.rxBytes, true);
                    else if (typeof object.rxBytes === "string")
                        message.rxBytes = parseInt(object.rxBytes, 10);
                    else if (typeof object.rxBytes === "number")
                        message.rxBytes = object.rxBytes;
                    else if (typeof object.rxBytes === "object")
                        message.rxBytes = new $util.LongBits(object.rxBytes.low >>> 0, object.rxBytes.high >>> 0).toNumber(true);
                if (object.txBytes != null)
                    if ($util.Long)
                        message.txBytes = $util.Long.fromValue(object.txBytes, true);
                    else if (typeof object.txBytes === "string")
                        message.txBytes = parseInt(object.txBytes, 10);
                    else if (typeof object.txBytes === "number")
                        message.txBytes = object.txBytes;
                    else if (typeof object.txBytes === "object")
                        message.txBytes = new $util.LongBits(object.txBytes.low >>> 0, object.txBytes.high >>> 0).toNumber(true);
                if (object.rxBytesDelta != null)
                    if ($util.Long)
                        message.rxBytesDelta = $util.Long.fromValue(object.rxBytesDelta, true);
                    else if (typeof object.rxBytesDelta === "string")
                        message.rxBytesDelta = parseInt(object.rxBytesDelta, 10);
                    else if (typeof object.rxBytesDelta === "number")
                        message.rxBytesDelta = object.rxBytesDelta;
                    else if (typeof object.rxBytesDelta === "object")
                        message.rxBytesDelta = new $util.LongBits(object.rxBytesDelta.low >>> 0, object.rxBytesDelta.high >>> 0).toNumber(true);
                if (object.txBytesDelta != null)
                    if ($util.Long)
                        message.txBytesDelta = $util.Long.fromValue(object.txBytesDelta, true);
                    else if (typeof object.txBytesDelta === "string")
                        message.txBytesDelta = parseInt(object.txBytesDelta, 10);
                    else if (typeof object.txBytesDelta === "number")
                        message.txBytesDelta = object.txBytesDelta;
                    else if (typeof object.txBytesDelta === "object")
                        message.txBytesDelta = new $util.LongBits(object.txBytesDelta.low >>> 0, object.txBytesDelta.high >>> 0).toNumber(true);
                return message;
            };

            /**
             * Creates a plain object from a NetworkInterfaceMetric message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {enoki.v1.NetworkInterfaceMetric} message NetworkInterfaceMetric
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            NetworkInterfaceMetric.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.name = "";
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.rxBytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.rxBytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.txBytes = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.txBytes = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.rxBytesDelta = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.rxBytesDelta = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.txBytesDelta = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.txBytesDelta = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                }
                if (message.name != null && Object.hasOwnProperty.call(message, "name"))
                    object.name = message.name;
                if (message.rxBytes != null && Object.hasOwnProperty.call(message, "rxBytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.rxBytes = typeof message.rxBytes === "number" ? BigInt(message.rxBytes) : $util.Long.fromBits(message.rxBytes.low >>> 0, message.rxBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.rxBytes === "number")
                        object.rxBytes = options.longs === String ? String(message.rxBytes) : message.rxBytes;
                    else
                        object.rxBytes = options.longs === String ? $util.Long.prototype.toString.call(message.rxBytes) : options.longs === Number ? new $util.LongBits(message.rxBytes.low >>> 0, message.rxBytes.high >>> 0).toNumber(true) : message.rxBytes;
                if (message.txBytes != null && Object.hasOwnProperty.call(message, "txBytes"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.txBytes = typeof message.txBytes === "number" ? BigInt(message.txBytes) : $util.Long.fromBits(message.txBytes.low >>> 0, message.txBytes.high >>> 0, true).toBigInt();
                    else if (typeof message.txBytes === "number")
                        object.txBytes = options.longs === String ? String(message.txBytes) : message.txBytes;
                    else
                        object.txBytes = options.longs === String ? $util.Long.prototype.toString.call(message.txBytes) : options.longs === Number ? new $util.LongBits(message.txBytes.low >>> 0, message.txBytes.high >>> 0).toNumber(true) : message.txBytes;
                if (message.rxBytesDelta != null && Object.hasOwnProperty.call(message, "rxBytesDelta"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.rxBytesDelta = typeof message.rxBytesDelta === "number" ? BigInt(message.rxBytesDelta) : $util.Long.fromBits(message.rxBytesDelta.low >>> 0, message.rxBytesDelta.high >>> 0, true).toBigInt();
                    else if (typeof message.rxBytesDelta === "number")
                        object.rxBytesDelta = options.longs === String ? String(message.rxBytesDelta) : message.rxBytesDelta;
                    else
                        object.rxBytesDelta = options.longs === String ? $util.Long.prototype.toString.call(message.rxBytesDelta) : options.longs === Number ? new $util.LongBits(message.rxBytesDelta.low >>> 0, message.rxBytesDelta.high >>> 0).toNumber(true) : message.rxBytesDelta;
                if (message.txBytesDelta != null && Object.hasOwnProperty.call(message, "txBytesDelta"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.txBytesDelta = typeof message.txBytesDelta === "number" ? BigInt(message.txBytesDelta) : $util.Long.fromBits(message.txBytesDelta.low >>> 0, message.txBytesDelta.high >>> 0, true).toBigInt();
                    else if (typeof message.txBytesDelta === "number")
                        object.txBytesDelta = options.longs === String ? String(message.txBytesDelta) : message.txBytesDelta;
                    else
                        object.txBytesDelta = options.longs === String ? $util.Long.prototype.toString.call(message.txBytesDelta) : options.longs === Number ? new $util.LongBits(message.txBytesDelta.low >>> 0, message.txBytesDelta.high >>> 0).toNumber(true) : message.txBytesDelta;
                return object;
            };

            /**
             * Converts this NetworkInterfaceMetric to JSON.
             * @function toJSON
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            NetworkInterfaceMetric.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for NetworkInterfaceMetric
             * @function getTypeUrl
             * @memberof enoki.v1.NetworkInterfaceMetric
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            NetworkInterfaceMetric.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.NetworkInterfaceMetric";
            };

            return NetworkInterfaceMetric;
        })();

        v1.ProbeReportResponse = (function() {

            /**
             * Properties of a ProbeReportResponse.
             * @memberof enoki.v1
             * @interface IProbeReportResponse
             * @property {Long|null} [acceptedSequenceEnd] ProbeReportResponse acceptedSequenceEnd
             * @property {Long|null} [serverTimeMs] ProbeReportResponse serverTimeMs
             * @property {string|null} [currentProbeConfigurationVersion] ProbeReportResponse currentProbeConfigurationVersion
             * @property {boolean|null} [inventoryNeeded] ProbeReportResponse inventoryNeeded
             * @property {enoki.v1.IProbeOperation|null} [pendingOperation] ProbeReportResponse pendingOperation
             */

            /**
             * Constructs a new ProbeReportResponse.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeReportResponse.
             * @implements IProbeReportResponse
             * @constructor
             * @param {enoki.v1.IProbeReportResponse=} [properties] Properties to set
             */
            function ProbeReportResponse(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeReportResponse acceptedSequenceEnd.
             * @member {Long} acceptedSequenceEnd
             * @memberof enoki.v1.ProbeReportResponse
             * @instance
             */
            ProbeReportResponse.prototype.acceptedSequenceEnd = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * ProbeReportResponse serverTimeMs.
             * @member {Long} serverTimeMs
             * @memberof enoki.v1.ProbeReportResponse
             * @instance
             */
            ProbeReportResponse.prototype.serverTimeMs = $util.Long ? $util.Long.fromBits(0,0,false) : 0;

            /**
             * ProbeReportResponse currentProbeConfigurationVersion.
             * @member {string} currentProbeConfigurationVersion
             * @memberof enoki.v1.ProbeReportResponse
             * @instance
             */
            ProbeReportResponse.prototype.currentProbeConfigurationVersion = "";

            /**
             * ProbeReportResponse inventoryNeeded.
             * @member {boolean} inventoryNeeded
             * @memberof enoki.v1.ProbeReportResponse
             * @instance
             */
            ProbeReportResponse.prototype.inventoryNeeded = false;

            /**
             * ProbeReportResponse pendingOperation.
             * @member {enoki.v1.IProbeOperation|null|undefined} pendingOperation
             * @memberof enoki.v1.ProbeReportResponse
             * @instance
             */
            ProbeReportResponse.prototype.pendingOperation = null;

            /**
             * Creates a new ProbeReportResponse instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {enoki.v1.IProbeReportResponse=} [properties] Properties to set
             * @returns {enoki.v1.ProbeReportResponse} ProbeReportResponse instance
             */
            ProbeReportResponse.create = function create(properties) {
                return new ProbeReportResponse(properties);
            };

            /**
             * Encodes the specified ProbeReportResponse message. Does not implicitly {@link enoki.v1.ProbeReportResponse.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {enoki.v1.IProbeReportResponse} message ProbeReportResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeReportResponse.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.acceptedSequenceEnd != null && Object.hasOwnProperty.call(message, "acceptedSequenceEnd"))
                    writer.uint32(/* id 1, wireType 0 =*/8).uint64(message.acceptedSequenceEnd);
                if (message.serverTimeMs != null && Object.hasOwnProperty.call(message, "serverTimeMs"))
                    writer.uint32(/* id 2, wireType 0 =*/16).int64(message.serverTimeMs);
                if (message.currentProbeConfigurationVersion != null && Object.hasOwnProperty.call(message, "currentProbeConfigurationVersion"))
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.currentProbeConfigurationVersion);
                if (message.inventoryNeeded != null && Object.hasOwnProperty.call(message, "inventoryNeeded"))
                    writer.uint32(/* id 4, wireType 0 =*/32).bool(message.inventoryNeeded);
                if (message.pendingOperation != null && Object.hasOwnProperty.call(message, "pendingOperation"))
                    $root.enoki.v1.ProbeOperation.encode(message.pendingOperation, writer.uint32(/* id 5, wireType 2 =*/42).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified ProbeReportResponse message, length delimited. Does not implicitly {@link enoki.v1.ProbeReportResponse.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {enoki.v1.IProbeReportResponse} message ProbeReportResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeReportResponse.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeReportResponse message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeReportResponse} ProbeReportResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeReportResponse.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeReportResponse();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.acceptedSequenceEnd = reader.uint64();
                            break;
                        }
                    case 2: {
                            message.serverTimeMs = reader.int64();
                            break;
                        }
                    case 3: {
                            message.currentProbeConfigurationVersion = reader.string();
                            break;
                        }
                    case 4: {
                            message.inventoryNeeded = reader.bool();
                            break;
                        }
                    case 5: {
                            message.pendingOperation = $root.enoki.v1.ProbeOperation.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeReportResponse message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeReportResponse} ProbeReportResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeReportResponse.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeReportResponse message.
             * @function verify
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeReportResponse.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.acceptedSequenceEnd != null && Object.hasOwnProperty.call(message, "acceptedSequenceEnd"))
                    if (!$util.isInteger(message.acceptedSequenceEnd) && !(message.acceptedSequenceEnd && $util.isInteger(message.acceptedSequenceEnd.low) && $util.isInteger(message.acceptedSequenceEnd.high)))
                        return "acceptedSequenceEnd: integer|Long expected";
                if (message.serverTimeMs != null && Object.hasOwnProperty.call(message, "serverTimeMs"))
                    if (!$util.isInteger(message.serverTimeMs) && !(message.serverTimeMs && $util.isInteger(message.serverTimeMs.low) && $util.isInteger(message.serverTimeMs.high)))
                        return "serverTimeMs: integer|Long expected";
                if (message.currentProbeConfigurationVersion != null && Object.hasOwnProperty.call(message, "currentProbeConfigurationVersion"))
                    if (!$util.isString(message.currentProbeConfigurationVersion))
                        return "currentProbeConfigurationVersion: string expected";
                if (message.inventoryNeeded != null && Object.hasOwnProperty.call(message, "inventoryNeeded"))
                    if (typeof message.inventoryNeeded !== "boolean")
                        return "inventoryNeeded: boolean expected";
                if (message.pendingOperation != null && Object.hasOwnProperty.call(message, "pendingOperation")) {
                    let error = $root.enoki.v1.ProbeOperation.verify(message.pendingOperation, long + 1);
                    if (error)
                        return "pendingOperation." + error;
                }
                return null;
            };

            /**
             * Creates a ProbeReportResponse message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeReportResponse} ProbeReportResponse
             */
            ProbeReportResponse.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeReportResponse)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeReportResponse: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeReportResponse();
                if (object.acceptedSequenceEnd != null)
                    if ($util.Long)
                        message.acceptedSequenceEnd = $util.Long.fromValue(object.acceptedSequenceEnd, true);
                    else if (typeof object.acceptedSequenceEnd === "string")
                        message.acceptedSequenceEnd = parseInt(object.acceptedSequenceEnd, 10);
                    else if (typeof object.acceptedSequenceEnd === "number")
                        message.acceptedSequenceEnd = object.acceptedSequenceEnd;
                    else if (typeof object.acceptedSequenceEnd === "object")
                        message.acceptedSequenceEnd = new $util.LongBits(object.acceptedSequenceEnd.low >>> 0, object.acceptedSequenceEnd.high >>> 0).toNumber(true);
                if (object.serverTimeMs != null)
                    if ($util.Long)
                        message.serverTimeMs = $util.Long.fromValue(object.serverTimeMs, false);
                    else if (typeof object.serverTimeMs === "string")
                        message.serverTimeMs = parseInt(object.serverTimeMs, 10);
                    else if (typeof object.serverTimeMs === "number")
                        message.serverTimeMs = object.serverTimeMs;
                    else if (typeof object.serverTimeMs === "object")
                        message.serverTimeMs = new $util.LongBits(object.serverTimeMs.low >>> 0, object.serverTimeMs.high >>> 0).toNumber();
                if (object.currentProbeConfigurationVersion != null)
                    message.currentProbeConfigurationVersion = String(object.currentProbeConfigurationVersion);
                if (object.inventoryNeeded != null)
                    message.inventoryNeeded = Boolean(object.inventoryNeeded);
                if (object.pendingOperation != null) {
                    if (!$util.isObject(object.pendingOperation))
                        throw TypeError(".enoki.v1.ProbeReportResponse.pendingOperation: object expected");
                    message.pendingOperation = $root.enoki.v1.ProbeOperation.fromObject(object.pendingOperation, long + 1);
                }
                return message;
            };

            /**
             * Creates a plain object from a ProbeReportResponse message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {enoki.v1.ProbeReportResponse} message ProbeReportResponse
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeReportResponse.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, true);
                        object.acceptedSequenceEnd = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.acceptedSequenceEnd = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    if ($util.Long) {
                        let long = new $util.Long(0, 0, false);
                        object.serverTimeMs = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : typeof BigInt !== "undefined" && options.longs === BigInt ? long.toBigInt() : long;
                    } else
                        object.serverTimeMs = options.longs === String ? "0" : typeof BigInt !== "undefined" && options.longs === BigInt ? BigInt("0") : 0;
                    object.currentProbeConfigurationVersion = "";
                    object.inventoryNeeded = false;
                    object.pendingOperation = null;
                }
                if (message.acceptedSequenceEnd != null && Object.hasOwnProperty.call(message, "acceptedSequenceEnd"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.acceptedSequenceEnd = typeof message.acceptedSequenceEnd === "number" ? BigInt(message.acceptedSequenceEnd) : $util.Long.fromBits(message.acceptedSequenceEnd.low >>> 0, message.acceptedSequenceEnd.high >>> 0, true).toBigInt();
                    else if (typeof message.acceptedSequenceEnd === "number")
                        object.acceptedSequenceEnd = options.longs === String ? String(message.acceptedSequenceEnd) : message.acceptedSequenceEnd;
                    else
                        object.acceptedSequenceEnd = options.longs === String ? $util.Long.prototype.toString.call(message.acceptedSequenceEnd) : options.longs === Number ? new $util.LongBits(message.acceptedSequenceEnd.low >>> 0, message.acceptedSequenceEnd.high >>> 0).toNumber(true) : message.acceptedSequenceEnd;
                if (message.serverTimeMs != null && Object.hasOwnProperty.call(message, "serverTimeMs"))
                    if (typeof BigInt !== "undefined" && options.longs === BigInt)
                        object.serverTimeMs = typeof message.serverTimeMs === "number" ? BigInt(message.serverTimeMs) : $util.Long.fromBits(message.serverTimeMs.low >>> 0, message.serverTimeMs.high >>> 0, false).toBigInt();
                    else if (typeof message.serverTimeMs === "number")
                        object.serverTimeMs = options.longs === String ? String(message.serverTimeMs) : message.serverTimeMs;
                    else
                        object.serverTimeMs = options.longs === String ? $util.Long.prototype.toString.call(message.serverTimeMs) : options.longs === Number ? new $util.LongBits(message.serverTimeMs.low >>> 0, message.serverTimeMs.high >>> 0).toNumber() : message.serverTimeMs;
                if (message.currentProbeConfigurationVersion != null && Object.hasOwnProperty.call(message, "currentProbeConfigurationVersion"))
                    object.currentProbeConfigurationVersion = message.currentProbeConfigurationVersion;
                if (message.inventoryNeeded != null && Object.hasOwnProperty.call(message, "inventoryNeeded"))
                    object.inventoryNeeded = message.inventoryNeeded;
                if (message.pendingOperation != null && Object.hasOwnProperty.call(message, "pendingOperation"))
                    object.pendingOperation = $root.enoki.v1.ProbeOperation.toObject(message.pendingOperation, options, q + 1);
                return object;
            };

            /**
             * Converts this ProbeReportResponse to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeReportResponse
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeReportResponse.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeReportResponse
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeReportResponse
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeReportResponse.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeReportResponse";
            };

            return ProbeReportResponse;
        })();

        v1.ProbeOperation = (function() {

            /**
             * Properties of a ProbeOperation.
             * @memberof enoki.v1
             * @interface IProbeOperation
             * @property {string|null} [id] ProbeOperation id
             * @property {enoki.v1.IProbeUpgradeOperation|null} [probeUpgrade] ProbeOperation probeUpgrade
             * @property {enoki.v1.IProbeUninstallOperation|null} [probeUninstall] ProbeOperation probeUninstall
             */

            /**
             * Constructs a new ProbeOperation.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeOperation.
             * @implements IProbeOperation
             * @constructor
             * @param {enoki.v1.IProbeOperation=} [properties] Properties to set
             */
            function ProbeOperation(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeOperation id.
             * @member {string} id
             * @memberof enoki.v1.ProbeOperation
             * @instance
             */
            ProbeOperation.prototype.id = "";

            /**
             * ProbeOperation probeUpgrade.
             * @member {enoki.v1.IProbeUpgradeOperation|null|undefined} probeUpgrade
             * @memberof enoki.v1.ProbeOperation
             * @instance
             */
            ProbeOperation.prototype.probeUpgrade = null;

            /**
             * ProbeOperation probeUninstall.
             * @member {enoki.v1.IProbeUninstallOperation|null|undefined} probeUninstall
             * @memberof enoki.v1.ProbeOperation
             * @instance
             */
            ProbeOperation.prototype.probeUninstall = null;

            // OneOf field names bound to virtual getters and setters
            let $oneOfFields;

            /**
             * ProbeOperation operation.
             * @member {"probeUpgrade"|"probeUninstall"|undefined} operation
             * @memberof enoki.v1.ProbeOperation
             * @instance
             */
            Object.defineProperty(ProbeOperation.prototype, "operation", {
                get: $util.oneOfGetter($oneOfFields = ["probeUpgrade", "probeUninstall"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            /**
             * Creates a new ProbeOperation instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {enoki.v1.IProbeOperation=} [properties] Properties to set
             * @returns {enoki.v1.ProbeOperation} ProbeOperation instance
             */
            ProbeOperation.create = function create(properties) {
                return new ProbeOperation(properties);
            };

            /**
             * Encodes the specified ProbeOperation message. Does not implicitly {@link enoki.v1.ProbeOperation.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {enoki.v1.IProbeOperation} message ProbeOperation message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperation.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.id != null && Object.hasOwnProperty.call(message, "id"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.id);
                if (message.probeUpgrade != null && Object.hasOwnProperty.call(message, "probeUpgrade"))
                    $root.enoki.v1.ProbeUpgradeOperation.encode(message.probeUpgrade, writer.uint32(/* id 2, wireType 2 =*/18).fork(), q + 1).ldelim();
                if (message.probeUninstall != null && Object.hasOwnProperty.call(message, "probeUninstall"))
                    $root.enoki.v1.ProbeUninstallOperation.encode(message.probeUninstall, writer.uint32(/* id 3, wireType 2 =*/26).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified ProbeOperation message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperation.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {enoki.v1.IProbeOperation} message ProbeOperation message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperation.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeOperation message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeOperation} ProbeOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperation.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeOperation();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.id = reader.string();
                            break;
                        }
                    case 2: {
                            message.probeUpgrade = $root.enoki.v1.ProbeUpgradeOperation.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 3: {
                            message.probeUninstall = $root.enoki.v1.ProbeUninstallOperation.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeOperation message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeOperation} ProbeOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperation.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeOperation message.
             * @function verify
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeOperation.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                let properties = {};
                if (message.id != null && Object.hasOwnProperty.call(message, "id"))
                    if (!$util.isString(message.id))
                        return "id: string expected";
                if (message.probeUpgrade != null && Object.hasOwnProperty.call(message, "probeUpgrade")) {
                    properties.operation = 1;
                    {
                        let error = $root.enoki.v1.ProbeUpgradeOperation.verify(message.probeUpgrade, long + 1);
                        if (error)
                            return "probeUpgrade." + error;
                    }
                }
                if (message.probeUninstall != null && Object.hasOwnProperty.call(message, "probeUninstall")) {
                    if (properties.operation === 1)
                        return "operation: multiple values";
                    properties.operation = 1;
                    {
                        let error = $root.enoki.v1.ProbeUninstallOperation.verify(message.probeUninstall, long + 1);
                        if (error)
                            return "probeUninstall." + error;
                    }
                }
                return null;
            };

            /**
             * Creates a ProbeOperation message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeOperation} ProbeOperation
             */
            ProbeOperation.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeOperation)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeOperation: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeOperation();
                if (object.id != null)
                    message.id = String(object.id);
                if (object.probeUpgrade != null) {
                    if (!$util.isObject(object.probeUpgrade))
                        throw TypeError(".enoki.v1.ProbeOperation.probeUpgrade: object expected");
                    message.probeUpgrade = $root.enoki.v1.ProbeUpgradeOperation.fromObject(object.probeUpgrade, long + 1);
                }
                if (object.probeUninstall != null) {
                    if (!$util.isObject(object.probeUninstall))
                        throw TypeError(".enoki.v1.ProbeOperation.probeUninstall: object expected");
                    message.probeUninstall = $root.enoki.v1.ProbeUninstallOperation.fromObject(object.probeUninstall, long + 1);
                }
                return message;
            };

            /**
             * Creates a plain object from a ProbeOperation message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {enoki.v1.ProbeOperation} message ProbeOperation
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeOperation.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults)
                    object.id = "";
                if (message.id != null && Object.hasOwnProperty.call(message, "id"))
                    object.id = message.id;
                if (message.probeUpgrade != null && Object.hasOwnProperty.call(message, "probeUpgrade")) {
                    object.probeUpgrade = $root.enoki.v1.ProbeUpgradeOperation.toObject(message.probeUpgrade, options, q + 1);
                    if (options.oneofs)
                        object.operation = "probeUpgrade";
                }
                if (message.probeUninstall != null && Object.hasOwnProperty.call(message, "probeUninstall")) {
                    object.probeUninstall = $root.enoki.v1.ProbeUninstallOperation.toObject(message.probeUninstall, options, q + 1);
                    if (options.oneofs)
                        object.operation = "probeUninstall";
                }
                return object;
            };

            /**
             * Converts this ProbeOperation to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeOperation
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeOperation.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeOperation
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeOperation
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeOperation.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeOperation";
            };

            return ProbeOperation;
        })();

        v1.ProbeUpgradeOperation = (function() {

            /**
             * Properties of a ProbeUpgradeOperation.
             * @memberof enoki.v1
             * @interface IProbeUpgradeOperation
             * @property {string|null} [currentProbeVersion] ProbeUpgradeOperation currentProbeVersion
             * @property {string|null} [targetProbeVersion] ProbeUpgradeOperation targetProbeVersion
             * @property {string|null} [operationToken] ProbeUpgradeOperation operationToken
             */

            /**
             * Constructs a new ProbeUpgradeOperation.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeUpgradeOperation.
             * @implements IProbeUpgradeOperation
             * @constructor
             * @param {enoki.v1.IProbeUpgradeOperation=} [properties] Properties to set
             */
            function ProbeUpgradeOperation(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeUpgradeOperation currentProbeVersion.
             * @member {string} currentProbeVersion
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @instance
             */
            ProbeUpgradeOperation.prototype.currentProbeVersion = "";

            /**
             * ProbeUpgradeOperation targetProbeVersion.
             * @member {string} targetProbeVersion
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @instance
             */
            ProbeUpgradeOperation.prototype.targetProbeVersion = "";

            /**
             * ProbeUpgradeOperation operationToken.
             * @member {string} operationToken
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @instance
             */
            ProbeUpgradeOperation.prototype.operationToken = "";

            /**
             * Creates a new ProbeUpgradeOperation instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {enoki.v1.IProbeUpgradeOperation=} [properties] Properties to set
             * @returns {enoki.v1.ProbeUpgradeOperation} ProbeUpgradeOperation instance
             */
            ProbeUpgradeOperation.create = function create(properties) {
                return new ProbeUpgradeOperation(properties);
            };

            /**
             * Encodes the specified ProbeUpgradeOperation message. Does not implicitly {@link enoki.v1.ProbeUpgradeOperation.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {enoki.v1.IProbeUpgradeOperation} message ProbeUpgradeOperation message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeUpgradeOperation.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.currentProbeVersion != null && Object.hasOwnProperty.call(message, "currentProbeVersion"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.currentProbeVersion);
                if (message.targetProbeVersion != null && Object.hasOwnProperty.call(message, "targetProbeVersion"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.targetProbeVersion);
                if (message.operationToken != null && Object.hasOwnProperty.call(message, "operationToken"))
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.operationToken);
                return writer;
            };

            /**
             * Encodes the specified ProbeUpgradeOperation message, length delimited. Does not implicitly {@link enoki.v1.ProbeUpgradeOperation.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {enoki.v1.IProbeUpgradeOperation} message ProbeUpgradeOperation message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeUpgradeOperation.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeUpgradeOperation message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeUpgradeOperation} ProbeUpgradeOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeUpgradeOperation.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeUpgradeOperation();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.currentProbeVersion = reader.string();
                            break;
                        }
                    case 2: {
                            message.targetProbeVersion = reader.string();
                            break;
                        }
                    case 3: {
                            message.operationToken = reader.string();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeUpgradeOperation message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeUpgradeOperation} ProbeUpgradeOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeUpgradeOperation.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeUpgradeOperation message.
             * @function verify
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeUpgradeOperation.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.currentProbeVersion != null && Object.hasOwnProperty.call(message, "currentProbeVersion"))
                    if (!$util.isString(message.currentProbeVersion))
                        return "currentProbeVersion: string expected";
                if (message.targetProbeVersion != null && Object.hasOwnProperty.call(message, "targetProbeVersion"))
                    if (!$util.isString(message.targetProbeVersion))
                        return "targetProbeVersion: string expected";
                if (message.operationToken != null && Object.hasOwnProperty.call(message, "operationToken"))
                    if (!$util.isString(message.operationToken))
                        return "operationToken: string expected";
                return null;
            };

            /**
             * Creates a ProbeUpgradeOperation message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeUpgradeOperation} ProbeUpgradeOperation
             */
            ProbeUpgradeOperation.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeUpgradeOperation)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeUpgradeOperation: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeUpgradeOperation();
                if (object.currentProbeVersion != null)
                    message.currentProbeVersion = String(object.currentProbeVersion);
                if (object.targetProbeVersion != null)
                    message.targetProbeVersion = String(object.targetProbeVersion);
                if (object.operationToken != null)
                    message.operationToken = String(object.operationToken);
                return message;
            };

            /**
             * Creates a plain object from a ProbeUpgradeOperation message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {enoki.v1.ProbeUpgradeOperation} message ProbeUpgradeOperation
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeUpgradeOperation.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.currentProbeVersion = "";
                    object.targetProbeVersion = "";
                    object.operationToken = "";
                }
                if (message.currentProbeVersion != null && Object.hasOwnProperty.call(message, "currentProbeVersion"))
                    object.currentProbeVersion = message.currentProbeVersion;
                if (message.targetProbeVersion != null && Object.hasOwnProperty.call(message, "targetProbeVersion"))
                    object.targetProbeVersion = message.targetProbeVersion;
                if (message.operationToken != null && Object.hasOwnProperty.call(message, "operationToken"))
                    object.operationToken = message.operationToken;
                return object;
            };

            /**
             * Converts this ProbeUpgradeOperation to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeUpgradeOperation.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeUpgradeOperation
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeUpgradeOperation
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeUpgradeOperation.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeUpgradeOperation";
            };

            return ProbeUpgradeOperation;
        })();

        v1.ProbeUninstallOperation = (function() {

            /**
             * Properties of a ProbeUninstallOperation.
             * @memberof enoki.v1
             * @interface IProbeUninstallOperation
             * @property {string|null} [operationToken] ProbeUninstallOperation operationToken
             */

            /**
             * Constructs a new ProbeUninstallOperation.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeUninstallOperation.
             * @implements IProbeUninstallOperation
             * @constructor
             * @param {enoki.v1.IProbeUninstallOperation=} [properties] Properties to set
             */
            function ProbeUninstallOperation(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeUninstallOperation operationToken.
             * @member {string} operationToken
             * @memberof enoki.v1.ProbeUninstallOperation
             * @instance
             */
            ProbeUninstallOperation.prototype.operationToken = "";

            /**
             * Creates a new ProbeUninstallOperation instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {enoki.v1.IProbeUninstallOperation=} [properties] Properties to set
             * @returns {enoki.v1.ProbeUninstallOperation} ProbeUninstallOperation instance
             */
            ProbeUninstallOperation.create = function create(properties) {
                return new ProbeUninstallOperation(properties);
            };

            /**
             * Encodes the specified ProbeUninstallOperation message. Does not implicitly {@link enoki.v1.ProbeUninstallOperation.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {enoki.v1.IProbeUninstallOperation} message ProbeUninstallOperation message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeUninstallOperation.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.operationToken != null && Object.hasOwnProperty.call(message, "operationToken"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.operationToken);
                return writer;
            };

            /**
             * Encodes the specified ProbeUninstallOperation message, length delimited. Does not implicitly {@link enoki.v1.ProbeUninstallOperation.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {enoki.v1.IProbeUninstallOperation} message ProbeUninstallOperation message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeUninstallOperation.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeUninstallOperation message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeUninstallOperation} ProbeUninstallOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeUninstallOperation.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeUninstallOperation();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.operationToken = reader.string();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeUninstallOperation message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeUninstallOperation} ProbeUninstallOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeUninstallOperation.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeUninstallOperation message.
             * @function verify
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeUninstallOperation.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.operationToken != null && Object.hasOwnProperty.call(message, "operationToken"))
                    if (!$util.isString(message.operationToken))
                        return "operationToken: string expected";
                return null;
            };

            /**
             * Creates a ProbeUninstallOperation message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeUninstallOperation} ProbeUninstallOperation
             */
            ProbeUninstallOperation.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeUninstallOperation)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeUninstallOperation: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeUninstallOperation();
                if (object.operationToken != null)
                    message.operationToken = String(object.operationToken);
                return message;
            };

            /**
             * Creates a plain object from a ProbeUninstallOperation message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {enoki.v1.ProbeUninstallOperation} message ProbeUninstallOperation
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeUninstallOperation.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults)
                    object.operationToken = "";
                if (message.operationToken != null && Object.hasOwnProperty.call(message, "operationToken"))
                    object.operationToken = message.operationToken;
                return object;
            };

            /**
             * Converts this ProbeUninstallOperation to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeUninstallOperation
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeUninstallOperation.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeUninstallOperation
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeUninstallOperation
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeUninstallOperation.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeUninstallOperation";
            };

            return ProbeUninstallOperation;
        })();

        v1.ProbeOperationAcknowledgement = (function() {

            /**
             * Properties of a ProbeOperationAcknowledgement.
             * @memberof enoki.v1
             * @interface IProbeOperationAcknowledgement
             * @property {string|null} [operationId] ProbeOperationAcknowledgement operationId
             */

            /**
             * Constructs a new ProbeOperationAcknowledgement.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeOperationAcknowledgement.
             * @implements IProbeOperationAcknowledgement
             * @constructor
             * @param {enoki.v1.IProbeOperationAcknowledgement=} [properties] Properties to set
             */
            function ProbeOperationAcknowledgement(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeOperationAcknowledgement operationId.
             * @member {string} operationId
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @instance
             */
            ProbeOperationAcknowledgement.prototype.operationId = "";

            /**
             * Creates a new ProbeOperationAcknowledgement instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {enoki.v1.IProbeOperationAcknowledgement=} [properties] Properties to set
             * @returns {enoki.v1.ProbeOperationAcknowledgement} ProbeOperationAcknowledgement instance
             */
            ProbeOperationAcknowledgement.create = function create(properties) {
                return new ProbeOperationAcknowledgement(properties);
            };

            /**
             * Encodes the specified ProbeOperationAcknowledgement message. Does not implicitly {@link enoki.v1.ProbeOperationAcknowledgement.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {enoki.v1.IProbeOperationAcknowledgement} message ProbeOperationAcknowledgement message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationAcknowledgement.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.operationId != null && Object.hasOwnProperty.call(message, "operationId"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.operationId);
                return writer;
            };

            /**
             * Encodes the specified ProbeOperationAcknowledgement message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationAcknowledgement.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {enoki.v1.IProbeOperationAcknowledgement} message ProbeOperationAcknowledgement message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationAcknowledgement.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeOperationAcknowledgement message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeOperationAcknowledgement} ProbeOperationAcknowledgement
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationAcknowledgement.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeOperationAcknowledgement();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.operationId = reader.string();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeOperationAcknowledgement message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeOperationAcknowledgement} ProbeOperationAcknowledgement
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationAcknowledgement.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeOperationAcknowledgement message.
             * @function verify
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeOperationAcknowledgement.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.operationId != null && Object.hasOwnProperty.call(message, "operationId"))
                    if (!$util.isString(message.operationId))
                        return "operationId: string expected";
                return null;
            };

            /**
             * Creates a ProbeOperationAcknowledgement message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeOperationAcknowledgement} ProbeOperationAcknowledgement
             */
            ProbeOperationAcknowledgement.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeOperationAcknowledgement)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeOperationAcknowledgement: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeOperationAcknowledgement();
                if (object.operationId != null)
                    message.operationId = String(object.operationId);
                return message;
            };

            /**
             * Creates a plain object from a ProbeOperationAcknowledgement message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {enoki.v1.ProbeOperationAcknowledgement} message ProbeOperationAcknowledgement
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeOperationAcknowledgement.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults)
                    object.operationId = "";
                if (message.operationId != null && Object.hasOwnProperty.call(message, "operationId"))
                    object.operationId = message.operationId;
                return object;
            };

            /**
             * Converts this ProbeOperationAcknowledgement to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeOperationAcknowledgement.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeOperationAcknowledgement
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeOperationAcknowledgement
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeOperationAcknowledgement.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeOperationAcknowledgement";
            };

            return ProbeOperationAcknowledgement;
        })();

        v1.ProbeOperationStatus = (function() {

            /**
             * Properties of a ProbeOperationStatus.
             * @memberof enoki.v1
             * @interface IProbeOperationStatus
             * @property {string|null} [operationId] ProbeOperationStatus operationId
             * @property {enoki.v1.IProbeOperationRunning|null} [running] ProbeOperationStatus running
             * @property {enoki.v1.IProbeOperationFailed|null} [failed] ProbeOperationStatus failed
             * @property {enoki.v1.IProbeOperationSucceeded|null} [succeeded] ProbeOperationStatus succeeded
             */

            /**
             * Constructs a new ProbeOperationStatus.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeOperationStatus.
             * @implements IProbeOperationStatus
             * @constructor
             * @param {enoki.v1.IProbeOperationStatus=} [properties] Properties to set
             */
            function ProbeOperationStatus(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeOperationStatus operationId.
             * @member {string} operationId
             * @memberof enoki.v1.ProbeOperationStatus
             * @instance
             */
            ProbeOperationStatus.prototype.operationId = "";

            /**
             * ProbeOperationStatus running.
             * @member {enoki.v1.IProbeOperationRunning|null|undefined} running
             * @memberof enoki.v1.ProbeOperationStatus
             * @instance
             */
            ProbeOperationStatus.prototype.running = null;

            /**
             * ProbeOperationStatus failed.
             * @member {enoki.v1.IProbeOperationFailed|null|undefined} failed
             * @memberof enoki.v1.ProbeOperationStatus
             * @instance
             */
            ProbeOperationStatus.prototype.failed = null;

            /**
             * ProbeOperationStatus succeeded.
             * @member {enoki.v1.IProbeOperationSucceeded|null|undefined} succeeded
             * @memberof enoki.v1.ProbeOperationStatus
             * @instance
             */
            ProbeOperationStatus.prototype.succeeded = null;

            // OneOf field names bound to virtual getters and setters
            let $oneOfFields;

            /**
             * ProbeOperationStatus status.
             * @member {"running"|"failed"|"succeeded"|undefined} status
             * @memberof enoki.v1.ProbeOperationStatus
             * @instance
             */
            Object.defineProperty(ProbeOperationStatus.prototype, "status", {
                get: $util.oneOfGetter($oneOfFields = ["running", "failed", "succeeded"]),
                set: $util.oneOfSetter($oneOfFields)
            });

            /**
             * Creates a new ProbeOperationStatus instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {enoki.v1.IProbeOperationStatus=} [properties] Properties to set
             * @returns {enoki.v1.ProbeOperationStatus} ProbeOperationStatus instance
             */
            ProbeOperationStatus.create = function create(properties) {
                return new ProbeOperationStatus(properties);
            };

            /**
             * Encodes the specified ProbeOperationStatus message. Does not implicitly {@link enoki.v1.ProbeOperationStatus.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {enoki.v1.IProbeOperationStatus} message ProbeOperationStatus message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationStatus.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.operationId != null && Object.hasOwnProperty.call(message, "operationId"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.operationId);
                if (message.running != null && Object.hasOwnProperty.call(message, "running"))
                    $root.enoki.v1.ProbeOperationRunning.encode(message.running, writer.uint32(/* id 2, wireType 2 =*/18).fork(), q + 1).ldelim();
                if (message.failed != null && Object.hasOwnProperty.call(message, "failed"))
                    $root.enoki.v1.ProbeOperationFailed.encode(message.failed, writer.uint32(/* id 3, wireType 2 =*/26).fork(), q + 1).ldelim();
                if (message.succeeded != null && Object.hasOwnProperty.call(message, "succeeded"))
                    $root.enoki.v1.ProbeOperationSucceeded.encode(message.succeeded, writer.uint32(/* id 4, wireType 2 =*/34).fork(), q + 1).ldelim();
                return writer;
            };

            /**
             * Encodes the specified ProbeOperationStatus message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationStatus.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {enoki.v1.IProbeOperationStatus} message ProbeOperationStatus message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationStatus.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeOperationStatus message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeOperationStatus} ProbeOperationStatus
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationStatus.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeOperationStatus();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.operationId = reader.string();
                            break;
                        }
                    case 2: {
                            message.running = $root.enoki.v1.ProbeOperationRunning.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 3: {
                            message.failed = $root.enoki.v1.ProbeOperationFailed.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    case 4: {
                            message.succeeded = $root.enoki.v1.ProbeOperationSucceeded.decode(reader, reader.uint32(), undefined, long + 1);
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeOperationStatus message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeOperationStatus} ProbeOperationStatus
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationStatus.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeOperationStatus message.
             * @function verify
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeOperationStatus.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                let properties = {};
                if (message.operationId != null && Object.hasOwnProperty.call(message, "operationId"))
                    if (!$util.isString(message.operationId))
                        return "operationId: string expected";
                if (message.running != null && Object.hasOwnProperty.call(message, "running")) {
                    properties.status = 1;
                    {
                        let error = $root.enoki.v1.ProbeOperationRunning.verify(message.running, long + 1);
                        if (error)
                            return "running." + error;
                    }
                }
                if (message.failed != null && Object.hasOwnProperty.call(message, "failed")) {
                    if (properties.status === 1)
                        return "status: multiple values";
                    properties.status = 1;
                    {
                        let error = $root.enoki.v1.ProbeOperationFailed.verify(message.failed, long + 1);
                        if (error)
                            return "failed." + error;
                    }
                }
                if (message.succeeded != null && Object.hasOwnProperty.call(message, "succeeded")) {
                    if (properties.status === 1)
                        return "status: multiple values";
                    properties.status = 1;
                    {
                        let error = $root.enoki.v1.ProbeOperationSucceeded.verify(message.succeeded, long + 1);
                        if (error)
                            return "succeeded." + error;
                    }
                }
                return null;
            };

            /**
             * Creates a ProbeOperationStatus message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeOperationStatus} ProbeOperationStatus
             */
            ProbeOperationStatus.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeOperationStatus)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeOperationStatus: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeOperationStatus();
                if (object.operationId != null)
                    message.operationId = String(object.operationId);
                if (object.running != null) {
                    if (!$util.isObject(object.running))
                        throw TypeError(".enoki.v1.ProbeOperationStatus.running: object expected");
                    message.running = $root.enoki.v1.ProbeOperationRunning.fromObject(object.running, long + 1);
                }
                if (object.failed != null) {
                    if (!$util.isObject(object.failed))
                        throw TypeError(".enoki.v1.ProbeOperationStatus.failed: object expected");
                    message.failed = $root.enoki.v1.ProbeOperationFailed.fromObject(object.failed, long + 1);
                }
                if (object.succeeded != null) {
                    if (!$util.isObject(object.succeeded))
                        throw TypeError(".enoki.v1.ProbeOperationStatus.succeeded: object expected");
                    message.succeeded = $root.enoki.v1.ProbeOperationSucceeded.fromObject(object.succeeded, long + 1);
                }
                return message;
            };

            /**
             * Creates a plain object from a ProbeOperationStatus message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {enoki.v1.ProbeOperationStatus} message ProbeOperationStatus
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeOperationStatus.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults)
                    object.operationId = "";
                if (message.operationId != null && Object.hasOwnProperty.call(message, "operationId"))
                    object.operationId = message.operationId;
                if (message.running != null && Object.hasOwnProperty.call(message, "running")) {
                    object.running = $root.enoki.v1.ProbeOperationRunning.toObject(message.running, options, q + 1);
                    if (options.oneofs)
                        object.status = "running";
                }
                if (message.failed != null && Object.hasOwnProperty.call(message, "failed")) {
                    object.failed = $root.enoki.v1.ProbeOperationFailed.toObject(message.failed, options, q + 1);
                    if (options.oneofs)
                        object.status = "failed";
                }
                if (message.succeeded != null && Object.hasOwnProperty.call(message, "succeeded")) {
                    object.succeeded = $root.enoki.v1.ProbeOperationSucceeded.toObject(message.succeeded, options, q + 1);
                    if (options.oneofs)
                        object.status = "succeeded";
                }
                return object;
            };

            /**
             * Converts this ProbeOperationStatus to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeOperationStatus
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeOperationStatus.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeOperationStatus
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeOperationStatus
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeOperationStatus.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeOperationStatus";
            };

            return ProbeOperationStatus;
        })();

        v1.ProbeOperationRunning = (function() {

            /**
             * Properties of a ProbeOperationRunning.
             * @memberof enoki.v1
             * @interface IProbeOperationRunning
             */

            /**
             * Constructs a new ProbeOperationRunning.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeOperationRunning.
             * @implements IProbeOperationRunning
             * @constructor
             * @param {enoki.v1.IProbeOperationRunning=} [properties] Properties to set
             */
            function ProbeOperationRunning(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * Creates a new ProbeOperationRunning instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {enoki.v1.IProbeOperationRunning=} [properties] Properties to set
             * @returns {enoki.v1.ProbeOperationRunning} ProbeOperationRunning instance
             */
            ProbeOperationRunning.create = function create(properties) {
                return new ProbeOperationRunning(properties);
            };

            /**
             * Encodes the specified ProbeOperationRunning message. Does not implicitly {@link enoki.v1.ProbeOperationRunning.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {enoki.v1.IProbeOperationRunning} message ProbeOperationRunning message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationRunning.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                return writer;
            };

            /**
             * Encodes the specified ProbeOperationRunning message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationRunning.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {enoki.v1.IProbeOperationRunning} message ProbeOperationRunning message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationRunning.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeOperationRunning message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeOperationRunning} ProbeOperationRunning
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationRunning.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeOperationRunning();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeOperationRunning message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeOperationRunning} ProbeOperationRunning
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationRunning.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeOperationRunning message.
             * @function verify
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeOperationRunning.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                return null;
            };

            /**
             * Creates a ProbeOperationRunning message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeOperationRunning} ProbeOperationRunning
             */
            ProbeOperationRunning.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeOperationRunning)
                    return object;
                return new $root.enoki.v1.ProbeOperationRunning();
            };

            /**
             * Creates a plain object from a ProbeOperationRunning message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {enoki.v1.ProbeOperationRunning} message ProbeOperationRunning
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeOperationRunning.toObject = function toObject() {
                return {};
            };

            /**
             * Converts this ProbeOperationRunning to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeOperationRunning
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeOperationRunning.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeOperationRunning
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeOperationRunning
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeOperationRunning.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeOperationRunning";
            };

            return ProbeOperationRunning;
        })();

        v1.ProbeOperationSucceeded = (function() {

            /**
             * Properties of a ProbeOperationSucceeded.
             * @memberof enoki.v1
             * @interface IProbeOperationSucceeded
             */

            /**
             * Constructs a new ProbeOperationSucceeded.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeOperationSucceeded.
             * @implements IProbeOperationSucceeded
             * @constructor
             * @param {enoki.v1.IProbeOperationSucceeded=} [properties] Properties to set
             */
            function ProbeOperationSucceeded(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * Creates a new ProbeOperationSucceeded instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {enoki.v1.IProbeOperationSucceeded=} [properties] Properties to set
             * @returns {enoki.v1.ProbeOperationSucceeded} ProbeOperationSucceeded instance
             */
            ProbeOperationSucceeded.create = function create(properties) {
                return new ProbeOperationSucceeded(properties);
            };

            /**
             * Encodes the specified ProbeOperationSucceeded message. Does not implicitly {@link enoki.v1.ProbeOperationSucceeded.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {enoki.v1.IProbeOperationSucceeded} message ProbeOperationSucceeded message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationSucceeded.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                return writer;
            };

            /**
             * Encodes the specified ProbeOperationSucceeded message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationSucceeded.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {enoki.v1.IProbeOperationSucceeded} message ProbeOperationSucceeded message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationSucceeded.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeOperationSucceeded message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeOperationSucceeded} ProbeOperationSucceeded
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationSucceeded.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeOperationSucceeded();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeOperationSucceeded message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeOperationSucceeded} ProbeOperationSucceeded
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationSucceeded.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeOperationSucceeded message.
             * @function verify
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeOperationSucceeded.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                return null;
            };

            /**
             * Creates a ProbeOperationSucceeded message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeOperationSucceeded} ProbeOperationSucceeded
             */
            ProbeOperationSucceeded.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeOperationSucceeded)
                    return object;
                return new $root.enoki.v1.ProbeOperationSucceeded();
            };

            /**
             * Creates a plain object from a ProbeOperationSucceeded message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {enoki.v1.ProbeOperationSucceeded} message ProbeOperationSucceeded
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeOperationSucceeded.toObject = function toObject() {
                return {};
            };

            /**
             * Converts this ProbeOperationSucceeded to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeOperationSucceeded.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeOperationSucceeded
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeOperationSucceeded
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeOperationSucceeded.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeOperationSucceeded";
            };

            return ProbeOperationSucceeded;
        })();

        v1.ProbeOperationFailed = (function() {

            /**
             * Properties of a ProbeOperationFailed.
             * @memberof enoki.v1
             * @interface IProbeOperationFailed
             * @property {string|null} [errorCode] ProbeOperationFailed errorCode
             * @property {string|null} [message] ProbeOperationFailed message
             */

            /**
             * Constructs a new ProbeOperationFailed.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeOperationFailed.
             * @implements IProbeOperationFailed
             * @constructor
             * @param {enoki.v1.IProbeOperationFailed=} [properties] Properties to set
             */
            function ProbeOperationFailed(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeOperationFailed errorCode.
             * @member {string} errorCode
             * @memberof enoki.v1.ProbeOperationFailed
             * @instance
             */
            ProbeOperationFailed.prototype.errorCode = "";

            /**
             * ProbeOperationFailed message.
             * @member {string} message
             * @memberof enoki.v1.ProbeOperationFailed
             * @instance
             */
            ProbeOperationFailed.prototype.message = "";

            /**
             * Creates a new ProbeOperationFailed instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {enoki.v1.IProbeOperationFailed=} [properties] Properties to set
             * @returns {enoki.v1.ProbeOperationFailed} ProbeOperationFailed instance
             */
            ProbeOperationFailed.create = function create(properties) {
                return new ProbeOperationFailed(properties);
            };

            /**
             * Encodes the specified ProbeOperationFailed message. Does not implicitly {@link enoki.v1.ProbeOperationFailed.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {enoki.v1.IProbeOperationFailed} message ProbeOperationFailed message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationFailed.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.errorCode != null && Object.hasOwnProperty.call(message, "errorCode"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.errorCode);
                if (message.message != null && Object.hasOwnProperty.call(message, "message"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.message);
                return writer;
            };

            /**
             * Encodes the specified ProbeOperationFailed message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationFailed.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {enoki.v1.IProbeOperationFailed} message ProbeOperationFailed message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeOperationFailed.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeOperationFailed message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeOperationFailed} ProbeOperationFailed
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationFailed.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeOperationFailed();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.errorCode = reader.string();
                            break;
                        }
                    case 2: {
                            message.message = reader.string();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeOperationFailed message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeOperationFailed} ProbeOperationFailed
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeOperationFailed.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeOperationFailed message.
             * @function verify
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeOperationFailed.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.errorCode != null && Object.hasOwnProperty.call(message, "errorCode"))
                    if (!$util.isString(message.errorCode))
                        return "errorCode: string expected";
                if (message.message != null && Object.hasOwnProperty.call(message, "message"))
                    if (!$util.isString(message.message))
                        return "message: string expected";
                return null;
            };

            /**
             * Creates a ProbeOperationFailed message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeOperationFailed} ProbeOperationFailed
             */
            ProbeOperationFailed.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeOperationFailed)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeOperationFailed: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeOperationFailed();
                if (object.errorCode != null)
                    message.errorCode = String(object.errorCode);
                if (object.message != null)
                    message.message = String(object.message);
                return message;
            };

            /**
             * Creates a plain object from a ProbeOperationFailed message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {enoki.v1.ProbeOperationFailed} message ProbeOperationFailed
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeOperationFailed.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.errorCode = "";
                    object.message = "";
                }
                if (message.errorCode != null && Object.hasOwnProperty.call(message, "errorCode"))
                    object.errorCode = message.errorCode;
                if (message.message != null && Object.hasOwnProperty.call(message, "message"))
                    object.message = message.message;
                return object;
            };

            /**
             * Converts this ProbeOperationFailed to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeOperationFailed
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeOperationFailed.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeOperationFailed
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeOperationFailed
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeOperationFailed.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeOperationFailed";
            };

            return ProbeOperationFailed;
        })();

        v1.ProbeConfigurationRequest = (function() {

            /**
             * Properties of a ProbeConfigurationRequest.
             * @memberof enoki.v1
             * @interface IProbeConfigurationRequest
             * @property {string|null} [probeId] ProbeConfigurationRequest probeId
             * @property {string|null} [currentVersion] ProbeConfigurationRequest currentVersion
             */

            /**
             * Constructs a new ProbeConfigurationRequest.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeConfigurationRequest.
             * @implements IProbeConfigurationRequest
             * @constructor
             * @param {enoki.v1.IProbeConfigurationRequest=} [properties] Properties to set
             */
            function ProbeConfigurationRequest(properties) {
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeConfigurationRequest probeId.
             * @member {string} probeId
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @instance
             */
            ProbeConfigurationRequest.prototype.probeId = "";

            /**
             * ProbeConfigurationRequest currentVersion.
             * @member {string} currentVersion
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @instance
             */
            ProbeConfigurationRequest.prototype.currentVersion = "";

            /**
             * Creates a new ProbeConfigurationRequest instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {enoki.v1.IProbeConfigurationRequest=} [properties] Properties to set
             * @returns {enoki.v1.ProbeConfigurationRequest} ProbeConfigurationRequest instance
             */
            ProbeConfigurationRequest.create = function create(properties) {
                return new ProbeConfigurationRequest(properties);
            };

            /**
             * Encodes the specified ProbeConfigurationRequest message. Does not implicitly {@link enoki.v1.ProbeConfigurationRequest.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {enoki.v1.IProbeConfigurationRequest} message ProbeConfigurationRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeConfigurationRequest.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.probeId);
                if (message.currentVersion != null && Object.hasOwnProperty.call(message, "currentVersion"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.currentVersion);
                return writer;
            };

            /**
             * Encodes the specified ProbeConfigurationRequest message, length delimited. Does not implicitly {@link enoki.v1.ProbeConfigurationRequest.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {enoki.v1.IProbeConfigurationRequest} message ProbeConfigurationRequest message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeConfigurationRequest.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeConfigurationRequest message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeConfigurationRequest} ProbeConfigurationRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeConfigurationRequest.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeConfigurationRequest();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.probeId = reader.string();
                            break;
                        }
                    case 2: {
                            message.currentVersion = reader.string();
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeConfigurationRequest message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeConfigurationRequest} ProbeConfigurationRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeConfigurationRequest.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeConfigurationRequest message.
             * @function verify
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeConfigurationRequest.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    if (!$util.isString(message.probeId))
                        return "probeId: string expected";
                if (message.currentVersion != null && Object.hasOwnProperty.call(message, "currentVersion"))
                    if (!$util.isString(message.currentVersion))
                        return "currentVersion: string expected";
                return null;
            };

            /**
             * Creates a ProbeConfigurationRequest message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeConfigurationRequest} ProbeConfigurationRequest
             */
            ProbeConfigurationRequest.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeConfigurationRequest)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeConfigurationRequest: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeConfigurationRequest();
                if (object.probeId != null)
                    message.probeId = String(object.probeId);
                if (object.currentVersion != null)
                    message.currentVersion = String(object.currentVersion);
                return message;
            };

            /**
             * Creates a plain object from a ProbeConfigurationRequest message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {enoki.v1.ProbeConfigurationRequest} message ProbeConfigurationRequest
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeConfigurationRequest.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.defaults) {
                    object.probeId = "";
                    object.currentVersion = "";
                }
                if (message.probeId != null && Object.hasOwnProperty.call(message, "probeId"))
                    object.probeId = message.probeId;
                if (message.currentVersion != null && Object.hasOwnProperty.call(message, "currentVersion"))
                    object.currentVersion = message.currentVersion;
                return object;
            };

            /**
             * Converts this ProbeConfigurationRequest to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeConfigurationRequest.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeConfigurationRequest
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeConfigurationRequest
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeConfigurationRequest.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeConfigurationRequest";
            };

            return ProbeConfigurationRequest;
        })();

        v1.ProbeConfigurationResponse = (function() {

            /**
             * Properties of a ProbeConfigurationResponse.
             * @memberof enoki.v1
             * @interface IProbeConfigurationResponse
             * @property {string|null} [version] ProbeConfigurationResponse version
             * @property {number|null} [metricsCollectionIntervalSeconds] ProbeConfigurationResponse metricsCollectionIntervalSeconds
             * @property {Array.<string>|null} [enabledCollectorIds] ProbeConfigurationResponse enabledCollectorIds
             */

            /**
             * Constructs a new ProbeConfigurationResponse.
             * @memberof enoki.v1
             * @classdesc Represents a ProbeConfigurationResponse.
             * @implements IProbeConfigurationResponse
             * @constructor
             * @param {enoki.v1.IProbeConfigurationResponse=} [properties] Properties to set
             */
            function ProbeConfigurationResponse(properties) {
                this.enabledCollectorIds = [];
                if (properties)
                    for (let keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * ProbeConfigurationResponse version.
             * @member {string} version
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @instance
             */
            ProbeConfigurationResponse.prototype.version = "";

            /**
             * ProbeConfigurationResponse metricsCollectionIntervalSeconds.
             * @member {number} metricsCollectionIntervalSeconds
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @instance
             */
            ProbeConfigurationResponse.prototype.metricsCollectionIntervalSeconds = 0;

            /**
             * ProbeConfigurationResponse enabledCollectorIds.
             * @member {Array.<string>} enabledCollectorIds
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @instance
             */
            ProbeConfigurationResponse.prototype.enabledCollectorIds = $util.emptyArray;

            /**
             * Creates a new ProbeConfigurationResponse instance using the specified properties.
             * @function create
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {enoki.v1.IProbeConfigurationResponse=} [properties] Properties to set
             * @returns {enoki.v1.ProbeConfigurationResponse} ProbeConfigurationResponse instance
             */
            ProbeConfigurationResponse.create = function create(properties) {
                return new ProbeConfigurationResponse(properties);
            };

            /**
             * Encodes the specified ProbeConfigurationResponse message. Does not implicitly {@link enoki.v1.ProbeConfigurationResponse.verify|verify} messages.
             * @function encode
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {enoki.v1.IProbeConfigurationResponse} message ProbeConfigurationResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeConfigurationResponse.encode = function encode(message, writer, q) {
                if (!writer)
                    writer = $Writer.create();
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                if (message.version != null && Object.hasOwnProperty.call(message, "version"))
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.version);
                if (message.metricsCollectionIntervalSeconds != null && Object.hasOwnProperty.call(message, "metricsCollectionIntervalSeconds"))
                    writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.metricsCollectionIntervalSeconds);
                if (message.enabledCollectorIds != null && message.enabledCollectorIds.length)
                    for (let i = 0; i < message.enabledCollectorIds.length; ++i)
                        writer.uint32(/* id 10, wireType 2 =*/82).string(message.enabledCollectorIds[i]);
                return writer;
            };

            /**
             * Encodes the specified ProbeConfigurationResponse message, length delimited. Does not implicitly {@link enoki.v1.ProbeConfigurationResponse.verify|verify} messages.
             * @function encodeDelimited
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {enoki.v1.IProbeConfigurationResponse} message ProbeConfigurationResponse message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            ProbeConfigurationResponse.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
            };

            /**
             * Decodes a ProbeConfigurationResponse message from the specified reader or buffer.
             * @function decode
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {enoki.v1.ProbeConfigurationResponse} ProbeConfigurationResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeConfigurationResponse.decode = function decode(reader, length, error, long) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (long === undefined)
                    long = 0;
                if (long > $Reader.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let end = length === undefined ? reader.len : reader.pos + length, message = new $root.enoki.v1.ProbeConfigurationResponse();
                while (reader.pos < end) {
                    let tag = reader.uint32();
                    if (tag === error)
                        break;
                    switch (tag >>> 3) {
                    case 1: {
                            message.version = reader.string();
                            break;
                        }
                    case 2: {
                            message.metricsCollectionIntervalSeconds = reader.uint32();
                            break;
                        }
                    case 10: {
                            if (!(message.enabledCollectorIds && message.enabledCollectorIds.length))
                                message.enabledCollectorIds = [];
                            message.enabledCollectorIds.push(reader.string());
                            break;
                        }
                    default:
                        reader.skipType(tag & 7, long);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a ProbeConfigurationResponse message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {enoki.v1.ProbeConfigurationResponse} ProbeConfigurationResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            ProbeConfigurationResponse.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a ProbeConfigurationResponse message.
             * @function verify
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            ProbeConfigurationResponse.verify = function verify(message, long) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    return "maximum nesting depth exceeded";
                if (message.version != null && Object.hasOwnProperty.call(message, "version"))
                    if (!$util.isString(message.version))
                        return "version: string expected";
                if (message.metricsCollectionIntervalSeconds != null && Object.hasOwnProperty.call(message, "metricsCollectionIntervalSeconds"))
                    if (!$util.isInteger(message.metricsCollectionIntervalSeconds))
                        return "metricsCollectionIntervalSeconds: integer expected";
                if (message.enabledCollectorIds != null && Object.hasOwnProperty.call(message, "enabledCollectorIds")) {
                    if (!Array.isArray(message.enabledCollectorIds))
                        return "enabledCollectorIds: array expected";
                    for (let i = 0; i < message.enabledCollectorIds.length; ++i)
                        if (!$util.isString(message.enabledCollectorIds[i]))
                            return "enabledCollectorIds: string[] expected";
                }
                return null;
            };

            /**
             * Creates a ProbeConfigurationResponse message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {enoki.v1.ProbeConfigurationResponse} ProbeConfigurationResponse
             */
            ProbeConfigurationResponse.fromObject = function fromObject(object, long) {
                if (object instanceof $root.enoki.v1.ProbeConfigurationResponse)
                    return object;
                if (!$util.isObject(object))
                    throw TypeError(".enoki.v1.ProbeConfigurationResponse: object expected");
                if (long === undefined)
                    long = 0;
                if (long > $util.recursionLimit)
                    throw Error("maximum nesting depth exceeded");
                let message = new $root.enoki.v1.ProbeConfigurationResponse();
                if (object.version != null)
                    message.version = String(object.version);
                if (object.metricsCollectionIntervalSeconds != null)
                    message.metricsCollectionIntervalSeconds = object.metricsCollectionIntervalSeconds >>> 0;
                if (object.enabledCollectorIds) {
                    if (!Array.isArray(object.enabledCollectorIds))
                        throw TypeError(".enoki.v1.ProbeConfigurationResponse.enabledCollectorIds: array expected");
                    message.enabledCollectorIds = [];
                    for (let i = 0; i < object.enabledCollectorIds.length; ++i)
                        message.enabledCollectorIds[i] = String(object.enabledCollectorIds[i]);
                }
                return message;
            };

            /**
             * Creates a plain object from a ProbeConfigurationResponse message. Also converts values to other types if specified.
             * @function toObject
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {enoki.v1.ProbeConfigurationResponse} message ProbeConfigurationResponse
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            ProbeConfigurationResponse.toObject = function toObject(message, options, q) {
                if (!options)
                    options = {};
                if (q === undefined)
                    q = 0;
                if (q > $util.recursionLimit)
                    throw Error("max depth exceeded");
                let object = {};
                if (options.arrays || options.defaults)
                    object.enabledCollectorIds = [];
                if (options.defaults) {
                    object.version = "";
                    object.metricsCollectionIntervalSeconds = 0;
                }
                if (message.version != null && Object.hasOwnProperty.call(message, "version"))
                    object.version = message.version;
                if (message.metricsCollectionIntervalSeconds != null && Object.hasOwnProperty.call(message, "metricsCollectionIntervalSeconds"))
                    object.metricsCollectionIntervalSeconds = message.metricsCollectionIntervalSeconds;
                if (message.enabledCollectorIds && message.enabledCollectorIds.length) {
                    object.enabledCollectorIds = [];
                    for (let j = 0; j < message.enabledCollectorIds.length; ++j)
                        object.enabledCollectorIds[j] = message.enabledCollectorIds[j];
                }
                return object;
            };

            /**
             * Converts this ProbeConfigurationResponse to JSON.
             * @function toJSON
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            ProbeConfigurationResponse.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            /**
             * Gets the default type url for ProbeConfigurationResponse
             * @function getTypeUrl
             * @memberof enoki.v1.ProbeConfigurationResponse
             * @static
             * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns {string} The default type url
             */
            ProbeConfigurationResponse.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                if (typeUrlPrefix === undefined) {
                    typeUrlPrefix = "type.googleapis.com";
                }
                return typeUrlPrefix + "/enoki.v1.ProbeConfigurationResponse";
            };

            return ProbeConfigurationResponse;
        })();

        return v1;
    })();

    return enoki;
})();

export { $root as default };
