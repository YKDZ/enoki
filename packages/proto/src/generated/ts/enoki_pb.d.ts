import * as $protobuf from "protobufjs";
import Long = require("long");
/** Namespace enoki. */
export namespace enoki {

    /** Namespace v1. */
    namespace v1 {

        /** Properties of a ProbeRegistrationRequest. */
        interface IProbeRegistrationRequest {

            /** ProbeRegistrationRequest enrollmentToken */
            enrollmentToken?: (string|null);

            /** ProbeRegistrationRequest inventory */
            inventory?: (enoki.v1.IInventory|null);

            /** ProbeRegistrationRequest probePublicKeyPem */
            probePublicKeyPem?: (string|null);
        }

        /** Represents a ProbeRegistrationRequest. */
        class ProbeRegistrationRequest implements IProbeRegistrationRequest {

            /**
             * Constructs a new ProbeRegistrationRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeRegistrationRequest);

            /** ProbeRegistrationRequest enrollmentToken. */
            public enrollmentToken: string;

            /** ProbeRegistrationRequest inventory. */
            public inventory?: (enoki.v1.IInventory|null);

            /** ProbeRegistrationRequest probePublicKeyPem. */
            public probePublicKeyPem: string;

            /**
             * Creates a new ProbeRegistrationRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeRegistrationRequest instance
             */
            public static create(properties?: enoki.v1.IProbeRegistrationRequest): enoki.v1.ProbeRegistrationRequest;

            /**
             * Encodes the specified ProbeRegistrationRequest message. Does not implicitly {@link enoki.v1.ProbeRegistrationRequest.verify|verify} messages.
             * @param message ProbeRegistrationRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeRegistrationRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeRegistrationRequest message, length delimited. Does not implicitly {@link enoki.v1.ProbeRegistrationRequest.verify|verify} messages.
             * @param message ProbeRegistrationRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeRegistrationRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeRegistrationRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeRegistrationRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeRegistrationRequest;

            /**
             * Decodes a ProbeRegistrationRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeRegistrationRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeRegistrationRequest;

            /**
             * Verifies a ProbeRegistrationRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeRegistrationRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeRegistrationRequest
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeRegistrationRequest;

            /**
             * Creates a plain object from a ProbeRegistrationRequest message. Also converts values to other types if specified.
             * @param message ProbeRegistrationRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeRegistrationRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeRegistrationRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeRegistrationRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeRegistrationResponse. */
        interface IProbeRegistrationResponse {

            /** ProbeRegistrationResponse probeId */
            probeId?: (string|null);

            /** ProbeRegistrationResponse probeSecret */
            probeSecret?: (string|null);

            /** ProbeRegistrationResponse serverTimeMs */
            serverTimeMs?: (Long|null);

            /** ProbeRegistrationResponse initialConfiguration */
            initialConfiguration?: (enoki.v1.IProbeConfigurationResponse|null);
        }

        /** Represents a ProbeRegistrationResponse. */
        class ProbeRegistrationResponse implements IProbeRegistrationResponse {

            /**
             * Constructs a new ProbeRegistrationResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeRegistrationResponse);

            /** ProbeRegistrationResponse probeId. */
            public probeId: string;

            /** ProbeRegistrationResponse probeSecret. */
            public probeSecret: string;

            /** ProbeRegistrationResponse serverTimeMs. */
            public serverTimeMs: Long;

            /** ProbeRegistrationResponse initialConfiguration. */
            public initialConfiguration?: (enoki.v1.IProbeConfigurationResponse|null);

            /**
             * Creates a new ProbeRegistrationResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeRegistrationResponse instance
             */
            public static create(properties?: enoki.v1.IProbeRegistrationResponse): enoki.v1.ProbeRegistrationResponse;

            /**
             * Encodes the specified ProbeRegistrationResponse message. Does not implicitly {@link enoki.v1.ProbeRegistrationResponse.verify|verify} messages.
             * @param message ProbeRegistrationResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeRegistrationResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeRegistrationResponse message, length delimited. Does not implicitly {@link enoki.v1.ProbeRegistrationResponse.verify|verify} messages.
             * @param message ProbeRegistrationResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeRegistrationResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeRegistrationResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeRegistrationResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeRegistrationResponse;

            /**
             * Decodes a ProbeRegistrationResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeRegistrationResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeRegistrationResponse;

            /**
             * Verifies a ProbeRegistrationResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeRegistrationResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeRegistrationResponse
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeRegistrationResponse;

            /**
             * Creates a plain object from a ProbeRegistrationResponse message. Also converts values to other types if specified.
             * @param message ProbeRegistrationResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeRegistrationResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeRegistrationResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeRegistrationResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeReportRequest. */
        interface IProbeReportRequest {

            /** ProbeReportRequest probeId */
            probeId?: (string|null);

            /** ProbeReportRequest bootId */
            bootId?: (string|null);

            /** ProbeReportRequest sequenceStart */
            sequenceStart?: (Long|null);

            /** ProbeReportRequest sequenceEnd */
            sequenceEnd?: (Long|null);

            /** ProbeReportRequest inventoryHash */
            inventoryHash?: (string|null);

            /** ProbeReportRequest probeConfigurationVersion */
            probeConfigurationVersion?: (string|null);

            /** ProbeReportRequest metrics */
            metrics?: (enoki.v1.IMetricSample[]|null);

            /** ProbeReportRequest inventory */
            inventory?: (enoki.v1.IInventory|null);

            /** ProbeReportRequest probeConfigurationError */
            probeConfigurationError?: (enoki.v1.IProbeConfigurationError|null);

            /** ProbeReportRequest operationAcknowledgements */
            operationAcknowledgements?: (enoki.v1.IProbeOperationAcknowledgement[]|null);

            /** ProbeReportRequest operationStatuses */
            operationStatuses?: (enoki.v1.IProbeOperationStatus[]|null);
        }

        /** Represents a ProbeReportRequest. */
        class ProbeReportRequest implements IProbeReportRequest {

            /**
             * Constructs a new ProbeReportRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeReportRequest);

            /** ProbeReportRequest probeId. */
            public probeId: string;

            /** ProbeReportRequest bootId. */
            public bootId: string;

            /** ProbeReportRequest sequenceStart. */
            public sequenceStart: Long;

            /** ProbeReportRequest sequenceEnd. */
            public sequenceEnd: Long;

            /** ProbeReportRequest inventoryHash. */
            public inventoryHash: string;

            /** ProbeReportRequest probeConfigurationVersion. */
            public probeConfigurationVersion: string;

            /** ProbeReportRequest metrics. */
            public metrics: enoki.v1.IMetricSample[];

            /** ProbeReportRequest inventory. */
            public inventory?: (enoki.v1.IInventory|null);

            /** ProbeReportRequest probeConfigurationError. */
            public probeConfigurationError?: (enoki.v1.IProbeConfigurationError|null);

            /** ProbeReportRequest operationAcknowledgements. */
            public operationAcknowledgements: enoki.v1.IProbeOperationAcknowledgement[];

            /** ProbeReportRequest operationStatuses. */
            public operationStatuses: enoki.v1.IProbeOperationStatus[];

            /**
             * Creates a new ProbeReportRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeReportRequest instance
             */
            public static create(properties?: enoki.v1.IProbeReportRequest): enoki.v1.ProbeReportRequest;

            /**
             * Encodes the specified ProbeReportRequest message. Does not implicitly {@link enoki.v1.ProbeReportRequest.verify|verify} messages.
             * @param message ProbeReportRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeReportRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeReportRequest message, length delimited. Does not implicitly {@link enoki.v1.ProbeReportRequest.verify|verify} messages.
             * @param message ProbeReportRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeReportRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeReportRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeReportRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeReportRequest;

            /**
             * Decodes a ProbeReportRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeReportRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeReportRequest;

            /**
             * Verifies a ProbeReportRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeReportRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeReportRequest
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeReportRequest;

            /**
             * Creates a plain object from a ProbeReportRequest message. Also converts values to other types if specified.
             * @param message ProbeReportRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeReportRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeReportRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeReportRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeReportResponse. */
        interface IProbeReportResponse {

            /** ProbeReportResponse acceptedSequenceEnd */
            acceptedSequenceEnd?: (Long|null);

            /** ProbeReportResponse serverTimeMs */
            serverTimeMs?: (Long|null);

            /** ProbeReportResponse currentProbeConfigurationVersion */
            currentProbeConfigurationVersion?: (string|null);

            /** ProbeReportResponse inventoryNeeded */
            inventoryNeeded?: (boolean|null);

            /** ProbeReportResponse pendingOperation */
            pendingOperation?: (enoki.v1.IProbeOperation|null);
        }

        /** Represents a ProbeReportResponse. */
        class ProbeReportResponse implements IProbeReportResponse {

            /**
             * Constructs a new ProbeReportResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeReportResponse);

            /** ProbeReportResponse acceptedSequenceEnd. */
            public acceptedSequenceEnd: Long;

            /** ProbeReportResponse serverTimeMs. */
            public serverTimeMs: Long;

            /** ProbeReportResponse currentProbeConfigurationVersion. */
            public currentProbeConfigurationVersion: string;

            /** ProbeReportResponse inventoryNeeded. */
            public inventoryNeeded: boolean;

            /** ProbeReportResponse pendingOperation. */
            public pendingOperation?: (enoki.v1.IProbeOperation|null);

            /**
             * Creates a new ProbeReportResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeReportResponse instance
             */
            public static create(properties?: enoki.v1.IProbeReportResponse): enoki.v1.ProbeReportResponse;

            /**
             * Encodes the specified ProbeReportResponse message. Does not implicitly {@link enoki.v1.ProbeReportResponse.verify|verify} messages.
             * @param message ProbeReportResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeReportResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeReportResponse message, length delimited. Does not implicitly {@link enoki.v1.ProbeReportResponse.verify|verify} messages.
             * @param message ProbeReportResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeReportResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeReportResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeReportResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeReportResponse;

            /**
             * Decodes a ProbeReportResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeReportResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeReportResponse;

            /**
             * Verifies a ProbeReportResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeReportResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeReportResponse
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeReportResponse;

            /**
             * Creates a plain object from a ProbeReportResponse message. Also converts values to other types if specified.
             * @param message ProbeReportResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeReportResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeReportResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeReportResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeConfigurationError. */
        interface IProbeConfigurationError {

            /** ProbeConfigurationError failedVersion */
            failedVersion?: (string|null);

            /** ProbeConfigurationError errorCode */
            errorCode?: (string|null);

            /** ProbeConfigurationError message */
            message?: (string|null);
        }

        /** Represents a ProbeConfigurationError. */
        class ProbeConfigurationError implements IProbeConfigurationError {

            /**
             * Constructs a new ProbeConfigurationError.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeConfigurationError);

            /** ProbeConfigurationError failedVersion. */
            public failedVersion: string;

            /** ProbeConfigurationError errorCode. */
            public errorCode: string;

            /** ProbeConfigurationError message. */
            public message: string;

            /**
             * Creates a new ProbeConfigurationError instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeConfigurationError instance
             */
            public static create(properties?: enoki.v1.IProbeConfigurationError): enoki.v1.ProbeConfigurationError;

            /**
             * Encodes the specified ProbeConfigurationError message. Does not implicitly {@link enoki.v1.ProbeConfigurationError.verify|verify} messages.
             * @param message ProbeConfigurationError message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeConfigurationError, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeConfigurationError message, length delimited. Does not implicitly {@link enoki.v1.ProbeConfigurationError.verify|verify} messages.
             * @param message ProbeConfigurationError message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeConfigurationError, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeConfigurationError message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeConfigurationError
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeConfigurationError;

            /**
             * Decodes a ProbeConfigurationError message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeConfigurationError
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeConfigurationError;

            /**
             * Verifies a ProbeConfigurationError message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeConfigurationError message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeConfigurationError
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeConfigurationError;

            /**
             * Creates a plain object from a ProbeConfigurationError message. Also converts values to other types if specified.
             * @param message ProbeConfigurationError
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeConfigurationError, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeConfigurationError to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeConfigurationError
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeConfigurationRequest. */
        interface IProbeConfigurationRequest {

            /** ProbeConfigurationRequest probeId */
            probeId?: (string|null);

            /** ProbeConfigurationRequest currentVersion */
            currentVersion?: (string|null);
        }

        /** Represents a ProbeConfigurationRequest. */
        class ProbeConfigurationRequest implements IProbeConfigurationRequest {

            /**
             * Constructs a new ProbeConfigurationRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeConfigurationRequest);

            /** ProbeConfigurationRequest probeId. */
            public probeId: string;

            /** ProbeConfigurationRequest currentVersion. */
            public currentVersion: string;

            /**
             * Creates a new ProbeConfigurationRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeConfigurationRequest instance
             */
            public static create(properties?: enoki.v1.IProbeConfigurationRequest): enoki.v1.ProbeConfigurationRequest;

            /**
             * Encodes the specified ProbeConfigurationRequest message. Does not implicitly {@link enoki.v1.ProbeConfigurationRequest.verify|verify} messages.
             * @param message ProbeConfigurationRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeConfigurationRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeConfigurationRequest message, length delimited. Does not implicitly {@link enoki.v1.ProbeConfigurationRequest.verify|verify} messages.
             * @param message ProbeConfigurationRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeConfigurationRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeConfigurationRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeConfigurationRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeConfigurationRequest;

            /**
             * Decodes a ProbeConfigurationRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeConfigurationRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeConfigurationRequest;

            /**
             * Verifies a ProbeConfigurationRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeConfigurationRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeConfigurationRequest
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeConfigurationRequest;

            /**
             * Creates a plain object from a ProbeConfigurationRequest message. Also converts values to other types if specified.
             * @param message ProbeConfigurationRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeConfigurationRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeConfigurationRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeConfigurationRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeConfigurationResponse. */
        interface IProbeConfigurationResponse {

            /** ProbeConfigurationResponse version */
            version?: (string|null);

            /** ProbeConfigurationResponse metricsCollectionIntervalSeconds */
            metricsCollectionIntervalSeconds?: (number|null);

            /** ProbeConfigurationResponse enabledCollectorIds */
            enabledCollectorIds?: (string[]|null);
        }

        /** Represents a ProbeConfigurationResponse. */
        class ProbeConfigurationResponse implements IProbeConfigurationResponse {

            /**
             * Constructs a new ProbeConfigurationResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeConfigurationResponse);

            /** ProbeConfigurationResponse version. */
            public version: string;

            /** ProbeConfigurationResponse metricsCollectionIntervalSeconds. */
            public metricsCollectionIntervalSeconds: number;

            /** ProbeConfigurationResponse enabledCollectorIds. */
            public enabledCollectorIds: string[];

            /**
             * Creates a new ProbeConfigurationResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeConfigurationResponse instance
             */
            public static create(properties?: enoki.v1.IProbeConfigurationResponse): enoki.v1.ProbeConfigurationResponse;

            /**
             * Encodes the specified ProbeConfigurationResponse message. Does not implicitly {@link enoki.v1.ProbeConfigurationResponse.verify|verify} messages.
             * @param message ProbeConfigurationResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeConfigurationResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeConfigurationResponse message, length delimited. Does not implicitly {@link enoki.v1.ProbeConfigurationResponse.verify|verify} messages.
             * @param message ProbeConfigurationResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeConfigurationResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeConfigurationResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeConfigurationResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeConfigurationResponse;

            /**
             * Decodes a ProbeConfigurationResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeConfigurationResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeConfigurationResponse;

            /**
             * Verifies a ProbeConfigurationResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeConfigurationResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeConfigurationResponse
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeConfigurationResponse;

            /**
             * Creates a plain object from a ProbeConfigurationResponse message. Also converts values to other types if specified.
             * @param message ProbeConfigurationResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeConfigurationResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeConfigurationResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeConfigurationResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an Inventory. */
        interface IInventory {

            /** Inventory hostname */
            hostname?: (string|null);

            /** Inventory os */
            os?: (string|null);

            /** Inventory kernel */
            kernel?: (string|null);

            /** Inventory architecture */
            architecture?: (string|null);

            /** Inventory cpuCount */
            cpuCount?: (number|null);

            /** Inventory memoryTotalBytes */
            memoryTotalBytes?: (Long|null);

            /** Inventory filesystems */
            filesystems?: (enoki.v1.IFilesystemInventory[]|null);

            /** Inventory networkInterfaces */
            networkInterfaces?: (enoki.v1.INetworkInterfaceInventory[]|null);

            /** Inventory probeVersion */
            probeVersion?: (string|null);

            /** Inventory cpuModel */
            cpuModel?: (string|null);

            /** Inventory processCount */
            processCount?: (number|null);

            /** Inventory threadCount */
            threadCount?: (number|null);

            /** Inventory cpuCacheL3Bytes */
            cpuCacheL3Bytes?: (Long|null);

            /** Inventory cpuBaseFrequencyMhz */
            cpuBaseFrequencyMhz?: (number|null);

            /** Inventory cpuSocketCount */
            cpuSocketCount?: (number|null);

            /** Inventory cpuPhysicalCount */
            cpuPhysicalCount?: (number|null);

            /** Inventory collectorCapabilities */
            collectorCapabilities?: (enoki.v1.ICollectorCapabilities|null);
        }

        /** Represents an Inventory. */
        class Inventory implements IInventory {

            /**
             * Constructs a new Inventory.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IInventory);

            /** Inventory hostname. */
            public hostname: string;

            /** Inventory os. */
            public os: string;

            /** Inventory kernel. */
            public kernel: string;

            /** Inventory architecture. */
            public architecture: string;

            /** Inventory cpuCount. */
            public cpuCount: number;

            /** Inventory memoryTotalBytes. */
            public memoryTotalBytes: Long;

            /** Inventory filesystems. */
            public filesystems: enoki.v1.IFilesystemInventory[];

            /** Inventory networkInterfaces. */
            public networkInterfaces: enoki.v1.INetworkInterfaceInventory[];

            /** Inventory probeVersion. */
            public probeVersion: string;

            /** Inventory cpuModel. */
            public cpuModel: string;

            /** Inventory processCount. */
            public processCount: number;

            /** Inventory threadCount. */
            public threadCount: number;

            /** Inventory cpuCacheL3Bytes. */
            public cpuCacheL3Bytes: Long;

            /** Inventory cpuBaseFrequencyMhz. */
            public cpuBaseFrequencyMhz: number;

            /** Inventory cpuSocketCount. */
            public cpuSocketCount: number;

            /** Inventory cpuPhysicalCount. */
            public cpuPhysicalCount: number;

            /** Inventory collectorCapabilities. */
            public collectorCapabilities?: (enoki.v1.ICollectorCapabilities|null);

            /**
             * Creates a new Inventory instance using the specified properties.
             * @param [properties] Properties to set
             * @returns Inventory instance
             */
            public static create(properties?: enoki.v1.IInventory): enoki.v1.Inventory;

            /**
             * Encodes the specified Inventory message. Does not implicitly {@link enoki.v1.Inventory.verify|verify} messages.
             * @param message Inventory message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IInventory, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified Inventory message, length delimited. Does not implicitly {@link enoki.v1.Inventory.verify|verify} messages.
             * @param message Inventory message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IInventory, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an Inventory message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns Inventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.Inventory;

            /**
             * Decodes an Inventory message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns Inventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.Inventory;

            /**
             * Verifies an Inventory message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an Inventory message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns Inventory
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.Inventory;

            /**
             * Creates a plain object from an Inventory message. Also converts values to other types if specified.
             * @param message Inventory
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.Inventory, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this Inventory to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for Inventory
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FilesystemInventory. */
        interface IFilesystemInventory {

            /** FilesystemInventory mountPoint */
            mountPoint?: (string|null);

            /** FilesystemInventory filesystemType */
            filesystemType?: (string|null);

            /** FilesystemInventory totalBytes */
            totalBytes?: (Long|null);

            /** FilesystemInventory availableBytes */
            availableBytes?: (Long|null);
        }

        /** Represents a FilesystemInventory. */
        class FilesystemInventory implements IFilesystemInventory {

            /**
             * Constructs a new FilesystemInventory.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IFilesystemInventory);

            /** FilesystemInventory mountPoint. */
            public mountPoint: string;

            /** FilesystemInventory filesystemType. */
            public filesystemType: string;

            /** FilesystemInventory totalBytes. */
            public totalBytes: Long;

            /** FilesystemInventory availableBytes. */
            public availableBytes: Long;

            /**
             * Creates a new FilesystemInventory instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FilesystemInventory instance
             */
            public static create(properties?: enoki.v1.IFilesystemInventory): enoki.v1.FilesystemInventory;

            /**
             * Encodes the specified FilesystemInventory message. Does not implicitly {@link enoki.v1.FilesystemInventory.verify|verify} messages.
             * @param message FilesystemInventory message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IFilesystemInventory, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FilesystemInventory message, length delimited. Does not implicitly {@link enoki.v1.FilesystemInventory.verify|verify} messages.
             * @param message FilesystemInventory message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IFilesystemInventory, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FilesystemInventory message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FilesystemInventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.FilesystemInventory;

            /**
             * Decodes a FilesystemInventory message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FilesystemInventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.FilesystemInventory;

            /**
             * Verifies a FilesystemInventory message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FilesystemInventory message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FilesystemInventory
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.FilesystemInventory;

            /**
             * Creates a plain object from a FilesystemInventory message. Also converts values to other types if specified.
             * @param message FilesystemInventory
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.FilesystemInventory, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FilesystemInventory to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FilesystemInventory
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a NetworkInterfaceInventory. */
        interface INetworkInterfaceInventory {

            /** NetworkInterfaceInventory name */
            name?: (string|null);

            /** NetworkInterfaceInventory addresses */
            addresses?: (string[]|null);
        }

        /** Represents a NetworkInterfaceInventory. */
        class NetworkInterfaceInventory implements INetworkInterfaceInventory {

            /**
             * Constructs a new NetworkInterfaceInventory.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.INetworkInterfaceInventory);

            /** NetworkInterfaceInventory name. */
            public name: string;

            /** NetworkInterfaceInventory addresses. */
            public addresses: string[];

            /**
             * Creates a new NetworkInterfaceInventory instance using the specified properties.
             * @param [properties] Properties to set
             * @returns NetworkInterfaceInventory instance
             */
            public static create(properties?: enoki.v1.INetworkInterfaceInventory): enoki.v1.NetworkInterfaceInventory;

            /**
             * Encodes the specified NetworkInterfaceInventory message. Does not implicitly {@link enoki.v1.NetworkInterfaceInventory.verify|verify} messages.
             * @param message NetworkInterfaceInventory message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.INetworkInterfaceInventory, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified NetworkInterfaceInventory message, length delimited. Does not implicitly {@link enoki.v1.NetworkInterfaceInventory.verify|verify} messages.
             * @param message NetworkInterfaceInventory message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.INetworkInterfaceInventory, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a NetworkInterfaceInventory message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns NetworkInterfaceInventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.NetworkInterfaceInventory;

            /**
             * Decodes a NetworkInterfaceInventory message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns NetworkInterfaceInventory
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.NetworkInterfaceInventory;

            /**
             * Verifies a NetworkInterfaceInventory message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a NetworkInterfaceInventory message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns NetworkInterfaceInventory
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.NetworkInterfaceInventory;

            /**
             * Creates a plain object from a NetworkInterfaceInventory message. Also converts values to other types if specified.
             * @param message NetworkInterfaceInventory
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.NetworkInterfaceInventory, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this NetworkInterfaceInventory to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for NetworkInterfaceInventory
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a CollectorAvailability. */
        interface ICollectorAvailability {

            /** CollectorAvailability available */
            available?: (boolean|null);
        }

        /** Represents a CollectorAvailability. */
        class CollectorAvailability implements ICollectorAvailability {

            /**
             * Constructs a new CollectorAvailability.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ICollectorAvailability);

            /** CollectorAvailability available. */
            public available: boolean;

            /**
             * Creates a new CollectorAvailability instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CollectorAvailability instance
             */
            public static create(properties?: enoki.v1.ICollectorAvailability): enoki.v1.CollectorAvailability;

            /**
             * Encodes the specified CollectorAvailability message. Does not implicitly {@link enoki.v1.CollectorAvailability.verify|verify} messages.
             * @param message CollectorAvailability message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ICollectorAvailability, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CollectorAvailability message, length delimited. Does not implicitly {@link enoki.v1.CollectorAvailability.verify|verify} messages.
             * @param message CollectorAvailability message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ICollectorAvailability, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CollectorAvailability message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CollectorAvailability
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.CollectorAvailability;

            /**
             * Decodes a CollectorAvailability message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CollectorAvailability
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.CollectorAvailability;

            /**
             * Verifies a CollectorAvailability message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CollectorAvailability message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CollectorAvailability
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.CollectorAvailability;

            /**
             * Creates a plain object from a CollectorAvailability message. Also converts values to other types if specified.
             * @param message CollectorAvailability
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.CollectorAvailability, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CollectorAvailability to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CollectorAvailability
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an OfficialCollectorCapabilities. */
        interface IOfficialCollectorCapabilities {

            /** OfficialCollectorCapabilities cpu */
            cpu?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities memory */
            memory?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities disk */
            disk?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities network */
            network?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities load */
            load?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities uptime */
            uptime?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities temperature */
            temperature?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities battery */
            battery?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities diskHealth */
            diskHealth?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities inventory */
            inventory?: (enoki.v1.ICollectorAvailability|null);
        }

        /** Represents an OfficialCollectorCapabilities. */
        class OfficialCollectorCapabilities implements IOfficialCollectorCapabilities {

            /**
             * Constructs a new OfficialCollectorCapabilities.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IOfficialCollectorCapabilities);

            /** OfficialCollectorCapabilities cpu. */
            public cpu?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities memory. */
            public memory?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities disk. */
            public disk?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities network. */
            public network?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities load. */
            public load?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities uptime. */
            public uptime?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities temperature. */
            public temperature?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities battery. */
            public battery?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities diskHealth. */
            public diskHealth?: (enoki.v1.ICollectorAvailability|null);

            /** OfficialCollectorCapabilities inventory. */
            public inventory?: (enoki.v1.ICollectorAvailability|null);

            /**
             * Creates a new OfficialCollectorCapabilities instance using the specified properties.
             * @param [properties] Properties to set
             * @returns OfficialCollectorCapabilities instance
             */
            public static create(properties?: enoki.v1.IOfficialCollectorCapabilities): enoki.v1.OfficialCollectorCapabilities;

            /**
             * Encodes the specified OfficialCollectorCapabilities message. Does not implicitly {@link enoki.v1.OfficialCollectorCapabilities.verify|verify} messages.
             * @param message OfficialCollectorCapabilities message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IOfficialCollectorCapabilities, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified OfficialCollectorCapabilities message, length delimited. Does not implicitly {@link enoki.v1.OfficialCollectorCapabilities.verify|verify} messages.
             * @param message OfficialCollectorCapabilities message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IOfficialCollectorCapabilities, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an OfficialCollectorCapabilities message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns OfficialCollectorCapabilities
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.OfficialCollectorCapabilities;

            /**
             * Decodes an OfficialCollectorCapabilities message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns OfficialCollectorCapabilities
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.OfficialCollectorCapabilities;

            /**
             * Verifies an OfficialCollectorCapabilities message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an OfficialCollectorCapabilities message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns OfficialCollectorCapabilities
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.OfficialCollectorCapabilities;

            /**
             * Creates a plain object from an OfficialCollectorCapabilities message. Also converts values to other types if specified.
             * @param message OfficialCollectorCapabilities
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.OfficialCollectorCapabilities, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this OfficialCollectorCapabilities to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for OfficialCollectorCapabilities
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a CollectorCapabilities. */
        interface ICollectorCapabilities {

            /** CollectorCapabilities official */
            official?: (enoki.v1.IOfficialCollectorCapabilities|null);
        }

        /** Represents a CollectorCapabilities. */
        class CollectorCapabilities implements ICollectorCapabilities {

            /**
             * Constructs a new CollectorCapabilities.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ICollectorCapabilities);

            /** CollectorCapabilities official. */
            public official?: (enoki.v1.IOfficialCollectorCapabilities|null);

            /**
             * Creates a new CollectorCapabilities instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CollectorCapabilities instance
             */
            public static create(properties?: enoki.v1.ICollectorCapabilities): enoki.v1.CollectorCapabilities;

            /**
             * Encodes the specified CollectorCapabilities message. Does not implicitly {@link enoki.v1.CollectorCapabilities.verify|verify} messages.
             * @param message CollectorCapabilities message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ICollectorCapabilities, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CollectorCapabilities message, length delimited. Does not implicitly {@link enoki.v1.CollectorCapabilities.verify|verify} messages.
             * @param message CollectorCapabilities message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ICollectorCapabilities, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CollectorCapabilities message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CollectorCapabilities
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.CollectorCapabilities;

            /**
             * Decodes a CollectorCapabilities message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CollectorCapabilities
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.CollectorCapabilities;

            /**
             * Verifies a CollectorCapabilities message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CollectorCapabilities message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CollectorCapabilities
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.CollectorCapabilities;

            /**
             * Creates a plain object from a CollectorCapabilities message. Also converts values to other types if specified.
             * @param message CollectorCapabilities
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.CollectorCapabilities, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CollectorCapabilities to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CollectorCapabilities
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MetricSample. */
        interface IMetricSample {

            /** MetricSample sequence */
            sequence?: (Long|null);

            /** MetricSample collectedAtMs */
            collectedAtMs?: (Long|null);

            /** MetricSample cpuPercent */
            cpuPercent?: (number|null);

            /** MetricSample memoryUsedBytes */
            memoryUsedBytes?: (Long|null);

            /** MetricSample load_1 */
            load_1?: (number|null);

            /** MetricSample load_5 */
            load_5?: (number|null);

            /** MetricSample load_15 */
            load_15?: (number|null);

            /** MetricSample uptimeSeconds */
            uptimeSeconds?: (Long|null);

            /** MetricSample disks */
            disks?: (enoki.v1.IDiskUsageMetric[]|null);

            /** MetricSample networkInterfaces */
            networkInterfaces?: (enoki.v1.INetworkInterfaceMetric[]|null);

            /** MetricSample cpuCores */
            cpuCores?: (enoki.v1.ICpuCoreMetric[]|null);

            /** MetricSample memoryTotalBytes */
            memoryTotalBytes?: (Long|null);

            /** MetricSample cpuUserPercent */
            cpuUserPercent?: (number|null);

            /** MetricSample cpuSystemPercent */
            cpuSystemPercent?: (number|null);

            /** MetricSample cpuIowaitPercent */
            cpuIowaitPercent?: (number|null);

            /** MetricSample cpuStealPercent */
            cpuStealPercent?: (number|null);

            /** MetricSample cpuIdlePercent */
            cpuIdlePercent?: (number|null);

            /** MetricSample memoryCacheBytes */
            memoryCacheBytes?: (Long|null);

            /** MetricSample swapTotalBytes */
            swapTotalBytes?: (Long|null);

            /** MetricSample swapUsedBytes */
            swapUsedBytes?: (Long|null);

            /** MetricSample temperatureCelsius */
            temperatureCelsius?: (number|null);

            /** MetricSample batteryPercent */
            batteryPercent?: (number|null);

            /** MetricSample batteryState */
            batteryState?: (string|null);

            /** MetricSample diskHealth */
            diskHealth?: (enoki.v1.IDiskHealthMetric[]|null);
        }

        /** Represents a MetricSample. */
        class MetricSample implements IMetricSample {

            /**
             * Constructs a new MetricSample.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IMetricSample);

            /** MetricSample sequence. */
            public sequence: Long;

            /** MetricSample collectedAtMs. */
            public collectedAtMs: Long;

            /** MetricSample cpuPercent. */
            public cpuPercent?: (number|null);

            /** MetricSample memoryUsedBytes. */
            public memoryUsedBytes?: (Long|null);

            /** MetricSample load_1. */
            public load_1?: (number|null);

            /** MetricSample load_5. */
            public load_5?: (number|null);

            /** MetricSample load_15. */
            public load_15?: (number|null);

            /** MetricSample uptimeSeconds. */
            public uptimeSeconds?: (Long|null);

            /** MetricSample disks. */
            public disks: enoki.v1.IDiskUsageMetric[];

            /** MetricSample networkInterfaces. */
            public networkInterfaces: enoki.v1.INetworkInterfaceMetric[];

            /** MetricSample cpuCores. */
            public cpuCores: enoki.v1.ICpuCoreMetric[];

            /** MetricSample memoryTotalBytes. */
            public memoryTotalBytes?: (Long|null);

            /** MetricSample cpuUserPercent. */
            public cpuUserPercent?: (number|null);

            /** MetricSample cpuSystemPercent. */
            public cpuSystemPercent?: (number|null);

            /** MetricSample cpuIowaitPercent. */
            public cpuIowaitPercent?: (number|null);

            /** MetricSample cpuStealPercent. */
            public cpuStealPercent?: (number|null);

            /** MetricSample cpuIdlePercent. */
            public cpuIdlePercent?: (number|null);

            /** MetricSample memoryCacheBytes. */
            public memoryCacheBytes?: (Long|null);

            /** MetricSample swapTotalBytes. */
            public swapTotalBytes?: (Long|null);

            /** MetricSample swapUsedBytes. */
            public swapUsedBytes?: (Long|null);

            /** MetricSample temperatureCelsius. */
            public temperatureCelsius?: (number|null);

            /** MetricSample batteryPercent. */
            public batteryPercent?: (number|null);

            /** MetricSample batteryState. */
            public batteryState?: (string|null);

            /** MetricSample diskHealth. */
            public diskHealth: enoki.v1.IDiskHealthMetric[];

            /**
             * Creates a new MetricSample instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MetricSample instance
             */
            public static create(properties?: enoki.v1.IMetricSample): enoki.v1.MetricSample;

            /**
             * Encodes the specified MetricSample message. Does not implicitly {@link enoki.v1.MetricSample.verify|verify} messages.
             * @param message MetricSample message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IMetricSample, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MetricSample message, length delimited. Does not implicitly {@link enoki.v1.MetricSample.verify|verify} messages.
             * @param message MetricSample message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IMetricSample, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MetricSample message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MetricSample
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.MetricSample;

            /**
             * Decodes a MetricSample message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MetricSample
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.MetricSample;

            /**
             * Verifies a MetricSample message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MetricSample message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MetricSample
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.MetricSample;

            /**
             * Creates a plain object from a MetricSample message. Also converts values to other types if specified.
             * @param message MetricSample
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.MetricSample, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MetricSample to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MetricSample
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a CpuCoreMetric. */
        interface ICpuCoreMetric {

            /** CpuCoreMetric name */
            name?: (string|null);

            /** CpuCoreMetric user */
            user?: (Long|null);

            /** CpuCoreMetric nice */
            nice?: (Long|null);

            /** CpuCoreMetric system */
            system?: (Long|null);

            /** CpuCoreMetric idle */
            idle?: (Long|null);

            /** CpuCoreMetric iowait */
            iowait?: (Long|null);

            /** CpuCoreMetric irq */
            irq?: (Long|null);

            /** CpuCoreMetric softirq */
            softirq?: (Long|null);

            /** CpuCoreMetric steal */
            steal?: (Long|null);

            /** CpuCoreMetric usagePercent */
            usagePercent?: (number|null);
        }

        /** Represents a CpuCoreMetric. */
        class CpuCoreMetric implements ICpuCoreMetric {

            /**
             * Constructs a new CpuCoreMetric.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ICpuCoreMetric);

            /** CpuCoreMetric name. */
            public name: string;

            /** CpuCoreMetric user. */
            public user: Long;

            /** CpuCoreMetric nice. */
            public nice: Long;

            /** CpuCoreMetric system. */
            public system: Long;

            /** CpuCoreMetric idle. */
            public idle: Long;

            /** CpuCoreMetric iowait. */
            public iowait: Long;

            /** CpuCoreMetric irq. */
            public irq: Long;

            /** CpuCoreMetric softirq. */
            public softirq: Long;

            /** CpuCoreMetric steal. */
            public steal: Long;

            /** CpuCoreMetric usagePercent. */
            public usagePercent: number;

            /**
             * Creates a new CpuCoreMetric instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CpuCoreMetric instance
             */
            public static create(properties?: enoki.v1.ICpuCoreMetric): enoki.v1.CpuCoreMetric;

            /**
             * Encodes the specified CpuCoreMetric message. Does not implicitly {@link enoki.v1.CpuCoreMetric.verify|verify} messages.
             * @param message CpuCoreMetric message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ICpuCoreMetric, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CpuCoreMetric message, length delimited. Does not implicitly {@link enoki.v1.CpuCoreMetric.verify|verify} messages.
             * @param message CpuCoreMetric message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ICpuCoreMetric, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CpuCoreMetric message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CpuCoreMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.CpuCoreMetric;

            /**
             * Decodes a CpuCoreMetric message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CpuCoreMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.CpuCoreMetric;

            /**
             * Verifies a CpuCoreMetric message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CpuCoreMetric message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CpuCoreMetric
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.CpuCoreMetric;

            /**
             * Creates a plain object from a CpuCoreMetric message. Also converts values to other types if specified.
             * @param message CpuCoreMetric
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.CpuCoreMetric, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CpuCoreMetric to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CpuCoreMetric
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a DiskUsageMetric. */
        interface IDiskUsageMetric {

            /** DiskUsageMetric mountPoint */
            mountPoint?: (string|null);

            /** DiskUsageMetric filesystemType */
            filesystemType?: (string|null);

            /** DiskUsageMetric totalBytes */
            totalBytes?: (Long|null);

            /** DiskUsageMetric usedBytes */
            usedBytes?: (Long|null);

            /** DiskUsageMetric availableBytes */
            availableBytes?: (Long|null);

            /** DiskUsageMetric readBytesDelta */
            readBytesDelta?: (Long|null);

            /** DiskUsageMetric writeBytesDelta */
            writeBytesDelta?: (Long|null);

            /** DiskUsageMetric ioUtilizationPercent */
            ioUtilizationPercent?: (number|null);

            /** DiskUsageMetric readAwaitMs */
            readAwaitMs?: (number|null);

            /** DiskUsageMetric writeAwaitMs */
            writeAwaitMs?: (number|null);

            /** DiskUsageMetric weightedIoPercent */
            weightedIoPercent?: (number|null);
        }

        /** Represents a DiskUsageMetric. */
        class DiskUsageMetric implements IDiskUsageMetric {

            /**
             * Constructs a new DiskUsageMetric.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IDiskUsageMetric);

            /** DiskUsageMetric mountPoint. */
            public mountPoint: string;

            /** DiskUsageMetric filesystemType. */
            public filesystemType: string;

            /** DiskUsageMetric totalBytes. */
            public totalBytes: Long;

            /** DiskUsageMetric usedBytes. */
            public usedBytes: Long;

            /** DiskUsageMetric availableBytes. */
            public availableBytes: Long;

            /** DiskUsageMetric readBytesDelta. */
            public readBytesDelta: Long;

            /** DiskUsageMetric writeBytesDelta. */
            public writeBytesDelta: Long;

            /** DiskUsageMetric ioUtilizationPercent. */
            public ioUtilizationPercent?: (number|null);

            /** DiskUsageMetric readAwaitMs. */
            public readAwaitMs?: (number|null);

            /** DiskUsageMetric writeAwaitMs. */
            public writeAwaitMs?: (number|null);

            /** DiskUsageMetric weightedIoPercent. */
            public weightedIoPercent?: (number|null);

            /**
             * Creates a new DiskUsageMetric instance using the specified properties.
             * @param [properties] Properties to set
             * @returns DiskUsageMetric instance
             */
            public static create(properties?: enoki.v1.IDiskUsageMetric): enoki.v1.DiskUsageMetric;

            /**
             * Encodes the specified DiskUsageMetric message. Does not implicitly {@link enoki.v1.DiskUsageMetric.verify|verify} messages.
             * @param message DiskUsageMetric message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IDiskUsageMetric, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified DiskUsageMetric message, length delimited. Does not implicitly {@link enoki.v1.DiskUsageMetric.verify|verify} messages.
             * @param message DiskUsageMetric message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IDiskUsageMetric, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a DiskUsageMetric message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns DiskUsageMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.DiskUsageMetric;

            /**
             * Decodes a DiskUsageMetric message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns DiskUsageMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.DiskUsageMetric;

            /**
             * Verifies a DiskUsageMetric message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a DiskUsageMetric message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns DiskUsageMetric
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.DiskUsageMetric;

            /**
             * Creates a plain object from a DiskUsageMetric message. Also converts values to other types if specified.
             * @param message DiskUsageMetric
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.DiskUsageMetric, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this DiskUsageMetric to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for DiskUsageMetric
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a DiskHealthMetric. */
        interface IDiskHealthMetric {

            /** DiskHealthMetric deviceName */
            deviceName?: (string|null);

            /** DiskHealthMetric model */
            model?: (string|null);

            /** DiskHealthMetric serialNumber */
            serialNumber?: (string|null);

            /** DiskHealthMetric passed */
            passed?: (boolean|null);

            /** DiskHealthMetric temperatureCelsius */
            temperatureCelsius?: (number|null);

            /** DiskHealthMetric powerOnHours */
            powerOnHours?: (Long|null);

            /** DiskHealthMetric totalBytes */
            totalBytes?: (Long|null);

            /** DiskHealthMetric usedBytes */
            usedBytes?: (Long|null);

            /** DiskHealthMetric usageMountPoint */
            usageMountPoint?: (string|null);

            /** DiskHealthMetric role */
            role?: (string|null);
        }

        /** Represents a DiskHealthMetric. */
        class DiskHealthMetric implements IDiskHealthMetric {

            /**
             * Constructs a new DiskHealthMetric.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IDiskHealthMetric);

            /** DiskHealthMetric deviceName. */
            public deviceName: string;

            /** DiskHealthMetric model. */
            public model: string;

            /** DiskHealthMetric serialNumber. */
            public serialNumber: string;

            /** DiskHealthMetric passed. */
            public passed: boolean;

            /** DiskHealthMetric temperatureCelsius. */
            public temperatureCelsius?: (number|null);

            /** DiskHealthMetric powerOnHours. */
            public powerOnHours?: (Long|null);

            /** DiskHealthMetric totalBytes. */
            public totalBytes?: (Long|null);

            /** DiskHealthMetric usedBytes. */
            public usedBytes?: (Long|null);

            /** DiskHealthMetric usageMountPoint. */
            public usageMountPoint: string;

            /** DiskHealthMetric role. */
            public role: string;

            /**
             * Creates a new DiskHealthMetric instance using the specified properties.
             * @param [properties] Properties to set
             * @returns DiskHealthMetric instance
             */
            public static create(properties?: enoki.v1.IDiskHealthMetric): enoki.v1.DiskHealthMetric;

            /**
             * Encodes the specified DiskHealthMetric message. Does not implicitly {@link enoki.v1.DiskHealthMetric.verify|verify} messages.
             * @param message DiskHealthMetric message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IDiskHealthMetric, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified DiskHealthMetric message, length delimited. Does not implicitly {@link enoki.v1.DiskHealthMetric.verify|verify} messages.
             * @param message DiskHealthMetric message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IDiskHealthMetric, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a DiskHealthMetric message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns DiskHealthMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.DiskHealthMetric;

            /**
             * Decodes a DiskHealthMetric message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns DiskHealthMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.DiskHealthMetric;

            /**
             * Verifies a DiskHealthMetric message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a DiskHealthMetric message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns DiskHealthMetric
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.DiskHealthMetric;

            /**
             * Creates a plain object from a DiskHealthMetric message. Also converts values to other types if specified.
             * @param message DiskHealthMetric
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.DiskHealthMetric, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this DiskHealthMetric to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for DiskHealthMetric
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a NetworkInterfaceMetric. */
        interface INetworkInterfaceMetric {

            /** NetworkInterfaceMetric name */
            name?: (string|null);

            /** NetworkInterfaceMetric rxBytes */
            rxBytes?: (Long|null);

            /** NetworkInterfaceMetric txBytes */
            txBytes?: (Long|null);

            /** NetworkInterfaceMetric rxBytesDelta */
            rxBytesDelta?: (Long|null);

            /** NetworkInterfaceMetric txBytesDelta */
            txBytesDelta?: (Long|null);
        }

        /** Represents a NetworkInterfaceMetric. */
        class NetworkInterfaceMetric implements INetworkInterfaceMetric {

            /**
             * Constructs a new NetworkInterfaceMetric.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.INetworkInterfaceMetric);

            /** NetworkInterfaceMetric name. */
            public name: string;

            /** NetworkInterfaceMetric rxBytes. */
            public rxBytes: Long;

            /** NetworkInterfaceMetric txBytes. */
            public txBytes: Long;

            /** NetworkInterfaceMetric rxBytesDelta. */
            public rxBytesDelta: Long;

            /** NetworkInterfaceMetric txBytesDelta. */
            public txBytesDelta: Long;

            /**
             * Creates a new NetworkInterfaceMetric instance using the specified properties.
             * @param [properties] Properties to set
             * @returns NetworkInterfaceMetric instance
             */
            public static create(properties?: enoki.v1.INetworkInterfaceMetric): enoki.v1.NetworkInterfaceMetric;

            /**
             * Encodes the specified NetworkInterfaceMetric message. Does not implicitly {@link enoki.v1.NetworkInterfaceMetric.verify|verify} messages.
             * @param message NetworkInterfaceMetric message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.INetworkInterfaceMetric, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified NetworkInterfaceMetric message, length delimited. Does not implicitly {@link enoki.v1.NetworkInterfaceMetric.verify|verify} messages.
             * @param message NetworkInterfaceMetric message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.INetworkInterfaceMetric, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a NetworkInterfaceMetric message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns NetworkInterfaceMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.NetworkInterfaceMetric;

            /**
             * Decodes a NetworkInterfaceMetric message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns NetworkInterfaceMetric
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.NetworkInterfaceMetric;

            /**
             * Verifies a NetworkInterfaceMetric message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a NetworkInterfaceMetric message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns NetworkInterfaceMetric
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.NetworkInterfaceMetric;

            /**
             * Creates a plain object from a NetworkInterfaceMetric message. Also converts values to other types if specified.
             * @param message NetworkInterfaceMetric
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.NetworkInterfaceMetric, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this NetworkInterfaceMetric to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for NetworkInterfaceMetric
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeOperation. */
        interface IProbeOperation {

            /** ProbeOperation id */
            id?: (string|null);

            /** ProbeOperation probeUpgrade */
            probeUpgrade?: (enoki.v1.IProbeUpgradeOperation|null);

            /** ProbeOperation probeUninstall */
            probeUninstall?: (enoki.v1.IProbeUninstallOperation|null);
        }

        /** Represents a ProbeOperation. */
        class ProbeOperation implements IProbeOperation {

            /**
             * Constructs a new ProbeOperation.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeOperation);

            /** ProbeOperation id. */
            public id: string;

            /** ProbeOperation probeUpgrade. */
            public probeUpgrade?: (enoki.v1.IProbeUpgradeOperation|null);

            /** ProbeOperation probeUninstall. */
            public probeUninstall?: (enoki.v1.IProbeUninstallOperation|null);

            /** ProbeOperation operation. */
            public operation?: ("probeUpgrade"|"probeUninstall");

            /**
             * Creates a new ProbeOperation instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeOperation instance
             */
            public static create(properties?: enoki.v1.IProbeOperation): enoki.v1.ProbeOperation;

            /**
             * Encodes the specified ProbeOperation message. Does not implicitly {@link enoki.v1.ProbeOperation.verify|verify} messages.
             * @param message ProbeOperation message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeOperation, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeOperation message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperation.verify|verify} messages.
             * @param message ProbeOperation message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeOperation, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeOperation message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeOperation;

            /**
             * Decodes a ProbeOperation message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeOperation;

            /**
             * Verifies a ProbeOperation message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeOperation message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeOperation
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeOperation;

            /**
             * Creates a plain object from a ProbeOperation message. Also converts values to other types if specified.
             * @param message ProbeOperation
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeOperation, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeOperation to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeOperation
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeUpgradeOperation. */
        interface IProbeUpgradeOperation {

            /** ProbeUpgradeOperation currentProbeVersion */
            currentProbeVersion?: (string|null);

            /** ProbeUpgradeOperation targetProbeVersion */
            targetProbeVersion?: (string|null);

            /** ProbeUpgradeOperation operationToken */
            operationToken?: (string|null);
        }

        /** Represents a ProbeUpgradeOperation. */
        class ProbeUpgradeOperation implements IProbeUpgradeOperation {

            /**
             * Constructs a new ProbeUpgradeOperation.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeUpgradeOperation);

            /** ProbeUpgradeOperation currentProbeVersion. */
            public currentProbeVersion: string;

            /** ProbeUpgradeOperation targetProbeVersion. */
            public targetProbeVersion: string;

            /** ProbeUpgradeOperation operationToken. */
            public operationToken: string;

            /**
             * Creates a new ProbeUpgradeOperation instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeUpgradeOperation instance
             */
            public static create(properties?: enoki.v1.IProbeUpgradeOperation): enoki.v1.ProbeUpgradeOperation;

            /**
             * Encodes the specified ProbeUpgradeOperation message. Does not implicitly {@link enoki.v1.ProbeUpgradeOperation.verify|verify} messages.
             * @param message ProbeUpgradeOperation message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeUpgradeOperation, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeUpgradeOperation message, length delimited. Does not implicitly {@link enoki.v1.ProbeUpgradeOperation.verify|verify} messages.
             * @param message ProbeUpgradeOperation message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeUpgradeOperation, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeUpgradeOperation message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeUpgradeOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeUpgradeOperation;

            /**
             * Decodes a ProbeUpgradeOperation message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeUpgradeOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeUpgradeOperation;

            /**
             * Verifies a ProbeUpgradeOperation message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeUpgradeOperation message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeUpgradeOperation
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeUpgradeOperation;

            /**
             * Creates a plain object from a ProbeUpgradeOperation message. Also converts values to other types if specified.
             * @param message ProbeUpgradeOperation
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeUpgradeOperation, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeUpgradeOperation to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeUpgradeOperation
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeUninstallOperation. */
        interface IProbeUninstallOperation {

            /** ProbeUninstallOperation operationToken */
            operationToken?: (string|null);
        }

        /** Represents a ProbeUninstallOperation. */
        class ProbeUninstallOperation implements IProbeUninstallOperation {

            /**
             * Constructs a new ProbeUninstallOperation.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeUninstallOperation);

            /** ProbeUninstallOperation operationToken. */
            public operationToken: string;

            /**
             * Creates a new ProbeUninstallOperation instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeUninstallOperation instance
             */
            public static create(properties?: enoki.v1.IProbeUninstallOperation): enoki.v1.ProbeUninstallOperation;

            /**
             * Encodes the specified ProbeUninstallOperation message. Does not implicitly {@link enoki.v1.ProbeUninstallOperation.verify|verify} messages.
             * @param message ProbeUninstallOperation message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeUninstallOperation, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeUninstallOperation message, length delimited. Does not implicitly {@link enoki.v1.ProbeUninstallOperation.verify|verify} messages.
             * @param message ProbeUninstallOperation message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeUninstallOperation, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeUninstallOperation message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeUninstallOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeUninstallOperation;

            /**
             * Decodes a ProbeUninstallOperation message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeUninstallOperation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeUninstallOperation;

            /**
             * Verifies a ProbeUninstallOperation message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeUninstallOperation message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeUninstallOperation
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeUninstallOperation;

            /**
             * Creates a plain object from a ProbeUninstallOperation message. Also converts values to other types if specified.
             * @param message ProbeUninstallOperation
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeUninstallOperation, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeUninstallOperation to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeUninstallOperation
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeOperationAcknowledgement. */
        interface IProbeOperationAcknowledgement {

            /** ProbeOperationAcknowledgement operationId */
            operationId?: (string|null);
        }

        /** Represents a ProbeOperationAcknowledgement. */
        class ProbeOperationAcknowledgement implements IProbeOperationAcknowledgement {

            /**
             * Constructs a new ProbeOperationAcknowledgement.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeOperationAcknowledgement);

            /** ProbeOperationAcknowledgement operationId. */
            public operationId: string;

            /**
             * Creates a new ProbeOperationAcknowledgement instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeOperationAcknowledgement instance
             */
            public static create(properties?: enoki.v1.IProbeOperationAcknowledgement): enoki.v1.ProbeOperationAcknowledgement;

            /**
             * Encodes the specified ProbeOperationAcknowledgement message. Does not implicitly {@link enoki.v1.ProbeOperationAcknowledgement.verify|verify} messages.
             * @param message ProbeOperationAcknowledgement message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeOperationAcknowledgement, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeOperationAcknowledgement message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationAcknowledgement.verify|verify} messages.
             * @param message ProbeOperationAcknowledgement message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeOperationAcknowledgement, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeOperationAcknowledgement message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeOperationAcknowledgement
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeOperationAcknowledgement;

            /**
             * Decodes a ProbeOperationAcknowledgement message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeOperationAcknowledgement
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeOperationAcknowledgement;

            /**
             * Verifies a ProbeOperationAcknowledgement message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeOperationAcknowledgement message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeOperationAcknowledgement
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeOperationAcknowledgement;

            /**
             * Creates a plain object from a ProbeOperationAcknowledgement message. Also converts values to other types if specified.
             * @param message ProbeOperationAcknowledgement
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeOperationAcknowledgement, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeOperationAcknowledgement to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeOperationAcknowledgement
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeOperationStatus. */
        interface IProbeOperationStatus {

            /** ProbeOperationStatus operationId */
            operationId?: (string|null);

            /** ProbeOperationStatus running */
            running?: (enoki.v1.IProbeOperationRunning|null);

            /** ProbeOperationStatus failed */
            failed?: (enoki.v1.IProbeOperationFailed|null);

            /** ProbeOperationStatus succeeded */
            succeeded?: (enoki.v1.IProbeOperationSucceeded|null);
        }

        /** Represents a ProbeOperationStatus. */
        class ProbeOperationStatus implements IProbeOperationStatus {

            /**
             * Constructs a new ProbeOperationStatus.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeOperationStatus);

            /** ProbeOperationStatus operationId. */
            public operationId: string;

            /** ProbeOperationStatus running. */
            public running?: (enoki.v1.IProbeOperationRunning|null);

            /** ProbeOperationStatus failed. */
            public failed?: (enoki.v1.IProbeOperationFailed|null);

            /** ProbeOperationStatus succeeded. */
            public succeeded?: (enoki.v1.IProbeOperationSucceeded|null);

            /** ProbeOperationStatus status. */
            public status?: ("running"|"failed"|"succeeded");

            /**
             * Creates a new ProbeOperationStatus instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeOperationStatus instance
             */
            public static create(properties?: enoki.v1.IProbeOperationStatus): enoki.v1.ProbeOperationStatus;

            /**
             * Encodes the specified ProbeOperationStatus message. Does not implicitly {@link enoki.v1.ProbeOperationStatus.verify|verify} messages.
             * @param message ProbeOperationStatus message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeOperationStatus, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeOperationStatus message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationStatus.verify|verify} messages.
             * @param message ProbeOperationStatus message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeOperationStatus, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeOperationStatus message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeOperationStatus
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeOperationStatus;

            /**
             * Decodes a ProbeOperationStatus message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeOperationStatus
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeOperationStatus;

            /**
             * Verifies a ProbeOperationStatus message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeOperationStatus message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeOperationStatus
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeOperationStatus;

            /**
             * Creates a plain object from a ProbeOperationStatus message. Also converts values to other types if specified.
             * @param message ProbeOperationStatus
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeOperationStatus, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeOperationStatus to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeOperationStatus
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeOperationRunning. */
        interface IProbeOperationRunning {
        }

        /** Represents a ProbeOperationRunning. */
        class ProbeOperationRunning implements IProbeOperationRunning {

            /**
             * Constructs a new ProbeOperationRunning.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeOperationRunning);

            /**
             * Creates a new ProbeOperationRunning instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeOperationRunning instance
             */
            public static create(properties?: enoki.v1.IProbeOperationRunning): enoki.v1.ProbeOperationRunning;

            /**
             * Encodes the specified ProbeOperationRunning message. Does not implicitly {@link enoki.v1.ProbeOperationRunning.verify|verify} messages.
             * @param message ProbeOperationRunning message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeOperationRunning, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeOperationRunning message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationRunning.verify|verify} messages.
             * @param message ProbeOperationRunning message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeOperationRunning, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeOperationRunning message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeOperationRunning
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeOperationRunning;

            /**
             * Decodes a ProbeOperationRunning message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeOperationRunning
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeOperationRunning;

            /**
             * Verifies a ProbeOperationRunning message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeOperationRunning message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeOperationRunning
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeOperationRunning;

            /**
             * Creates a plain object from a ProbeOperationRunning message. Also converts values to other types if specified.
             * @param message ProbeOperationRunning
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeOperationRunning, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeOperationRunning to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeOperationRunning
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeOperationSucceeded. */
        interface IProbeOperationSucceeded {
        }

        /** Represents a ProbeOperationSucceeded. */
        class ProbeOperationSucceeded implements IProbeOperationSucceeded {

            /**
             * Constructs a new ProbeOperationSucceeded.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeOperationSucceeded);

            /**
             * Creates a new ProbeOperationSucceeded instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeOperationSucceeded instance
             */
            public static create(properties?: enoki.v1.IProbeOperationSucceeded): enoki.v1.ProbeOperationSucceeded;

            /**
             * Encodes the specified ProbeOperationSucceeded message. Does not implicitly {@link enoki.v1.ProbeOperationSucceeded.verify|verify} messages.
             * @param message ProbeOperationSucceeded message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeOperationSucceeded, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeOperationSucceeded message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationSucceeded.verify|verify} messages.
             * @param message ProbeOperationSucceeded message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeOperationSucceeded, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeOperationSucceeded message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeOperationSucceeded
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeOperationSucceeded;

            /**
             * Decodes a ProbeOperationSucceeded message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeOperationSucceeded
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeOperationSucceeded;

            /**
             * Verifies a ProbeOperationSucceeded message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeOperationSucceeded message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeOperationSucceeded
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeOperationSucceeded;

            /**
             * Creates a plain object from a ProbeOperationSucceeded message. Also converts values to other types if specified.
             * @param message ProbeOperationSucceeded
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeOperationSucceeded, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeOperationSucceeded to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeOperationSucceeded
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeOperationFailed. */
        interface IProbeOperationFailed {

            /** ProbeOperationFailed errorCode */
            errorCode?: (string|null);

            /** ProbeOperationFailed message */
            message?: (string|null);
        }

        /** Represents a ProbeOperationFailed. */
        class ProbeOperationFailed implements IProbeOperationFailed {

            /**
             * Constructs a new ProbeOperationFailed.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeOperationFailed);

            /** ProbeOperationFailed errorCode. */
            public errorCode: string;

            /** ProbeOperationFailed message. */
            public message: string;

            /**
             * Creates a new ProbeOperationFailed instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeOperationFailed instance
             */
            public static create(properties?: enoki.v1.IProbeOperationFailed): enoki.v1.ProbeOperationFailed;

            /**
             * Encodes the specified ProbeOperationFailed message. Does not implicitly {@link enoki.v1.ProbeOperationFailed.verify|verify} messages.
             * @param message ProbeOperationFailed message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeOperationFailed, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeOperationFailed message, length delimited. Does not implicitly {@link enoki.v1.ProbeOperationFailed.verify|verify} messages.
             * @param message ProbeOperationFailed message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeOperationFailed, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeOperationFailed message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeOperationFailed
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeOperationFailed;

            /**
             * Decodes a ProbeOperationFailed message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeOperationFailed
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeOperationFailed;

            /**
             * Verifies a ProbeOperationFailed message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeOperationFailed message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeOperationFailed
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeOperationFailed;

            /**
             * Creates a plain object from a ProbeOperationFailed message. Also converts values to other types if specified.
             * @param message ProbeOperationFailed
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeOperationFailed, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeOperationFailed to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeOperationFailed
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }
    }
}
