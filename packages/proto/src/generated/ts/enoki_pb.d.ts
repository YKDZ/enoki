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

            /** ProbeRegistrationRequest probePublicKeyPem */
            probePublicKeyPem?: (string|null);

            /** ProbeRegistrationRequest snapshots */
            snapshots?: (enoki.v1.ISnapshot[]|null);

            /** ProbeRegistrationRequest installationRejection */
            installationRejection?: (enoki.v1.IProbeInstallationRejection|null);

            /** ProbeRegistrationRequest installationInspection */
            installationInspection?: (enoki.v1.IProbeInstallationInspection|null);
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

            /** ProbeRegistrationRequest probePublicKeyPem. */
            public probePublicKeyPem: string;

            /** ProbeRegistrationRequest snapshots. */
            public snapshots: enoki.v1.ISnapshot[];

            /** ProbeRegistrationRequest installationRejection. */
            public installationRejection?: (enoki.v1.IProbeInstallationRejection|null);

            /** ProbeRegistrationRequest installationInspection. */
            public installationInspection?: (enoki.v1.IProbeInstallationInspection|null);

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

        /** Properties of a ProbeInstallationInspection. */
        interface IProbeInstallationInspection {
        }

        /** Represents a ProbeInstallationInspection. */
        class ProbeInstallationInspection implements IProbeInstallationInspection {

            /**
             * Constructs a new ProbeInstallationInspection.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeInstallationInspection);

            /**
             * Creates a new ProbeInstallationInspection instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeInstallationInspection instance
             */
            public static create(properties?: enoki.v1.IProbeInstallationInspection): enoki.v1.ProbeInstallationInspection;

            /**
             * Encodes the specified ProbeInstallationInspection message. Does not implicitly {@link enoki.v1.ProbeInstallationInspection.verify|verify} messages.
             * @param message ProbeInstallationInspection message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeInstallationInspection, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeInstallationInspection message, length delimited. Does not implicitly {@link enoki.v1.ProbeInstallationInspection.verify|verify} messages.
             * @param message ProbeInstallationInspection message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeInstallationInspection, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeInstallationInspection message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeInstallationInspection
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeInstallationInspection;

            /**
             * Decodes a ProbeInstallationInspection message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeInstallationInspection
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeInstallationInspection;

            /**
             * Verifies a ProbeInstallationInspection message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeInstallationInspection message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeInstallationInspection
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeInstallationInspection;

            /**
             * Creates a plain object from a ProbeInstallationInspection message. Also converts values to other types if specified.
             * @param message ProbeInstallationInspection
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeInstallationInspection, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeInstallationInspection to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeInstallationInspection
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** ProbeEnrollmentTargetKind enum. */
        enum ProbeEnrollmentTargetKind {
            PROBE_ENROLLMENT_TARGET_KIND_UNSPECIFIED = 0,
            NEW_HOST = 1,
            EXISTING_HOST = 2
        }

        /** Properties of a ProbeInstallationInspectionResponse. */
        interface IProbeInstallationInspectionResponse {

            /** ProbeInstallationInspectionResponse targetKind */
            targetKind?: (enoki.v1.ProbeEnrollmentTargetKind|null);
        }

        /** Represents a ProbeInstallationInspectionResponse. */
        class ProbeInstallationInspectionResponse implements IProbeInstallationInspectionResponse {

            /**
             * Constructs a new ProbeInstallationInspectionResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeInstallationInspectionResponse);

            /** ProbeInstallationInspectionResponse targetKind. */
            public targetKind: enoki.v1.ProbeEnrollmentTargetKind;

            /**
             * Creates a new ProbeInstallationInspectionResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeInstallationInspectionResponse instance
             */
            public static create(properties?: enoki.v1.IProbeInstallationInspectionResponse): enoki.v1.ProbeInstallationInspectionResponse;

            /**
             * Encodes the specified ProbeInstallationInspectionResponse message. Does not implicitly {@link enoki.v1.ProbeInstallationInspectionResponse.verify|verify} messages.
             * @param message ProbeInstallationInspectionResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeInstallationInspectionResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeInstallationInspectionResponse message, length delimited. Does not implicitly {@link enoki.v1.ProbeInstallationInspectionResponse.verify|verify} messages.
             * @param message ProbeInstallationInspectionResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeInstallationInspectionResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeInstallationInspectionResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeInstallationInspectionResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeInstallationInspectionResponse;

            /**
             * Decodes a ProbeInstallationInspectionResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeInstallationInspectionResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeInstallationInspectionResponse;

            /**
             * Verifies a ProbeInstallationInspectionResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeInstallationInspectionResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeInstallationInspectionResponse
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeInstallationInspectionResponse;

            /**
             * Creates a plain object from a ProbeInstallationInspectionResponse message. Also converts values to other types if specified.
             * @param message ProbeInstallationInspectionResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeInstallationInspectionResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeInstallationInspectionResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeInstallationInspectionResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a ProbeInstallationRejection. */
        interface IProbeInstallationRejection {

            /** ProbeInstallationRejection code */
            code?: (string|null);

            /** ProbeInstallationRejection message */
            message?: (string|null);

            /** ProbeInstallationRejection existingProbeId */
            existingProbeId?: (string|null);
        }

        /** Represents a ProbeInstallationRejection. */
        class ProbeInstallationRejection implements IProbeInstallationRejection {

            /**
             * Constructs a new ProbeInstallationRejection.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeInstallationRejection);

            /** ProbeInstallationRejection code. */
            public code: string;

            /** ProbeInstallationRejection message. */
            public message: string;

            /** ProbeInstallationRejection existingProbeId. */
            public existingProbeId: string;

            /**
             * Creates a new ProbeInstallationRejection instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ProbeInstallationRejection instance
             */
            public static create(properties?: enoki.v1.IProbeInstallationRejection): enoki.v1.ProbeInstallationRejection;

            /**
             * Encodes the specified ProbeInstallationRejection message. Does not implicitly {@link enoki.v1.ProbeInstallationRejection.verify|verify} messages.
             * @param message ProbeInstallationRejection message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IProbeInstallationRejection, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ProbeInstallationRejection message, length delimited. Does not implicitly {@link enoki.v1.ProbeInstallationRejection.verify|verify} messages.
             * @param message ProbeInstallationRejection message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IProbeInstallationRejection, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a ProbeInstallationRejection message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ProbeInstallationRejection
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ProbeInstallationRejection;

            /**
             * Decodes a ProbeInstallationRejection message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ProbeInstallationRejection
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ProbeInstallationRejection;

            /**
             * Verifies a ProbeInstallationRejection message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a ProbeInstallationRejection message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ProbeInstallationRejection
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ProbeInstallationRejection;

            /**
             * Creates a plain object from a ProbeInstallationRejection message. Also converts values to other types if specified.
             * @param message ProbeInstallationRejection
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ProbeInstallationRejection, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ProbeInstallationRejection to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ProbeInstallationRejection
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
            serverTimeMs?: (number|Long|null);

            /** ProbeRegistrationResponse initialConfiguration */
            initialConfiguration?: (enoki.v1.IProbeConfigurationResponse|null);

            /** ProbeRegistrationResponse enrollmentId */
            enrollmentId?: (string|null);

            /** ProbeRegistrationResponse installationInspection */
            installationInspection?: (enoki.v1.IProbeInstallationInspectionResponse|null);
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
            public serverTimeMs: (number|Long);

            /** ProbeRegistrationResponse initialConfiguration. */
            public initialConfiguration?: (enoki.v1.IProbeConfigurationResponse|null);

            /** ProbeRegistrationResponse enrollmentId. */
            public enrollmentId: string;

            /** ProbeRegistrationResponse installationInspection. */
            public installationInspection?: (enoki.v1.IProbeInstallationInspectionResponse|null);

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
            sequenceStart?: (number|Long|null);

            /** ProbeReportRequest sequenceEnd */
            sequenceEnd?: (number|Long|null);

            /** ProbeReportRequest probeConfigurationVersion */
            probeConfigurationVersion?: (string|null);

            /** ProbeReportRequest metrics */
            metrics?: (enoki.v1.IMetricSample[]|null);

            /** ProbeReportRequest probeConfigurationError */
            probeConfigurationError?: (enoki.v1.IProbeConfigurationError|null);

            /** ProbeReportRequest operationAcknowledgements */
            operationAcknowledgements?: (enoki.v1.IProbeOperationAcknowledgement[]|null);

            /** ProbeReportRequest operationStatuses */
            operationStatuses?: (enoki.v1.IProbeOperationStatus[]|null);

            /** ProbeReportRequest snapshots */
            snapshots?: (enoki.v1.ISnapshot[]|null);

            /** ProbeReportRequest enrollmentId */
            enrollmentId?: (string|null);

            /** ProbeReportRequest observationWindowFailure */
            observationWindowFailure?: (enoki.v1.IObservationWindowFailure|null);

            /** ProbeReportRequest cpuResourceCollectionOutcomes */
            cpuResourceCollectionOutcomes?: (enoki.v1.ICpuResourceCollectionOutcome[]|null);

            /** ProbeReportRequest probeAssetBundleVersion */
            probeAssetBundleVersion?: (string|null);
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
            public sequenceStart: (number|Long);

            /** ProbeReportRequest sequenceEnd. */
            public sequenceEnd: (number|Long);

            /** ProbeReportRequest probeConfigurationVersion. */
            public probeConfigurationVersion: string;

            /** ProbeReportRequest metrics. */
            public metrics: enoki.v1.IMetricSample[];

            /** ProbeReportRequest probeConfigurationError. */
            public probeConfigurationError?: (enoki.v1.IProbeConfigurationError|null);

            /** ProbeReportRequest operationAcknowledgements. */
            public operationAcknowledgements: enoki.v1.IProbeOperationAcknowledgement[];

            /** ProbeReportRequest operationStatuses. */
            public operationStatuses: enoki.v1.IProbeOperationStatus[];

            /** ProbeReportRequest snapshots. */
            public snapshots: enoki.v1.ISnapshot[];

            /** ProbeReportRequest enrollmentId. */
            public enrollmentId: string;

            /** ProbeReportRequest observationWindowFailure. */
            public observationWindowFailure?: (enoki.v1.IObservationWindowFailure|null);

            /** ProbeReportRequest cpuResourceCollectionOutcomes. */
            public cpuResourceCollectionOutcomes: enoki.v1.ICpuResourceCollectionOutcome[];

            /** ProbeReportRequest probeAssetBundleVersion. */
            public probeAssetBundleVersion: string;

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

        /** Properties of a CpuResourceCollectionOutcome. */
        interface ICpuResourceCollectionOutcome {

            /** CpuResourceCollectionOutcome sequence */
            sequence?: (number|Long|null);

            /** CpuResourceCollectionOutcome reason */
            reason?: (enoki.v1.CpuResourceCollectionOutcomeReason|null);
        }

        /** Represents a CpuResourceCollectionOutcome. */
        class CpuResourceCollectionOutcome implements ICpuResourceCollectionOutcome {

            /**
             * Constructs a new CpuResourceCollectionOutcome.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ICpuResourceCollectionOutcome);

            /** CpuResourceCollectionOutcome sequence. */
            public sequence: (number|Long);

            /** CpuResourceCollectionOutcome reason. */
            public reason: enoki.v1.CpuResourceCollectionOutcomeReason;

            /**
             * Creates a new CpuResourceCollectionOutcome instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CpuResourceCollectionOutcome instance
             */
            public static create(properties?: enoki.v1.ICpuResourceCollectionOutcome): enoki.v1.CpuResourceCollectionOutcome;

            /**
             * Encodes the specified CpuResourceCollectionOutcome message. Does not implicitly {@link enoki.v1.CpuResourceCollectionOutcome.verify|verify} messages.
             * @param message CpuResourceCollectionOutcome message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ICpuResourceCollectionOutcome, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CpuResourceCollectionOutcome message, length delimited. Does not implicitly {@link enoki.v1.CpuResourceCollectionOutcome.verify|verify} messages.
             * @param message CpuResourceCollectionOutcome message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ICpuResourceCollectionOutcome, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CpuResourceCollectionOutcome message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CpuResourceCollectionOutcome
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.CpuResourceCollectionOutcome;

            /**
             * Decodes a CpuResourceCollectionOutcome message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CpuResourceCollectionOutcome
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.CpuResourceCollectionOutcome;

            /**
             * Verifies a CpuResourceCollectionOutcome message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CpuResourceCollectionOutcome message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CpuResourceCollectionOutcome
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.CpuResourceCollectionOutcome;

            /**
             * Creates a plain object from a CpuResourceCollectionOutcome message. Also converts values to other types if specified.
             * @param message CpuResourceCollectionOutcome
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.CpuResourceCollectionOutcome, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CpuResourceCollectionOutcome to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CpuResourceCollectionOutcome
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** CpuResourceCollectionOutcomeReason enum. */
        enum CpuResourceCollectionOutcomeReason {
            CPU_RESOURCE_COLLECTION_OUTCOME_REASON_UNSPECIFIED = 0,
            CPU_RESOURCE_UNAVAILABLE = 1,
            CPU_RESOURCE_MALFORMED = 2,
            CPU_PROVIDER_ACTIVATION_BUDGET_EXHAUSTED = 3
        }

        /** Properties of an ObservationWindowFailure. */
        interface IObservationWindowFailure {

            /** ObservationWindowFailure reason */
            reason?: (enoki.v1.ObservationWindowFailureReason|null);
        }

        /** Represents an ObservationWindowFailure. */
        class ObservationWindowFailure implements IObservationWindowFailure {

            /**
             * Constructs a new ObservationWindowFailure.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IObservationWindowFailure);

            /** ObservationWindowFailure reason. */
            public reason: enoki.v1.ObservationWindowFailureReason;

            /**
             * Creates a new ObservationWindowFailure instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ObservationWindowFailure instance
             */
            public static create(properties?: enoki.v1.IObservationWindowFailure): enoki.v1.ObservationWindowFailure;

            /**
             * Encodes the specified ObservationWindowFailure message. Does not implicitly {@link enoki.v1.ObservationWindowFailure.verify|verify} messages.
             * @param message ObservationWindowFailure message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IObservationWindowFailure, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ObservationWindowFailure message, length delimited. Does not implicitly {@link enoki.v1.ObservationWindowFailure.verify|verify} messages.
             * @param message ObservationWindowFailure message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IObservationWindowFailure, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an ObservationWindowFailure message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ObservationWindowFailure
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.ObservationWindowFailure;

            /**
             * Decodes an ObservationWindowFailure message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ObservationWindowFailure
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.ObservationWindowFailure;

            /**
             * Verifies an ObservationWindowFailure message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an ObservationWindowFailure message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ObservationWindowFailure
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.ObservationWindowFailure;

            /**
             * Creates a plain object from an ObservationWindowFailure message. Also converts values to other types if specified.
             * @param message ObservationWindowFailure
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.ObservationWindowFailure, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ObservationWindowFailure to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ObservationWindowFailure
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** ObservationWindowFailureReason enum. */
        enum ObservationWindowFailureReason {
            OBSERVATION_WINDOW_FAILURE_REASON_UNSPECIFIED = 0,
            OBSERVATION_RUNTIME_UNAVAILABLE = 1,
            OBSERVATION_RUNTIME_INVALID_RESPONSE = 2,
            PROBE_ASSET_BUNDLE_INCOHERENT = 3
        }

        /** Properties of a ProbeReportResponse. */
        interface IProbeReportResponse {

            /** ProbeReportResponse acceptedSequenceEnd */
            acceptedSequenceEnd?: (number|Long|null);

            /** ProbeReportResponse serverTimeMs */
            serverTimeMs?: (number|Long|null);

            /** ProbeReportResponse currentProbeConfigurationVersion */
            currentProbeConfigurationVersion?: (string|null);

            /** ProbeReportResponse pendingOperation */
            pendingOperation?: (enoki.v1.IProbeOperation|null);

            /** ProbeReportResponse requestedSnapshotCollectorIds */
            requestedSnapshotCollectorIds?: (string[]|null);
        }

        /** Represents a ProbeReportResponse. */
        class ProbeReportResponse implements IProbeReportResponse {

            /**
             * Constructs a new ProbeReportResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IProbeReportResponse);

            /** ProbeReportResponse acceptedSequenceEnd. */
            public acceptedSequenceEnd: (number|Long);

            /** ProbeReportResponse serverTimeMs. */
            public serverTimeMs: (number|Long);

            /** ProbeReportResponse currentProbeConfigurationVersion. */
            public currentProbeConfigurationVersion: string;

            /** ProbeReportResponse pendingOperation. */
            public pendingOperation?: (enoki.v1.IProbeOperation|null);

            /** ProbeReportResponse requestedSnapshotCollectorIds. */
            public requestedSnapshotCollectorIds: string[];

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

        /** Properties of a HostProfileSnapshot. */
        interface IHostProfileSnapshot {

            /** HostProfileSnapshot hostname */
            hostname?: (string|null);

            /** HostProfileSnapshot os */
            os?: (string|null);

            /** HostProfileSnapshot kernel */
            kernel?: (string|null);

            /** HostProfileSnapshot architecture */
            architecture?: (string|null);

            /** HostProfileSnapshot cpuCount */
            cpuCount?: (number|null);

            /** HostProfileSnapshot memoryTotalBytes */
            memoryTotalBytes?: (number|Long|null);

            /** HostProfileSnapshot filesystems */
            filesystems?: (enoki.v1.IFilesystemProfile[]|null);

            /** HostProfileSnapshot networkInterfaces */
            networkInterfaces?: (enoki.v1.INetworkInterfaceProfile[]|null);

            /** HostProfileSnapshot probeVersion */
            probeVersion?: (string|null);

            /** HostProfileSnapshot cpuModel */
            cpuModel?: (string|null);

            /** HostProfileSnapshot processCount */
            processCount?: (number|null);

            /** HostProfileSnapshot threadCount */
            threadCount?: (number|null);

            /** HostProfileSnapshot cpuCacheL3Bytes */
            cpuCacheL3Bytes?: (number|Long|null);

            /** HostProfileSnapshot cpuBaseFrequencyMhz */
            cpuBaseFrequencyMhz?: (number|null);

            /** HostProfileSnapshot cpuSocketCount */
            cpuSocketCount?: (number|null);

            /** HostProfileSnapshot cpuPhysicalCount */
            cpuPhysicalCount?: (number|null);

            /** HostProfileSnapshot collectorCapabilities */
            collectorCapabilities?: (enoki.v1.ICollectorCapabilities|null);

            /** HostProfileSnapshot probeAssetBundleVersion */
            probeAssetBundleVersion?: (string|null);
        }

        /** Represents a HostProfileSnapshot. */
        class HostProfileSnapshot implements IHostProfileSnapshot {

            /**
             * Constructs a new HostProfileSnapshot.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IHostProfileSnapshot);

            /** HostProfileSnapshot hostname. */
            public hostname: string;

            /** HostProfileSnapshot os. */
            public os: string;

            /** HostProfileSnapshot kernel. */
            public kernel: string;

            /** HostProfileSnapshot architecture. */
            public architecture: string;

            /** HostProfileSnapshot cpuCount. */
            public cpuCount: number;

            /** HostProfileSnapshot memoryTotalBytes. */
            public memoryTotalBytes: (number|Long);

            /** HostProfileSnapshot filesystems. */
            public filesystems: enoki.v1.IFilesystemProfile[];

            /** HostProfileSnapshot networkInterfaces. */
            public networkInterfaces: enoki.v1.INetworkInterfaceProfile[];

            /** HostProfileSnapshot probeVersion. */
            public probeVersion: string;

            /** HostProfileSnapshot cpuModel. */
            public cpuModel: string;

            /** HostProfileSnapshot processCount. */
            public processCount: number;

            /** HostProfileSnapshot threadCount. */
            public threadCount: number;

            /** HostProfileSnapshot cpuCacheL3Bytes. */
            public cpuCacheL3Bytes: (number|Long);

            /** HostProfileSnapshot cpuBaseFrequencyMhz. */
            public cpuBaseFrequencyMhz: number;

            /** HostProfileSnapshot cpuSocketCount. */
            public cpuSocketCount: number;

            /** HostProfileSnapshot cpuPhysicalCount. */
            public cpuPhysicalCount: number;

            /** HostProfileSnapshot collectorCapabilities. */
            public collectorCapabilities?: (enoki.v1.ICollectorCapabilities|null);

            /** HostProfileSnapshot probeAssetBundleVersion. */
            public probeAssetBundleVersion: string;

            /**
             * Creates a new HostProfileSnapshot instance using the specified properties.
             * @param [properties] Properties to set
             * @returns HostProfileSnapshot instance
             */
            public static create(properties?: enoki.v1.IHostProfileSnapshot): enoki.v1.HostProfileSnapshot;

            /**
             * Encodes the specified HostProfileSnapshot message. Does not implicitly {@link enoki.v1.HostProfileSnapshot.verify|verify} messages.
             * @param message HostProfileSnapshot message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IHostProfileSnapshot, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified HostProfileSnapshot message, length delimited. Does not implicitly {@link enoki.v1.HostProfileSnapshot.verify|verify} messages.
             * @param message HostProfileSnapshot message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IHostProfileSnapshot, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a HostProfileSnapshot message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns HostProfileSnapshot
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.HostProfileSnapshot;

            /**
             * Decodes a HostProfileSnapshot message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns HostProfileSnapshot
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.HostProfileSnapshot;

            /**
             * Verifies a HostProfileSnapshot message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a HostProfileSnapshot message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns HostProfileSnapshot
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.HostProfileSnapshot;

            /**
             * Creates a plain object from a HostProfileSnapshot message. Also converts values to other types if specified.
             * @param message HostProfileSnapshot
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.HostProfileSnapshot, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this HostProfileSnapshot to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for HostProfileSnapshot
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a HostProfileResourceFacts. */
        interface IHostProfileResourceFacts {

            /** HostProfileResourceFacts hostname */
            hostname?: (string|null);

            /** HostProfileResourceFacts os */
            os?: (string|null);

            /** HostProfileResourceFacts kernel */
            kernel?: (string|null);

            /** HostProfileResourceFacts architecture */
            architecture?: (string|null);

            /** HostProfileResourceFacts cpuCount */
            cpuCount?: (number|null);

            /** HostProfileResourceFacts memoryTotalBytes */
            memoryTotalBytes?: (number|Long|null);

            /** HostProfileResourceFacts filesystems */
            filesystems?: (enoki.v1.IFilesystemProfile[]|null);

            /** HostProfileResourceFacts networkInterfaces */
            networkInterfaces?: (enoki.v1.INetworkInterfaceProfile[]|null);

            /** HostProfileResourceFacts cpuModel */
            cpuModel?: (string|null);

            /** HostProfileResourceFacts processCount */
            processCount?: (number|null);

            /** HostProfileResourceFacts threadCount */
            threadCount?: (number|null);

            /** HostProfileResourceFacts cpuCacheL3Bytes */
            cpuCacheL3Bytes?: (number|Long|null);

            /** HostProfileResourceFacts cpuBaseFrequencyMhz */
            cpuBaseFrequencyMhz?: (number|null);

            /** HostProfileResourceFacts cpuSocketCount */
            cpuSocketCount?: (number|null);

            /** HostProfileResourceFacts cpuPhysicalCount */
            cpuPhysicalCount?: (number|null);
        }

        /** Represents a HostProfileResourceFacts. */
        class HostProfileResourceFacts implements IHostProfileResourceFacts {

            /**
             * Constructs a new HostProfileResourceFacts.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IHostProfileResourceFacts);

            /** HostProfileResourceFacts hostname. */
            public hostname: string;

            /** HostProfileResourceFacts os. */
            public os: string;

            /** HostProfileResourceFacts kernel. */
            public kernel: string;

            /** HostProfileResourceFacts architecture. */
            public architecture: string;

            /** HostProfileResourceFacts cpuCount. */
            public cpuCount: number;

            /** HostProfileResourceFacts memoryTotalBytes. */
            public memoryTotalBytes: (number|Long);

            /** HostProfileResourceFacts filesystems. */
            public filesystems: enoki.v1.IFilesystemProfile[];

            /** HostProfileResourceFacts networkInterfaces. */
            public networkInterfaces: enoki.v1.INetworkInterfaceProfile[];

            /** HostProfileResourceFacts cpuModel. */
            public cpuModel: string;

            /** HostProfileResourceFacts processCount. */
            public processCount: number;

            /** HostProfileResourceFacts threadCount. */
            public threadCount: number;

            /** HostProfileResourceFacts cpuCacheL3Bytes. */
            public cpuCacheL3Bytes: (number|Long);

            /** HostProfileResourceFacts cpuBaseFrequencyMhz. */
            public cpuBaseFrequencyMhz: number;

            /** HostProfileResourceFacts cpuSocketCount. */
            public cpuSocketCount: number;

            /** HostProfileResourceFacts cpuPhysicalCount. */
            public cpuPhysicalCount: number;

            /**
             * Creates a new HostProfileResourceFacts instance using the specified properties.
             * @param [properties] Properties to set
             * @returns HostProfileResourceFacts instance
             */
            public static create(properties?: enoki.v1.IHostProfileResourceFacts): enoki.v1.HostProfileResourceFacts;

            /**
             * Encodes the specified HostProfileResourceFacts message. Does not implicitly {@link enoki.v1.HostProfileResourceFacts.verify|verify} messages.
             * @param message HostProfileResourceFacts message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IHostProfileResourceFacts, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified HostProfileResourceFacts message, length delimited. Does not implicitly {@link enoki.v1.HostProfileResourceFacts.verify|verify} messages.
             * @param message HostProfileResourceFacts message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IHostProfileResourceFacts, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a HostProfileResourceFacts message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns HostProfileResourceFacts
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.HostProfileResourceFacts;

            /**
             * Decodes a HostProfileResourceFacts message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns HostProfileResourceFacts
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.HostProfileResourceFacts;

            /**
             * Verifies a HostProfileResourceFacts message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a HostProfileResourceFacts message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns HostProfileResourceFacts
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.HostProfileResourceFacts;

            /**
             * Creates a plain object from a HostProfileResourceFacts message. Also converts values to other types if specified.
             * @param message HostProfileResourceFacts
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.HostProfileResourceFacts, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this HostProfileResourceFacts to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for HostProfileResourceFacts
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a Snapshot. */
        interface ISnapshot {

            /** Snapshot collectorId */
            collectorId?: (string|null);

            /** Snapshot snapshotHash */
            snapshotHash?: (string|null);

            /** Snapshot hostProfile */
            hostProfile?: (enoki.v1.IHostProfileSnapshot|null);
        }

        /** Represents a Snapshot. */
        class Snapshot implements ISnapshot {

            /**
             * Constructs a new Snapshot.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ISnapshot);

            /** Snapshot collectorId. */
            public collectorId: string;

            /** Snapshot snapshotHash. */
            public snapshotHash: string;

            /** Snapshot hostProfile. */
            public hostProfile?: (enoki.v1.IHostProfileSnapshot|null);

            /** Snapshot payload. */
            public payload?: "hostProfile";

            /**
             * Creates a new Snapshot instance using the specified properties.
             * @param [properties] Properties to set
             * @returns Snapshot instance
             */
            public static create(properties?: enoki.v1.ISnapshot): enoki.v1.Snapshot;

            /**
             * Encodes the specified Snapshot message. Does not implicitly {@link enoki.v1.Snapshot.verify|verify} messages.
             * @param message Snapshot message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ISnapshot, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified Snapshot message, length delimited. Does not implicitly {@link enoki.v1.Snapshot.verify|verify} messages.
             * @param message Snapshot message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ISnapshot, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a Snapshot message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns Snapshot
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.Snapshot;

            /**
             * Decodes a Snapshot message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns Snapshot
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.Snapshot;

            /**
             * Verifies a Snapshot message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a Snapshot message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns Snapshot
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.Snapshot;

            /**
             * Creates a plain object from a Snapshot message. Also converts values to other types if specified.
             * @param message Snapshot
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.Snapshot, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this Snapshot to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for Snapshot
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FilesystemProfile. */
        interface IFilesystemProfile {

            /** FilesystemProfile mountPoint */
            mountPoint?: (string|null);

            /** FilesystemProfile filesystemType */
            filesystemType?: (string|null);

            /** FilesystemProfile totalBytes */
            totalBytes?: (number|Long|null);

            /** FilesystemProfile availableBytes */
            availableBytes?: (number|Long|null);
        }

        /** Represents a FilesystemProfile. */
        class FilesystemProfile implements IFilesystemProfile {

            /**
             * Constructs a new FilesystemProfile.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IFilesystemProfile);

            /** FilesystemProfile mountPoint. */
            public mountPoint: string;

            /** FilesystemProfile filesystemType. */
            public filesystemType: string;

            /** FilesystemProfile totalBytes. */
            public totalBytes: (number|Long);

            /** FilesystemProfile availableBytes. */
            public availableBytes: (number|Long);

            /**
             * Creates a new FilesystemProfile instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FilesystemProfile instance
             */
            public static create(properties?: enoki.v1.IFilesystemProfile): enoki.v1.FilesystemProfile;

            /**
             * Encodes the specified FilesystemProfile message. Does not implicitly {@link enoki.v1.FilesystemProfile.verify|verify} messages.
             * @param message FilesystemProfile message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IFilesystemProfile, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FilesystemProfile message, length delimited. Does not implicitly {@link enoki.v1.FilesystemProfile.verify|verify} messages.
             * @param message FilesystemProfile message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IFilesystemProfile, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FilesystemProfile message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FilesystemProfile
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.FilesystemProfile;

            /**
             * Decodes a FilesystemProfile message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FilesystemProfile
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.FilesystemProfile;

            /**
             * Verifies a FilesystemProfile message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FilesystemProfile message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FilesystemProfile
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.FilesystemProfile;

            /**
             * Creates a plain object from a FilesystemProfile message. Also converts values to other types if specified.
             * @param message FilesystemProfile
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.FilesystemProfile, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FilesystemProfile to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FilesystemProfile
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a NetworkInterfaceProfile. */
        interface INetworkInterfaceProfile {

            /** NetworkInterfaceProfile name */
            name?: (string|null);

            /** NetworkInterfaceProfile addresses */
            addresses?: (string[]|null);
        }

        /** Represents a NetworkInterfaceProfile. */
        class NetworkInterfaceProfile implements INetworkInterfaceProfile {

            /**
             * Constructs a new NetworkInterfaceProfile.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.INetworkInterfaceProfile);

            /** NetworkInterfaceProfile name. */
            public name: string;

            /** NetworkInterfaceProfile addresses. */
            public addresses: string[];

            /**
             * Creates a new NetworkInterfaceProfile instance using the specified properties.
             * @param [properties] Properties to set
             * @returns NetworkInterfaceProfile instance
             */
            public static create(properties?: enoki.v1.INetworkInterfaceProfile): enoki.v1.NetworkInterfaceProfile;

            /**
             * Encodes the specified NetworkInterfaceProfile message. Does not implicitly {@link enoki.v1.NetworkInterfaceProfile.verify|verify} messages.
             * @param message NetworkInterfaceProfile message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.INetworkInterfaceProfile, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified NetworkInterfaceProfile message, length delimited. Does not implicitly {@link enoki.v1.NetworkInterfaceProfile.verify|verify} messages.
             * @param message NetworkInterfaceProfile message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.INetworkInterfaceProfile, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a NetworkInterfaceProfile message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns NetworkInterfaceProfile
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.NetworkInterfaceProfile;

            /**
             * Decodes a NetworkInterfaceProfile message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns NetworkInterfaceProfile
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.NetworkInterfaceProfile;

            /**
             * Verifies a NetworkInterfaceProfile message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a NetworkInterfaceProfile message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns NetworkInterfaceProfile
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.NetworkInterfaceProfile;

            /**
             * Creates a plain object from a NetworkInterfaceProfile message. Also converts values to other types if specified.
             * @param message NetworkInterfaceProfile
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.NetworkInterfaceProfile, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this NetworkInterfaceProfile to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for NetworkInterfaceProfile
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an OfficialCollectorCapabilities. */
        interface IOfficialCollectorCapabilities {

            /** OfficialCollectorCapabilities diskHealth */
            diskHealth?: (enoki.v1.IDiskHealthCollectorCapability|null);
        }

        /** Represents an OfficialCollectorCapabilities. */
        class OfficialCollectorCapabilities implements IOfficialCollectorCapabilities {

            /**
             * Constructs a new OfficialCollectorCapabilities.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IOfficialCollectorCapabilities);

            /** OfficialCollectorCapabilities diskHealth. */
            public diskHealth?: (enoki.v1.IDiskHealthCollectorCapability|null);

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

        /** Properties of a DiskHealthCollectorCapability. */
        interface IDiskHealthCollectorCapability {

            /** DiskHealthCollectorCapability status */
            status?: (enoki.v1.DiskHealthCollectorCapabilityStatus|null);

            /** DiskHealthCollectorCapability diagnostic */
            diagnostic?: (string|null);
        }

        /** Represents a DiskHealthCollectorCapability. */
        class DiskHealthCollectorCapability implements IDiskHealthCollectorCapability {

            /**
             * Constructs a new DiskHealthCollectorCapability.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IDiskHealthCollectorCapability);

            /** DiskHealthCollectorCapability status. */
            public status: enoki.v1.DiskHealthCollectorCapabilityStatus;

            /** DiskHealthCollectorCapability diagnostic. */
            public diagnostic: string;

            /**
             * Creates a new DiskHealthCollectorCapability instance using the specified properties.
             * @param [properties] Properties to set
             * @returns DiskHealthCollectorCapability instance
             */
            public static create(properties?: enoki.v1.IDiskHealthCollectorCapability): enoki.v1.DiskHealthCollectorCapability;

            /**
             * Encodes the specified DiskHealthCollectorCapability message. Does not implicitly {@link enoki.v1.DiskHealthCollectorCapability.verify|verify} messages.
             * @param message DiskHealthCollectorCapability message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IDiskHealthCollectorCapability, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified DiskHealthCollectorCapability message, length delimited. Does not implicitly {@link enoki.v1.DiskHealthCollectorCapability.verify|verify} messages.
             * @param message DiskHealthCollectorCapability message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IDiskHealthCollectorCapability, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a DiskHealthCollectorCapability message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns DiskHealthCollectorCapability
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.DiskHealthCollectorCapability;

            /**
             * Decodes a DiskHealthCollectorCapability message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns DiskHealthCollectorCapability
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.DiskHealthCollectorCapability;

            /**
             * Verifies a DiskHealthCollectorCapability message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a DiskHealthCollectorCapability message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns DiskHealthCollectorCapability
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.DiskHealthCollectorCapability;

            /**
             * Creates a plain object from a DiskHealthCollectorCapability message. Also converts values to other types if specified.
             * @param message DiskHealthCollectorCapability
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.DiskHealthCollectorCapability, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this DiskHealthCollectorCapability to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for DiskHealthCollectorCapability
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** DiskHealthCollectorCapabilityStatus enum. */
        enum DiskHealthCollectorCapabilityStatus {
            DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_UNSPECIFIED = 0,
            DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_AVAILABLE = 1,
            DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_MISSING_SMARTCTL = 2,
            DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_INSUFFICIENT_LOCAL_PRIVILEGE = 3,
            DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_HELPER_FAILED = 4,
            DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_SCAN_FAILED = 5,
            DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_UNSUPPORTED_SMART_DATA = 6,
            DISK_HEALTH_COLLECTOR_CAPABILITY_STATUS_MALFORMED_OUTPUT = 7
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
            powerOnHours?: (number|Long|null);

            /** DiskHealthMetric totalBytes */
            totalBytes?: (number|Long|null);

            /** DiskHealthMetric usedBytes */
            usedBytes?: (number|Long|null);

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
            public powerOnHours?: (number|Long|null);

            /** DiskHealthMetric totalBytes. */
            public totalBytes?: (number|Long|null);

            /** DiskHealthMetric usedBytes. */
            public usedBytes?: (number|Long|null);

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

        /** Properties of a DiskHealthDeviceResourceFact. */
        interface IDiskHealthDeviceResourceFact {

            /** DiskHealthDeviceResourceFact deviceName */
            deviceName?: (string|null);

            /** DiskHealthDeviceResourceFact smartctlJson */
            smartctlJson?: (Uint8Array|null);

            /** DiskHealthDeviceResourceFact exitCode */
            exitCode?: (number|null);
        }

        /** Represents a DiskHealthDeviceResourceFact. */
        class DiskHealthDeviceResourceFact implements IDiskHealthDeviceResourceFact {

            /**
             * Constructs a new DiskHealthDeviceResourceFact.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IDiskHealthDeviceResourceFact);

            /** DiskHealthDeviceResourceFact deviceName. */
            public deviceName: string;

            /** DiskHealthDeviceResourceFact smartctlJson. */
            public smartctlJson: Uint8Array;

            /** DiskHealthDeviceResourceFact exitCode. */
            public exitCode: number;

            /**
             * Creates a new DiskHealthDeviceResourceFact instance using the specified properties.
             * @param [properties] Properties to set
             * @returns DiskHealthDeviceResourceFact instance
             */
            public static create(properties?: enoki.v1.IDiskHealthDeviceResourceFact): enoki.v1.DiskHealthDeviceResourceFact;

            /**
             * Encodes the specified DiskHealthDeviceResourceFact message. Does not implicitly {@link enoki.v1.DiskHealthDeviceResourceFact.verify|verify} messages.
             * @param message DiskHealthDeviceResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IDiskHealthDeviceResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified DiskHealthDeviceResourceFact message, length delimited. Does not implicitly {@link enoki.v1.DiskHealthDeviceResourceFact.verify|verify} messages.
             * @param message DiskHealthDeviceResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IDiskHealthDeviceResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a DiskHealthDeviceResourceFact message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns DiskHealthDeviceResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.DiskHealthDeviceResourceFact;

            /**
             * Decodes a DiskHealthDeviceResourceFact message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns DiskHealthDeviceResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.DiskHealthDeviceResourceFact;

            /**
             * Verifies a DiskHealthDeviceResourceFact message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a DiskHealthDeviceResourceFact message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns DiskHealthDeviceResourceFact
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.DiskHealthDeviceResourceFact;

            /**
             * Creates a plain object from a DiskHealthDeviceResourceFact message. Also converts values to other types if specified.
             * @param message DiskHealthDeviceResourceFact
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.DiskHealthDeviceResourceFact, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this DiskHealthDeviceResourceFact to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for DiskHealthDeviceResourceFact
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a DiskHealthResourceResult. */
        interface IDiskHealthResourceResult {

            /** DiskHealthResourceResult devices */
            devices?: (enoki.v1.IDiskHealthDeviceResourceFact[]|null);

            /** DiskHealthResourceResult capabilityStatus */
            capabilityStatus?: (enoki.v1.DiskHealthCollectorCapabilityStatus|null);

            /** DiskHealthResourceResult failureCode */
            failureCode?: (string|null);

            /** DiskHealthResourceResult unraidDisksIni */
            unraidDisksIni?: (string|null);
        }

        /** Represents a DiskHealthResourceResult. */
        class DiskHealthResourceResult implements IDiskHealthResourceResult {

            /**
             * Constructs a new DiskHealthResourceResult.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IDiskHealthResourceResult);

            /** DiskHealthResourceResult devices. */
            public devices: enoki.v1.IDiskHealthDeviceResourceFact[];

            /** DiskHealthResourceResult capabilityStatus. */
            public capabilityStatus: enoki.v1.DiskHealthCollectorCapabilityStatus;

            /** DiskHealthResourceResult failureCode. */
            public failureCode: string;

            /** DiskHealthResourceResult unraidDisksIni. */
            public unraidDisksIni: string;

            /**
             * Creates a new DiskHealthResourceResult instance using the specified properties.
             * @param [properties] Properties to set
             * @returns DiskHealthResourceResult instance
             */
            public static create(properties?: enoki.v1.IDiskHealthResourceResult): enoki.v1.DiskHealthResourceResult;

            /**
             * Encodes the specified DiskHealthResourceResult message. Does not implicitly {@link enoki.v1.DiskHealthResourceResult.verify|verify} messages.
             * @param message DiskHealthResourceResult message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IDiskHealthResourceResult, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified DiskHealthResourceResult message, length delimited. Does not implicitly {@link enoki.v1.DiskHealthResourceResult.verify|verify} messages.
             * @param message DiskHealthResourceResult message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IDiskHealthResourceResult, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a DiskHealthResourceResult message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns DiskHealthResourceResult
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.DiskHealthResourceResult;

            /**
             * Decodes a DiskHealthResourceResult message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns DiskHealthResourceResult
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.DiskHealthResourceResult;

            /**
             * Verifies a DiskHealthResourceResult message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a DiskHealthResourceResult message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns DiskHealthResourceResult
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.DiskHealthResourceResult;

            /**
             * Creates a plain object from a DiskHealthResourceResult message. Also converts values to other types if specified.
             * @param message DiskHealthResourceResult
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.DiskHealthResourceResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this DiskHealthResourceResult to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for DiskHealthResourceResult
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a CpuCounterResourceFact. */
        interface ICpuCounterResourceFact {

            /** CpuCounterResourceFact name */
            name?: (string|null);

            /** CpuCounterResourceFact user */
            user?: (number|Long|null);

            /** CpuCounterResourceFact nice */
            nice?: (number|Long|null);

            /** CpuCounterResourceFact system */
            system?: (number|Long|null);

            /** CpuCounterResourceFact idle */
            idle?: (number|Long|null);

            /** CpuCounterResourceFact iowait */
            iowait?: (number|Long|null);

            /** CpuCounterResourceFact irq */
            irq?: (number|Long|null);

            /** CpuCounterResourceFact softirq */
            softirq?: (number|Long|null);

            /** CpuCounterResourceFact steal */
            steal?: (number|Long|null);
        }

        /** Represents a CpuCounterResourceFact. */
        class CpuCounterResourceFact implements ICpuCounterResourceFact {

            /**
             * Constructs a new CpuCounterResourceFact.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ICpuCounterResourceFact);

            /** CpuCounterResourceFact name. */
            public name: string;

            /** CpuCounterResourceFact user. */
            public user: (number|Long);

            /** CpuCounterResourceFact nice. */
            public nice: (number|Long);

            /** CpuCounterResourceFact system. */
            public system: (number|Long);

            /** CpuCounterResourceFact idle. */
            public idle: (number|Long);

            /** CpuCounterResourceFact iowait. */
            public iowait: (number|Long);

            /** CpuCounterResourceFact irq. */
            public irq: (number|Long);

            /** CpuCounterResourceFact softirq. */
            public softirq: (number|Long);

            /** CpuCounterResourceFact steal. */
            public steal: (number|Long);

            /**
             * Creates a new CpuCounterResourceFact instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CpuCounterResourceFact instance
             */
            public static create(properties?: enoki.v1.ICpuCounterResourceFact): enoki.v1.CpuCounterResourceFact;

            /**
             * Encodes the specified CpuCounterResourceFact message. Does not implicitly {@link enoki.v1.CpuCounterResourceFact.verify|verify} messages.
             * @param message CpuCounterResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ICpuCounterResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CpuCounterResourceFact message, length delimited. Does not implicitly {@link enoki.v1.CpuCounterResourceFact.verify|verify} messages.
             * @param message CpuCounterResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ICpuCounterResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CpuCounterResourceFact message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CpuCounterResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.CpuCounterResourceFact;

            /**
             * Decodes a CpuCounterResourceFact message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CpuCounterResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.CpuCounterResourceFact;

            /**
             * Verifies a CpuCounterResourceFact message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CpuCounterResourceFact message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CpuCounterResourceFact
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.CpuCounterResourceFact;

            /**
             * Creates a plain object from a CpuCounterResourceFact message. Also converts values to other types if specified.
             * @param message CpuCounterResourceFact
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.CpuCounterResourceFact, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CpuCounterResourceFact to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CpuCounterResourceFact
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FilesystemCapacityResourceFact. */
        interface IFilesystemCapacityResourceFact {

            /** FilesystemCapacityResourceFact mountPoint */
            mountPoint?: (string|null);

            /** FilesystemCapacityResourceFact totalBytes */
            totalBytes?: (number|Long|null);

            /** FilesystemCapacityResourceFact freeBytes */
            freeBytes?: (number|Long|null);

            /** FilesystemCapacityResourceFact availableBytes */
            availableBytes?: (number|Long|null);
        }

        /** Represents a FilesystemCapacityResourceFact. */
        class FilesystemCapacityResourceFact implements IFilesystemCapacityResourceFact {

            /**
             * Constructs a new FilesystemCapacityResourceFact.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IFilesystemCapacityResourceFact);

            /** FilesystemCapacityResourceFact mountPoint. */
            public mountPoint: string;

            /** FilesystemCapacityResourceFact totalBytes. */
            public totalBytes: (number|Long);

            /** FilesystemCapacityResourceFact freeBytes. */
            public freeBytes: (number|Long);

            /** FilesystemCapacityResourceFact availableBytes. */
            public availableBytes: (number|Long);

            /**
             * Creates a new FilesystemCapacityResourceFact instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FilesystemCapacityResourceFact instance
             */
            public static create(properties?: enoki.v1.IFilesystemCapacityResourceFact): enoki.v1.FilesystemCapacityResourceFact;

            /**
             * Encodes the specified FilesystemCapacityResourceFact message. Does not implicitly {@link enoki.v1.FilesystemCapacityResourceFact.verify|verify} messages.
             * @param message FilesystemCapacityResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IFilesystemCapacityResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FilesystemCapacityResourceFact message, length delimited. Does not implicitly {@link enoki.v1.FilesystemCapacityResourceFact.verify|verify} messages.
             * @param message FilesystemCapacityResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IFilesystemCapacityResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FilesystemCapacityResourceFact message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FilesystemCapacityResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.FilesystemCapacityResourceFact;

            /**
             * Decodes a FilesystemCapacityResourceFact message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FilesystemCapacityResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.FilesystemCapacityResourceFact;

            /**
             * Verifies a FilesystemCapacityResourceFact message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FilesystemCapacityResourceFact message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FilesystemCapacityResourceFact
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.FilesystemCapacityResourceFact;

            /**
             * Creates a plain object from a FilesystemCapacityResourceFact message. Also converts values to other types if specified.
             * @param message FilesystemCapacityResourceFact
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.FilesystemCapacityResourceFact, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FilesystemCapacityResourceFact to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FilesystemCapacityResourceFact
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a BatterySupplyResourceFact. */
        interface IBatterySupplyResourceFact {

            /** BatterySupplyResourceFact supplyType */
            supplyType?: (string|null);

            /** BatterySupplyResourceFact capacity */
            capacity?: (string|null);

            /** BatterySupplyResourceFact status */
            status?: (string|null);
        }

        /** Represents a BatterySupplyResourceFact. */
        class BatterySupplyResourceFact implements IBatterySupplyResourceFact {

            /**
             * Constructs a new BatterySupplyResourceFact.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IBatterySupplyResourceFact);

            /** BatterySupplyResourceFact supplyType. */
            public supplyType: string;

            /** BatterySupplyResourceFact capacity. */
            public capacity: string;

            /** BatterySupplyResourceFact status. */
            public status: string;

            /**
             * Creates a new BatterySupplyResourceFact instance using the specified properties.
             * @param [properties] Properties to set
             * @returns BatterySupplyResourceFact instance
             */
            public static create(properties?: enoki.v1.IBatterySupplyResourceFact): enoki.v1.BatterySupplyResourceFact;

            /**
             * Encodes the specified BatterySupplyResourceFact message. Does not implicitly {@link enoki.v1.BatterySupplyResourceFact.verify|verify} messages.
             * @param message BatterySupplyResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IBatterySupplyResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified BatterySupplyResourceFact message, length delimited. Does not implicitly {@link enoki.v1.BatterySupplyResourceFact.verify|verify} messages.
             * @param message BatterySupplyResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IBatterySupplyResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a BatterySupplyResourceFact message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns BatterySupplyResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.BatterySupplyResourceFact;

            /**
             * Decodes a BatterySupplyResourceFact message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns BatterySupplyResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.BatterySupplyResourceFact;

            /**
             * Verifies a BatterySupplyResourceFact message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a BatterySupplyResourceFact message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns BatterySupplyResourceFact
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.BatterySupplyResourceFact;

            /**
             * Creates a plain object from a BatterySupplyResourceFact message. Also converts values to other types if specified.
             * @param message BatterySupplyResourceFact
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.BatterySupplyResourceFact, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this BatterySupplyResourceFact to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for BatterySupplyResourceFact
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a BlockDeviceTopologyResourceFact. */
        interface IBlockDeviceTopologyResourceFact {

            /** BlockDeviceTopologyResourceFact source */
            source?: (string|null);

            /** BlockDeviceTopologyResourceFact physicalDevice */
            physicalDevice?: (string|null);
        }

        /** Represents a BlockDeviceTopologyResourceFact. */
        class BlockDeviceTopologyResourceFact implements IBlockDeviceTopologyResourceFact {

            /**
             * Constructs a new BlockDeviceTopologyResourceFact.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IBlockDeviceTopologyResourceFact);

            /** BlockDeviceTopologyResourceFact source. */
            public source: string;

            /** BlockDeviceTopologyResourceFact physicalDevice. */
            public physicalDevice: string;

            /**
             * Creates a new BlockDeviceTopologyResourceFact instance using the specified properties.
             * @param [properties] Properties to set
             * @returns BlockDeviceTopologyResourceFact instance
             */
            public static create(properties?: enoki.v1.IBlockDeviceTopologyResourceFact): enoki.v1.BlockDeviceTopologyResourceFact;

            /**
             * Encodes the specified BlockDeviceTopologyResourceFact message. Does not implicitly {@link enoki.v1.BlockDeviceTopologyResourceFact.verify|verify} messages.
             * @param message BlockDeviceTopologyResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.IBlockDeviceTopologyResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified BlockDeviceTopologyResourceFact message, length delimited. Does not implicitly {@link enoki.v1.BlockDeviceTopologyResourceFact.verify|verify} messages.
             * @param message BlockDeviceTopologyResourceFact message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.IBlockDeviceTopologyResourceFact, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a BlockDeviceTopologyResourceFact message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns BlockDeviceTopologyResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.BlockDeviceTopologyResourceFact;

            /**
             * Decodes a BlockDeviceTopologyResourceFact message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns BlockDeviceTopologyResourceFact
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.BlockDeviceTopologyResourceFact;

            /**
             * Verifies a BlockDeviceTopologyResourceFact message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a BlockDeviceTopologyResourceFact message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns BlockDeviceTopologyResourceFact
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.BlockDeviceTopologyResourceFact;

            /**
             * Creates a plain object from a BlockDeviceTopologyResourceFact message. Also converts values to other types if specified.
             * @param message BlockDeviceTopologyResourceFact
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.BlockDeviceTopologyResourceFact, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this BlockDeviceTopologyResourceFact to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for BlockDeviceTopologyResourceFact
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a SystemStateResourceResult. */
        interface ISystemStateResourceResult {

            /** SystemStateResourceResult cpuCounters */
            cpuCounters?: (enoki.v1.ICpuCounterResourceFact[]|null);

            /** SystemStateResourceResult procLoadavg */
            procLoadavg?: (string|null);

            /** SystemStateResourceResult procMeminfo */
            procMeminfo?: (string|null);

            /** SystemStateResourceResult procUptime */
            procUptime?: (string|null);

            /** SystemStateResourceResult hostProfile */
            hostProfile?: (enoki.v1.IHostProfileResourceFacts|null);

            /** SystemStateResourceResult procNetDev */
            procNetDev?: (string|null);

            /** SystemStateResourceResult procNetRoute */
            procNetRoute?: (string|null);

            /** SystemStateResourceResult procNetIpv6Route */
            procNetIpv6Route?: (string|null);

            /** SystemStateResourceResult procMounts */
            procMounts?: (string|null);

            /** SystemStateResourceResult procDiskstats */
            procDiskstats?: (string|null);

            /** SystemStateResourceResult diskCountersCollectedAtMs */
            diskCountersCollectedAtMs?: (number|Long|null);

            /** SystemStateResourceResult filesystemCapacities */
            filesystemCapacities?: (enoki.v1.IFilesystemCapacityResourceFact[]|null);

            /** SystemStateResourceResult temperatureInputs */
            temperatureInputs?: (string[]|null);

            /** SystemStateResourceResult batterySupplies */
            batterySupplies?: (enoki.v1.IBatterySupplyResourceFact[]|null);

            /** SystemStateResourceResult networkFailureCode */
            networkFailureCode?: (string|null);

            /** SystemStateResourceResult diskFailureCode */
            diskFailureCode?: (string|null);

            /** SystemStateResourceResult temperatureFailureCode */
            temperatureFailureCode?: (string|null);

            /** SystemStateResourceResult batteryFailureCode */
            batteryFailureCode?: (string|null);

            /** SystemStateResourceResult blockDeviceTopology */
            blockDeviceTopology?: (enoki.v1.IBlockDeviceTopologyResourceFact[]|null);
        }

        /** Represents a SystemStateResourceResult. */
        class SystemStateResourceResult implements ISystemStateResourceResult {

            /**
             * Constructs a new SystemStateResourceResult.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ISystemStateResourceResult);

            /** SystemStateResourceResult cpuCounters. */
            public cpuCounters: enoki.v1.ICpuCounterResourceFact[];

            /** SystemStateResourceResult procLoadavg. */
            public procLoadavg: string;

            /** SystemStateResourceResult procMeminfo. */
            public procMeminfo: string;

            /** SystemStateResourceResult procUptime. */
            public procUptime: string;

            /** SystemStateResourceResult hostProfile. */
            public hostProfile?: (enoki.v1.IHostProfileResourceFacts|null);

            /** SystemStateResourceResult procNetDev. */
            public procNetDev: string;

            /** SystemStateResourceResult procNetRoute. */
            public procNetRoute: string;

            /** SystemStateResourceResult procNetIpv6Route. */
            public procNetIpv6Route: string;

            /** SystemStateResourceResult procMounts. */
            public procMounts: string;

            /** SystemStateResourceResult procDiskstats. */
            public procDiskstats: string;

            /** SystemStateResourceResult diskCountersCollectedAtMs. */
            public diskCountersCollectedAtMs: (number|Long);

            /** SystemStateResourceResult filesystemCapacities. */
            public filesystemCapacities: enoki.v1.IFilesystemCapacityResourceFact[];

            /** SystemStateResourceResult temperatureInputs. */
            public temperatureInputs: string[];

            /** SystemStateResourceResult batterySupplies. */
            public batterySupplies: enoki.v1.IBatterySupplyResourceFact[];

            /** SystemStateResourceResult networkFailureCode. */
            public networkFailureCode: string;

            /** SystemStateResourceResult diskFailureCode. */
            public diskFailureCode: string;

            /** SystemStateResourceResult temperatureFailureCode. */
            public temperatureFailureCode: string;

            /** SystemStateResourceResult batteryFailureCode. */
            public batteryFailureCode: string;

            /** SystemStateResourceResult blockDeviceTopology. */
            public blockDeviceTopology: enoki.v1.IBlockDeviceTopologyResourceFact[];

            /**
             * Creates a new SystemStateResourceResult instance using the specified properties.
             * @param [properties] Properties to set
             * @returns SystemStateResourceResult instance
             */
            public static create(properties?: enoki.v1.ISystemStateResourceResult): enoki.v1.SystemStateResourceResult;

            /**
             * Encodes the specified SystemStateResourceResult message. Does not implicitly {@link enoki.v1.SystemStateResourceResult.verify|verify} messages.
             * @param message SystemStateResourceResult message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ISystemStateResourceResult, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified SystemStateResourceResult message, length delimited. Does not implicitly {@link enoki.v1.SystemStateResourceResult.verify|verify} messages.
             * @param message SystemStateResourceResult message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ISystemStateResourceResult, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a SystemStateResourceResult message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns SystemStateResourceResult
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.SystemStateResourceResult;

            /**
             * Decodes a SystemStateResourceResult message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns SystemStateResourceResult
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.SystemStateResourceResult;

            /**
             * Verifies a SystemStateResourceResult message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a SystemStateResourceResult message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns SystemStateResourceResult
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.SystemStateResourceResult;

            /**
             * Creates a plain object from a SystemStateResourceResult message. Also converts values to other types if specified.
             * @param message SystemStateResourceResult
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.SystemStateResourceResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this SystemStateResourceResult to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for SystemStateResourceResult
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MetricSample. */
        interface IMetricSample {

            /** MetricSample sequence */
            sequence?: (number|Long|null);

            /** MetricSample collectedAtMs */
            collectedAtMs?: (number|Long|null);

            /** MetricSample cpuPercent */
            cpuPercent?: (number|null);

            /** MetricSample memoryUsedBytes */
            memoryUsedBytes?: (number|Long|null);

            /** MetricSample load_1 */
            load_1?: (number|null);

            /** MetricSample load_5 */
            load_5?: (number|null);

            /** MetricSample load_15 */
            load_15?: (number|null);

            /** MetricSample uptimeSeconds */
            uptimeSeconds?: (number|Long|null);

            /** MetricSample disks */
            disks?: (enoki.v1.IDiskUsageMetric[]|null);

            /** MetricSample networkInterfaces */
            networkInterfaces?: (enoki.v1.INetworkInterfaceMetric[]|null);

            /** MetricSample cpuCores */
            cpuCores?: (enoki.v1.ICpuCoreMetric[]|null);

            /** MetricSample memoryTotalBytes */
            memoryTotalBytes?: (number|Long|null);

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
            memoryCacheBytes?: (number|Long|null);

            /** MetricSample swapTotalBytes */
            swapTotalBytes?: (number|Long|null);

            /** MetricSample swapUsedBytes */
            swapUsedBytes?: (number|Long|null);

            /** MetricSample temperatureCelsius */
            temperatureCelsius?: (number|null);

            /** MetricSample batteryPercent */
            batteryPercent?: (number|null);

            /** MetricSample batteryState */
            batteryState?: (string|null);

            /** MetricSample diskHealth */
            diskHealth?: (enoki.v1.IDiskHealthMetric[]|null);

            /** MetricSample collectorOutcomes */
            collectorOutcomes?: (enoki.v1.ICollectorOutcome[]|null);
        }

        /** Represents a MetricSample. */
        class MetricSample implements IMetricSample {

            /**
             * Constructs a new MetricSample.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.IMetricSample);

            /** MetricSample sequence. */
            public sequence: (number|Long);

            /** MetricSample collectedAtMs. */
            public collectedAtMs: (number|Long);

            /** MetricSample cpuPercent. */
            public cpuPercent?: (number|null);

            /** MetricSample memoryUsedBytes. */
            public memoryUsedBytes?: (number|Long|null);

            /** MetricSample load_1. */
            public load_1?: (number|null);

            /** MetricSample load_5. */
            public load_5?: (number|null);

            /** MetricSample load_15. */
            public load_15?: (number|null);

            /** MetricSample uptimeSeconds. */
            public uptimeSeconds?: (number|Long|null);

            /** MetricSample disks. */
            public disks: enoki.v1.IDiskUsageMetric[];

            /** MetricSample networkInterfaces. */
            public networkInterfaces: enoki.v1.INetworkInterfaceMetric[];

            /** MetricSample cpuCores. */
            public cpuCores: enoki.v1.ICpuCoreMetric[];

            /** MetricSample memoryTotalBytes. */
            public memoryTotalBytes?: (number|Long|null);

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
            public memoryCacheBytes?: (number|Long|null);

            /** MetricSample swapTotalBytes. */
            public swapTotalBytes?: (number|Long|null);

            /** MetricSample swapUsedBytes. */
            public swapUsedBytes?: (number|Long|null);

            /** MetricSample temperatureCelsius. */
            public temperatureCelsius?: (number|null);

            /** MetricSample batteryPercent. */
            public batteryPercent?: (number|null);

            /** MetricSample batteryState. */
            public batteryState?: (string|null);

            /** MetricSample diskHealth. */
            public diskHealth: enoki.v1.IDiskHealthMetric[];

            /** MetricSample collectorOutcomes. */
            public collectorOutcomes: enoki.v1.ICollectorOutcome[];

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

        /** Properties of a CollectorOutcome. */
        interface ICollectorOutcome {

            /** CollectorOutcome collectorId */
            collectorId?: (string|null);

            /** CollectorOutcome state */
            state?: (enoki.v1.CollectorOutcomeState|null);

            /** CollectorOutcome failure */
            failure?: (enoki.v1.ICollectorFailure|null);
        }

        /** Represents a CollectorOutcome. */
        class CollectorOutcome implements ICollectorOutcome {

            /**
             * Constructs a new CollectorOutcome.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ICollectorOutcome);

            /** CollectorOutcome collectorId. */
            public collectorId: string;

            /** CollectorOutcome state. */
            public state: enoki.v1.CollectorOutcomeState;

            /** CollectorOutcome failure. */
            public failure?: (enoki.v1.ICollectorFailure|null);

            /**
             * Creates a new CollectorOutcome instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CollectorOutcome instance
             */
            public static create(properties?: enoki.v1.ICollectorOutcome): enoki.v1.CollectorOutcome;

            /**
             * Encodes the specified CollectorOutcome message. Does not implicitly {@link enoki.v1.CollectorOutcome.verify|verify} messages.
             * @param message CollectorOutcome message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ICollectorOutcome, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CollectorOutcome message, length delimited. Does not implicitly {@link enoki.v1.CollectorOutcome.verify|verify} messages.
             * @param message CollectorOutcome message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ICollectorOutcome, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CollectorOutcome message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CollectorOutcome
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.CollectorOutcome;

            /**
             * Decodes a CollectorOutcome message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CollectorOutcome
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.CollectorOutcome;

            /**
             * Verifies a CollectorOutcome message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CollectorOutcome message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CollectorOutcome
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.CollectorOutcome;

            /**
             * Creates a plain object from a CollectorOutcome message. Also converts values to other types if specified.
             * @param message CollectorOutcome
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.CollectorOutcome, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CollectorOutcome to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CollectorOutcome
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** CollectorOutcomeState enum. */
        enum CollectorOutcomeState {
            COLLECTOR_OUTCOME_STATE_UNSPECIFIED = 0,
            COLLECTOR_OUTCOME_STATE_PRODUCED = 1,
            COLLECTOR_OUTCOME_STATE_NO_DATA = 2,
            COLLECTOR_OUTCOME_STATE_FAILED = 3
        }

        /** Properties of a CollectorFailure. */
        interface ICollectorFailure {

            /** CollectorFailure phase */
            phase?: (enoki.v1.CollectorFailurePhase|null);

            /** CollectorFailure legacyCode */
            legacyCode?: (number|null);

            /** CollectorFailure code */
            code?: (string|null);
        }

        /** Represents a CollectorFailure. */
        class CollectorFailure implements ICollectorFailure {

            /**
             * Constructs a new CollectorFailure.
             * @param [properties] Properties to set
             */
            constructor(properties?: enoki.v1.ICollectorFailure);

            /** CollectorFailure phase. */
            public phase: enoki.v1.CollectorFailurePhase;

            /** CollectorFailure legacyCode. */
            public legacyCode: number;

            /** CollectorFailure code. */
            public code: string;

            /**
             * Creates a new CollectorFailure instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CollectorFailure instance
             */
            public static create(properties?: enoki.v1.ICollectorFailure): enoki.v1.CollectorFailure;

            /**
             * Encodes the specified CollectorFailure message. Does not implicitly {@link enoki.v1.CollectorFailure.verify|verify} messages.
             * @param message CollectorFailure message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: enoki.v1.ICollectorFailure, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CollectorFailure message, length delimited. Does not implicitly {@link enoki.v1.CollectorFailure.verify|verify} messages.
             * @param message CollectorFailure message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: enoki.v1.ICollectorFailure, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CollectorFailure message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CollectorFailure
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): enoki.v1.CollectorFailure;

            /**
             * Decodes a CollectorFailure message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CollectorFailure
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): enoki.v1.CollectorFailure;

            /**
             * Verifies a CollectorFailure message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CollectorFailure message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CollectorFailure
             */
            public static fromObject(object: { [k: string]: any }): enoki.v1.CollectorFailure;

            /**
             * Creates a plain object from a CollectorFailure message. Also converts values to other types if specified.
             * @param message CollectorFailure
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: enoki.v1.CollectorFailure, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CollectorFailure to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CollectorFailure
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** CollectorFailurePhase enum. */
        enum CollectorFailurePhase {
            COLLECTOR_FAILURE_PHASE_UNSPECIFIED = 0,
            COLLECTOR_FAILURE_PHASE_RESOURCE = 1,
            COLLECTOR_FAILURE_PHASE_CALCULATION = 2
        }

        /** Properties of a CpuCoreMetric. */
        interface ICpuCoreMetric {

            /** CpuCoreMetric name */
            name?: (string|null);

            /** CpuCoreMetric user */
            user?: (number|Long|null);

            /** CpuCoreMetric nice */
            nice?: (number|Long|null);

            /** CpuCoreMetric system */
            system?: (number|Long|null);

            /** CpuCoreMetric idle */
            idle?: (number|Long|null);

            /** CpuCoreMetric iowait */
            iowait?: (number|Long|null);

            /** CpuCoreMetric irq */
            irq?: (number|Long|null);

            /** CpuCoreMetric softirq */
            softirq?: (number|Long|null);

            /** CpuCoreMetric steal */
            steal?: (number|Long|null);

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
            public user: (number|Long);

            /** CpuCoreMetric nice. */
            public nice: (number|Long);

            /** CpuCoreMetric system. */
            public system: (number|Long);

            /** CpuCoreMetric idle. */
            public idle: (number|Long);

            /** CpuCoreMetric iowait. */
            public iowait: (number|Long);

            /** CpuCoreMetric irq. */
            public irq: (number|Long);

            /** CpuCoreMetric softirq. */
            public softirq: (number|Long);

            /** CpuCoreMetric steal. */
            public steal: (number|Long);

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
            totalBytes?: (number|Long|null);

            /** DiskUsageMetric usedBytes */
            usedBytes?: (number|Long|null);

            /** DiskUsageMetric availableBytes */
            availableBytes?: (number|Long|null);

            /** DiskUsageMetric readBytesDelta */
            readBytesDelta?: (number|Long|null);

            /** DiskUsageMetric writeBytesDelta */
            writeBytesDelta?: (number|Long|null);

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
            public totalBytes: (number|Long);

            /** DiskUsageMetric usedBytes. */
            public usedBytes: (number|Long);

            /** DiskUsageMetric availableBytes. */
            public availableBytes: (number|Long);

            /** DiskUsageMetric readBytesDelta. */
            public readBytesDelta: (number|Long);

            /** DiskUsageMetric writeBytesDelta. */
            public writeBytesDelta: (number|Long);

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

        /** Properties of a NetworkInterfaceMetric. */
        interface INetworkInterfaceMetric {

            /** NetworkInterfaceMetric name */
            name?: (string|null);

            /** NetworkInterfaceMetric rxBytes */
            rxBytes?: (number|Long|null);

            /** NetworkInterfaceMetric txBytes */
            txBytes?: (number|Long|null);

            /** NetworkInterfaceMetric rxBytesDelta */
            rxBytesDelta?: (number|Long|null);

            /** NetworkInterfaceMetric txBytesDelta */
            txBytesDelta?: (number|Long|null);
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
            public rxBytes: (number|Long);

            /** NetworkInterfaceMetric txBytes. */
            public txBytes: (number|Long);

            /** NetworkInterfaceMetric rxBytesDelta. */
            public rxBytesDelta: (number|Long);

            /** NetworkInterfaceMetric txBytesDelta. */
            public txBytesDelta: (number|Long);

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

            /** ProbeUpgradeOperation targetAssetSetDigest */
            targetAssetSetDigest?: (string|null);
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

            /** ProbeUpgradeOperation targetAssetSetDigest. */
            public targetAssetSetDigest: string;

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
