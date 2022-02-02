import { Express } from "express";
import { GetIdPrefsResponse, GetNewIdResponse, Identifier, IdAndOptionalPreferences, PostIdPrefsResponse } from "paf-mvp-core-js/dist/model/generated-model";
import { UnsignedMessage } from "paf-mvp-core-js/dist/model/model";
import { GetIdPrefsRequestSigner, PostIdPrefsRequestSigner } from "paf-mvp-core-js/dist/crypto/message-signature";
import { PublicKeys } from "paf-mvp-core-js/dist/crypto/keys";
export declare const addOperatorApi: (app: Express, operatorHost: string, privateKey: string, publicKeyStore: PublicKeys) => void;
export declare class OperatorApi {
    host: string;
    private readonly idSigner;
    private readonly ecdsaKey;
    private getIdPrefsResponseSigner;
    signGetIdPrefsResponse: (data: UnsignedMessage<GetIdPrefsResponse>) => string;
    private postIdPrefsResponseSigner;
    signPostIdPrefsResponse: (data: UnsignedMessage<PostIdPrefsResponse>) => string;
    private getNewIdResponseSigner;
    signGetNewIdResponse: (data: UnsignedMessage<GetNewIdResponse>) => string;
    readonly getIdPrefsRequestVerifier: GetIdPrefsRequestSigner;
    readonly postIdPrefsRequestVerifier: PostIdPrefsRequestSigner;
    constructor(host: string, privateKey: string);
    generateNewId(timestamp?: number): Identifier;
    buildGetIdPrefsResponse(receiver: string, { identifiers, preferences }: IdAndOptionalPreferences, timestamp?: number): GetIdPrefsResponse;
    buildPostIdPrefsResponse(receiver: string, { identifiers, preferences }: IdAndOptionalPreferences, timestamp?: number): PostIdPrefsResponse;
    buildGetNewIdResponse(receiver: string, newId?: Identifier, timestamp?: number): GetNewIdResponse;
    signId(value: string, timestamp?: number): Identifier;
}
