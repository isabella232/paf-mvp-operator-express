import {Express, Request, Response} from "express";
import {getReturnUrl, httpRedirect, removeCookie, setCookie} from "../paf-mvp-core-js/src/express";
import cors, {CorsOptions} from "cors";
import {v4 as uuidv4} from "uuid";
import {
    GetIdPrefsRequest,
    GetIdPrefsResponse,
    GetNewIdResponse,
    Id,
    IdAndOptionalPrefs,
    PostIdPrefsRequest,
    PostIdPrefsResponse,
    Preferences
} from "../paf-mvp-core-js/src/model/generated-model";
import {isEmptyListOfIds, UnsignedData, UnsignedMessage} from "../paf-mvp-core-js/src/model/model";
import {
    GetIdPrefsRequestSigner,
    GetIdPrefsResponseSigner,
    GetNewIdResponseSigner,
    PostIdPrefsRequestSigner,
    PostIdPrefsResponseSigner
} from "../paf-mvp-core-js/src/crypto/message-signature";
import {Cookies} from "../paf-mvp-core-js/src/cookies";
import {IdSigner} from "../paf-mvp-core-js/src/crypto/data-signature";
import {PrivateKey, privateKeyFromString, PublicKeys} from "../paf-mvp-core-js/src/crypto/keys";
import {jsonEndpoints, redirectEndpoints, uriParams} from "../paf-mvp-core-js/src/endpoints";

const domainParser = require('tld-extract');

// Expiration: now + 3 months
const getOperatorExpiration = (date: Date = new Date()) => {
    const expirationDate = new Date(date);
    expirationDate.setMonth(expirationDate.getMonth() + 3);
    return expirationDate;
}

const getExistingId = (req: Request): Id | undefined => {
    const cookies = req.cookies;
    return cookies[Cookies.ID] ? JSON.parse(cookies[Cookies.ID]) : undefined
}

const getExistingPrefs = (req: Request): Preferences | undefined => {
    const cookies = req.cookies;
    return cookies[Cookies.PREFS] ? JSON.parse(cookies[Cookies.PREFS]) : undefined
}

// TODO should be a proper ExpressJS middleware
// TODO all received requests should be verified (signature)
export const addOperatorApi = (app: Express, operatorHost: string, privateKey: string, publicKeyStore: PublicKeys) => {

    const tld = domainParser(operatorHost).domain

    const writeAsCookies = (input: PostIdPrefsRequest, res: Response) => {
        // TODO here we should verify signatures
        if (input.body.identifiers?.[0] !== undefined) {
            setCookie(res, Cookies.ID, JSON.stringify(input.body.identifiers[0]), getOperatorExpiration(), {domain: tld})
        }
        if (input.body.preferences !== undefined) {
            setCookie(res, Cookies.PREFS, JSON.stringify(input.body.preferences), getOperatorExpiration(), {domain: tld})
        }
    };

    const operatorApi = new OperatorApi(operatorHost, privateKey)

    const getReadRequest = (req: Request): GetIdPrefsRequest => ({
        sender: req.query[uriParams.sender] as string,
        receiver: req.query[uriParams.receiver] as string,
        timestamp: parseInt(req.query[uriParams.timestamp] as string),
        signature: req.query[uriParams.signature] as string
    });

    /* FIXME should be parsed similar to read request. Get read of uriParams.data
    const getWriteRequest = (req: Request): WriteRequest => ({
        sender: req.query[uriParams.sender] as string,
        receiver: req.query[uriParams.signature] as string,
        timestamp: parseInt(req.query[uriParams.timestamp] as string),
        signature: req.query[uriParams.signature] as string
    });

     */


    const processWrite = (input: PostIdPrefsRequest, res: Response) => {
        if (!operatorApi.postIdPrefsRequestVerifier.verify(publicKeyStore[input.sender], input)) {
            throw 'Write request verification failed'
        }

        // because default value is true, we just remove it to save space
        input.body.identifiers[0].persisted = undefined;

        writeAsCookies(input, res);

        const {identifiers, preferences} = input.body

        return operatorApi.buildPostIdPrefsResponse(input.sender, {identifiers, preferences});
    };

    // *****************************************************************************************************************
    // ******************************************************************************************************* REDIRECTS
    // *****************************************************************************************************************

    app.get(redirectEndpoints.read, (req, res) => {
        const message = getReadRequest(req);

        if (!operatorApi.getIdPrefsRequestVerifier.verify(publicKeyStore[message.sender], message)) {
            throw 'Read request verification failed'
        }

        const existingId = getExistingId(req)
        const preferences = getExistingPrefs(req)

        const redirectUrl = getReturnUrl(req, res)
        if (redirectUrl) {
            const response = operatorApi.buildGetIdPrefsResponse(message.sender, {
                identifiers: [existingId],
                preferences
            })

            redirectUrl.searchParams.set(uriParams.data, JSON.stringify(response))

            httpRedirect(res, redirectUrl.toString());
        } else {
            res.sendStatus(400)
        }
    });

    app.get(redirectEndpoints.write, (req, res) => {
        const input = JSON.parse(req.query[uriParams.data] as string) as PostIdPrefsRequest;

        const redirectUrl = getReturnUrl(req, res)
        if (redirectUrl) {

            try {
                const signedData = processWrite(input, res);

                redirectUrl.searchParams.set(uriParams.data, JSON.stringify(signedData))

                httpRedirect(res, redirectUrl.toString());
            } catch (e) {
                res.sendStatus(400)
                res.send(e)
            }
        } else {
            res.sendStatus(400)
        }
    });

    // *****************************************************************************************************************
    // ************************************************************************************************************ JSON
    // *****************************************************************************************************************

    // Note that CORS is "disabled" here because the check is done via signature
    // So accept whatever the referer is
    const corsOptions = (req: Request, callback: (err: Error | null, options?: CorsOptions) => void) => {
        callback(null, {
            origin: req.header('Origin'),
            optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
            credentials: true
        });
    };

    app.get(jsonEndpoints.read, cors(corsOptions), (req, res) => {
        // Attempt to set a cookie (as 3PC), will be useful later if this call fails to get Prebid cookie values
        const now = new Date();
        const expirationDate = new Date(now)
        expirationDate.setTime(now.getTime() + 1000 * 60) // Lifespan: 1 minute
        setCookie(res, Cookies.TEST_3PC, now.getTime(), expirationDate, {domain: tld})

        const message = getReadRequest(req);

        if (!operatorApi.getIdPrefsRequestVerifier.verify(publicKeyStore[message.sender], message)) {
            throw 'Read request verification failed'
        }

        const existingId = getExistingId(req)
        const preferences = getExistingPrefs(req)

        const response = operatorApi.buildGetIdPrefsResponse(message.sender, {identifiers: [existingId], preferences})

        res.send(JSON.stringify(response))
    });

    app.get(jsonEndpoints.verify3PC, cors(corsOptions), (req, res) => {
        // Note: no signature verification here

        const cookies = req.cookies;
        const testCookieValue = cookies[Cookies.TEST_3PC]

        // Clean up
        removeCookie(req, res, Cookies.TEST_3PC, {domain: tld})

        const isOk = testCookieValue?.length > 0;

        res.send(JSON.stringify(isOk))
    });

    app.post(jsonEndpoints.write, cors(corsOptions), (req, res) => {
        const input = JSON.parse(req.body as string) as PostIdPrefsRequest;

        try {
            const signedData = processWrite(input, res);

            res.send(JSON.stringify(signedData))
        } catch (e) {
            res.sendStatus(400)
            res.send(e)
        }
    });
}

export class OperatorApi {
    private readonly idSigner = new IdSigner()
    private readonly ecdsaKey: PrivateKey

    private getIdPrefsResponseSigner = new GetIdPrefsResponseSigner();
    signGetIdPrefsResponse = (data: UnsignedMessage<GetIdPrefsResponse>) => this.getIdPrefsResponseSigner.sign(this.ecdsaKey, data)

    private postIdPrefsResponseSigner = new PostIdPrefsResponseSigner();
    signPostIdPrefsResponse = (data: UnsignedMessage<PostIdPrefsResponse>) => this.postIdPrefsResponseSigner.sign(this.ecdsaKey, data)

    private getNewIdResponseSigner = new GetNewIdResponseSigner();
    signGetNewIdResponse = (data: UnsignedMessage<GetNewIdResponse>) => this.getNewIdResponseSigner.sign(this.ecdsaKey, data)

    readonly getIdPrefsRequestVerifier = new GetIdPrefsRequestSigner();
    readonly postIdPrefsRequestVerifier = new PostIdPrefsRequestSigner();

    constructor(public host: string, privateKey: string) {
        this.ecdsaKey = privateKeyFromString(privateKey)
    }

    generateNewId(timestamp = new Date().getTime()): Id {
        return {
            ...this.signId(uuidv4(), timestamp),
            persisted: false
        };
    }

    buildGetIdPrefsResponse(receiver: string, {
        identifiers,
        preferences
    }: IdAndOptionalPrefs, timestamp = new Date().getTime()): GetIdPrefsResponse {
        const data: UnsignedMessage<GetIdPrefsResponse> = {
            body: {
                identifiers: isEmptyListOfIds(identifiers) ? [this.generateNewId()] : identifiers,
                preferences
            },
            sender: this.host,
            receiver,
            timestamp
        };

        return {
            ...data,
            signature: this.signGetIdPrefsResponse(data)
        }
    }

    buildPostIdPrefsResponse(receiver: string, {
        identifiers,
        preferences
    }: IdAndOptionalPrefs, timestamp = new Date().getTime()): PostIdPrefsResponse {
        const data: UnsignedMessage<PostIdPrefsResponse> = {
            body: {
                identifiers: isEmptyListOfIds(identifiers) ? [this.generateNewId()] : identifiers,
                preferences
            },
            sender: this.host,
            receiver,
            timestamp
        };

        return {
            ...data,
            signature: this.signPostIdPrefsResponse(data)
        }
    }

    buildGetNewIdResponse(receiver: string, newId = this.generateNewId(), timestamp = new Date().getTime()): GetNewIdResponse {
        const data: UnsignedMessage<GetNewIdResponse> = {
            body: {
                identifiers: [newId],
            },
            sender: this.host,
            receiver,
            timestamp
        };

        return {
            ...data,
            signature: this.signGetNewIdResponse(data)
        }
    }

    signId(value: string, timestamp = new Date().getTime()) {
        const unsignedId: UnsignedData<Id> = {
            version: 0,
            type: 'prebid_id',
            value,
            source: {
                domain: this.host,
                timestamp
            }
        };
        const {source, ...rest} = unsignedId

        return {
            ...rest,
            source: {
                ...source,
                signature: this.idSigner.sign(this.ecdsaKey, unsignedId)
            }
        };
    }
}
