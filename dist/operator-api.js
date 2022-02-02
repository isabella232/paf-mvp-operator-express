"use strict";
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OperatorApi = exports.addOperatorApi = void 0;
const express_1 = require("paf-mvp-core-js/dist/express");
const cors_1 = __importDefault(require("cors"));
const uuid_1 = require("uuid");
const model_1 = require("paf-mvp-core-js/dist/model/model");
const message_signature_1 = require("paf-mvp-core-js/dist/crypto/message-signature");
const cookies_1 = require("paf-mvp-core-js/dist/cookies");
const data_signature_1 = require("paf-mvp-core-js/dist/crypto/data-signature");
const keys_1 = require("paf-mvp-core-js/dist/crypto/keys");
const endpoints_1 = require("paf-mvp-core-js/dist/endpoints");
const domainParser = require('tld-extract');
// Expiration: now + 3 months
const getOperatorExpiration = (date = new Date()) => {
    const expirationDate = new Date(date);
    expirationDate.setMonth(expirationDate.getMonth() + 3);
    return expirationDate;
};
const getExistingId = (req) => {
    const cookies = req.cookies;
    return cookies[cookies_1.Cookies.ID] ? JSON.parse(cookies[cookies_1.Cookies.ID]) : undefined;
};
const getExistingPrefs = (req) => {
    const cookies = req.cookies;
    return cookies[cookies_1.Cookies.PREFS] ? JSON.parse(cookies[cookies_1.Cookies.PREFS]) : undefined;
};
// TODO should be a proper ExpressJS middleware
// TODO all received requests should be verified (signature)
const addOperatorApi = (app, operatorHost, privateKey, publicKeyStore) => {
    const tld = domainParser(`https://${operatorHost}`).domain;
    const writeAsCookies = (input, res) => {
        var _a;
        // TODO here we should verify signatures
        if (((_a = input.body.identifiers) === null || _a === void 0 ? void 0 : _a[0]) !== undefined) {
            (0, express_1.setCookie)(res, cookies_1.Cookies.ID, JSON.stringify(input.body.identifiers[0]), getOperatorExpiration(), { domain: tld });
        }
        if (input.body.preferences !== undefined) {
            (0, express_1.setCookie)(res, cookies_1.Cookies.PREFS, JSON.stringify(input.body.preferences), getOperatorExpiration(), { domain: tld });
        }
    };
    const operatorApi = new OperatorApi(operatorHost, privateKey);
    const getReadRequest = (req) => ({
        sender: req.query[endpoints_1.uriParams.sender],
        receiver: req.query[endpoints_1.uriParams.receiver],
        timestamp: parseInt(req.query[endpoints_1.uriParams.timestamp]),
        signature: req.query[endpoints_1.uriParams.signature]
    });
    /* FIXME should be parsed similar to read request. Get read of uriParams.data
    const getWriteRequest = (req: Request): WriteRequest => ({
        sender: req.query[uriParams.sender] as string,
        receiver: req.query[uriParams.signature] as string,
        timestamp: parseInt(req.query[uriParams.timestamp] as string),
        signature: req.query[uriParams.signature] as string
    });

     */
    const processWrite = (input, res) => {
        if (!operatorApi.postIdPrefsRequestVerifier.verify(publicKeyStore[input.sender], input)) {
            throw 'Write request verification failed';
        }
        // because default value is true, we just remove it to save space
        input.body.identifiers[0].persisted = undefined;
        writeAsCookies(input, res);
        const { identifiers, preferences } = input.body;
        return operatorApi.buildPostIdPrefsResponse(input.sender, { identifiers, preferences });
    };
    // *****************************************************************************************************************
    // ******************************************************************************************************* REDIRECTS
    // *****************************************************************************************************************
    app.get(endpoints_1.redirectEndpoints.read, (req, res) => {
        const message = getReadRequest(req);
        if (!operatorApi.getIdPrefsRequestVerifier.verify(publicKeyStore[message.sender], message)) {
            throw 'Read request verification failed';
        }
        const existingId = getExistingId(req);
        const preferences = getExistingPrefs(req);
        const redirectUrl = (0, express_1.getReturnUrl)(req, res);
        if (redirectUrl) {
            const response = operatorApi.buildGetIdPrefsResponse(message.sender, {
                identifiers: [existingId],
                preferences
            });
            redirectUrl.searchParams.set(endpoints_1.uriParams.data, JSON.stringify(response));
            (0, express_1.httpRedirect)(res, redirectUrl.toString());
        }
        else {
            res.sendStatus(400);
        }
    });
    app.get(endpoints_1.redirectEndpoints.write, (req, res) => {
        const input = JSON.parse(req.query[endpoints_1.uriParams.data]);
        const redirectUrl = (0, express_1.getReturnUrl)(req, res);
        if (redirectUrl) {
            try {
                const signedData = processWrite(input, res);
                redirectUrl.searchParams.set(endpoints_1.uriParams.data, JSON.stringify(signedData));
                (0, express_1.httpRedirect)(res, redirectUrl.toString());
            }
            catch (e) {
                res.sendStatus(400);
                res.send(e);
            }
        }
        else {
            res.sendStatus(400);
        }
    });
    // *****************************************************************************************************************
    // ************************************************************************************************************ JSON
    // *****************************************************************************************************************
    // Note that CORS is "disabled" here because the check is done via signature
    // So accept whatever the referer is
    const corsOptions = (req, callback) => {
        callback(null, {
            origin: req.header('Origin'),
            optionsSuccessStatus: 200,
            credentials: true
        });
    };
    app.get(endpoints_1.jsonEndpoints.read, (0, cors_1.default)(corsOptions), (req, res) => {
        // Attempt to set a cookie (as 3PC), will be useful later if this call fails to get Prebid cookie values
        const now = new Date();
        const expirationDate = new Date(now);
        expirationDate.setTime(now.getTime() + 1000 * 60); // Lifespan: 1 minute
        (0, express_1.setCookie)(res, cookies_1.Cookies.TEST_3PC, now.getTime(), expirationDate, { domain: tld });
        const message = getReadRequest(req);
        if (!operatorApi.getIdPrefsRequestVerifier.verify(publicKeyStore[message.sender], message)) {
            throw 'Read request verification failed';
        }
        const existingId = getExistingId(req);
        const preferences = getExistingPrefs(req);
        const response = operatorApi.buildGetIdPrefsResponse(message.sender, { identifiers: [existingId], preferences });
        res.send(JSON.stringify(response));
    });
    app.get(endpoints_1.jsonEndpoints.verify3PC, (0, cors_1.default)(corsOptions), (req, res) => {
        // Note: no signature verification here
        const cookies = req.cookies;
        const testCookieValue = cookies[cookies_1.Cookies.TEST_3PC];
        // Clean up
        (0, express_1.removeCookie)(req, res, cookies_1.Cookies.TEST_3PC, { domain: tld });
        const isOk = (testCookieValue === null || testCookieValue === void 0 ? void 0 : testCookieValue.length) > 0;
        res.send(JSON.stringify(isOk));
    });
    app.post(endpoints_1.jsonEndpoints.write, (0, cors_1.default)(corsOptions), (req, res) => {
        const input = JSON.parse(req.body);
        try {
            const signedData = processWrite(input, res);
            res.send(JSON.stringify(signedData));
        }
        catch (e) {
            res.sendStatus(400);
            res.send(e);
        }
    });
};
exports.addOperatorApi = addOperatorApi;
class OperatorApi {
    constructor(host, privateKey) {
        this.host = host;
        this.idSigner = new data_signature_1.IdSigner();
        this.getIdPrefsResponseSigner = new message_signature_1.GetIdPrefsResponseSigner();
        this.signGetIdPrefsResponse = (data) => this.getIdPrefsResponseSigner.sign(this.ecdsaKey, data);
        this.postIdPrefsResponseSigner = new message_signature_1.PostIdPrefsResponseSigner();
        this.signPostIdPrefsResponse = (data) => this.postIdPrefsResponseSigner.sign(this.ecdsaKey, data);
        this.getNewIdResponseSigner = new message_signature_1.GetNewIdResponseSigner();
        this.signGetNewIdResponse = (data) => this.getNewIdResponseSigner.sign(this.ecdsaKey, data);
        this.getIdPrefsRequestVerifier = new message_signature_1.GetIdPrefsRequestSigner();
        this.postIdPrefsRequestVerifier = new message_signature_1.PostIdPrefsRequestSigner();
        this.ecdsaKey = (0, keys_1.privateKeyFromString)(privateKey);
    }
    generateNewId(timestamp = new Date().getTime()) {
        return Object.assign(Object.assign({}, this.signId((0, uuid_1.v4)(), timestamp)), { persisted: false });
    }
    buildGetIdPrefsResponse(receiver, { identifiers, preferences }, timestamp = new Date().getTime()) {
        const data = {
            body: {
                identifiers: (0, model_1.isEmptyListOfIds)(identifiers) ? [this.generateNewId()] : identifiers,
                preferences
            },
            sender: this.host,
            receiver,
            timestamp
        };
        return Object.assign(Object.assign({}, data), { signature: this.signGetIdPrefsResponse(data) });
    }
    buildPostIdPrefsResponse(receiver, { identifiers, preferences }, timestamp = new Date().getTime()) {
        const data = {
            body: {
                identifiers: (0, model_1.isEmptyListOfIds)(identifiers) ? [this.generateNewId()] : identifiers,
                preferences
            },
            sender: this.host,
            receiver,
            timestamp
        };
        return Object.assign(Object.assign({}, data), { signature: this.signPostIdPrefsResponse(data) });
    }
    buildGetNewIdResponse(receiver, newId = this.generateNewId(), timestamp = new Date().getTime()) {
        const data = {
            body: {
                identifiers: [newId],
            },
            sender: this.host,
            receiver,
            timestamp
        };
        return Object.assign(Object.assign({}, data), { signature: this.signGetNewIdResponse(data) });
    }
    signId(value, timestamp = new Date().getTime()) {
        const unsignedId = {
            version: 0,
            type: 'prebid_id',
            value,
            source: {
                domain: this.host,
                timestamp
            }
        };
        const { source } = unsignedId, rest = __rest(unsignedId, ["source"]);
        return Object.assign(Object.assign({}, rest), { source: Object.assign(Object.assign({}, source), { signature: this.idSigner.sign(this.ecdsaKey, unsignedId) }) });
    }
}
exports.OperatorApi = OperatorApi;
//# sourceMappingURL=operator-api.js.map