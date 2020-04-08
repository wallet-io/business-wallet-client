let superAgent = require('superagent');
let Q = require('q');
let sha256 = require('sha256');
let bip66 = require('bip66');
let ecc = require('elliptic').ec;
let ec = new ecc('secp256k1');
let jsonStableStringify = require('json-stable-stringify');

const HOST = 'https://business.wallet.io';

const PRV_KEY = '72385d02f3823c3f8467b523f4b270eb470ffcb00665cc39a23ab0772740c2ef';
const PUB_KEY = '0312ddba8f8ea5ae591ad5d69e2a8947a8115e82ed111e91914f158a457625bd66';
const SERVER_PUB_KEY = '0201f423cd5bb21aafede6841e105bfa078f372a6c11840960f3c5152714f6754b';

const ZERO = Buffer.alloc(1, 0);

let Client = {

    generateKeyPair: function () {
        let key = ec.genKeyPair();

        let keyPair = {};
        keyPair.privateKey = key.getPrivate('hex');
        keyPair.publicKey = key.getPublic(true, 'hex');

        return keyPair;
    },

    call: Q.async(function* (url, params, optPrvKey, optPubKey, optServerKey, optHost) {
        params = params || {}
        let prvKey = optPrvKey || PRV_KEY;
        let pubKey = optPubKey || PUB_KEY;
        let serverPubKey = optServerKey || SERVER_PUB_KEY;
        let timestamp = parseInt(new Date().getTime() / 1000);

        let data = jsonStableStringify(params);
        let httpMethod = 'POST'
        let message = [httpMethod, url, data, timestamp].join('|');

        let sign = Client._sign(message, prvKey);

        var req = superAgent.post((optHost || HOST) + url).send(params);

        req.set({
            'api-auth-key': pubKey,
            'api-auth-timestamp': timestamp,
            'api-auth-sign': sign
        });

        //req.timeout(2000);

        let res = yield req;
        let authSign = res.header['api-resp-sign'];

        if (!authSign) {
            throw Error('no server api-resp-sign header');
        }
        let body = jsonStableStringify(res.body);

        timestamp = res.header['api-resp-timestamp'];
        message = [httpMethod, url, res.statusCode, body, timestamp].join('|');

        let verifyResult = Client._verify(message, authSign, serverPubKey);

        if (!verifyResult) {
            console.log('client demo sign error');
            throw new Error('server response verification error');
        }

        return res.body;

    }),

    /**
     * 签名
     * @param message 签名数据
     * @param privKey 私钥
     * @returns {string}
     */
    _sign: function (message, privKey) {

        let privateKey = Buffer.from(privKey, 'hex');
        let messageHash = Client._hash(message);
        let messageBuffer = Buffer.from(messageHash, 'hex');
        let signature = ec.sign(messageBuffer, privateKey);
        let rHex = new Buffer(signature.r.toString(16, 64), 'hex');
        let sHex = new Buffer(signature.s.toString(16, 64), 'hex');
        let r = Client._toDER(rHex);
        let s = Client._toDER(sHex);

        return bip66.encode(r, s).toString('hex');
    },

    /**
     * 签名验证
     * @param message 签名数据
     * @param signature 签名
     * @param pubKey
     * @returns {*}
     */
    _verify: function (message, signature, pubKey) {
        let pubKeyBuffer = Buffer.from(pubKey, 'hex');
        let messageDoubleHash = Client._hash(message);
        let messageBuffer = Buffer.from(messageDoubleHash, 'hex');

        return ec.verify(messageBuffer, signature, pubKeyBuffer);
    },

    _toDER: function (x) {
        let i = 0;
        while (x[i] === 0) ++i;
        if (i === x.length) return ZERO;
        x = x.slice(i);
        if (x[0] & 0x80) return Buffer.concat([ZERO, x], 1 + x.length);
        return x;
    },

    _hash: function (message) {
        let messageBuffer = Buffer.from(message, 'utf-8');
        return sha256(messageBuffer);
    },
}

module.exports = Client