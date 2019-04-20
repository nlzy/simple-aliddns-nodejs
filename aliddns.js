'use strict'

const https = require('https')
const crypto = require('crypto')

const config = {
    rr: 'ddns',
    domain: 'example.com',
    accessKeyId: '',
    accessKeySecret: '',
    interval: 0,
    alidnsAPI: 'https://alidns.aliyuncs.com/',
    ipAPI: 'https://api.ipify.org/?format=json'
}

/**
 * Encode string for sign.
 * 
 * @param {string} str string to encode.
 * @returns {string} encoded sting.
 */
function percentEncode(str) {
    return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
        return '%' + c.charCodeAt(0).toString(16);
    })
}

/**
 * Make signature string from parames.
 * 
 * @param {object} parames parames to sign. with common parames.
 * @returns {string} signature.
 */
function makeSignature(parames) {
    const magicPrefix = 'GET&%2F&'

    const canonicalizedQueryString = Object.keys(parames)
        .sort()
        .map(k => percentEncode(k) + '=' + percentEncode(parames[k]))
        .join('&')

    const data = magicPrefix + percentEncode(canonicalizedQueryString)
    const key = config.accessKeySecret + '&'

    return crypto.createHmac('sha1', key).update(data).digest('base64')
}

/**
 * Attach common parameters and signature to API specific parameters.
 * 
 * @param {object} specParam API specific parameters.
 * @returns {object} Parameters with signature and common parameters.
 */
function attachParam(specParam) {
    let parames = Object.assign({
        'Format':'JSON',
        'Version':'2015-01-09',
        'AccessKeyId':config.accessKeyId,
        'SignatureMethod':'HMAC-SHA1',
        'SignatureVersion':'1.0',
        'SignatureNonce':crypto.randomBytes(16).toString('hex'),
        'Timestamp':(new Date()).toISOString(),
    }, specParam)
    return Object.assign(parames, {'Signature': percentEncode(makeSignature(parames))})
}

/**
 * A wrap of native https.get
 * 
 * @param {string} url HTTPS GET URL.
 * @param {object} args HTTPS GET args.
 * @returns {Promise} HTTPS GET promise, resolve data, reject error.
 */
function get(url, args) {
    if (args) {
        url += '?'
        url += Object.keys(args).map(k => k + '=' + args[k]).join('&')
    }
    return new Promise((resolve, reject) => {
        https.get(url, (resp) => {
            let data = '';
            resp.on('data', (chunk) => {
                data += chunk;
            })
            resp.on('end', () => {
                resolve(data)
            });
        }).on('error', (e) => {
            reject(new Error('(Error) HTTP request error. Code: ' + e.code))
        })
    })
}

/**
 * Get IP from public API
 * 
 * @returns {string} IP Address
 */
async function getIp() {
    const request = await get(config.ipAPI)

    try {
        const ipv4RegExp = /^\d+\.\d+\.\d+\.\d+$/
        var data = JSON.parse(request).ip
        if (typeof(data) !== 'string' || !ipv4RegExp.test(data)) {
            throw new Error()
        }
    } catch(e) {
        throw new Error(`(Error) Get IP fail. Can't parse server respone.`)
    }

    return data
}

/**
 * Get domain A record
 * 
 * @returns {object} domain reocrd
 */
async function getRecord() {
    const request = await get(config.alidnsAPI, attachParam({
        'Action':'DescribeSubDomainRecords',
        'SubDomain':config.rr + '.' + config.domain,
        'Type':'A'
    }))
    try {
        var data = JSON.parse(request)
    } catch(e) {
        throw new Error(`(Error) Query record fail. Can't parse server respone.`)
    }
    if (data.TotalCount === 1) {
        return data.DomainRecords.Record[0]
    } else if (data.TotalCount === 0) {
        return null
    } else {
        throw new Error(`(Error) Query record fail. ${data.Code ? 'Code: ' + data.Code : ''}`)
    }
}

/**
 * Update/Add domain A record. Add record when recordId == 0.
 * 
 * @param {string} ip
 * @param {number} recordId
 * @returns {object} response json
 */
async function updateRecord(ip, recordId) {
    if (recordId) {
        var request = await get(config.alidnsAPI, attachParam({
            'Action': 'UpdateDomainRecord',
            'RecordId': recordId,
            'RR': config.rr,
            'Type': 'A',
            'Value': ip
        }))
    } else {
        var request = await get(config.alidnsAPI, attachParam({
            'Action': 'AddDomainRecord',
            'DomainName': config.domain,
            'RR': config.rr,
            'Type': 'A',
            'Value': ip
        }))
    }
    try {
        var data = JSON.parse(request)
    } catch(e) {
        throw new Error(`(Error) Update record fail. Can't parse server respone.`)
    }
    if (!data.RecordId) {
        throw new Error(`(Error) Update record fail. ${data.Code ? 'Code: ' + data.Code : ''}`)
    }
    return data
}

async function start() {
    try {
        const ip = await getIp()
        const record = await getRecord()
        if (record && record.Value === ip) {
            console.log(`(No change) ${config.rr}.${config.domain} ${ip}`)
        } else if (record && record.Value !== ip) {
            await updateRecord(ip, record.RecordId)
            console.log(`(Updated) ${config.rr}.${config.domain} ${record.Value} -> ${ip}`)
        } else {
            await updateRecord(ip)
            console.log(`(Added) ${config.rr}.${config.domain} ${ip}`)
        }
    } catch(e) {
        console.log(e.message)
    }
}

if (config.interval) {
    setInterval(start, config.interval * 1000)
}

start()
