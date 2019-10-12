'use strict'

const https = require('https')
const crypto = require('crypto')
const { URL } = require('url')

const config = {
    rr: 'ddns',
    domain: 'example.com',

    accessKeyId: '',
    accessKeySecret: '',

    mode: "both",
    interval: 0,

    alidnsAPI: 'https://alidns.aliyuncs.com/',
    ip4Api: 'https://api.ipify.org/?format=json',
    ip6Api: 'https://api6.ipify.org?format=json'
}

/**
 * Attach common parameters and signature to API specific parameters.
 * 
 * @param {object} specParam API specific parameters.
 * @returns {object} Parameters with signature and common parameters.
 */
function attachParam(specParam) {
    function percentEncode(str) {
        return encodeURIComponent(str).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16))
    }

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

    let parames = Object.assign({
        'Format':'JSON',
        'Version':'2015-01-09',
        'AccessKeyId':config.accessKeyId,
        'SignatureMethod':'HMAC-SHA1',
        'SignatureVersion':'1.0',
        'SignatureNonce':crypto.randomBytes(16).toString('hex'),
        'Timestamp':(new Date()).toISOString(),
    }, specParam)
    return Object.assign(parames, { 'Signature': makeSignature(parames) })
}

/**
 * A wrap of native https.get
 * 
 * @param {string} url HTTPS GET URL.
 * @param {object} params HTTPS GET args.
 * @param {object} options NodeJS request options.
 * @returns {Promise} HTTPS GET promise, resolve data, reject error.
 */
function get(url, params = {}, options = {}) {
    url = new URL(url)

    for (const [k, v] of Object.entries(params)) {
        url.searchParams.append(k, v)
    }
    Object.assign(options, {
        hostname: url.hostname,
        path: url.pathname + url.search
    })

    return new Promise((resolve, reject) => {
        https.get(options, (resp) => {
            let data = ''
            resp.on('data', (chunk) => {
                data += chunk
            })
            resp.on('end', () => {
                resolve(data)
            })
        }).on('error', (e) => {
            reject(new Error('(Error) HTTP request error. Code: ' + e.code))
        })
    })
}

const { getIp4, getIp6 } = (function () {
    async function getIp(family, ipApi, regexp) {
        const request = await get(ipApi, undefined, { family: family })

        try {
            var data = JSON.parse(request).ip
            if (typeof (data) !== 'string' || !regexp.test(data)) {
                throw new Error()
            }
        } catch (e) {
            throw new Error(`(Error) Get IP fail. Can't parse server respone.`)
        }

        return data
    }
    return {
        getIp4: () => getIp(4, config.ip4Api, /^\d+\.\d+\.\d+\.\d+$/),
        getIp6: () => getIp(6, config.ip6Api, /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/)
    }
})()

const { getRecord4, getRecord6 } = (function () {
    async function getRecord(type) {
        const request = await get(config.alidnsAPI, attachParam({
            'Action': 'DescribeSubDomainRecords',
            'SubDomain': config.rr + '.' + config.domain,
            'Type': type
        }))
        try {
            var data = JSON.parse(request)
        } catch (e) {
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
    return {
        getRecord4: () => getRecord('A'),
        getRecord6: () => getRecord('AAAA')
    }
})()

const { addRecord4, addRecord6, updateRecord4, updateRecord6 } = (function () {
    async function updateRecord(ip, recordId, type) {
        let parame = {
            'RR': config.rr,
            'Value': ip,
            'Type': type,
            'Action': recordId ? 'UpdateDomainRecord' : 'AddDomainRecord'
        }
        Object.assign(parame, recordId ? { 'RecordId': recordId } : { 'DomainName': config.domain })

        let request = await get(config.alidnsAPI, attachParam(parame))
        try {
            var data = JSON.parse(request)
        } catch (e) {
            throw new Error(`(Error) Update record fail. Can't parse server respone.`)
        }
        if (!data.RecordId) {
            throw new Error(`(Error) Update record fail. ${data.Code ? 'Code: ' + data.Code : ''}`)
        }
        return data
    }
    return {
        addRecord4: (ip) => updateRecord(ip, 0, 'A'),
        addRecord6: (ip) => updateRecord(ip, 0, 'AAAA'),
        updateRecord4: (ip, recordId) => updateRecord(ip, recordId, 'A'),
        updateRecord6: (ip, recordId) => updateRecord(ip, recordId, 'AAAA')
    }
})();

async function start() {
    let ip4, ip6

    if (config.mode === 'both' || config.mode === 'ipv4') {
        try {
            ip4 = await getIp4()
        } catch (e) {
            console.log(e.message)
        }
    }

    if (ip4) {
        try {
            const record = await getRecord4()
            if (record && record.Value === ip4) {
                console.log(`(No change) ${config.rr}.${config.domain} ${ip4}`)
            } else if (record && record.Value !== ip4) {
                await updateRecord4(ip4, record.RecordId)
                console.log(`(Updated) ${config.rr}.${config.domain} ${record.Value} -> ${ip4}`)
            } else {
                await addRecord4(ip4)
                console.log(`(Added) ${config.rr}.${config.domain} ${ip4}`)
            }
        } catch (e) {
            console.log(e.message)
        }
    }

    if (config.mode === 'both' || config.mode === 'ipv6') {
        try {
            ip6 = await getIp6()
        } catch (e) {
            console.log(e.message)
        }
    }

    if (ip6) {
        try {
            const record = await getRecord6()
            if (record && record.Value === ip6) {
                console.log(`(No change) ${config.rr}.${config.domain} ${ip6}`)
            } else if (record && record.Value !== ip6) {
                await updateRecord6(ip6, record.RecordId)
                console.log(`(Updated) ${config.rr}.${config.domain} ${record.Value} -> ${ip6}`)
            } else {
                await addRecord6(ip6)
                console.log(`(Added) ${config.rr}.${config.domain} ${ip6}`)
            }
        } catch (e) {
            console.log(e.message)
        }
    }
}

if (config.interval) {
    setInterval(start, config.interval * 1000)
}

start()
