const crypto = require('crypto')

const settings = {
    hmac: true,
    algorithm: '',
    encoding: '',
    salt: ''
}

function getSignature(body)
{
    let hash = settings.hmac ?  crypto.createHmac(settings.algorithm, settings.salt) : crypto.createHash(settings.algorithm, settings.salt)

    return hash.update(body)
        .digest(settings.encoding)
}

module.exports.templateTags = [{
    name: 'signedrequest',
    displayName: 'SignedRequest',
    description: 'Create signature based on request or parameter',
    args: [
        {
            displayName: 'Is HMAC?',
            description: 'Use HMAC for encoding',
            defaultValue: true,
            type: 'boolean',
        }, {
            dispayName: 'Algorithm',
            description: 'The encryption algorithm',
            type: 'enum',
            options: [
                { displayName: 'MD5', value: 'md5' },
                { displayName: 'SHA1', value: 'sha1' },
                { displayName: 'SHA256', value: 'sha256' },
                { displayName: 'SHA512', value: 'sha512' }
            ]
        }, {
            displayName: 'Encoding',
            description: 'The encoding',
            type: 'enum',
            options: [
                { displayName: 'Hexadecimal', value: 'hex' },
                { displayName: 'Base64', value: 'base64' }
            ]
        }, {
            displayName: 'Salt / Key',
            type: 'string',
        }
    ],

    async run (context, hmac = true, algorithm = '', encoding = '', salt = '')
    {
        const { meta } = context

        settings.hmac = hmac
        settings.algorithm = algorithm
        settings.encoding = encoding
        settings.salt = salt

        const request = await context.util.models.request.getById( meta.requestId )

        if (request.method === 'GET'){
            return getSignature(JSON.stringify(request.parameters))
        } else {
            if (request.body.mimeType === 'application/json')
            {
                return getSignature(JSON.stringify(JSON.parse(request.body.text)))
            } else {
                let params = {}
                request.body.params.forEach((function (item) {
                    params[item.name] = item.value 
                }))

                console.log(JSON.stringify(params))

                return getSignature(JSON.stringify(params))
            }
        }
    }
}];