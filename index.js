const crypto = require('crypto')

//generate base64 key
//const keyBase64 = crypto.randomBytes(32).toString('base64')
const key = Buffer.from('BW8gmec9zpz10t21tKWAZVTNsd7eOEvVTZjoU07IPTI=','base64')
//Generate IV
const iv = Buffer.from(crypto.randomBytes(32), 'utf8');
console.log('done')
//mensaje
const msgUTF8 = 'plain text mesg'
const msgBuf=Buffer.from(msgUTF8,'utf8')
//algoritmo
const alg = 'aes-256-gcm'

const cipher = crypto.createCipheriv(alg,key,iv)
//cifrado
let encrypted = Buffer.from(cipher.update(msgBuf),'utf8')
Buffer.concat([encrypted,cipher.final()])

//gcm tiene autenticacion tambien, hay que enviar el authtag ademas del encrypted (y el iv)
const authTag = cipher.getAuthTag();

const encryptedBase64 = encrypted.toString('base64');
const authTagBase64 = authTag.toString('base64');

console.log(`Encrypted: ${encryptedBase64}`)
console.log(`Auth tag: ${authTagBase64}`)

//Descifrado
const decipher = crypto.createDecipheriv(alg, key, iv)
decipher.setAuthTag(authTag)
const decrypted = Buffer.concat([decipher.update(encrypted),decipher.final()]);

console.log(`Value decrypted: ${decrypted.toString('utf-8')}`)
console.log('done');


