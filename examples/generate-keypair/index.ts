import { generatePrivateKey, publicKey } from '../../lib';

const privateKey = generatePrivateKey();
const pubKey = publicKey(privateKey);

console.log('private key:', privateKey);
console.log('public key: ', pubKey);
