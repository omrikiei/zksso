import { Mina, PrivateKey, Field, AccountUpdate, isReady } from 'snarkyjs';
import { SSO } from './SSO.js';
import { Token } from './token.js';

await isReady;

let zkAppPrivateKey = PrivateKey.random();
let zkAppAddress = zkAppPrivateKey.toPublicKey();
let zkapp = new SSO(zkAppAddress);

let Local = Mina.LocalBlockchain();
Mina.setActiveInstance(Local);
const publisherAccount = Local.testAccounts[0].privateKey;
console.log('Local Blockchain Online!');

console.log('compiling...');
await Token.compile();
await SSO.compile();

console.log('deploying contract...');
let tx = await Mina.transaction(publisherAccount, () => {
  AccountUpdate.fundNewAccount(publisherAccount);
  zkapp.deploy({ zkappKey: zkAppPrivateKey });
});

await tx.send().wait();

console.log('calling init...');
let tx2 = await Mina.transaction(publisherAccount, () => {
  zkapp.init(Field.random(), Field.random());
});

await tx2.sign([publisherAccount]).send().wait();
