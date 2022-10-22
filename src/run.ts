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
console.log(SSO.Proof());

let tx = await Mina.transaction(publisherAccount, () => {
  AccountUpdate.fundNewAccount(publisherAccount);
  zkapp.deploy({ zkappKey: zkAppPrivateKey });
});
tx.send().wait();

tx = await Mina.transaction(publisherAccount, () => {
  zkapp.init(Field.zero, Field.zero);
  zkapp.sign(zkAppPrivateKey);
});
