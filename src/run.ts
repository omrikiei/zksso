import {
  Mina,
  PrivateKey,
  AccountUpdate,
  isReady,
  UInt64,
  Experimental,
  CircuitString,
} from 'snarkyjs';
import { SSO } from './SSO.js';
import { AuthState, PrivateAuthArgs, Token } from './token.js';
import { Role, User } from './sso-lib.js';
import { tree_height } from './index.js';
import { MerkleWitness } from './index.js';

await isReady;

let zkAppPrivateKey = PrivateKey.random();
let zkAppAddress = zkAppPrivateKey.toPublicKey();
let zkapp = new SSO(zkAppAddress);

let Local = Mina.LocalBlockchain();
Local.setTimestamp(UInt64.from(new Date().valueOf()));
Mina.setActiveInstance(Local);
const publisherAccount = Local.testAccounts[0].privateKey;
console.log('Local Blockchain Online!');

console.log('compiling token...');
await Token.compile();
console.log('compiling contract...');
await SSO.compile();
console.log('deploying contract...');
let tx = await Mina.transaction(publisherAccount, () => {
  AccountUpdate.fundNewAccount(publisherAccount);
  zkapp.deploy({ zkappKey: zkAppPrivateKey });
});

await tx.send();

const iat = Mina.getNetworkState().timestamp;
const exp = iat.add(UInt64.from(3600));

const users = [PrivateKey.random(), PrivateKey.random(), PrivateKey.random()];

const adminRole = new Role('admin', [
  'funds:transfer',
  'funds:view',
  'users:read',
  'users:write',
]);

const userRole = new Role('user', ['funds:view', 'users:read']);
const roles = [adminRole, userRole];

const userMerkleTree = new Experimental.MerkleTree(tree_height);
const admin = User.fromPrivateKey(users[0], roles[0].hash());
const user = User.fromPrivateKey(users[1], roles[1].hash());

const adminHash = admin.hash();
console.log('setting leaf for user admin');
userMerkleTree.setLeaf(0n, adminHash);

console.log('setting leaf for user user');
userMerkleTree.setLeaf(1n, user.hash());

console.log('creating role tree');
let roleMerkleTree = new Experimental.MerkleTree(tree_height);
roles.forEach((role, i) => {
  console.log('creating role leaf');
  const roleHash = role.hash();
  console.log('roleHash: ' + roleHash);
  roleMerkleTree.setLeaf(BigInt(i), roleHash);
  console.log('created role leaf');
});

console.log('calling init...');
let tx2 = await Mina.transaction(publisherAccount, () => {
  console.log('init');
  zkapp.init(
    userMerkleTree.getRoot(),
    roleMerkleTree.getRoot(),
    UInt64.from(3600)
  );
  console.log('sign');
  zkapp.sign(zkAppPrivateKey);
});

await tx2.sign().send();

const networkTime = Mina.getNetworkState().timestamp;

const authState = new AuthState(
  zkapp.userStoreCommitment.get().toConstant(),
  zkapp.roleStoreCommitment.get().toConstant(),
  networkTime,
  exp,
  adminRole.scopes
);

const privateAuthArgs = new PrivateAuthArgs(networkTime, users[0], adminRole);

const rolePath = new MerkleWitness(roleMerkleTree.getWitness(0n));
const userPath = new MerkleWitness(userMerkleTree.getWitness(0n));

try {
  /*const tr = await Mina.transaction(publisherAccount, () => {
        console.log('authn');
        const tr = zkapp.authenticate(publisherAccount, adminRole, userPath, rolePath);
        //authState = new AuthState(tr.userStoreCommitment, tr.roleStoreCommitment, tr.iat, tr.exp, tr.scopes)
    });
    console.log(tr.toJSON())*/
  let token = await Token.init(authState, privateAuthArgs, userPath, rolePath);
  console.log('logged in!');
  let authorization = await Mina.transaction(publisherAccount, () => {
    console.log('authorize');
    zkapp.authorize(token, CircuitString.fromString('funds:transfer'));
    console.log('sign');
    zkapp.sign(zkAppPrivateKey);
  });

  const p = await authorization.prove();
  console.log('authorized: ' + p);
  let unauthorized = await Mina.transaction(publisherAccount, () => {
    console.log('unauthorized');
    zkapp.authorize(token, CircuitString.fromString('funds:badscope'));
    console.log('sign');
    zkapp.sign(zkAppPrivateKey);
  });

  console.log('unauthorized?: ' + unauthorized);
} catch (e) {
  console.log('encountered an ERROR!');
  console.log(e);
}
