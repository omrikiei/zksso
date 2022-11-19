import {
  Mina,
  PrivateKey,
  AccountUpdate,
  isReady,
  UInt64,
  MerkleTree,
  Field,
} from 'snarkyjs';
import { SSO } from './SSO.js';
import { AuthState, PrivateAuthArgs, Token } from './token.js';
import { Scope, Role, User } from './sso-lib.js';
import { tree_height } from './index.js';
import { SSOMerkleWitness } from './index.js';

await isReady;

let zkAppPrivateKey = PrivateKey.random();
let zkAppAddress = zkAppPrivateKey.toPublicKey();
let zkapp = new SSO(zkAppAddress);

let Local = Mina.LocalBlockchain({ proofsEnabled: false });
Local.setTimestamp(UInt64.from(new Date().valueOf()));
Mina.setActiveInstance(Local);
const publisherAccount = Local.testAccounts[0].privateKey;
console.log('Local Blockchain Online!');

console.log('compiling token...');
const tokenCompilation = await Token.compile();
console.log("compiled token verification key: " + tokenCompilation.verificationKey)

console.log('compiling contract...');
await SSO.compile();
console.log('deploying contract...');
let tx = await Mina.transaction(publisherAccount, () => {
  AccountUpdate.fundNewAccount(publisherAccount);
  zkapp.deploy({ zkappKey: zkAppPrivateKey });
  zkapp.init(zkAppPrivateKey);
});

await tx.prove();
tx.sign([zkAppPrivateKey]);
await tx.send();

const iat = Mina.getNetworkState().timestamp;
const exp = iat.add(UInt64.from(3600));

const users = [PrivateKey.random(), PrivateKey.random(), PrivateKey.random()];

const scopes = [
  new Scope({ name: 'funds:transfer', value: Field(28688) }),
  new Scope({ name: 'funds:read', value: Field(28689) }),
  new Scope({ name: 'user:read', value: Field(28690) }),
  new Scope({ name: 'users:write', value: Field(28691) }),
];

const adminRole = Role.init('admin', scopes);

const userRole = Role.init('user', [scopes[1], scopes[2]]);
const roles = [adminRole, userRole];

const userMerkleTree = new MerkleTree(tree_height);
const admin = User.fromPrivateKey(users[0], roles[0].hash());
const user = User.fromPrivateKey(users[1], roles[1].hash());

const adminHash = admin.hash();
console.log('setting leaf for user admin');
userMerkleTree.setLeaf(0n, adminHash);

console.log('setting leaf for user user');
userMerkleTree.setLeaf(1n, user.hash());

console.log('creating role tree');
let roleMerkleTree = new MerkleTree(tree_height);
roles.forEach((role, i) => {
  console.log('creating role leaf');
  const roleHash = role.hash();
  console.log('roleHash: ' + roleHash);
  roleMerkleTree.setLeaf(BigInt(i), roleHash);
  console.log('created role leaf');
});

let updateTx = await Mina.transaction(publisherAccount, () => {
  console.log('update');
  zkapp.updateStateCommitments(
    userMerkleTree.getRoot(),
    roleMerkleTree.getRoot(),
    UInt64.from(3600)
  );
  console.log('updated');
  zkapp.requireSignature();
});

await updateTx.prove();
updateTx.sign([zkAppPrivateKey]);
await updateTx.sign().send();

const networkTime = Mina.getNetworkState().timestamp;

const authState = AuthState.init(
  zkapp.userStoreCommitment.get().toConstant(),
  zkapp.roleStoreCommitment.get().toConstant(),
  networkTime,
  exp,
  adminRole.scopes as Scope[]
);

const privateAuthArgs = PrivateAuthArgs.init(networkTime, users[0], adminRole);

const rolePath = new SSOMerkleWitness(roleMerkleTree.getWitness(0n));
const userPath = new SSOMerkleWitness(userMerkleTree.getWitness(0n));

let token = await Token.init(authState, privateAuthArgs, userPath, rolePath);

try {
  console.log('logged in!');
  let authorization = await Mina.transaction(publisherAccount, () => {
    console.log('authorize');
    zkapp.authorize(token, scopes[0]);
  });
  const p = await authorization.prove();
  console.log('authorized: ' + p);
} catch (e) {
  console.log('encountered an ERROR!');
  console.log(e);
}

try {
  let unauthorized = await Mina.transaction(publisherAccount, () => {
    console.log('unauthorized');
    zkapp.authorize(token, new Scope({ name: 'badscope', value: Field(3) }));
  });
  console.log(unauthorized.toJSON());
} catch (e) {
  console.log('great: ' + e);
  console.log(e);
}
