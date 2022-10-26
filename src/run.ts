import {
  Mina,
  PrivateKey,
  Field,
  AccountUpdate,
  isReady,
  UInt64,
  Poseidon,
  Experimental,
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

await tx.send().wait();

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
userMerkleTree.setLeaf(BigInt(0), adminHash);

console.log('setting leaf for user user');
userMerkleTree.setLeaf(BigInt(1), user.hash());

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
  zkapp.init(userMerkleTree.getRoot(), roleMerkleTree.getRoot());
  console.log('sign');
  zkapp.sign(zkAppPrivateKey);
});

await tx2.sign().send().wait();

const scopes = Array<Field>(10);
for (let i = 0; i < scopes.length; i++) {
  scopes[i] = Poseidon.hash([...exp.toFields(), adminRole.scopes[i].hash()]);
}

const authState = new AuthState(
  zkapp.userStoreCommitment.get(),
  zkapp.roleStoreCommitment.get(),
  Mina.getNetworkState().timestamp,
  exp,
  scopes
);

const privateAuthArgs = new PrivateAuthArgs(publisherAccount, adminRole);

const rolePath = new MerkleWitness(roleMerkleTree.getWitness(0n));
const userPath = new MerkleWitness(userMerkleTree.getWitness(0n));

const token = await Token.authenticate(
  authState,
  privateAuthArgs,
  userPath,
  rolePath
);
console.log(token);
