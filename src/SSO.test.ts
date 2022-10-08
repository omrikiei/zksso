import { SSO } from './SSO';
import {
  isReady,
  shutdown,
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate, Experimental,
} from 'snarkyjs';

import {Role} from "./role";
import User from "./user";
import MerkleTree = Experimental.MerkleTree;
import {BaseMerkleWitness} from "snarkyjs/dist/web/lib/merkle_tree";


function createLocalBlockchain() {
  const Local = Mina.LocalBlockchain();
  Mina.setActiveInstance(Local);
  return Local.testAccounts[0].privateKey;
}

async function localDeploy(
  zkAppInstance: SSO,
  zkAppPrivatekey: PrivateKey,
  deployerAccount: PrivateKey
) {
  const txn = await Mina.transaction(deployerAccount, () => {
    AccountUpdate.fundNewAccount(deployerAccount);
    zkAppInstance.deploy({ zkappKey: zkAppPrivatekey });
    zkAppInstance.sign(zkAppPrivatekey);
  });
  await txn.send().wait();
}

describe('SSO', () => {
  let deployerAccount: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    users: PrivateKey[],
    roles: Role[],
    userMerkleTree: typeof MerkleTree,
    roleMerkleTree: typeof MerkleTree;

  beforeEach(async () => {
    await isReady;
    deployerAccount = createLocalBlockchain();
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    users = [PrivateKey.random(), PrivateKey.random(), PrivateKey.random()];
    roles = [new Role(Field.fromString("admin"), ["funds:transfer", "funds:view", "users:read", "users:write"]), new Role(Field.fromString("user"), ["funds:view", "users:read"])];
    let userMerkleTree = new Experimental.MerkleTree(users.length / 2);
    userMerkleTree.setLeaf(BigInt(0), User.fromPrivateKey(users[0], roles[0].name).hash())
    userMerkleTree.setLeaf(BigInt(1), User.fromPrivateKey(users[1], roles[1].name).hash())
    userMerkleTree.setLeaf(BigInt(2), Field.zero);
    userMerkleTree.setLeaf(BigInt(4), Field.zero);

    let roleMerkleTree = new Experimental.MerkleTree(roles.length / 2);
    roles.forEach((role, i) => {
      roleMerkleTree.setLeaf(BigInt(i), role.hash())
    })
  });

  afterAll(async () => {
    // `shutdown()` internally calls `process.exit()` which will exit the running Jest process early.
    // Specifying a timeout of 0 is a workaround to defer `shutdown()` until Jest is done running all tests.
    // This should be fixed with https://github.com/MinaProtocol/mina/issues/10943
    setTimeout(shutdown, 0);
  });

  it('generates and deploys the `SSO` smart contract and updates state', async () => {
    const zkAppInstance = new SSO(zkAppAddress);
    await localDeploy(zkAppInstance, zkAppPrivateKey, deployerAccount);
    await zkAppInstance.init(Field.random(), Field.random());
    await zkAppInstance.updateStateCommitments(userMerkleTree.prototype.getRoot(), roleMerkleTree.prototype.getRoot());
    expect(zkAppInstance.userStoreCommitment).toEqual(userMerkleTree.prototype.getRoot());
    expect(zkAppInstance.roleStoreCommitment).toEqual(roleMerkleTree.prototype.getRoot());
  });

  it('authentication', async () => {
    const zkAppInstance = new SSO(zkAppAddress);
    await localDeploy(zkAppInstance, zkAppPrivateKey, deployerAccount);
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.init(userMerkleTree.prototype.getRoot(), roleMerkleTree.prototype.getRoot());
      zkAppInstance.sign(zkAppPrivateKey);
    });
    await txn.send().wait();

    const adminToken = await zkAppInstance.authenticate(users[0], roles[0], new BaseMerkleWitness(userMerkleTree.prototype.getWitness(BigInt(0))), new BaseMerkleWitness(roleMerkleTree.prototype.getWitness(BigInt(0))));
    //const userToken = await zkAppInstance.authenticate(users[1], roles[1], userMerkleTree.prototype.getWitness(BigInt(1)), roleMerkleTree.prototype.getWitness(BigInt(1)));
    //const invalidToken = await zkAppInstance.authenticate(users[2], roles[1], userMerkleTree.prototype.getWitness(BigInt(3)), roleMerkleTree.prototype.getWitness(BigInt(1)));

    console.log(adminToken.toJSON());
  });
});
