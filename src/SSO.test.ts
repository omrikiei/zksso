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

import { Role, User } from './sso-lib'
import {BaseMerkleWitness} from "snarkyjs/dist/node/lib/merkle_tree";

const MerkleTree = Experimental.MerkleTree;

function createLocalBlockchain() {
  const Local = Mina.LocalBlockchain();
  Mina.setActiveInstance(Local);
  return Local.testAccounts[0].privateKey;
}

async function localDeploy(
  zkAppInstance: SSO,
  zkAppPrivateKey: PrivateKey,
  deployerAccount: PrivateKey
) {
  const txn = await Mina.transaction(deployerAccount, () => {
    AccountUpdate.fundNewAccount(deployerAccount);
    zkAppInstance.deploy({ zkappKey: zkAppPrivateKey });
    zkAppInstance.sign(zkAppPrivateKey);
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
    const adminRole = new Role("admin", ["funds:transfer", "funds:view", "users:read", "users:write"]);
    roles = [adminRole, new Role("user", ["funds:view", "users:read"])];
    let userMerkleTree = new Experimental.MerkleTree(10);
    for (let i = 0; i <= 20; i++) {
      userMerkleTree.setLeaf(BigInt(i), Field.zero);
    }
    userMerkleTree.setLeaf(BigInt(0), User.fromPrivateKey(users[0], roles[0].hash()).hash())
    userMerkleTree.setLeaf(BigInt(1), User.fromPrivateKey(users[1], roles[1].hash()).hash())


    let roleMerkleTree = new Experimental.MerkleTree(10);
    for (let i = 0; i <= 20; i++) {
      userMerkleTree.setLeaf(BigInt(i), Field.zero);
    }
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
