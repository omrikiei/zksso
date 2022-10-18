import { SSO } from './SSO';
import {
  isReady,
  shutdown,
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  Experimental,
} from 'snarkyjs';

import { Role, User } from './sso-lib';
import { BaseMerkleWitness } from 'snarkyjs/dist/node/lib/merkle_tree';
import { tree_height } from './index';

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
    console.log('funding');
    AccountUpdate.fundNewAccount(deployerAccount);
    console.log('deploying');
    zkAppInstance.deploy({ zkappKey: zkAppPrivateKey });
    console.log('signing');
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
    const adminRole = new Role('admin', [
      'funds:transfer',
      'funds:view',
      'users:read',
      'users:write',
    ]);

    const userRole = new Role('user', ['funds:view', 'users:read']);
    roles = [adminRole, userRole];

    let userMerkleTree = new Experimental.MerkleTree(tree_height);
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
  });

  afterAll(async () => {
    // `shutdown()` internally calls `process.exit()` which will exit the running Jest process early.
    // Specifying a timeout of 0 is a workaround to defer `shutdown()` until Jest is done running all tests.
    // This should be fixed with https://github.com/MinaProtocol/mina/issues/10943
    setTimeout(shutdown, 0);
  });

  it('generates and deploys the `SSO` smart contract and updates state', async () => {
    const zkAppInstance = new SSO(zkAppAddress);
    console.log('gooogogogogog');
    await localDeploy(zkAppInstance, zkAppPrivateKey, deployerAccount);
    await zkAppInstance.init(Field.random(), Field.random());
    await zkAppInstance.updateStateCommitments(
      userMerkleTree.prototype.getRoot(),
      roleMerkleTree.prototype.getRoot()
    );
    expect(zkAppInstance.userStoreCommitment).toEqual(
      userMerkleTree.prototype.getRoot()
    );
    expect(zkAppInstance.roleStoreCommitment).toEqual(
      roleMerkleTree.prototype.getRoot()
    );
  });

  it('authentication', async () => {
    const zkAppInstance = new SSO(zkAppAddress);
    await localDeploy(zkAppInstance, zkAppPrivateKey, deployerAccount);
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.init(
        userMerkleTree.prototype.getRoot(),
        roleMerkleTree.prototype.getRoot()
      );
      zkAppInstance.sign(zkAppPrivateKey);
    });
    await txn.send().wait();

    const adminToken = await zkAppInstance.authenticate(
      users[0],
      roles[0],
      new BaseMerkleWitness(userMerkleTree.prototype.getWitness(BigInt(0))),
      new BaseMerkleWitness(roleMerkleTree.prototype.getWitness(BigInt(0)))
    );
    //const userToken = await zkAppInstance.authenticate(users[1], roles[1], userMerkleTree.prototype.getWitness(BigInt(1)), roleMerkleTree.prototype.getWitness(BigInt(1)));
    //const invalidToken = await zkAppInstance.authenticate(users[2], roles[1], userMerkleTree.prototype.getWitness(BigInt(3)), roleMerkleTree.prototype.getWitness(BigInt(1)));

    console.log(adminToken.toJSON());
  });
});
