import {
  Field,
  Struct,
  Experimental,
  UInt64,
  PrivateKey,
  Poseidon,
  Proof,
} from 'snarkyjs';
import ZkProgram = Experimental.ZkProgram;
import { Scope, Role, User } from './sso-lib.js';
import { SSOMerkleWitness } from './index.js';

export { AuthState, PrivateAuthArgs, Token };

class AuthState extends Struct({
  userStoreCommitment: Field,
  roleStoreCommitment: Field,
  iat: UInt64,
  exp: UInt64,
  scopes: [
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
    Field,
  ],
}) {
  static init(
    userStoreCommitment: Field,
    roleStoreCommitment: Field,
    iat: UInt64,
    exp: UInt64,
    scopes: Scope[]
  ) {
    const hashedScopes = Array<Field>(10);
    for (let i = 0; i < scopes.length; i++) {
      hashedScopes[i] = Poseidon.hash([iat.value, scopes[i].value]);
    }
    return new AuthState({
      userStoreCommitment,
      roleStoreCommitment,
      iat,
      exp,
      scopes: hashedScopes,
    });
  }

  hash() {
    return Poseidon.hash([
      this.userStoreCommitment,
      this.roleStoreCommitment,
      this.iat.value,
      this.exp.value,
      ...this.scopes,
    ]);
  }
}

class PrivateAuthArgs extends Struct({
  networkTime: UInt64,
  userHash: Field,
  roleHash: Field,
}) {
  static init(networkTime: UInt64, privateKey: PrivateKey, role: Role) {
    const roleHash = role.hash();
    return new PrivateAuthArgs({
      roleHash: roleHash,
      userHash: User.fromPrivateKey(privateKey, roleHash).hash(),
      networkTime,
    });
  }

  hash() {
    return Poseidon.hash([
      this.networkTime.value,
      this.userHash,
      this.roleHash,
    ]);
  }
}

export class AuthProof extends Proof<AuthState> {
  static publicInputType = AuthState;
  static tag = () => Token;
}

const Token = ZkProgram({
  publicInput: AuthState,
  methods: {
    init: {
      privateInputs: [PrivateAuthArgs, SSOMerkleWitness, SSOMerkleWitness],
      method(
        publicInput: AuthState,
        privateAuthArgs: PrivateAuthArgs,
        userCommitment: SSOMerkleWitness,
        roleCommitment: SSOMerkleWitness
      ) {
        publicInput.roleStoreCommitment.assertEquals(
          roleCommitment.calculateRoot(privateAuthArgs.roleHash)
        );

        publicInput.userStoreCommitment.assertEquals(
          userCommitment.calculateRoot(privateAuthArgs.userHash)
        );
      },
    },
  },
});
