import {
  Field,
  CircuitValue,
  prop,
  Experimental,
  UInt64,
  PrivateKey,
  arrayProp,
  Poseidon,
  Proof,
  CircuitString,
} from 'snarkyjs';
import ZkProgram = Experimental.ZkProgram;
import { Role, User } from './sso-lib.js';
import { MerkleWitness } from './index.js';

export { AuthState, PrivateAuthArgs, Token };

class AuthState extends CircuitValue {
  @prop userStoreCommitment: Field;
  @prop roleStoreCommitment: Field;
  @prop iat: UInt64;
  @prop exp: UInt64;
  @arrayProp(Field, 10) scopes: Field[];

  constructor(
    userStoreCommitment: Field,
    roleStoreCommitment: Field,
    iat: UInt64,
    exp: UInt64,
    scopes: CircuitString[]
  ) {
    super();
    this.userStoreCommitment = userStoreCommitment;
    this.roleStoreCommitment = roleStoreCommitment;
    this.iat = iat;
    this.exp = exp;
    const hashedScopes = Array<Field>(10);
    for (let i = 0; i < scopes.length; i++) {
      hashedScopes[i] = Poseidon.hash([iat.value, scopes[i].hash()]);
    }
    this.scopes = hashedScopes;
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

class PrivateAuthArgs extends CircuitValue {
  @prop networkTime: UInt64;
  @prop userHash: Field;
  @prop roleHash: Field;

  constructor(networkTime: UInt64, privateKey: PrivateKey, role: Role) {
    super();
    this.roleHash = role.hash();
    this.userHash = User.fromPrivateKey(privateKey, this.roleHash).hash();
    this.networkTime = networkTime;
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
      privateInputs: [PrivateAuthArgs, MerkleWitness, MerkleWitness],
      method(
        publicInput: AuthState,
        privateAuthArgs: PrivateAuthArgs,
        userCommitment: MerkleWitness,
        roleCommitment: MerkleWitness
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
