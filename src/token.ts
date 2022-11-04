import {
  Field,
  CircuitValue,
  prop,
  Experimental,
  UInt64,
  // CircuitString,
  PrivateKey,
  // SelfProof,
  arrayProp,
  Poseidon,
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
    scopes: Field[]
  ) {
    super();
    this.userStoreCommitment = userStoreCommitment;
    this.roleStoreCommitment = roleStoreCommitment;
    this.iat = iat;
    this.exp = exp;
    this.scopes = scopes;
  }

  /*hash() {
        return Poseidon.hash([this.userStoreCommitment, this.roleStoreCommitment, this.iat.value, this.exp.value, ...this.scopes]);
    }*/
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

const Token = ZkProgram({
  publicInput: AuthState,
  methods: {
    init: {
      privateInputs: [PrivateAuthArgs, MerkleWitness, MerkleWitness],
      method(
        publicInput: AuthState,
        privateAuthArgs: PrivateAuthArgs,
        roleCommitment: MerkleWitness,
        userCommitment: MerkleWitness
      ) {
        publicInput.roleStoreCommitment.assertEquals(
          roleCommitment.calculateRoot(privateAuthArgs.roleHash)
        );

        publicInput.userStoreCommitment.assertEquals(
          userCommitment.calculateRoot(privateAuthArgs.userHash)
        );
      },
    },
    /*authorize: {
                privateInputs: [CircuitString, SelfProof],
                method(
                    publicInput: AuthState,
                    scope: CircuitString,
                    proof: SelfProof<AuthState>,
                ) {
                    proof.verify();
                    /*        let authorized = Field(0);
                            let hashedScope = Field.random();
                            Circuit.asProver(() => {
                              hashedScope = Poseidon.hash([
                                Field(publicInput.exp.toString()),
                                scope.hash(),
                              ]);
                            });
                            publicInput.scopes.forEach((v) => {
                              authorized = Circuit.if(
                                hashedScope.equals(v),
                                authorized.add(0),
                                authorized
                              );
                            });
                            authorized.assertGt(0);
                },
            },*/
  },
});
