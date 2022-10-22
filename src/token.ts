import {
  Field,
  CircuitValue,
  prop,
  Experimental,
  UInt64,
  CircuitString,
  PrivateKey,
  SelfProof,
  Circuit,
  arrayProp,
  Poseidon,
} from 'snarkyjs';
import ZkProgram = Experimental.ZkProgram;
import { Role, User } from './sso-lib.js';
import { TreeWitness } from './index.js';

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

  hash() {
    return Poseidon.hash(this.toFields());
  }
}

class PrivateAuthArgs extends CircuitValue {
  @prop userProof: Field;
  @prop roleProof: Field;
  @prop networkTime: UInt64;

  constructor(
    privateKey: PrivateKey,
    role: Role,
    userProof: TreeWitness,
    roleProof: TreeWitness,
    networkTime: UInt64
  ) {
    super();
    this.userProof = userProof.calculateRoot(
      User.fromPrivateKey(privateKey, role.name.hash()).hash()
    );
    this.roleProof = roleProof.calculateRoot(role.hash());
    this.networkTime = networkTime;
  }

  hash() {
    return Poseidon.hash(this.toFields());
  }
}

const Token = ZkProgram({
  publicInput: AuthState,
  methods: {
    authenticate: {
      privateInputs: [PrivateAuthArgs],
      method(publicInput: AuthState, privateAuthArgs: PrivateAuthArgs) {
        publicInput.exp.assertGt(privateAuthArgs.networkTime);
        publicInput.iat.assertLte(privateAuthArgs.networkTime);
        privateAuthArgs.roleProof.assertEquals(publicInput.roleStoreCommitment);
        privateAuthArgs.userProof.assertEquals(publicInput.userStoreCommitment);
      },
    },
    authorize: {
      privateInputs: [SelfProof, CircuitString],
      method(
        publicInput: AuthState,
        authProof: SelfProof<AuthState>,
        scope: CircuitString
      ) {
        authProof.verify();
        let authorized = Field(0);
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
    },
  },
});
