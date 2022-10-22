import {
  Field,
  SmartContract,
  state,
  State,
  method,
  DeployArgs,
  Permissions,
  PrivateKey,
  UInt64,
  Proof,
  Poseidon,
} from 'snarkyjs';

import { Token, AuthState, PrivateAuthArgs } from './token.js';
import { Role } from './sso-lib.js';
import { MerkleWitness } from './index.js';

const TOKEN_LIFETIME = 3600;
export { SSO };

export class AuthProof extends Proof<AuthState> {
  static publicInputType = AuthState;
  static tag = () => SSO;
}

class SSO extends SmartContract {
  @state(Field) userStoreCommitment = State<Field>();
  @state(Field) roleStoreCommitment = State<Field>();

  deploy(args: DeployArgs) {
    super.deploy(args);
    this.setPermissions({
      ...Permissions.default(),
      editState: Permissions.signature(),
    });
    this.userStoreCommitment.set(Field.zero);
    this.roleStoreCommitment.set(Field.zero);
  }

  @method init(userStoreCommitment: Field, roleStoreCommitment: Field) {
    this.userStoreCommitment.set(userStoreCommitment);
    this.roleStoreCommitment.set(roleStoreCommitment);
  }

  @method updateStateCommitments(
    userStoreCommitment: Field,
    roleStoreCommitment: Field
  ) {
    const currentUserState = this.userStoreCommitment.get();
    const currentRoleState = this.roleStoreCommitment.get();
    this.userStoreCommitment.assertEquals(currentUserState);
    this.roleStoreCommitment.assertEquals(currentRoleState);
    this.userStoreCommitment.set(userStoreCommitment);
    this.roleStoreCommitment.set(roleStoreCommitment);
  }

  @method authenticate(
    privateKey: PrivateKey,
    role: Role,
    userMerkleProof: MerkleWitness,
    roleMerkleProof: MerkleWitness
  ): Promise<AuthProof> {
    this.userStoreCommitment.assertEquals(this.userStoreCommitment.get());
    this.roleStoreCommitment.assertEquals(this.roleStoreCommitment.get());
    this.network.timestamp.assertEquals(this.network.timestamp.get());
    const iat = this.network.timestamp.get();
    const exp = iat.add(UInt64.from(TOKEN_LIFETIME));
    const scopes = Array<Field>(10);
    for (let i = 0; i < scopes.length; i++) {
      scopes[i] = Poseidon.hash([...exp.toFields(), role.scopes[i].hash()]);
    }
    // TODO: add relevant role scopes
    const authState = new AuthState(
      this.userStoreCommitment.get(),
      this.roleStoreCommitment.get(),
      iat,
      exp,
      scopes
    );
    const privateAuthArgs = new PrivateAuthArgs(
      privateKey,
      role,
      userMerkleProof,
      roleMerkleProof,
      this.network.timestamp.get()
    );
    return Token.authenticate(authState, privateAuthArgs);
  }

  /*@method authorize(authState: AuthProof) {

      }*/
}
