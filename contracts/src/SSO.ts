import {
  Field,
  SmartContract,
  state,
  State,
  method,
  DeployArgs,
  Permissions,
  Poseidon,
  UInt64,
  PrivateKey,
} from 'snarkyjs';

import { AuthProof } from './token.js';
import { Scope } from './sso-lib.js';
import { token_lifetime_secs } from './index.js';

export { SSO };

class SSO extends SmartContract {
  @state(Field) userStoreCommitment = State<Field>();
  @state(Field) roleStoreCommitment = State<Field>();
  @state(UInt64) maxTokenLifetime = State<UInt64>();

  deploy(args: DeployArgs) {
    super.deploy(args);
    this.setPermissions({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
    });
    this.userStoreCommitment.set(Field(0));
    this.roleStoreCommitment.set(Field(0));
    this.maxTokenLifetime.set(UInt64.from(3600));
  }

  @method init(zkappKey: PrivateKey) {
    super.init(zkappKey);
    this.userStoreCommitment.set(Field(0));
    this.roleStoreCommitment.set(Field(0));
    this.maxTokenLifetime.set(UInt64.from(0));
    this.requireSignature();
  }

  @method
  updateStateCommitments(
    userStoreCommitment: Field,
    roleStoreCommitment: Field,
    maxTokenLifetime: UInt64
  ) {
    const currentUserState = this.userStoreCommitment.get();
    const currentRoleState = this.roleStoreCommitment.get();
    const currentTokenLifetime = this.maxTokenLifetime.get();
    this.userStoreCommitment.assertEquals(currentUserState);
    this.roleStoreCommitment.assertEquals(currentRoleState);
    this.maxTokenLifetime.assertEquals(currentTokenLifetime);
    this.userStoreCommitment.set(userStoreCommitment);
    this.roleStoreCommitment.set(roleStoreCommitment);
    this.maxTokenLifetime.set(maxTokenLifetime);
    this.requireSignature();
  }

  @method
  authorize(authNProof: AuthProof, scope: Scope) {
    this.userStoreCommitment.assertEquals(this.userStoreCommitment.get());
    this.roleStoreCommitment.assertEquals(this.roleStoreCommitment.get());
    this.maxTokenLifetime.assertEquals(this.maxTokenLifetime.get());
    authNProof.verify();
    this.roleStoreCommitment
      .get()
      .assertEquals(authNProof.publicInput.roleStoreCommitment);
    this.userStoreCommitment
      .get()
      .assertEquals(authNProof.publicInput.userStoreCommitment);
    this.network.timestamp.assertEquals(this.network.timestamp.get());
    authNProof.publicInput.iat.assertLte(this.network.timestamp.get());
    authNProof.publicInput.exp.assertGte(this.network.timestamp.get());
    authNProof.publicInput.iat
      .add(new UInt64(token_lifetime_secs))
      .assertGte(authNProof.publicInput.exp);
    authNProof.verify();
    const hashedScope = Poseidon.hash([
      authNProof.publicInput.iat.value,
      scope.value,
    ]);
    authNProof.publicInput.scopes.includes(hashedScope);
  }
}
