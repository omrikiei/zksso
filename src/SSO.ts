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
  CircuitString,
} from 'snarkyjs';

import { AuthProof } from './token.js';

export { SSO };

class SSO extends SmartContract {
  @state(Field) userStoreCommitment = State<Field>();
  @state(Field) roleStoreCommitment = State<Field>();
  @state(UInt64) maxTokenLifetime = State<UInt64>();

  deploy(args: DeployArgs) {
    super.deploy(args);
    this.setPermissions({
      ...Permissions.default(),
      editState: Permissions.signature(),
    });
    this.userStoreCommitment.set(Field.zero);
    this.roleStoreCommitment.set(Field.zero);
    this.maxTokenLifetime.set(UInt64.from(3600));
  }

  @method init(
    userStoreCommitment: Field,
    roleStoreCommitment: Field,
    maxTokenLifetime: UInt64
  ) {
    const currentUserState = this.userStoreCommitment.get();
    const currentRoleState = this.roleStoreCommitment.get();
    const currentMaxTokenLifetime = this.maxTokenLifetime.get();
    this.maxTokenLifetime.assertEquals(currentMaxTokenLifetime);
    this.userStoreCommitment.assertEquals(currentUserState);
    this.roleStoreCommitment.assertEquals(currentRoleState);
    this.userStoreCommitment.set(userStoreCommitment);
    this.roleStoreCommitment.set(roleStoreCommitment);
    this.maxTokenLifetime.set(maxTokenLifetime);
  }

  @method updateStateCommitments(
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
  }

  @method authorize(authNProof: AuthProof, scope: CircuitString) {
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
    authNProof.publicInput.iat.assertGte(this.network.timestamp.get());
    authNProof.publicInput.exp.assertLte(this.network.timestamp.get());
    authNProof.publicInput.exp
      .sub(UInt64.from(this.maxTokenLifetime.get()))
      .assertLte(authNProof.publicInput.iat);
    authNProof.verify();
    const hashedScope = Poseidon.hash([
      authNProof.publicInput.iat.value,
      scope.hash(),
    ]);
    authNProof.publicInput.scopes.includes(hashedScope);
  }
}
