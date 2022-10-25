import {
  Field,
  SmartContract,
  state,
  State,
  method,
  DeployArgs,
  Permissions,
  Proof, //UInt64, Poseidon, CircuitString,
} from 'snarkyjs';

import { AuthState, Token } from './token.js';
//import {Role} from './sso-lib.js';
//import {MerkleWitness} from './index.js';

//const MAX_TOKEN_LIFETIME = 3600;
export { SSO };

class AuthProof extends Proof<AuthState> {
  static publicInputType = AuthState;
  static tag = () => Token;
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
    const currentUserState = this.userStoreCommitment.get();
    const currentRoleState = this.roleStoreCommitment.get();
    this.userStoreCommitment.assertEquals(currentUserState);
    this.roleStoreCommitment.assertEquals(currentRoleState);
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

  /*@method authenticate(
         privateKey: PrivateKey,
         role: Role,
         userMerkleProof: MerkleWitness,
         roleMerkleProof: MerkleWitness
     ): Promise<AuthProof> {
         /*this.userStoreCommitment.assertEquals(this.userStoreCommitment.get());
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
         );
         return Token.authenticate(authState, privateAuthArgs);
     }*/

  @method authorize(authState: AuthProof) {
    //}, scope: CircuitString) {
    //this.userStoreCommitment.assertEquals(this.userStoreCommitment.get());
    //this.roleStoreCommitment.assertEquals(this.roleStoreCommitment.get());
    //this.roleStoreCommitment.get().assertEquals(authState.publicInput.roleStoreCommitment);
    //this.userStoreCommitment.get().assertEquals(authState.publicInput.userStoreCommitment);
    //this.network.timestamp.assertEquals(this.network.timestamp.get());
    //authState.publicInput.iat.assertGte(this.network.timestamp.get());
    //authState.publicInput.exp.assertLte(this.network.timestamp.get());
    // authState.publicInput.exp.sub(UInt64.from(MAX_TOKEN_LIFETIME)).assertLte(authState.publicInput.iat);
    authState.verify();
    //const hashedScope = Poseidon.hash([authState.publicInput.exp.value, scope.hash()]);
    // authState.publicInput.scopes.includes(hashedScope);
  }
}
