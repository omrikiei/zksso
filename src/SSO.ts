import {
    Field,
    SmartContract,
    state,
    State,
    method,
    DeployArgs,
    Permissions,
    PrivateKey,
    UInt64, Proof,
} from 'snarkyjs';

import {Token, AuthState, PrivateAuthArgs} from "./token";
import { Role } from './sso-lib'
import type {TreeWitness} from "./index";

const TOKEN_LIFETIME = 3600;

export class SSO extends SmartContract {
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
  
    @method updateStateCommitments(userStoreCommitment: Field, roleStoreCommitment: Field) {
      const currentUserState = this.userStoreCommitment.get();
      const currentRoleState = this.roleStoreCommitment.get();
      this.userStoreCommitment.assertEquals(currentUserState);
      this.roleStoreCommitment.assertEquals(currentRoleState);
      this.userStoreCommitment.set(userStoreCommitment);
      this.roleStoreCommitment.set(roleStoreCommitment);
    }

    @method authenticate(privateKey: PrivateKey, role: Role ,userMerkleProof: TreeWitness, roleMerkleProof: TreeWitness): Promise<Proof<AuthState>> {
        this.userStoreCommitment.assertEquals(this.userStoreCommitment.get());
        this.roleStoreCommitment.assertEquals(this.roleStoreCommitment.get());
        const iat = this.network.timestamp.get();
        const exp = iat.add(UInt64.from(TOKEN_LIFETIME));
        // TODO: add relevant role scopes
        const authState = new AuthState(this.userStoreCommitment.get(), this.roleStoreCommitment.get(), iat, exp, role.scopes)
        const privateAuthArgs = new PrivateAuthArgs(privateKey,
            role,
            userMerkleProof,
            roleMerkleProof)
        return Token.authenticate(
            authState,
            privateAuthArgs
        );
    }

    @method authorize(authState: Proof<AuthState>) {

    }
  }
  