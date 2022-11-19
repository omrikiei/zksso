import { MerkleWitness } from 'snarkyjs';
import { User, Role, Scope } from './sso-lib.js'
import { AuthState, PrivateAuthArgs, Token } from './token.js';
import { SSO } from './SSO.js'

export const tree_height = 500; // capped by 1000 users
export const token_lifetime_secs = 3600;
export class SSOMerkleWitness extends MerkleWitness(tree_height) {}
export {User, Role, Scope}
export { AuthState, PrivateAuthArgs, Token }
export { SSO }